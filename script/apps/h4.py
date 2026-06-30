"""
Digital Twin (h4): 5-bus model (sama arsitektur field), sinkron via OPC UA gateway.
"""
import math
import json
import os
import sys
import time
from datetime import datetime

import pandapower as pp
from opcua import Client

GATEWAY_OPC = os.environ.get(
    "GATEWAY_OPC",
    "opc.tcp://10.0.2.2:4840/mininet/",
)
LOOP_INTERVAL_S = float(os.environ.get("DT_LOOP_INTERVAL_S", "0.2"))
NUM_BUS = 5

OPEN_FACTOR = 1.00
CLOSE_FACTOR = 0.95

# field bus -> pandapower line index (bus 5 tanpa switch line di model ini)
LINE_BY_BUS = {1: 0, 2: 1, 3: 2, 4: 3}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(BASE_DIR)
from src.logger.host_csv_logger import breaker_state, log_control_plane, log_data_plane, timestamp


def energized_from_slack(brk_fb):
    """
    Bus teraliri dari slack (bus 1) sepanjang radial: edge b -> b+1 hanya jika switch b tertutup.
    brk_fb[b]=1 berarti field/CB tertutup untuk line b -> b+1.
    """
    live = {1}
    changed = True
    while changed:
        changed = False
        for b in range(1, NUM_BUS):
            if b in live and brk_fb.get(b, 1) == 1 and (b + 1) not in live:
                live.add(b + 1)
                changed = True
    return live


def _pp_bus_to_logical(bus_nums):
    return {int(bus_nums[k]): k for k in bus_nums}


def apply_blackout_model(net, bus_nums, loads, energized):
    """
    Blackout hilir: bus tidak teraliri slack -> out of service, beban/gen 0, line mati.
    Menghindari island tanpa slack di PF (sumber NaN).
    """
    pp_to_log = _pp_bus_to_logical(bus_nums)

    for b in range(1, NUM_BUS + 1):
        idx_pp = bus_nums[b]
        net.bus.at[idx_pp, "in_service"] = b in energized

    for bus, load_idx in loads.items():
        if bus not in energized:
            net.load.at[load_idx, "p_mw"] = 0.0
            net.load.at[load_idx, "q_mvar"] = 0.0

    for gi in net.gen.index:
        gen_bus_pp = int(net.gen.at[gi, "bus"])
        log_bus = pp_to_log.get(gen_bus_pp, 4)
        net.gen.at[gi, "in_service"] = log_bus in energized
        if log_bus not in energized:
            net.gen.at[gi, "p_mw"] = 0.0

    for li in net.line.index:
        fb = int(net.line.at[li, "from_bus"])
        tb = int(net.line.at[li, "to_bus"])
        b_from = pp_to_log.get(fb)
        b_to = pp_to_log.get(tb)
        if b_from is None or b_to is None:
            continue
        net.line.at[li, "in_service"] = (b_from in energized) and (b_to in energized)


def build_network():
    net = pp.create_empty_network()

    bus1 = pp.create_bus(net, vn_kv=110, name="Slack Bus")
    bus2 = pp.create_bus(net, vn_kv=110, name="Load Bus 1")
    bus3 = pp.create_bus(net, vn_kv=110, name="Load Bus 2")
    bus4 = pp.create_bus(net, vn_kv=110, name="Generator Bus")
    bus5 = pp.create_bus(net, vn_kv=110, name="Critical Load")

    pp.create_ext_grid(net, bus=bus1, vm_pu=1.02, name="Grid Connection")
    pp.create_gen(net, bus=bus4, p_mw=80, vm_pu=1.01, name="Generator")

    load2 = pp.create_load(net, bus=bus2, p_mw=60, q_mvar=15, name="Load 2")
    load3 = pp.create_load(net, bus=bus3, p_mw=70, q_mvar=20, name="Load 3")
    load5 = pp.create_load(net, bus=bus5, p_mw=90, q_mvar=30, name="Critical Load")

    line1 = pp.create_line_from_parameters(
        net, from_bus=bus1, to_bus=bus2, length_km=10,
        r_ohm_per_km=0.05, x_ohm_per_km=0.12, c_nf_per_km=0, max_i_ka=1.176, name="Line 1",
    )
    line2 = pp.create_line_from_parameters(
        net, from_bus=bus2, to_bus=bus3, length_km=5,
        r_ohm_per_km=0.04, x_ohm_per_km=0.10, c_nf_per_km=0, max_i_ka=0.682, name="Line 2",
    )
    line3 = pp.create_line_from_parameters(
        net, from_bus=bus3, to_bus=bus4, length_km=5,
        r_ohm_per_km=0.06, x_ohm_per_km=0.15, c_nf_per_km=0, max_i_ka=0.227, name="Line 3",
    )
    line4 = pp.create_line_from_parameters(
        net, from_bus=bus4, to_bus=bus5, length_km=8,
        r_ohm_per_km=0.03, x_ohm_per_km=0.08, c_nf_per_km=0, max_i_ka=0.646, name="Line 4",
    )

    switches_by_bus = {
        1: pp.create_switch(net, bus=bus1, element=line1, et="l", closed=True, type="CB"),
        2: pp.create_switch(net, bus=bus2, element=line2, et="l", closed=True, type="CB"),
        3: pp.create_switch(net, bus=bus3, element=line3, et="l", closed=True, type="CB"),
        4: pp.create_switch(net, bus=bus4, element=line4, et="l", closed=True, type="CB"),
    }

    bus_nums = {1: bus1, 2: bus2, 3: bus3, 4: bus4, 5: bus5}
    loads = {2: load2, 3: load3, 5: load5}
    return net, bus_nums, loads, switches_by_bus


def apply_topology_from_feedback(net, switches_by_bus, brk_fb):
    for bus, sw_idx in switches_by_bus.items():
        net.switch.at[sw_idx, "closed"] = brk_fb.get(bus, 1) == 1


def apply_pq_to_loads(net, loads, p_by_bus, q_by_bus, energized):
    """P/Q dari OPC hanya untuk bus teraliri; bus blackout -> 0."""
    for bus, load_idx in loads.items():
        if bus not in energized:
            net.load.at[load_idx, "p_mw"] = 0.0
            net.load.at[load_idx, "q_mvar"] = 0.0
        else:
            net.load.at[load_idx, "p_mw"] = float(p_by_bus[bus])
            net.load.at[load_idx, "q_mvar"] = float(q_by_bus[bus])


def _finite_or_zero(x):
    try:
        v = float(x)
    except (TypeError, ValueError):
        return 0.0
    return v if math.isfinite(v) else 0.0


def _voltage_snapshot(net, bus_nums, energized):
    out = []
    for b in range(1, NUM_BUS + 1):
        vm = _finite_or_zero(net.res_bus.vm_pu.at[bus_nums[b]])
        if b not in energized:
            vm = 0.0
        out.append(vm)
    return out


def _line_i_ka_safe(net, line_idx):
    try:
        i_from = float(net.res_line.i_from_ka.at[line_idx])
        i_to = float(net.res_line.i_to_ka.at[line_idx])
    except (KeyError, TypeError, ValueError):
        return 0.0, 0.0, 0.0
    if not math.isfinite(i_from) or not math.isfinite(i_to):
        return 0.0, 0.0, 0.0
    a, b = abs(i_from), abs(i_to)
    return a, b, max(a, b)


def _log_bus_cycle(
    ts_row,
    bus,
    bus_nums,
    switches_by_bus,
    net,
    brk_fb,
    cmd,
    p_in,
    q_in,
    energized,
):
    idx_pp = bus_nums[bus]
    dead = bus not in energized
    vm_pu = 0.0 if dead else _finite_or_zero(net.res_bus.vm_pu.at[idx_pp])

    line_idx = LINE_BY_BUS.get(bus)
    if line_idx is None:
        print(
            f"[h4] {ts_row} bus={bus} line=- pp_bus={idx_pp} | "
            f"no_line_switch | dead={dead} brk_fb={brk_fb[bus]} cmd={cmd[bus]} | "
            f"vm_pu={vm_pu:.4f} P_in={p_in:.4f} Q_in={q_in:.4f}",
            flush=True,
        )
        return

    sw_idx = switches_by_bus[bus]
    i_from_ka, i_to_ka, i_line_ka = _line_i_ka_safe(net, line_idx)
    max_i = float(net.line.max_i_ka.at[line_idx])
    thr_open = max_i * OPEN_FACTOR
    thr_close = max_i * CLOSE_FACTOR
    was_closed = bool(net.switch.at[sw_idx, "closed"])
    in_svc = bool(net.line.in_service.at[line_idx])

    print(
        f"[h4] {ts_row} bus={bus} line={line_idx} pp_bus={idx_pp} | "
        f"i_from={i_from_ka:.4f} i_to={i_to_ka:.4f} i_line={i_line_ka:.4f} kA | "
        f"max_i={max_i:.4f} thr_open={thr_open:.4f} thr_close={thr_close:.4f} | "
        f"was_closed={was_closed} cmd={cmd[bus]} in_svc={in_svc} brk_fb={brk_fb[bus]} dead={dead} | "
        f"vm_pu={vm_pu:.4f} P_in={p_in:.4f} Q_in={q_in:.4f}",
        flush=True,
    )


def protection_commands(net, switches_by_bus, brk_fb, energized):
    """
    O/C pada line yang teraliri; bus mati / arus tidak valid -> CMD ikut brk_fb (topologi).
    """
    cmd = {bus: int(brk_fb.get(bus, 1)) for bus in range(1, NUM_BUS + 1)}

    for bus, sw_idx in switches_by_bus.items():
        line_idx = LINE_BY_BUS[bus]
        if bus not in energized:
            cmd[bus] = int(brk_fb.get(bus, 1))
            continue

        was_closed = bool(net.switch.at[sw_idx, "closed"])
        if not was_closed:
            _ifr, _ito, i_line = _line_i_ka_safe(net, line_idx)
            max_i = float(net.line.max_i_ka.at[line_idx])
            i_close = max_i * CLOSE_FACTOR
            cmd[bus] = 1 if i_line < i_close else 0
            continue

        _ifr, _ito, i_line = _line_i_ka_safe(net, line_idx)
        max_i = float(net.line.max_i_ka.at[line_idx])
        i_open = max_i * OPEN_FACTOR
        i_close = max_i * CLOSE_FACTOR
        if i_line > i_open:
            cmd[bus] = 0
        elif i_line < i_close:
            cmd[bus] = 1
        else:
            cmd[bus] = 1
    return cmd


def connect_opcua():
    client = Client(GATEWAY_OPC)
    while True:
        try:
            client.connect()
            print(f"OPC UA connected: {GATEWAY_OPC}", flush=True)
            return client
        except Exception as exc:
            print(f"OPC connect failed: {exc}; retry 2s", flush=True)
            time.sleep(2)


def get_opcua_nodes(client):
    idx = client.get_namespace_index("mininet-opcua")
    print(f"Namespace index: {idx}", flush=True)
    root = client.get_root_node()
    p_nodes, q_nodes, v_dt_nodes, brk_fb_nodes, cmd_nodes = {}, {}, {}, {}, {}
    for bus in range(1, NUM_BUS + 1):
        p_nodes[bus] = root.get_child(["0:Objects", f"{idx}:SENSORS", f"{idx}:P_bus_{bus}"])
        q_nodes[bus] = root.get_child(["0:Objects", f"{idx}:SENSORS", f"{idx}:Q_bus_{bus}"])
        v_dt_nodes[bus] = root.get_child(["0:Objects", f"{idx}:SENSORS", f"{idx}:V_DT_bus_{bus}"])
        brk_fb_nodes[bus] = root.get_child(["0:Objects", f"{idx}:SENSORS", f"{idx}:BRK_FB_bus_{bus}"])
        cmd_nodes[bus] = root.get_child(["0:Objects", f"{idx}:COMMANDS", f"{idx}:CMD_bus_{bus}"])
    data_cycle_node = root.get_child(["0:Objects", f"{idx}:SENSORS", f"{idx}:DATA_cycle"])
    data_queue_node = root.get_child(["0:Objects", f"{idx}:SENSORS", f"{idx}:DATA_queue"])
    cmd_id_node = root.get_child(["0:Objects", f"{idx}:COMMANDS", f"{idx}:CMD_id"])
    origin_cycle_node = root.get_child(["0:Objects", f"{idx}:COMMANDS", f"{idx}:ORIGIN_cycle"])
    return p_nodes, q_nodes, v_dt_nodes, brk_fb_nodes, cmd_nodes, data_cycle_node, data_queue_node, cmd_id_node, origin_cycle_node


def main():
    net, bus_nums, loads, switches_by_bus = build_network()
    pp.runpp(net)

    print("Field bus -> Pandapower bus mapping:", bus_nums, flush=True)
    print("Unique bus->line mapping:", LINE_BY_BUS, flush=True)

    client = connect_opcua()
    (
        p_nodes,
        q_nodes,
        v_dt_nodes,
        brk_fb_nodes,
        cmd_nodes,
        data_cycle_node,
        data_queue_node,
        cmd_id_node,
        origin_cycle_node,
    ) = get_opcua_nodes(client)
    cmd_id = 0
    processed_cycles = set()

    while True:
        try:
            t_iter = time.monotonic()
            ts_received = timestamp()
            try:
                snapshots = json.loads(data_queue_node.get_value() or "[]")
            except Exception:
                snapshots = []

            snapshot = None
            for candidate in snapshots:
                candidate_cycle = int(candidate.get("cycle_id", 0))
                if candidate_cycle > 0 and candidate_cycle not in processed_cycles:
                    snapshot = candidate
                    break

            if snapshot is not None:
                cycle_id = int(snapshot["cycle_id"])
                p_raw = snapshot.get("p", {})
                q_raw = snapshot.get("q", {})
                brk_raw = snapshot.get("brk", {})
                brk_fb = {
                    bus: (1 if int(brk_raw.get(str(bus), 1)) == 1 else 0)
                    for bus in range(1, NUM_BUS + 1)
                }
                p_in = {bus: float(p_raw.get(str(bus), 0.0)) for bus in range(1, NUM_BUS + 1)}
                q_in = {bus: float(q_raw.get(str(bus), 0.0)) for bus in range(1, NUM_BUS + 1)}
            else:
                cycle_id = int(data_cycle_node.get_value())
                if cycle_id <= 0 or cycle_id in processed_cycles:
                    elapsed = time.monotonic() - t_iter
                    remain = LOOP_INTERVAL_S - elapsed
                    if remain > 0:
                        time.sleep(remain)
                    continue
                brk_fb = {
                    bus: (1 if int(brk_fb_nodes[bus].get_value()) == 1 else 0)
                    for bus in range(1, NUM_BUS + 1)
                }
                p_in = {bus: float(p_nodes[bus].get_value()) for bus in range(1, NUM_BUS + 1)}
                q_in = {bus: float(q_nodes[bus].get_value()) for bus in range(1, NUM_BUS + 1)}

            if cycle_id <= 0:
                elapsed = time.monotonic() - t_iter
                remain = LOOP_INTERVAL_S - elapsed
                if remain > 0:
                    time.sleep(remain)
                continue

            apply_topology_from_feedback(net, switches_by_bus, brk_fb)
            energized = energized_from_slack(brk_fb)
            dead = sorted(set(range(1, NUM_BUS + 1)) - energized)
            apply_pq_to_loads(net, loads, p_in, q_in, energized)
            apply_blackout_model(net, bus_nums, loads, energized)

            ts_row = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                pp.runpp(net)
                for bus in range(1, NUM_BUS + 1):
                    if bus in energized:
                        vm = _finite_or_zero(net.res_bus.vm_pu.at[bus_nums[bus]])
                    else:
                        vm = 0.0
                    v_dt_nodes[bus].set_value(vm)
                print("\n", ts_row, flush=True)
                print(
                    f"Island: energized={sorted(energized)} dead={dead}",
                    flush=True,
                )
                print(
                    "Load flow sukses. Voltage snapshot (pu):",
                    _voltage_snapshot(net, bus_nums, energized),
                    flush=True,
                )
            except Exception:
                print("\n", ts_row, flush=True)
                print("Load flow gagal", flush=True)
                raise

            cmd = protection_commands(net, switches_by_bus, brk_fb, energized)
            cmd_id = ((cmd_id + 1) & 0xFFFF) or 1
            for bus in range(1, NUM_BUS + 1):
                cmd_nodes[bus].set_value(int(cmd[bus]))
            cmd_id_node.set_value(int(cmd_id))
            origin_cycle_node.set_value(int(cycle_id))
            log_control_plane(
                "h4",
                {
                    "cmd_id": cmd_id,
                    "origin_cycle": cycle_id,
                    "ts_sent": timestamp(),
                    "breaker_DT": breaker_state(cmd),
                },
            )

            print("[h4] Siklus selesai, CMD siap ke gateway", flush=True)

            for bus in range(1, NUM_BUS + 1):
                line_idx = LINE_BY_BUS.get(bus)
                if line_idx is None or bus not in energized:
                    i_line = 0.0
                else:
                    _ifr, _ito, i_line_ka = _line_i_ka_safe(net, line_idx)
                    i_line = i_line_ka * 1000.0
                if bus in energized:
                    v_dt = _finite_or_zero(net.res_bus.vm_pu.at[bus_nums[bus]])
                else:
                    v_dt = 0.0
                log_data_plane(
                    "h4",
                    {
                        "cycle_id": cycle_id,
                        "ts_received": ts_received,
                        "bus": bus,
                        "line": "" if line_idx is None else line_idx+1,
                        "V_DT": f"{v_dt:.6f}",
                        "I_line": f"{i_line:.6f}",
                        "breaker_actual": brk_fb[bus],
                    },
                )
                _log_bus_cycle(
                    ts_row,
                    bus,
                    bus_nums,
                    switches_by_bus,
                    net,
                    brk_fb,
                    cmd,
                    p_in[bus],
                    q_in[bus],
                    energized,
                )
            processed_cycles.add(cycle_id)

        except Exception as exc:
            print(f"DT cycle error: {exc}", flush=True)
            try:
                client.disconnect()
            except Exception:
                pass
            client = connect_opcua()
            (
                p_nodes,
                q_nodes,
                v_dt_nodes,
                brk_fb_nodes,
                cmd_nodes,
                data_cycle_node,
                data_queue_node,
                cmd_id_node,
                origin_cycle_node,
            ) = get_opcua_nodes(client)

        elapsed = time.monotonic() - t_iter
        remain = LOOP_INTERVAL_S - elapsed
        if remain > 0:
            time.sleep(remain)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("DT dihentikan", flush=True)
