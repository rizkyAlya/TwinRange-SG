from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException
import os
import random
import sys
import time
from datetime import datetime

FIELD_IP = "10.0.1.2"
GATEWAY_IP = "10.0.2.2"
MODBUS_PORT = 5020

V_BASE_ADDR = 0
I_BASE_ADDR = 10
PF_BASE_ADDR = 30
BREAKER_BASE_ADDR = 0
BREAKER_FB_BASE_ADDR = 20
PF_FB_BASE_ADDR = 30
DATA_CYCLE_ADDR = 90
CMD_ID_ADDR = 91
ORIGIN_CYCLE_ADDR = 92
V_SCALE = 1000
I_SCALE = 30
PF_SCALE = 10000
NUM_BUS = 5

LOOP_INTERVAL_S = float(os.environ.get("RTU_LOOP_INTERVAL_S", "1"))

RTU_NOISE_SEED = int(os.environ.get("RTU_NOISE_SEED", "7"))
V_NOISE_SIGMA = float(os.environ.get("RTU_V_NOISE_SIGMA", "0.003"))
I_NOISE_SIGMA = float(os.environ.get("RTU_I_NOISE_SIGMA", "1.5"))
_noise_rng = random.Random(RTU_NOISE_SEED)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(BASE_DIR)
from src.logger.host_csv_logger import breaker_state, log_control_plane, log_data_plane, timestamp

field_client = ModbusTcpClient(FIELD_IP, port=MODBUS_PORT)
gateway_client = ModbusTcpClient(GATEWAY_IP, port=MODBUS_PORT)


def _connect_with_retry(client: ModbusTcpClient, label: str, retry_delay_s: float = 1.0) -> None:
    while True:
        try:
            ok = client.connect()
            if ok:
                return
            print(f"Connection to {label} failed (connect() returned False). Retrying in {retry_delay_s}s...")
        except Exception as e:
            print(f"Connection to {label} failed: {e}. Retrying in {retry_delay_s}s...")
        time.sleep(retry_delay_s)


def _is_connected(client: ModbusTcpClient) -> bool:
    val = getattr(client, "connected", None)
    if val is None:
        return False
    try:
        return bool(val)
    except Exception:
        return False


def ensure_connections() -> None:
    if not _is_connected(field_client):
        _connect_with_retry(field_client, f"FIELD ({FIELD_IP}:{MODBUS_PORT})")
    if not _is_connected(gateway_client):
        _connect_with_retry(gateway_client, f"GATEWAY ({GATEWAY_IP}:{MODBUS_PORT})")


breaker_cmd = {bus: 1 for bus in range(1, NUM_BUS + 1)}


def apply_measurement_noise(v_pu, i_amp):
    v_noisy = v_pu + _noise_rng.gauss(0.0, V_NOISE_SIGMA)
    i_noisy = max(0.0, i_amp + _noise_rng.gauss(0.0, I_NOISE_SIGMA))
    return v_noisy, i_noisy


def read_modbus_bus(bus):
    addr_v = V_BASE_ADDR + (bus - 1)
    addr_i = I_BASE_ADDR + (bus - 1)
    addr_pf = PF_BASE_ADDR + (bus - 1)
    rr_v = field_client.read_holding_registers(addr_v, 1, unit=1)
    rr_i = field_client.read_holding_registers(addr_i, 1, unit=1)
    rr_pf = field_client.read_holding_registers(addr_pf, 1, unit=1)
    if rr_v.isError() or rr_i.isError() or rr_pf.isError():
        return None, None, None
    v = rr_v.registers[0] / V_SCALE
    i = rr_i.registers[0] / I_SCALE
    pf = rr_pf.registers[0] / PF_SCALE
    return v, i, pf


def read_data_cycle():
    rr = field_client.read_holding_registers(DATA_CYCLE_ADDR, 1, unit=1)
    if rr.isError() or not rr.registers:
        return 0
    return int(rr.registers[0])


def read_breaker_field(bus):
    """Status switch aktual di field."""
    addr = BREAKER_BASE_ADDR + (bus - 1)
    rr = field_client.read_coils(addr, 1, unit=0)
    if rr.isError() or not rr.bits:
        return None
    return 1 if rr.bits[0] else 0


def read_breaker_command(bus):
    addr_cmd = BREAKER_BASE_ADDR + (bus - 1)
    rr_cmd = gateway_client.read_coils(addr_cmd, 1, unit=1)
    if rr_cmd.isError() or not rr_cmd.bits:
        return None
    return 1 if rr_cmd.bits[0] else 0


def read_command_meta():
    rr_cmd = gateway_client.read_holding_registers(CMD_ID_ADDR, 1, unit=1)
    rr_origin = gateway_client.read_holding_registers(ORIGIN_CYCLE_ADDR, 1, unit=1)
    cmd_id = 0 if rr_cmd.isError() or not rr_cmd.registers else int(rr_cmd.registers[0])
    origin_cycle = 0 if rr_origin.isError() or not rr_origin.registers else int(rr_origin.registers[0])
    return cmd_id, origin_cycle


def update_breaker_field(bus, status):
    addr_brk = BREAKER_BASE_ADDR + (bus - 1)
    try:
        field_client.write_coil(addr_brk, bool(status), unit=0)
    except Exception as e:
        print(f"Error update breaker FIELD bus {bus}: {e}")


def update_field_command_meta(cmd_id, origin_cycle):
    try:
        field_client.write_register(CMD_ID_ADDR, int(cmd_id), unit=0)
        field_client.write_register(ORIGIN_CYCLE_ADDR, int(origin_cycle), unit=0)
    except Exception as e:
        print(f"Error update command metadata FIELD: {e}")


def send_to_gateway_modbus(bus, v, i, pf, breaker_fb):
    addr_v = V_BASE_ADDR + (bus - 1)
    addr_i = I_BASE_ADDR + (bus - 1)
    addr_pf = PF_FB_BASE_ADDR + (bus - 1)
    addr_b = BREAKER_FB_BASE_ADDR + (bus - 1)
    try:
        gateway_client.write_register(DATA_CYCLE_ADDR, int(read_data_cycle()), unit=1)
        gateway_client.write_register(addr_v, int(v * V_SCALE), unit=1)
        gateway_client.write_register(addr_i, int(i * I_SCALE), unit=1)
        gateway_client.write_register(addr_pf, int(pf * PF_SCALE), unit=1)
        gateway_client.write_register(addr_b, int(breaker_fb), unit=1)
    except Exception as e:
        print(f"Error kirim ke gateway Modbus bus {bus}: {e}")


def apply_dt_commands(ts):
    """Terapkan perintah breaker terbaru dari gateway ke field."""
    ts_received = timestamp()
    cmd_id, origin_cycle = read_command_meta()
    for bus in range(1, NUM_BUS + 1):
        cmd = read_breaker_command(bus)
        if cmd in (0, 1):
            breaker_cmd[bus] = cmd
        update_breaker_field(bus, breaker_cmd[bus])
    update_field_command_meta(cmd_id, origin_cycle)
    log_control_plane(
        "h2",
        {
            "cmd_id": cmd_id,
            "origin_cycle": origin_cycle,
            "ts_received": ts_received,
            "ts_sent": timestamp(),
            "breaker_DT": breaker_state(breaker_cmd),
        },
    )
    print(f"[{ts}] CMD DT diterapkan ke field")


def upload_measurements(ts):
    """Baca pengukuran field dan kirim ke gateway."""
    ok = True
    cycle_id = read_data_cycle()
    for bus in range(1, NUM_BUS + 1):
        v, i, pf = read_modbus_bus(bus)
        ts_received = timestamp()
        if v is None or i is None or pf is None:
            print(f"Error baca Modbus bus {bus}")
            ok = False
            continue

        v_raw, i_raw = v, i
        v, i = apply_measurement_noise(v, i)

        brk_fb = read_breaker_field(bus)
        if brk_fb is None:
            brk_fb = breaker_cmd[bus]

        ts_sent = timestamp()
        send_to_gateway_modbus(bus, v, i, pf, brk_fb)
        log_data_plane(
            "h2",
            {
                "cycle_id": cycle_id,
                "ts_received": ts_received,
                "ts_sent": ts_sent,
                "bus": bus,
                "V_sent": f"{v:.6f}",
                "I_sent": f"{i:.6f}",
                "power_factor": f"{pf:.6f}",
                "breaker_actual": brk_fb,
            },
        )

        print(
            f"[{ts}] Bus {bus}: V={v:.3f} pu (raw {v_raw:.3f}) "
            f"I={i:.1f} A (raw {i_raw:.1f}) PF={pf:.4f} "
            f"FB={'CLOSE' if brk_fb == 1 else 'OPEN'} "
            f"CMD={'CLOSE' if breaker_cmd[bus] == 1 else 'OPEN'}"
        )
    return ok


try:
    ensure_connections()
    print(
        f"RTU measurement noise: seed={RTU_NOISE_SEED} V_sigma={V_NOISE_SIGMA} "
        f"I_sigma={I_NOISE_SIGMA}"
    )
    print(f"Siklus realtime RTU: interval={LOOP_INTERVAL_S}s")

    while True:
        print("\n")
        t_cycle = time.monotonic()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            ensure_connections()

            apply_dt_commands(ts)

            if not upload_measurements(ts):
                time.sleep(1)
                continue

        except ConnectionException as e:
            print(f"[{ts}] Koneksi Modbus terputus: {e}. Reconnecting...")
            try:
                field_client.close()
            except Exception:
                pass
            try:
                gateway_client.close()
            except Exception:
                pass
            time.sleep(1)
            continue

        elapsed = time.monotonic() - t_cycle
        remain = LOOP_INTERVAL_S - elapsed
        if remain > 0:
            time.sleep(remain)

except KeyboardInterrupt:
    print("RTU/IED dihentikan")

finally:
    field_client.close()
    gateway_client.close()
