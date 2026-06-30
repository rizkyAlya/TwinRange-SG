# Collector metrik jaringan: ping untuk RTT/loss dan iperf untuk throughput,
# lalu merangkum mean/std_dev per layer komunikasi.
import re
import csv
import datetime
import time
import os
import shlex
import statistics
import yaml

# Parameter default pengukuran jaringan; dapat dioverride dari pemanggil collect_data.
NUM_RUNS = 3
IPERF_PORT = 5001
IPERF_DURATION_S = 5
IPERF_CONNECT_TIMEOUT_S = 8
IPERF_MAX_RETRIES = 3
IPERF_ERROR_TAIL_CHARS = 220

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_CONFIG_PATH = os.path.join(project_root, "configs", "topology.yaml")


def _resolve_links_from_config(config_path):
    """
    Ambil link pengukuran dari role pertama di topology.yaml:
    field = rtu[0] -> gateway[0], system = gateway[0] -> dt[0].
    Return tuple: (layer, source_host, destination_ip, destination_host).
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    zones = config.get("topology", {}).get("zones", {})
    hosts_by_role = {}
    ip_by_host = {}

    for zone in zones.values():
        subnet = zone.get("subnet", "")
        subnet_base = subnet.split("/")[0].rsplit(".", 1)[0] if subnet else ""
        for i, host in enumerate(zone.get("hosts", [])):
            name = host.get("name")
            role = host.get("role")
            if not name or not role:
                continue
            hosts_by_role.setdefault(role, []).append(name)
            if subnet_base:
                ip_by_host[name] = f"{subnet_base}.{i + 2}"

    required_roles = ("rtu", "gateway", "dt")
    missing = [r for r in required_roles if r not in hosts_by_role or not hosts_by_role[r]]
    if missing:
        raise ValueError(f"Missing required role(s) in config: {', '.join(missing)}")

    rtu = hosts_by_role["rtu"][0]
    gateway = hosts_by_role["gateway"][0]
    dt_host = hosts_by_role["dt"][0]

    return [
        ("field", rtu, ip_by_host[gateway], gateway),
        ("system", gateway, ip_by_host[dt_host], dt_host),
    ]


def _is_scenario_session_root(logs_path):
    """True jika logs_path = logs/<baseline|mitm|dos>/<run_id>/ (satu sesi orchestrator)."""
    if not logs_path:
        return False
    parent = os.path.basename(os.path.dirname(os.path.abspath(logs_path)))
    return parent in ("baseline", "mitm", "dos")


def _extract_throughput_mbps(output: str):
    """
    Parse throughput dari output iperf2/iperf3 teks.
    Return float Mbps atau None jika tidak ada match valid.
    """
    # Contoh: "4.95 Mbits/sec", "980 Kbits/sec", "1.2 Gbits/sec"
    matches = re.findall(r'(\d+(?:\.\d+)?)\s*([KMG])bits/sec', output, flags=re.IGNORECASE)
    if not matches:
        return None
    value_s, unit = matches[-1]
    value = float(value_s)
    u = unit.upper()
    if u == "K":
        return value / 1000.0
    if u == "G":
        return value * 1000.0
    return value


def _write_header_if_needed(writer, path, header):
    """Tulis header hanya saat file baru/kosong agar append per iterasi tetap rapi."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        writer.writerow(header)


def _group_metric_values(path, value_column, *, throughput=False):
    """Kelompokkan nilai metrik per layer/source/destination untuk summary."""
    grouped = {}
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return grouped

    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = float(row.get(value_column, ""))
            except (TypeError, ValueError):
                continue
            if throughput and row.get("status") != "ok":
                continue
            key = (row.get("layer", ""), row.get("source", ""), row.get("destination", ""))
            grouped.setdefault(key, []).append(value)
    return grouped


def _write_summary_from_metric_csvs(summary_path, rtt_path, loss_path, th_path):
    """Bangun summary.csv dari CSV RTT, packet loss, dan throughput."""
    groups = [
        ("RTT", _group_metric_values(rtt_path, "latency_ms")),
        ("Packet Loss", _group_metric_values(loss_path, "packet_loss_percent")),
        ("Throughput", _group_metric_values(th_path, "throughput_Mbps", throughput=True)),
    ]

    with open(summary_path, "w", newline="") as sum_file:
        sum_writer = csv.writer(sum_file)
        sum_writer.writerow(["metric","layer","source","destination","mean","std_dev"])

        for metric, grouped in groups:
            for key, values in grouped.items():
                if values:
                    layer, src, dst = key
                    mean = round(statistics.mean(values), 2)
                    std = round(statistics.stdev(values), 2) if len(values) > 1 else 0
                    sum_writer.writerow([metric, layer, src, dst, mean, std])


def collect_data(
    net,
    mode="baseline",
    logs_path=None,
    config_path=None,
    measure_phase=None,
    iteration=None,
    num_runs=NUM_RUNS,
):
    """
    Kumpulkan RTT, packet loss, dan throughput.

    Unified (logs_path = logs/<baseline|mitm|dos>/<run_id>/): menyimpan di
    .../network/baseline|mitm|dos/...

    measure_phase: jika diisi, kolom fase ditambahkan pada CSV (selaras trace).
    iteration: jika diisi, kolom run memakai N dan data di-append ke CSV mode yang sama.

    Legacy flat timestamp (logs_path = logs/<timestamp>/): seperti semula,
    langsung di bawah logs_path tanpa subfolder network/.

    Tanpa logs_path: logs/baseline atau logs/dos/<mode> / logs/<mode>.
    """
    if logs_path:
        if _is_scenario_session_root(logs_path):
            net_prefix = os.path.join(logs_path, "network")
            if mode == "baseline":
                log_dir = os.path.join(net_prefix, "baseline")
            elif mode in ("light", "heavy"):
                log_dir = os.path.join(net_prefix, "dos", mode)
            else:
                log_dir = os.path.join(net_prefix, mode)
        elif mode == "baseline":
            log_dir = os.path.join(logs_path, "baseline")
        elif mode in ("light", "heavy"):
            log_dir = os.path.join(logs_path, "dos", mode)
        else:
            log_dir = os.path.join(logs_path, mode)
    else:
        if mode == "baseline":
            log_dir = os.path.join(base_dir, "logs", "baseline")
        elif mode in ("light", "heavy"):
            log_dir = os.path.join(base_dir, "logs", "dos", mode)
        else:
            log_dir = os.path.join(base_dir, "logs", mode)

    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    try:
        links = _resolve_links_from_config(config_path)
    except Exception as e:
        print(f"Warning: using fallback links, failed to parse config ({e})")
        links = [
            ("field", "h2", "10.0.2.2", "h3"),
            ("system", "h3", "10.0.3.2", "h4"),
        ]

    os.makedirs(log_dir, exist_ok=True)

    rtt_path = os.path.join(log_dir, "rtt.csv")
    loss_path = os.path.join(log_dir, "packet_loss.csv")
    th_path = os.path.join(log_dir, "throughput.csv")
    summary_path = os.path.join(log_dir, "summary.csv")

    print(f"\nStarting data collection mode: {mode}")
    print(f"Saving to: {log_dir}")

    use_fase = measure_phase is not None
    file_mode = "a" if iteration is not None else "w"
    rtt_header = ["timestamp", "run", "layer", "source", "destination", "latency_ms"]
    loss_header = ["timestamp", "run", "layer", "source", "destination", "packet_loss_percent"]
    th_header = [
        "timestamp",
        "run",
        "layer",
        "source",
        "destination",
        "throughput_Mbps",
        "status",
        "error",
        "raw_output_tail",
    ]
    if use_fase:
        rtt_header.insert(2, "fase")
        loss_header.insert(2, "fase")
        th_header.insert(2, "fase")

    # Ping menghasilkan sampel RTT per paket dan ringkasan packet loss per run.
    with open(rtt_path, file_mode, newline="") as rtt_file, \
         open(loss_path, file_mode, newline="") as loss_file:

        rtt_writer = csv.writer(rtt_file)
        loss_writer = csv.writer(loss_file)

        _write_header_if_needed(rtt_writer, rtt_path, rtt_header)
        _write_header_if_needed(loss_writer, loss_path, loss_header)

        for layer, host, dest_ip, dest_host in links:
            for run in range(num_runs):
                run_id = int(iteration) if iteration is not None else run + 1
                print(f"[{datetime.datetime.now()}] {mode.upper()} - RTT & Loss: {layer} (Run {run_id})")

                output = net.get(host).cmd(f"ping -c 20 {dest_ip}")

                # Parsing RTT: satu baris ping sukses menjadi satu sampel latency.
                for line in output.split("\n"):
                    if "time=" in line:
                        latency = re.search(r'time=(\d+\.?\d*)', line)
                        if latency:
                            value = float(latency.group(1))
                            row_rtt = [
                                datetime.datetime.now(),
                                run_id,
                                layer,
                                host,
                                dest_host,
                                value,
                            ]
                            if use_fase:
                                row_rtt.insert(2, measure_phase)
                            rtt_writer.writerow(row_rtt)

                # Parsing packet loss dari baris ringkasan ping.
                for line in output.split("\n"):
                    if "packet loss" in line:
                        loss = re.search(r'(\d+)% packet loss', line)
                        if loss:
                            value = float(loss.group(1))
                            row_loss = [
                                datetime.datetime.now(),
                                run_id,
                                layer,
                                host,
                                dest_host,
                                value,
                            ]
                            if use_fase:
                                row_loss.insert(2, measure_phase)
                            loss_writer.writerow(row_loss)

                time.sleep(1)

    # Throughput diukur dengan iperf; server dinyalakan di host tujuan tiap run.
    with open(th_path, file_mode, newline="") as th_file:

        th_writer = csv.writer(th_file)
        _write_header_if_needed(th_writer, th_path, th_header)

        for layer, host, dest_ip, dest_host in links:
            for run in range(num_runs):
                run_id = int(iteration) if iteration is not None else run + 1
                print(f"[{datetime.datetime.now()}] {mode.upper()} - Throughput: {layer} (Run {run_id})")
                server_host = dest_host

                throughput = 0.0
                status = "failed"
                error = "parse_failed"
                output_tail = ""

                # Retry menangani kasus server belum siap atau koneksi sempat gagal.
                for attempt in range(1, IPERF_MAX_RETRIES + 1):
                    net.get(server_host).cmd("killall -9 iperf >/dev/null 2>&1 || true")
                    net.get(server_host).cmd(f"iperf -s -p {IPERF_PORT} >/dev/null 2>&1 &")
                    time.sleep(1.2)

                    output = net.get(host).cmd(
                        f"timeout {IPERF_CONNECT_TIMEOUT_S}s iperf -c {dest_ip} -p {IPERF_PORT} -t {IPERF_DURATION_S}"
                    )
                    output_tail = (output or "").strip()[-IPERF_ERROR_TAIL_CHARS:]

                    parsed_value = _extract_throughput_mbps(output or "")
                    if parsed_value is not None:
                        throughput = parsed_value
                        status = "ok"
                        error = ""
                        break

                    text = (output or "").lower()
                    if "timed out" in text or "timeout" in text:
                        error = "timeout"
                    elif "connection refused" in text:
                        error = "refused"
                    elif "unable to connect" in text:
                        error = "unreachable"
                    else:
                        error = "parse_failed"
                    status = f"failed_retry_{attempt}"
                    time.sleep(0.6 * attempt)

                row_th = [
                    datetime.datetime.now(),
                    run_id,
                    layer,
                    host,
                    dest_host,
                    round(throughput, 2),
                    "ok" if throughput > 0 else status,
                    error if throughput == 0 else "",
                    output_tail if throughput == 0 else "",
                ]
                if use_fase:
                    row_th.insert(2, measure_phase)
                th_writer.writerow(row_th)

                net.get(server_host).cmd("killall -9 iperf >/dev/null 2>&1 || true")
                time.sleep(1)

    _write_summary_from_metric_csvs(summary_path, rtt_path, loss_path, th_path)

    print(f"\nData collection ({mode}) complete")
    print(f"CSVs saved in {log_dir}")
