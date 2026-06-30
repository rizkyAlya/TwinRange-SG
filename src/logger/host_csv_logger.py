# Logger CSV ringan yang dipanggil oleh app host h1-h4 untuk mencatat data plane
# dan control plane per iterasi eksperimen.
import csv
import os
import time

# Marker /tmp ini ditulis orchestrator di setiap namespace host Mininet.
RUN_ROOT_HOST_FILE = "/tmp/cyber_range_run_root"
MEASURE_ITER_HOST_FILE = "/tmp/cyber_range_measure_iter"
MEASURE_PHASE_HOST_FILE = "/tmp/cyber_range_measure_phase"

# Skema CSV data plane per host mengikuti posisi host pada rantai komunikasi.
DATA_HEADERS = {
    "h1": [
        "cycle_id",
        "ts_sent",
        "bus",
        "V_sent",
        "I_sent",
        "P_bus",
        "Q_bus",
        "power_factor",
        "breaker_actual",
    ],
    "h2": [
        "cycle_id",
        "ts_received",
        "ts_sent",
        "bus",
        "V_sent",
        "I_sent",
        "power_factor",
        "breaker_actual",
    ],
    "h3": [
        "cycle_id",
        "ts_received",
        "ts_sent",
        "bus",
        "V_received",
        "I_received",
        "P_sent",
        "Q_sent",
        "breaker_actual",
    ],
    "h4": [
        "cycle_id",
        "ts_received",
        "bus",
        "line",
        "V_DT",
        "I_line",
        "breaker_actual",
    ],
}

# Skema CSV control plane dipecah per bus saat breaker_DT berisi banyak bus.
CONTROL_HEADERS = {
    "h1": ["cmd_id", "origin_cycle", "ts_received", "bus", "breaker_DT"],
    "h2": ["cmd_id", "origin_cycle", "ts_received", "ts_sent", "bus", "breaker_DT"],
    "h3": ["cmd_id", "origin_cycle", "ts_received", "ts_sent", "bus", "breaker_DT"],
    "h4": ["cmd_id", "origin_cycle", "ts_sent", "bus", "breaker_DT"],
}


def timestamp():
    """Timestamp epoch presisi mikrodetik untuk korelasi latency antar host."""
    return f"{time.time():.6f}"


def breaker_state(values):
    """Serialisasi status breaker dict menjadi format bus:state;bus:state."""
    if isinstance(values, dict):
        return ";".join(f"{int(k)}:{int(values[k])}" for k in sorted(values))
    return str(values)


def _read_run_root():
    """Baca root log sesi dari marker host; None bila orchestrator belum menulisnya."""
    try:
        if os.path.exists(RUN_ROOT_HOST_FILE):
            with open(RUN_ROOT_HOST_FILE, "r", encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value
    except Exception:
        pass
    return None


def _read_measure_iteration():
    """Baca nomor iterasi pengukuran untuk memisahkan folder CSV."""
    try:
        if os.path.exists(MEASURE_ITER_HOST_FILE):
            with open(MEASURE_ITER_HOST_FILE, "r", encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return max(0, int(value))
    except Exception:
        pass
    return 0


def _read_measure_phase():
    """Baca fase pengukuran dan amankan agar aman menjadi nama folder."""
    try:
        if os.path.exists(MEASURE_PHASE_HOST_FILE):
            with open(MEASURE_PHASE_HOST_FILE, "r", encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value.replace("/", "_").replace("\\", "_")
    except Exception:
        pass
    return ""


def _fallback_root():
    """Fallback saat app host dijalankan manual tanpa orchestrator."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_dir, "logs")


def _csv_path(plane, host):
    """Bangun path CSV berdasarkan root sesi, fase, iterasi, dan plane."""
    root = _read_run_root() or _fallback_root()
    phase = _read_measure_phase()
    iteration = _read_measure_iteration()
    iter_dir = f"iteration_{iteration}" if iteration > 0 else "iteration_0"
    if phase:
        return os.path.join(root, "host_csv", phase, iter_dir, plane, f"{host}.csv")
    return os.path.join(root, "host_csv", iter_dir, plane, f"{host}.csv")


def _append_row(path, headers, row):
    """Append satu baris CSV dan tulis header bila file baru/kosong."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_header = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in headers})


def _breaker_items(value):
    """Parse breaker_DT menjadi pasangan (bus, status) untuk logging per bus."""
    if isinstance(value, dict):
        return [(int(bus), int(value[bus])) for bus in sorted(value)]

    items = []
    for part in str(value).split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        bus, state = part.split(":", 1)
        try:
            items.append((int(bus), int(state)))
        except ValueError:
            items.append((bus.strip(), state.strip()))
    return items


def log_data_plane(host, row):
    """Catat event data plane host."""
    headers = DATA_HEADERS[host]
    _append_row(_csv_path("data_plane", host), headers, row)


def log_control_plane(host, row):
    """Catat event control plane; dict breaker dipecah menjadi satu baris per bus."""
    headers = CONTROL_HEADERS[host]
    path = _csv_path("control_plane", host)
    breaker_items = _breaker_items(row.get("breaker_DT", ""))
    if not breaker_items or row.get("bus", "") != "":
        _append_row(path, headers, row)
        return

    for bus, breaker_dt in breaker_items:
        bus_row = dict(row)
        bus_row["bus"] = bus
        bus_row["breaker_DT"] = breaker_dt
        _append_row(path, headers, bus_row)
