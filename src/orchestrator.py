# Orchestrator utama cyber range: membangun topologi Mininet, menjalankan app host,
# mengaktifkan skenario baseline/MITM/DoS, lalu menyimpan CSV dan PCAP per iterasi.
import os
import sys
import time
import argparse
import importlib.util
import json
import shlex
import yaml
import platform
from datetime import datetime

from mininet.cli import CLI
from mininet.log import setLogLevel
from src.generator.generator import generate_project

# Path inti proyek dan marker /tmp yang dibaca oleh host di dalam namespace Mininet.
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(PACKAGE_DIR, ".."))
OUTPUT_DIR = os.path.join(BASE_DIR, "generated")
APPS_DIR = os.path.join(OUTPUT_DIR, "apps")
TOPOLOGY_PATH = os.path.join(OUTPUT_DIR, "topology.py")
GENERATION_MANIFEST_PATH = os.path.join(OUTPUT_DIR, "generation_manifest.json")
CONFIG_PATH = os.path.join(BASE_DIR, "configs", "topology.yaml")
DEFAULT_RESULTS_DIR = os.path.join(BASE_DIR, "results", "raw")
ATTACK_ACTIVE_FLAG = "/tmp/mitm_attack_active"
MITM_RUN_ID_FILE = "/tmp/mitm_run_id"

sys.path.append(OUTPUT_DIR)
sys.path.append(BASE_DIR)

from src.logger.collector import collect_data
from src.logger.host_csv_logger import (
    MEASURE_ITER_HOST_FILE,
    MEASURE_PHASE_HOST_FILE,
    RUN_ROOT_HOST_FILE,
)
from src.logger.pcap_collector import (
    start_trace_iteration_captures,
    stop_any_running_captures,
    stop_trace_iteration_captures,
    write_pcap_manifest,
)
# Jeda fase normal (tanpa pengumpulan baseline) sebelum serangan MITM.
NORMAL_PHASE_PRE_ATTACK_S = 5

# PCAP sebelum collect_data jaringan (baseline & MITM, durasi sama agar comparable).
# Satu tick kolom "waktu" ≈ satu putaran loop gateway — selaras generator/templates/gateway.j2 (time.sleep akhir loop).
MEASUREMENT_ITERATIONS = 3
MEASUREMENT_WINDOW_S = 20
MEASUREMENT_APP_WARMUP_S = float(os.environ.get("MEASUREMENT_APP_WARMUP_S", "5"))


def publish_measure_iteration_on_hosts(net, iteration: int):
    """Tulis penanda iterasi pengukuran agar host_csv_logger memisahkan folder CSV."""
    value = str(int(iteration))
    snippet = (
        f"open({repr(MEASURE_ITER_HOST_FILE)},'w',encoding='utf-8').write({repr(value)})"
    )
    arg = shlex.quote(snippet)
    for host in net.hosts:
        try:
            host.cmd(f"python3 -c {arg}")
        except Exception:
            pass


def publish_measure_phase_on_hosts(net, phase: str):
    """Tulis penanda fase agar host_csv_logger memisahkan subfolder host_csv."""
    value = str(phase).strip()
    snippet = (
        f"open({repr(MEASURE_PHASE_HOST_FILE)},'w',encoding='utf-8').write({repr(value)})"
    )
    arg = shlex.quote(snippet)
    for host in net.hosts:
        try:
            host.cmd(f"python3 -c {arg}")
        except Exception:
            pass


def clear_measure_phase_on_hosts(net):
    """Bersihkan marker fase agar logging berikutnya kembali ke folder default."""
    for host in net.hosts:
        try:
            host.cmd(f"rm -f {MEASURE_PHASE_HOST_FILE} 2>/dev/null || true")
        except Exception:
            pass


def clear_measure_iteration_on_hosts(net):
    """Bersihkan marker iterasi setelah window pengukuran selesai."""
    for host in net.hosts:
        try:
            host.cmd(f"rm -f {MEASURE_ITER_HOST_FILE} 2>/dev/null || true")
        except Exception:
            pass


def run_measurement_iterations(
    net,
    log_label: str,
    *,
    pcap_dir=None,
    pcap_phase: str = None,
    include_mitm_eth1: bool = False,
    pcap_manifest: list = None,
    host_csv_phase: str = None,
    collect_fn=None,
) -> None:
    """
    Jalankan window pengukuran yang sinkron:
    restart app, warm-up, pasang marker iterasi, lalu kumpulkan PCAP/CSV/network metric.
    """
    wait_s = MEASUREMENT_WINDOW_S
    warmup_s = MEASUREMENT_APP_WARMUP_S
    n = MEASUREMENT_ITERATIONS
    phase_key = (pcap_phase or log_label).lower()

    try:
        for i in range(1, n + 1):
            if host_csv_phase:
                publish_measure_phase_on_hosts(net, host_csv_phase)
            else:
                clear_measure_phase_on_hosts(net)
            clear_measure_iteration_on_hosts(net)
            restart_apps(net, reason=f"{log_label} iteration {i}/{n}")
            if warmup_s > 0:
                print(
                    f"[orchestrator] Warm-up {log_label}: iterasi={i}/{n}, "
                    f"menunggu app sinkron {warmup_s}s sebelum logging iteration..."
                )
                time.sleep(warmup_s)
            publish_measure_iteration_on_hosts(net, i)
            iter_entries = []
            try:
                if pcap_dir:
                    iter_entries = start_trace_iteration_captures(
                        net,
                        pcap_dir,
                        phase_key,
                        i,
                        include_mitm_eth1=include_mitm_eth1,
                    )
                print(
                    f"[orchestrator] Pengukuran {log_label}: iterasi={i}/{n}, "
                    f"window host_csv/pcap {wait_s}s..."
                )
                time.sleep(wait_s)
                if iter_entries:
                    saved = stop_trace_iteration_captures(net, iter_entries)
                    iter_entries = []
                    if pcap_manifest is not None:
                        pcap_manifest.extend(saved)
                        write_pcap_manifest(
                            pcap_dir,
                            pcap_manifest,
                            trace_iterations=n,
                            aligned_with=f"{phase_key} host_csv_logger + network collect",
                        )
                if collect_fn is not None:
                    collect_fn(i)
            finally:
                if pcap_dir and iter_entries:
                    saved = stop_trace_iteration_captures(net, iter_entries)
                    if pcap_manifest is not None:
                        pcap_manifest.extend(saved)
                        write_pcap_manifest(
                            pcap_dir,
                            pcap_manifest,
                            trace_iterations=n,
                            aligned_with=f"{phase_key} host_csv_logger + network collect",
                        )
    finally:
        clear_measure_iteration_on_hosts(net)
        clear_measure_phase_on_hosts(net)


def reset_attack_flags():
    """Pastikan flag serangan lokal host orchestration bersih sebelum run baru."""
    for flag_path in (ATTACK_ACTIVE_FLAG, MITM_RUN_ID_FILE):
        try:
            if os.path.exists(flag_path):
                os.remove(flag_path)
        except Exception as e:
            print(f"Warning: failed to remove {flag_path}: {e}")


def clear_mininet_mitm_trace_state(net):
    """
    Hapus marker MITM dan pointer run root di /tmp setiap host Mininet.
    """
    extras = (
        f"{ATTACK_ACTIVE_FLAG} {MITM_RUN_ID_FILE} "
        f"{RUN_ROOT_HOST_FILE} {MEASURE_ITER_HOST_FILE} {MEASURE_PHASE_HOST_FILE}"
    )
    for host in net.hosts:
        try:
            host.cmd(f"rm -f {extras} 2>/dev/null || true")
        except Exception:
            pass


def publish_run_root_on_hosts(net, run_root_abs: str):
    """Tulis path absolut results/raw/<scenario>/<run_id>/ untuk trace CSV host."""
    path = os.path.abspath(run_root_abs)
    snippet = f"open({repr(RUN_ROOT_HOST_FILE)},'w',encoding='utf-8').write({repr(path)})"
    arg = shlex.quote(snippet)
    for host in net.hosts:
        try:
            host.cmd(f"python3 -c {arg}")
        except Exception:
            pass


def prime_mitm_phase_on_hosts(net):
    """
    Untuk mode --mitm, aktifkan marker serangan sebelum app start agar
    iterasi awal trace langsung masuk bucket mitm.
    """
    for host in net.hosts:
        try:
            host.cmd(f"touch {ATTACK_ACTIVE_FLAG}")
        except Exception:
            pass


def write_session_meta(
    session_root: str,
    run_id_str: str,
    args,
    pcap_dir=None,
) -> None:
    """Simpan metadata sesi agar hasil CSV/PCAP bisa ditelusuri ke mode dan parameter run."""
    os.makedirs(session_root, exist_ok=True)
    meta_path = os.path.join(session_root, "meta.json")
    generation_manifest = None
    if os.path.isfile(GENERATION_MANIFEST_PATH):
        with open(GENERATION_MANIFEST_PATH, "r", encoding="utf-8") as manifest_file:
            generation_manifest = json.load(manifest_file)
    experiment_config = None
    experiment_config_path = os.environ.get("EXPERIMENT_CONFIG_PATH")
    if experiment_config_path and os.path.isfile(experiment_config_path):
        with open(experiment_config_path, "r", encoding="utf-8") as config_file:
            experiment_config = yaml.safe_load(config_file)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "run_id": run_id_str,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "modes": {
                    "baseline": bool(args.baseline),
                    "mitm": bool(args.mitm),
                    "dos": bool(args.dos),
                },
                "collect_delay_s": args.collect_delay if args.baseline else None,
                "measurement_iterations": MEASUREMENT_ITERATIONS,
                "measurement_window_s": MEASUREMENT_WINDOW_S,
                "measurement_app_warmup_s": MEASUREMENT_APP_WARMUP_S,
                "pcap_dir": pcap_dir,
                "output_layout": {
                    "host_csv": "host_csv",
                    "network": "network",
                    "pcap": "pcap",
                },
                "experiment_config": {
                    "file": os.path.basename(experiment_config_path)
                    if experiment_config_path
                    else None,
                    "sha256": os.environ.get("EXPERIMENT_CONFIG_SHA256"),
                    "content": experiment_config,
                },
                "generation": generation_manifest,
                "runtime": {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                    "field_random_seed": int(os.environ.get("FIELD_RANDOM_SEED", "42")),
                    "rtu_noise_seed": int(os.environ.get("RTU_NOISE_SEED", "7")),
                    "mitm_fixed_seed": int(os.environ.get("MITM_FIXED_SEED", "424242")),
                    "mitm_i_factor": float(os.environ.get("MITM_I_FACTOR", "1.5")),
                    "mitm_modify_probability": float(
                        os.environ.get("MITM_MODIFY_PROBABILITY", "0.5")
                    ),
                },
            },
            f,
            indent=2,
        )


def prepare_session_layout(results_root: str, scenario: str, run_id_str: str) -> dict:
    """Buat layout konsisten results/raw/<scenario>/<run_id> untuk satu sesi."""
    session_root = os.path.join(results_root, scenario, run_id_str)
    paths = {
        "root": session_root,
        "host_csv": os.path.join(session_root, "host_csv"),
        "network": os.path.join(session_root, "network"),
        "pcap": os.path.join(session_root, "pcap"),
    }
    for path in paths.values():
        os.makedirs(path, exist_ok=True)
    return paths


def initial_trace_session_root(path_baseline, path_mitm, path_dos, args):
    """Folder RUN_ROOT awal: mitm > baseline > dos (output trace sesi utama)."""
    if args.mitm and path_mitm:
        return path_mitm
    if args.baseline and path_baseline:
        return path_baseline
    if args.dos and path_dos:
        return path_dos
    return None


def load_app_map():
    """Baca pemetaan host -> file app yang dibuat generator; fallback kosong bila belum ada."""
    app_map_path = os.path.join(APPS_DIR, "app_map.json")
    if not os.path.exists(app_map_path):
        return {}
    try:
        with open(app_map_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_start_order_from_config(config_path=CONFIG_PATH):
    """
    Ambil urutan startup host dari config berdasarkan role:
    field -> gateway -> rtu -> dt.
    """
    role_order = ("field", "gateway", "rtu", "dt")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        zones = cfg.get("topology", {}).get("zones", {})
        hosts = []
        for zone in zones.values():
            hosts.extend(zone.get("hosts", []))
        by_role = {role: [] for role in role_order}
        for h in hosts:
            name = h.get("name")
            role = h.get("role")
            if name and role in by_role:
                by_role[role].append(name)
        ordered = []
        for role in role_order:
            ordered.extend(by_role[role])
        return ordered
    except Exception:
        return []


def load_topology_module():
    """Import topology.py hasil generator tanpa mengandalkan paket Python."""
    if not os.path.exists(TOPOLOGY_PATH):
        raise FileNotFoundError(f"Generated topology not found: {TOPOLOGY_PATH}")

    spec = importlib.util.spec_from_file_location("generated_topology", TOPOLOGY_PATH)
    topology_mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(topology_mod)
    return topology_mod

def create_network_from_generated_topology():
    """
    Use generated topology output directly (do not rebuild from config).
    Expected API in generated/topology.py: create_network()
    """
    topology_mod = load_topology_module()
    if not hasattr(topology_mod, "create_network"):
        raise AttributeError(
            "generated/topology.py does not expose create_network(). "
            "Update topology template to provide create_network() that returns a Mininet object."
        )
    return topology_mod.create_network(), topology_mod

def load_generated_attacker_module():
    """Muat helper attacker h5.py yang berisi fungsi run_mitm_attack dan run_dos_attack."""
    app_map = load_app_map()
    attacker_filename_candidates = []
    if "h5" in app_map:
        attacker_filename_candidates.append(app_map["h5"])
    attacker_filename_candidates.extend(["h5.py", "attacker.py", "attacker_1.py"])

    attacker_path = None
    for filename in attacker_filename_candidates:
        path = os.path.join(APPS_DIR, filename)
        if os.path.exists(path):
            attacker_path = path
            break
    if attacker_path is None:
        return None

    spec = importlib.util.spec_from_file_location("generated_h5", attacker_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module

def _app_path_for_host(name, app_map):
    """Resolusi file app host dari app_map, dengan fallback nama host."""
    app_filename = app_map.get(name, f"{name}.py")
    app_path = os.path.join(APPS_DIR, app_filename)
    if not os.path.exists(app_path):
        return None, app_filename
    return app_path, app_filename


def stop_apps(net):
    print("Stopping host apps...")
    app_map = load_app_map()
    for host in sorted(net.hosts, key=lambda h: h.name):
        # h5 adalah helper/proxy attacker, bukan service host reguler yang perlu direstart di sini.
        if host.name == "h5":
            continue
        app_path, app_filename = _app_path_for_host(host.name, app_map)
        if app_path is None:
            continue
        host.cmd(f"pkill -TERM -f {shlex.quote(app_path)} >/dev/null 2>&1 || true")
        print(f" {host.name} stopped ({app_filename})")
    time.sleep(0.5)


# UTIL: START APPS
def start_apps(net):
    """Start service h1-h4 sesuai urutan role agar dependency Modbus/OPC UA siap."""
    print("Starting apps...")
    app_map = load_app_map()

    def _start_host_app(host):
        name = host.name
        # h5 adalah helper berbasis fungsi; prosesnya dinyalakan hanya saat skenario attack.
        if name == "h5":
            print(" h5 skipped (attack helper)")
            return

        app_path, app_filename = _app_path_for_host(name, app_map)
        if app_path is None:
            return

        host.cmd(f"python3 -u {shlex.quote(app_path)} >/dev/null 2>&1 &")
        print(f" {name} started ({app_filename})")

    # Priority order mengikuti config role: field -> gateway -> rtu -> dt.
    order = load_start_order_from_config()
    started = set()

    for name in order:
        if name in started:
            continue
        try:
            host = net.get(name)
        except KeyError:
            continue
        _start_host_app(host)
        started.add(name)
        time.sleep(2)

    # Host yang tidak ada di config tetap dinyalakan secara deterministik.
    for host in sorted(net.hosts, key=lambda h: h.name):
        if host.name in started:
            continue
        _start_host_app(host)

    print("All apps started\n")


def restart_apps(net, reason: str = ""):
    """Restart app host untuk mengawali tiap iterasi dari kondisi yang konsisten."""
    label = f" ({reason})" if reason else ""
    print(f"Restarting host apps{label}...")
    stop_apps(net)
    start_apps(net)

def run_mitm(net, attacker_log_dir):
    """Aktifkan skenario MITM melalui helper attacker dan laporkan sukses/gagalnya."""
    print("Starting MITM attack...")
    attacker_module = load_generated_attacker_module()

    if attacker_module is None:
        print("Attacker module not found (generated/apps/h5.py)")
        return False

    run_mitm_attack = getattr(attacker_module, "run_mitm_attack", None)
    if run_mitm_attack is None:
        print("MITM function not found (generated/apps/h5.py::run_mitm_attack)")
        return False

    try:
        run_mitm_attack(net, host_log_dir=attacker_log_dir)
        print("MITM running\n")
        return True
    except Exception as e:
        print(f"MITM failed: {e}")
        return False

# UTIL: RUN DOS
def run_dos(net, mode, attacker_log_dir):
    """Aktifkan trafik DoS light/heavy dari host attacker."""
    print(f"Starting DoS attack ({mode})...")
    attacker_module = load_generated_attacker_module()

    if attacker_module is None:
        print("Attacker module not found (generated/apps/h5.py)")
        return False

    run_dos_attack = getattr(attacker_module, "run_dos_attack", None)
    if run_dos_attack is None:
        print("DoS function not found (generated/apps/h5.py::run_dos_attack)")
        return False

    try:
        run_dos_attack(net, mode=mode, host_log_dir=attacker_log_dir)
        print(f"DoS {mode} running\n")
        return True
    except Exception as e:
        print(f"DoS failed: {e}")
        return False


def stop_dos_hping_on_net(net):
    """Hentikan hping3 di host attacker (topologi ini: h5)."""
    try:
        h = net.get("h5")
        if h:
            h.cmd("killall hping3 >/dev/null 2>&1 || true")
    except Exception:
        pass


def clear_mitm_attack_flag_on_hosts(net):
    """Hapus marker serangan MITM di semua host (setelah pengumpulan fase attack)."""
    for host in net.hosts:
        try:
            host.cmd(f"rm -f {ATTACK_ACTIVE_FLAG} 2>/dev/null || true")
        except Exception:
            pass


# MAIN
def main():
    """Parse argumen, siapkan folder run, jalankan skenario, lalu cleanup Mininet."""
    global CONFIG_PATH
    global MEASUREMENT_ITERATIONS
    global MEASUREMENT_WINDOW_S
    global MEASUREMENT_APP_WARMUP_S
    global NORMAL_PHASE_PRE_ATTACK_S

    parser = argparse.ArgumentParser(description="Cyber Range Orchestrator")
    parser.add_argument(
        "--topology-config",
        default=CONFIG_PATH,
        help="Topology YAML used by the generator",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_RESULTS_DIR,
        help="Root directory for raw experiment results",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Collect baseline metrics after apps started"
    )
    parser.add_argument(
        "--dos",
        action="store_true",
        help="Run DoS scenario after apps started (requires generated/apps/h5.py)"
    )
    parser.add_argument(
        "--mitm",
        action="store_true",
        help="MITM: h2 route control via h5 Field; DNAT Modbus to proxy; I diubah in-path (mitm_modbus_proxy)"
    )
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="Run without Mininet CLI"
    )
    parser.add_argument(
        "--collect-delay",
        type=int,
        default=5,
        help="Seconds to wait before baseline collection (when enabled)"
    )
    parser.add_argument(
        "--no-pcap",
        action="store_true",
        help="Disable tcpdump capture on h1–h5 and r0",
    )
    parser.add_argument(
        "--measurement-iterations",
        type=int,
        default=MEASUREMENT_ITERATIONS,
        help="Number of repeated measurement windows",
    )
    parser.add_argument(
        "--measurement-window",
        type=float,
        default=MEASUREMENT_WINDOW_S,
        help="Duration of each measurement window in seconds",
    )
    parser.add_argument(
        "--app-warmup",
        type=float,
        default=MEASUREMENT_APP_WARMUP_S,
        help="Application warm-up before each measurement in seconds",
    )
    parser.add_argument(
        "--normal-phase-duration",
        type=float,
        default=NORMAL_PHASE_PRE_ATTACK_S,
        help="Normal phase duration before MITM in seconds",
    )
    parser.add_argument(
        "--dos-modes",
        nargs="+",
        choices=("light", "heavy"),
        default=("light", "heavy"),
        help="DoS intensities to execute",
    )

    args = parser.parse_args()
    CONFIG_PATH = os.path.abspath(args.topology_config)
    results_root = os.path.abspath(args.output_dir)
    MEASUREMENT_ITERATIONS = max(1, args.measurement_iterations)
    MEASUREMENT_WINDOW_S = max(0.0, args.measurement_window)
    MEASUREMENT_APP_WARMUP_S = max(0.0, args.app_warmup)
    NORMAL_PHASE_PRE_ATTACK_S = max(0.0, args.normal_phase_duration)
    # Artefak runtime selalu dibangkitkan ulang dari config dan template sumber.
    generation_manifest = generate_project(CONFIG_PATH, app_mode="host")
    print(
        "Generated runtime artifacts "
        f"(config SHA-256: {generation_manifest['config']['sha256']})"
    )
    # Baseline collection hanya saat diminta eksplisit.
    should_collect_baseline = bool(args.baseline)
    # results/raw/<baseline|mitm|dos>/<run_id>/ per skenario.
    should_create_run_folder = bool(args.baseline or args.mitm or args.dos)
    run_id_str = None
    path_baseline = path_mitm = path_dos = None
    pcap_baseline = pcap_mitm = pcap_dos = None
    if should_create_run_folder:
        run_id_str = datetime.now().strftime("%Y-%m-%d_%H%M%S_%f")
        if args.baseline:
            baseline_layout = prepare_session_layout(results_root, "baseline", run_id_str)
            path_baseline = baseline_layout["root"]
            pcap_baseline = None if args.no_pcap else baseline_layout["pcap"]
            write_session_meta(path_baseline, run_id_str, args, pcap_baseline)
        if args.mitm:
            mitm_layout = prepare_session_layout(results_root, "mitm", run_id_str)
            path_mitm = mitm_layout["root"]
            pcap_mitm = None if args.no_pcap else mitm_layout["pcap"]
            write_session_meta(path_mitm, run_id_str, args, pcap_mitm)
        if args.dos:
            dos_layout = prepare_session_layout(results_root, "dos", run_id_str)
            path_dos = dos_layout["root"]
            pcap_dos = None if args.no_pcap else dos_layout["pcap"]
            write_session_meta(path_dos, run_id_str, args, pcap_dos)
        log_lines = []
        if path_baseline:
            log_lines.append(f"baseline -> {path_baseline}")
        if path_mitm:
            log_lines.append(f"mitm -> {path_mitm}")
        if path_dos:
            log_lines.append(f"dos -> {path_dos}")
        print("Run logs paths:\n  " + "\n  ".join(log_lines))

    print("\n==============================")
    print("MODE: ORCHESTRATOR")
    print(f"Baseline: {'ON' if should_collect_baseline else 'OFF'}")
    print(f"MITM: {'ON' if args.mitm else 'OFF'}")
    print(f"DoS : {'ON' if args.dos else 'OFF'}")
    enabled_pcap_dirs = [
        path for path in (pcap_baseline, pcap_mitm, pcap_dos) if path is not None
    ]
    if args.no_pcap:
        print("PCAP: OFF (--no-pcap)")
    elif enabled_pcap_dirs:
        print("PCAP:\n  " + "\n  ".join(enabled_pcap_dirs))
    else:
        print("PCAP: OFF (no scenario flags)")
    print("==============================\n")

    # Hindari marker fase/attack lama ikut terbaca oleh logger pada run baru.
    reset_attack_flags()
    attacker_log_dir_mitm = (
        os.path.join(path_mitm, "host_csv", "attacker") if path_mitm else None
    )
    attacker_log_dir_dos = (
        os.path.join(path_dos, "host_csv", "attacker") if path_dos else None
    )
    if attacker_log_dir_mitm:
        print(f"MITM attacker log: {os.path.join(attacker_log_dir_mitm, 'h5.log')}")
    if attacker_log_dir_dos:
        print(f"DoS attacker log: {os.path.join(attacker_log_dir_dos, 'h5.log')}")

    # Topologi selalu berasal dari generated/topology.py hasil generator atau file statis saat ini.
    print("Starting generated topology...")
    net = None
    pcap_manifests = {
        path: [] for path in enabled_pcap_dirs
    }
    try:
        net, topology_mod = create_network_from_generated_topology()
        net.start()
        if hasattr(topology_mod, "post_start_setup"):
            topology_mod.post_start_setup(net)

        print("Waiting for stabilization...")
        time.sleep(3)

        clear_mininet_mitm_trace_state(net)

        trace_root0 = initial_trace_session_root(path_baseline, path_mitm, path_dos, args)
        if trace_root0:
            publish_run_root_on_hosts(net, trace_root0)

        # Service host harus hidup sebelum baseline/attack karena logger berada di app masing-masing.
        start_apps(net)

        for pcap_path in enabled_pcap_dirs:
            print(f"PCAP per iterasi (N={MEASUREMENT_ITERATIONS}) -> {pcap_path}")

        # Baseline hanya dikumpulkan bila diminta eksplisit.
        if should_collect_baseline:
            delay = max(0, args.collect_delay)
            print(f"Collecting baseline in {delay}s...")
            time.sleep(delay)
            if path_baseline:
                publish_run_root_on_hosts(net, path_baseline)
            run_measurement_iterations(
                net,
                "baseline",
                pcap_dir=pcap_baseline,
                pcap_phase="baseline",
                pcap_manifest=pcap_manifests.get(pcap_baseline),
                collect_fn=lambda iteration: collect_data(
                    net,
                    mode="baseline",
                    logs_path=path_baseline,
                    measure_phase="normal",
                    iteration=iteration,
                    num_runs=1,
                    config_path=CONFIG_PATH,
                ),
            )
            print("Baseline collection complete.\n")

        if args.mitm:
            if not should_collect_baseline:
                print(f"Normal phase (pre-attack, {NORMAL_PHASE_PRE_ATTACK_S}s)...")
                time.sleep(NORMAL_PHASE_PRE_ATTACK_S)
            prime_mitm_phase_on_hosts(net)
            # Topologi: attacker foothold di Control dulu; eskalasi ke Field hanya saat MITM.
            if hasattr(topology_mod, "escalate_attacker_to_field"):
                topology_mod.escalate_attacker_to_field(net)
                time.sleep(1)
            if path_mitm:
                publish_run_root_on_hosts(net, path_mitm)
            run_mitm(net, attacker_log_dir_mitm)
            run_measurement_iterations(
                net,
                "MITM",
                pcap_dir=pcap_mitm,
                pcap_phase="mitm",
                include_mitm_eth1=True,
                pcap_manifest=pcap_manifests.get(pcap_mitm),
                collect_fn=lambda iteration: collect_data(
                    net,
                    mode="mitm",
                    logs_path=path_mitm,
                    measure_phase="attack",
                    iteration=iteration,
                    num_runs=1,
                    config_path=CONFIG_PATH,
                ),
            )
            print("Stopping MITM attack...")
            clear_mitm_attack_flag_on_hosts(net)
            print("MITM collection complete.\n")

        if args.dos:
            if path_dos:
                publish_run_root_on_hosts(net, path_dos)
            # Untuk DoS, tiap mode attack dinyalakan lalu metrik diambil dalam window iterasi.
            for dos_mode in args.dos_modes:
                phase_label = f"dos_{dos_mode}"
                ok = run_dos(net, dos_mode, attacker_log_dir_dos)
                if not ok:
                    continue
                run_measurement_iterations(
                    net,
                    f"DoS ({dos_mode})",
                    pcap_dir=pcap_dos,
                    pcap_phase=phase_label,
                    pcap_manifest=pcap_manifests.get(pcap_dos),
                    host_csv_phase=phase_label,
                    collect_fn=lambda iteration, mode=dos_mode, label=phase_label: collect_data(
                        net,
                        mode=mode,
                        logs_path=path_dos,
                        measure_phase=label,
                        iteration=iteration,
                        num_runs=1,
                        config_path=CONFIG_PATH,
                    ),
                )
                print(f"DoS ({dos_mode}) network metrics complete.\n")
                stop_dos_hping_on_net(net)
            stop_dos_hping_on_net(net)
            print("DoS stopped (hping3 cleared).\n")

        print("System ready\n")

        # CLI tetap tersedia untuk inspeksi manual setelah skenario otomatis selesai.
        if not args.no_cli:
            CLI(net)
    finally:
        if net is not None:
            for manifest in pcap_manifests.values():
                stop_any_running_captures(net, manifest)
        if net is not None:
            print("Stopping network...")
            net.stop()

# Entry point CLI.
if __name__ == "__main__":
    setLogLevel("info")
    main()
