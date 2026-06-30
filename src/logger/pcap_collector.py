"""
tcpdump per iterasi pengukuran trace (selaras iterasi_ke di trace.csv).
Output: logs/pcap/<timestamp>/<phase>/iterNN/<label>.pcap (+ manifest.json)
"""
from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

# Spesifikasi capture per host; label menjadi nama file .pcap.
# defer=mitm berarti interface h5-eth1 hanya dicapture saat fase MITM aktif.
CAPTURE_SPECS: List[Dict[str, str]] = [
    {
        "host": "h1",
        "label": "field_modbus_5020",
        "iface": "h1-eth0",
        "filter": "tcp port 5020",
    },
    {
        "host": "h2",
        "label": "rtu_modbus_5020",
        "iface": "h2-eth0",
        "filter": "tcp port 5020 or udp port 5001",
    },
    {
        "host": "h3",
        "label": "gateway_modbus_opcua",
        "iface": "h3-eth0",
        "filter": "tcp port 5020 or tcp port 4840 or udp port 5001",
    },
    {
        "host": "h4",
        "label": "dt_opcua_4840",
        "iface": "h4-eth0",
        "filter": "tcp port 4840",
    },
    {
        "host": "h5",
        "label": "attacker_control_eth0",
        "iface": "h5-eth0",
        "filter": "tcp port 5020 or tcp port 50201 or udp port 5001",
    },
    {
        "host": "h5",
        "label": "attacker_field_mitm_eth1",
        "iface": "h5-eth1",
        "filter": "tcp port 5020 or tcp port 50201",
        "defer": "mitm",
    },
    {
        "host": "r0",
        "label": "router_ot_crosszone",
        "iface": "any",
        "filter": "tcp port 5020 or tcp port 4840 or udp port 5001",
    },
]

_PID_DIR = "/tmp/twinrange_sg_pcap"
_REMOTE_PCAP_DIR = "/tmp/twinrange_sg_pcap/out"


def _iface_up(host, iface: str) -> bool:
    """Cek status interface Mininet sebelum tcpdump dimulai."""
    if iface == "any":
        return True
    out = (host.cmd(f"cat /sys/class/net/{iface}/operstate 2>/dev/null") or "").strip()
    return out in ("up", "unknown", "dormant")


def _host_has_tcpdump(host) -> bool:
    """Pastikan tcpdump tersedia di namespace host."""
    return bool((host.cmd("command -v tcpdump 2>/dev/null") or "").strip())


def _remote_pcap_path(host_name: str, label: str, phase: str, iteration: int) -> str:
    """Path file pcap sementara di dalam filesystem namespace host."""
    safe = label.replace("/", "_")
    return f"{_REMOTE_PCAP_DIR}/{phase}_iter{iteration:02d}_{host_name}_{safe}.pcap"


def _pid_file(host_name: str, label: str, phase: str, iteration: int) -> str:
    """Path file PID tcpdump agar proses bisa dihentikan tepat per iterasi."""
    safe = label.replace("/", "_")
    return f"{_PID_DIR}/{phase}_iter{iteration:02d}_{host_name}_{safe}.pid"


def _copy_from_host_namespace(host, remote_path: str, local_path: str) -> bool:
    """Salin file dari namespace host melalui /proc/<pid>/root ke filesystem host utama."""
    pid = getattr(host, "pid", None)
    if not pid:
        return False
    src = f"/proc/{pid}/root{remote_path}"
    if not os.path.isfile(src):
        return False
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    shutil.copy2(src, local_path)
    return True


def _iter_output_dir(output_dir: str, phase: str, iteration: int) -> str:
    return os.path.join(output_dir, phase, f"iter{iteration:02d}")


def write_pcap_manifest(output_dir: str, manifest: List[Dict[str, Any]], **extra) -> None:
    """Tulis manifest yang mencatat status semua capture dalam satu sesi."""
    payload = {
        "output_dir": output_dir,
        "layout": "<phase>/iterNN/<label>.pcap",
        "captures": manifest,
    }
    payload.update(extra)
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _specs_for_phase(include_mitm_eth1: bool) -> List[Dict[str, str]]:
    """Pilih daftar capture sesuai fase baseline/MITM/DoS."""
    specs = []
    for spec in CAPTURE_SPECS:
        if spec.get("defer") == "mitm":
            if include_mitm_eth1:
                specs.append(spec)
            continue
        specs.append(spec)
    return specs


def start_trace_iteration_captures(
    net,
    output_dir: str,
    phase: str,
    iteration: int,
    *,
    include_mitm_eth1: bool = False,
) -> List[Dict[str, Any]]:
    """Mulai tcpdump untuk satu iterasi trace (iterasi_ke = iteration)."""
    os.makedirs(output_dir, exist_ok=True)
    iter_dir = _iter_output_dir(output_dir, phase, iteration)
    os.makedirs(iter_dir, exist_ok=True)
    started_at = datetime.now().isoformat(timespec="seconds")
    entries: List[Dict[str, Any]] = []

    for spec in _specs_for_phase(include_mitm_eth1):
        host_name = spec["host"]
        label = spec["label"]
        bpf = spec["filter"]
        iface = spec["iface"]

        if host_name not in net.nameToNode:
            entries.append(
                {
                    "phase": phase,
                    "iteration": iteration,
                    "host": host_name,
                    "label": label,
                    "status": "skipped",
                    "reason": "host_not_in_topology",
                }
            )
            continue

        host = net.get(host_name)
        if not _host_has_tcpdump(host):
            print(f"[pcap] SKIP {host_name} ({label}) iter {iteration}: tcpdump not found")
            entries.append(
                {
                    "phase": phase,
                    "iteration": iteration,
                    "host": host_name,
                    "label": label,
                    "status": "skipped",
                    "reason": "tcpdump_not_installed",
                }
            )
            continue

        if not _iface_up(host, iface):
            print(
                f"[pcap] WARN {host_name} ({label}) iter {iteration}: "
                f"{iface} not up yet (starting anyway)"
            )

        remote_pcap = _remote_pcap_path(host_name, label, phase, iteration)
        pid_file = _pid_file(host_name, label, phase, iteration)
        host.cmd(f"mkdir -p {_REMOTE_PCAP_DIR} {_PID_DIR}")
        host.cmd(f"rm -f {remote_pcap} {pid_file}")

        bpf_q = bpf.replace('"', '\\"')
        host.cmd(
            f"nohup tcpdump -i {iface} -w {remote_pcap} "
            f'"{bpf_q}" -U -s 0 '
            f"</dev/null >/dev/null 2>&1 & echo $! > {pid_file}"
        )
        time.sleep(0.15)
        pid_out = (host.cmd(f"cat {pid_file} 2>/dev/null") or "").strip()
        if not pid_out.isdigit():
            print(
                f"[pcap] FAIL {phase} iter{iteration:02d} {host_name} ({label}) iface={iface}"
            )
            entries.append(
                {
                    "phase": phase,
                    "iteration": iteration,
                    "host": host_name,
                    "label": label,
                    "status": "failed",
                    "reason": "tcpdump_start_failed",
                    "iface": iface,
                    "filter": bpf,
                }
            )
            continue

        local_file = os.path.join(iter_dir, f"{label}.pcap")
        print(
            f"[pcap] START {phase} iter{iteration:02d} {host_name} ({label}) "
            f"iface={iface} pid={pid_out}"
        )
        entries.append(
            {
                "phase": phase,
                "iteration": iteration,
                "host": host_name,
                "label": label,
                "status": "running",
                "pid": int(pid_out),
                "iface": iface,
                "filter": bpf,
                "remote_pcap": remote_pcap,
                "pid_file": pid_file,
                "local_file": local_file,
                "started_at": started_at,
            }
        )

    return entries


def stop_trace_iteration_captures(net, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stop tcpdump satu iterasi dan tarik .pcap ke disk."""
    stopped_at = datetime.now().isoformat(timespec="seconds")

    for entry in entries:
        if entry.get("status") != "running":
            continue

        host = net.get(entry["host"])
        pid_file = entry["pid_file"]
        remote_pcap = entry["remote_pcap"]
        local_file = entry["local_file"]

        host.cmd(
            f"if [ -f {pid_file} ]; then "
            f"kill -TERM $(cat {pid_file}) 2>/dev/null; "
            f"sleep 0.4; "
            f"kill -KILL $(cat {pid_file}) 2>/dev/null; "
            f"rm -f {pid_file}; fi"
        )
        time.sleep(0.2)

        ok = _copy_from_host_namespace(host, remote_pcap, local_file)
        size = os.path.getsize(local_file) if ok and os.path.isfile(local_file) else 0
        entry["status"] = "saved" if ok and size > 0 else "empty_or_missing"
        entry["stopped_at"] = stopped_at
        entry["bytes"] = size
        host.cmd(f"rm -f {remote_pcap}")

        tag = "OK" if size > 0 else "WARN"
        print(
            f"[pcap] {tag} {entry['phase']} iter{entry['iteration']:02d} "
            f"{entry['host']} -> {local_file} ({size} bytes)"
        )

    return entries


def stop_any_running_captures(net, manifest: List[Dict[str, Any]]) -> None:
    """Safety: hentikan proses tcpdump yang masih running (mis. setelah interrupt)."""
    running = [e for e in manifest if e.get("status") == "running"]
    if running:
        stop_trace_iteration_captures(net, running)


def pcap_session_dir(base_dir: str, run_id: str) -> str:
    """Folder PCAP sesi mengikuti run_id orchestrator."""
    return os.path.join(base_dir, "logs", "pcap", run_id)
