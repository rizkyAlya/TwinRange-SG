#!/usr/bin/env python3
"""Public one-command entry point for reproducible cyber-range experiments."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENGINE_MODULE = "src.orchestrator"
SCENARIO_FLAGS = ("baseline", "mitm", "dos")


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ValueError("Experiment config must be a YAML mapping")
    if config.get("schema_version") != 1:
        raise ValueError("Unsupported or missing schema_version; expected 1")
    return config


def resolve_from_config(config_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_command(config_path: Path, config: dict) -> tuple[list[str], dict[str, str]]:
    scenario = config.get("scenario")
    execution = config.get("execution", {})
    if not isinstance(scenario, dict) or not isinstance(execution, dict):
        raise ValueError("scenario and execution must be YAML mappings")

    enabled = [name for name in SCENARIO_FLAGS if scenario.get(name) is True]
    if not enabled:
        raise ValueError("Enable at least one of scenario.baseline, scenario.mitm, or scenario.dos")

    topology_value = config.get("topology_config", "../topology.yaml")
    output_value = config.get("output_dir", "../../results/raw")
    topology_path = resolve_from_config(config_path, topology_value)
    output_path = resolve_from_config(config_path, output_value)
    if not topology_path.is_file():
        raise FileNotFoundError(f"Topology config not found: {topology_path}")

    command = [
        sys.executable,
        "-m",
        ENGINE_MODULE,
        "--topology-config",
        str(topology_path),
        "--output-dir",
        str(output_path),
    ]
    for name in enabled:
        command.append(f"--{name}")

    if execution.get("interactive_cli", False) is False:
        command.append("--no-cli")
    if execution.get("capture_pcap", True) is False:
        command.append("--no-pcap")

    scalar_options = {
        "collect_delay_s": "--collect-delay",
        "measurement_iterations": "--measurement-iterations",
        "measurement_window_s": "--measurement-window",
        "app_warmup_s": "--app-warmup",
        "normal_phase_duration_s": "--normal-phase-duration",
    }
    for key, flag in scalar_options.items():
        if key in execution:
            command.extend([flag, str(execution[key])])

    if scenario.get("dos") is True:
        dos_modes = execution.get("dos_modes", ["light", "heavy"])
        if not isinstance(dos_modes, list) or not dos_modes:
            raise ValueError("execution.dos_modes must be a non-empty list")
        invalid_modes = sorted(set(dos_modes) - {"light", "heavy"})
        if invalid_modes:
            raise ValueError(f"Unsupported DoS modes: {', '.join(invalid_modes)}")
        command.extend(["--dos-modes", *dos_modes])

    environment = os.environ.copy()
    configured_environment = config.get("environment", {})
    if not isinstance(configured_environment, dict):
        raise ValueError("environment must be a YAML mapping")
    for key, value in configured_environment.items():
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError(f"environment.{key} must be a scalar value")
        environment[str(key)] = str(value)
    environment["EXPERIMENT_CONFIG_PATH"] = str(config_path)
    environment["EXPERIMENT_CONFIG_SHA256"] = sha256_file(config_path)
    return command, environment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the cyber range and execute a configured experiment end to end."
    )
    parser.add_argument("--config", type=Path, required=True, help="Experiment YAML file")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the config and print the engine command without running Mininet",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = args.config.expanduser().resolve()
    if not config_path.is_file():
        raise SystemExit(f"Experiment config not found: {config_path}")
    try:
        config = load_config(config_path)
        command, environment = build_command(config_path, config)
    except (FileNotFoundError, TypeError, ValueError) as error:
        raise SystemExit(f"Invalid experiment config: {error}") from error

    print(f"Experiment: {config.get('name', config_path.stem)}")
    print(f"Config SHA-256: {environment['EXPERIMENT_CONFIG_SHA256']}")
    print(f"Engine command: {shlex.join(command)}")
    if args.dry_run:
        print("Dry run complete; Mininet was not started.")
        return 0

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise SystemExit("Mininet requires root privileges; rerun with sudo.")
    completed = subprocess.run(command, cwd=PROJECT_ROOT, env=environment, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
