#!/usr/bin/env python3
"""Convert raw experiment data into reproducible summaries and figures."""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path
import statistics


SCENARIO_ORDER = ["baseline", "mitm", "dos_light", "dos_heavy"]
SCENARIO_LABELS = {
    "baseline": "Baseline",
    "mitm": "MITM",
    "dos_light": "DoS Light",
    "dos_heavy": "DoS Heavy",
}
NETWORK_FILES = {
    "rtt.csv": ("RTT", "latency_ms", "ms"),
    "packet_loss.csv": ("Packet Loss", "packet_loss_percent", "%"),
    "throughput.csv": ("Throughput", "throughput_Mbps", "Mbps"),
}
TELEMETRY_METRICS = {
    "voltage_abs_error_pu": ("DT Voltage Absolute Error", "p.u."),
    "voltage_abs_error_pct": ("DT Voltage Absolute Error", "%"),
    "aoi_s": ("Age of Information", "s"),
}
PLOT_COLORS = [
    "#6B8E9F",
    "#87A878",
    "#C49A6C",
    "#9A86A4",
    "#C47F7F",
    "#709FB0",
]
PLOT_MARKERS = ["o", "s", "^", "D", "v", "P"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_root(input_path: Path) -> Path:
    nested = input_path / "raw"
    return nested if nested.is_dir() else input_path


def scenario_from_path(path: Path, root: Path) -> str | None:
    try:
        parts = [part.lower() for part in path.relative_to(root).parts]
    except ValueError:
        return None
    if not parts:
        return None
    if parts[0] in {"baseline", "mitm"}:
        return parts[0]
    if parts[0] == "dos":
        if "dos_light" in parts or "light" in parts:
            return "dos_light"
        if "dos_heavy" in parts or "heavy" in parts:
            return "dos_heavy"
        return "dos"
    return None


def numeric_summary(values: list[float]) -> dict[str, float | int]:
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "std_dev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def read_network(root: Path, consumed: set[Path]) -> list[dict]:
    grouped: dict[tuple, list[float]] = defaultdict(list)
    units = {}
    for filename, (metric, value_column, unit) in NETWORK_FILES.items():
        for path in sorted(root.rglob(filename)):
            if "network" not in [part.lower() for part in path.parts]:
                continue
            scenario = scenario_from_path(path, root)
            if scenario is None:
                continue
            consumed.add(path)
            with path.open("r", newline="", encoding="utf-8-sig") as handle:
                for row in csv.DictReader(handle):
                    if filename == "throughput.csv" and row.get("status", "ok") != "ok":
                        continue
                    try:
                        value = float(row[value_column])
                    except (KeyError, TypeError, ValueError):
                        continue
                    key = (
                        scenario,
                        metric,
                        row.get("layer", "unknown"),
                        row.get("source", ""),
                        row.get("destination", ""),
                    )
                    grouped[key].append(value)
                    units[metric] = unit

    rows = []
    for key, values in sorted(grouped.items()):
        scenario, metric, layer, source, destination = key
        rows.append(
            {
                "scenario": scenario,
                "metric": metric,
                "unit": units[metric],
                "layer": layer,
                "source": source,
                "destination": destination,
                **numeric_summary(values),
            }
        )
    return rows


def read_csv_index(path: Path, columns: tuple[str, str]) -> dict[tuple[str, str], dict]:
    indexed = {}
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            first = row.get(columns[0])
            second = row.get(columns[1])
            if first is not None and second is not None:
                indexed[(first, second)] = row
    return indexed


def read_telemetry(root: Path, consumed: set[Path]) -> list[dict]:
    grouped: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for field_path in sorted(root.rglob("h1.csv")):
        lower_parts = [part.lower() for part in field_path.parts]
        if "host_csv" not in lower_parts or "data_plane" not in lower_parts:
            continue
        dt_path = field_path.with_name("h4.csv")
        if not dt_path.is_file():
            continue
        scenario = scenario_from_path(field_path, root)
        if scenario is None:
            continue
        field_rows = read_csv_index(field_path, ("cycle_id", "bus"))
        dt_rows = read_csv_index(dt_path, ("cycle_id", "bus"))
        consumed.update((field_path, dt_path))
        for key in sorted(field_rows.keys() & dt_rows.keys()):
            field_row = field_rows[key]
            dt_row = dt_rows[key]
            try:
                sent_voltage = float(field_row["V_sent"])
                dt_voltage = float(dt_row["V_DT"])
                sent_time = float(field_row["ts_sent"])
                received_time = float(dt_row["ts_received"])
            except (KeyError, TypeError, ValueError):
                continue
            line = (dt_row.get("line") or "").strip()
            if not line:
                continue
            absolute_error = abs(dt_voltage - sent_voltage)
            grouped[(scenario, line, "voltage_abs_error_pu")].append(absolute_error)
            if abs(sent_voltage) > 1e-12:
                grouped[(scenario, line, "voltage_abs_error_pct")].append(
                    absolute_error / abs(sent_voltage) * 100.0
                )
            grouped[(scenario, line, "aoi_s")].append(max(0.0, received_time - sent_time))

    rows = []
    for (scenario, line, metric), values in sorted(grouped.items()):
        title, unit = TELEMETRY_METRICS[metric]
        rows.append(
            {
                "scenario": scenario,
                "line": line,
                "metric": metric,
                "label": title,
                "unit": unit,
                **numeric_summary(values),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def scenario_sort_key(name: str) -> tuple[int, str]:
    try:
        return SCENARIO_ORDER.index(name), name
    except ValueError:
        return len(SCENARIO_ORDER), name


def series_sort_key(name: str) -> tuple[int, int | str]:
    try:
        return 0, int(name)
    except ValueError:
        return 1, name


def plot_summary_lines(rows: list[dict], metric: str, series_column: str, output: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    selected = [row for row in rows if row["metric"] == metric]
    if not selected:
        return
    scenarios = sorted({row["scenario"] for row in selected}, key=scenario_sort_key)
    series = sorted({str(row[series_column]) for row in selected}, key=series_sort_key)
    indexed = {(row["scenario"], str(row[series_column])): row for row in selected}
    positions = list(range(len(scenarios)))

    figure, axis = plt.subplots(figsize=(11.5, 6.1), dpi=160)
    figure.patch.set_facecolor("#F8FAFC")
    axis.set_facecolor("#FFFFFF")
    for index, series_name in enumerate(series):
        points = [
            (position, indexed[(scenario, series_name)])
            for position, scenario in zip(positions, scenarios)
            if (scenario, series_name) in indexed
        ]
        if not points:
            continue
        x_values = [position for position, _row in points]
        means = [row["mean"] for _position, row in points]
        errors = [row["std_dev"] for _position, row in points]
        label_prefix = "Line" if series_column == "line" else ""
        label = f"{label_prefix} {series_name}".strip()
        axis.errorbar(
            x_values,
            means,
            yerr=errors,
            capsize=4,
            marker=PLOT_MARKERS[index % len(PLOT_MARKERS)],
            markersize=6,
            linewidth=2.1,
            color=PLOT_COLORS[index % len(PLOT_COLORS)],
            label=label,
        )

    sample = selected[0]
    title = sample.get("label", metric)
    axis.set_title(
        f"{title} by Scenario",
        fontsize=15,
        fontweight="bold",
        color="#0F172A",
        pad=14,
    )
    axis.set_xlabel("Test Scenario", fontsize=11, fontweight="semibold", color="#334155")
    axis.set_ylabel(
        f"{title} ({sample['unit']})",
        fontsize=11,
        fontweight="semibold",
        color="#334155",
    )
    axis.set_xticks(positions)
    axis.set_xticklabels([SCENARIO_LABELS.get(name, name) for name in scenarios])
    axis.set_xlim(-0.25, max(positions) + 0.25)
    axis.set_ylim(bottom=0)
    axis.grid(axis="both", linestyle="--", linewidth=0.8, alpha=0.45, color="#94A3B8")
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.spines["left"].set_color("#CBD5E1")
    axis.spines["bottom"].set_color("#CBD5E1")
    axis.tick_params(axis="both", colors="#334155")
    axis.legend(
        title=series_column.replace("_", " ").title(),
        frameon=True,
        facecolor="#FFFFFF",
        edgecolor="#CBD5E1",
        fontsize=9,
        title_fontsize=10,
        loc="best",
    )
    figure.text(
        0.01,
        0.015,
        "Points show summary means; error bars show standard deviation.",
        fontsize=9,
        color="#475569",
    )
    figure.tight_layout(rect=(0, 0.035, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def write_inventory(root: Path, output: Path, consumed: set[Path]) -> None:
    rows = []
    for path in sorted(root.rglob("meta.json")):
        scenario = scenario_from_path(path, root)
        if scenario is None:
            continue
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        consumed.add(path)
        generation = metadata.get("generation") or {}
        runtime = metadata.get("runtime") or {}
        experiment = metadata.get("experiment_config") or {}
        rows.append(
            {
                "scenario": scenario,
                "run_id": metadata.get("run_id", path.parent.name),
                "created_at": metadata.get("created_at", ""),
                "experiment_config_sha256": experiment.get("sha256", ""),
                "topology_config_sha256": (generation.get("config") or {}).get("sha256", ""),
                "python": runtime.get("python", ""),
                "platform": runtime.get("platform", ""),
            }
        )
    write_csv(
        output,
        rows,
        [
            "scenario",
            "run_id",
            "created_at",
            "experiment_config_sha256",
            "topology_config_sha256",
            "python",
            "platform",
        ],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize raw cyber-range results and create publication-ready figures."
    )
    parser.add_argument("--input", type=Path, required=True, help="results/ or results/raw/")
    parser.add_argument("--output", type=Path, required=True, help="Summary output directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = args.input.expanduser().resolve()
    output_path = args.output.expanduser().resolve()
    root = raw_root(input_path)
    if not root.is_dir():
        raise SystemExit(f"Raw results directory not found: {root}")

    consumed: set[Path] = set()
    network_rows = read_network(root, consumed)
    telemetry_rows = read_telemetry(root, consumed)
    if not network_rows and not telemetry_rows:
        raise SystemExit(f"No supported raw CSV data found under {root}")

    network_csv = output_path / "network_summary.csv"
    telemetry_csv = output_path / "telemetry_summary.csv"
    write_csv(
        network_csv,
        network_rows,
        ["scenario", "metric", "unit", "layer", "source", "destination", "n", "mean", "std_dev", "min", "max"],
    )
    write_csv(
        telemetry_csv,
        telemetry_rows,
        ["scenario", "line", "metric", "label", "unit", "n", "mean", "std_dev", "min", "max"],
    )
    write_inventory(root, output_path / "run_inventory.csv", consumed)

    for metric in sorted({row["metric"] for row in network_rows}):
        route_rows = []
        for row in network_rows:
            if row["metric"] == metric:
                route_rows.append({**row, "route": f"{row['layer']} ({row['source']}→{row['destination']})", "label": metric})
        for route_row in route_rows:
            route_row["route"] = (
                f"{route_row['layer']} ({route_row['source']} -> {route_row['destination']})"
            )
        filename = metric.lower().replace(" ", "_") + ".png"
        plot_summary_lines(route_rows, metric, "route", output_path / "figures" / filename)
    for metric in sorted({row["metric"] for row in telemetry_rows}):
        plot_summary_lines(
            telemetry_rows,
            metric,
            "line",
            output_path / "figures" / f"{metric}.png",
        )

    manifest_path = output_path / "analysis_manifest.json"
    output_files = sorted(
        path
        for path in output_path.rglob("*")
        if path.is_file() and path != manifest_path
    )
    manifest = {
        "input_root": root.name,
        "inputs": {
            str(path.relative_to(root)).replace("\\", "/"): sha256_file(path)
            for path in sorted(consumed)
        },
        "outputs": {
            str(path.relative_to(output_path)).replace("\\", "/"): sha256_file(path)
            for path in output_files
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote network summary: {network_csv}")
    print(f"Wrote telemetry summary: {telemetry_csv}")
    print(f"Wrote figures: {output_path / 'figures'}")
    print(f"Wrote analysis manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
