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
SCENARIO_DIRECTORIES = ("baseline", "mitm", "dos")
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
    "voltage_abs_error_pu": ("DT Voltage Drift", "p.u."),
    "voltage_abs_error_pct": ("DT Voltage Drift", "%"),
}
AOI_THRESHOLD_S = 3.0
NETWORK_PLOT_LABELS = {
    "RTT": ("RTT Comparison", "Latency (ms)", "{:.2f}"),
    "Packet Loss": ("Packet Loss Comparison", "Packet Loss (%)", "{:.2f}"),
    "Throughput": ("Throughput Comparison", "Throughput (Mbps)", "{:.2f}"),
}
PLOT_COLORS = [
    "#35B8F9",
    "#89FF52",
    "#FFA94D",
    "#CB62FF",
    "#FF5858",
    "#7DDCFF",
]
PLOT_MARKERS = ["o", "s", "^", "D", "v", "P"]
SCENARIO_COLORS = {
    "baseline": "#2563EB",
    "mitm": "#10B981",
    "dos_light": "#F59E0B",
    "dos_heavy": "#EF4444",
}
SCENARIO_MARKERS = {
    "baseline": "o",
    "mitm": "s",
    "dos_light": "^",
    "dos_heavy": "D",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_root(input_path: Path) -> Path:
    nested = input_path / "raw"
    return nested if nested.is_dir() else input_path


def iter_run_roots(root: Path):
    """Yield only results/raw/<scenario>/<run_id> directories from the canonical layout."""
    for scenario in SCENARIO_DIRECTORIES:
        scenario_root = root / scenario
        if not scenario_root.is_dir():
            continue
        for run_root in sorted(scenario_root.iterdir()):
            if run_root.is_dir():
                yield scenario, run_root


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
        for _, run_root in iter_run_roots(root):
            network_root = run_root / "network"
            if not network_root.is_dir():
                continue
            for path in sorted(network_root.rglob(filename)):
                scenario = scenario_from_path(path, root)
                if scenario not in SCENARIO_ORDER:
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


def read_telemetry(root: Path, consumed: set[Path]) -> tuple[list[dict], list[dict]]:
    grouped: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    drift_by_cycle: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    for _, run_root in iter_run_roots(root):
        host_csv_root = run_root / "host_csv"
        if not host_csv_root.is_dir():
            continue
        for field_path in sorted(host_csv_root.rglob("h1.csv")):
            lower_parts = [part.lower() for part in field_path.parts]
            if "data_plane" not in lower_parts:
                continue
            dt_path = field_path.with_name("h4.csv")
            if not dt_path.is_file():
                continue
            scenario = scenario_from_path(field_path, root)
            if scenario not in SCENARIO_ORDER:
                continue
            field_rows = read_csv_index(field_path, ("cycle_id", "bus"))
            dt_rows = read_csv_index(dt_path, ("cycle_id", "bus"))
            iteration_path = field_path.parent.parent.relative_to(host_csv_root)
            iteration = f"{run_root.name}/{iteration_path.as_posix()}"
            consumed.update((field_path, dt_path))
            for key in sorted(field_rows.keys() & dt_rows.keys()):
                field_row = field_rows[key]
                dt_row = dt_rows[key]
                try:
                    sent_voltage = float(field_row["V_sent"])
                    dt_voltage = float(dt_row["V_DT"])
                    cycle_id = int(key[0])
                except (KeyError, TypeError, ValueError):
                    continue
                line = (dt_row.get("line") or "").strip()
                if not line:
                    continue
                absolute_error = abs(dt_voltage - sent_voltage)
                grouped[(scenario, line, "voltage_abs_error_pu")].append(absolute_error)
                drift_by_cycle[
                    (scenario, iteration, cycle_id, "voltage_abs_error_pu")
                ].append(absolute_error)
                if abs(sent_voltage) > 1e-12:
                    percentage_error = absolute_error / abs(sent_voltage) * 100.0
                    grouped[(scenario, line, "voltage_abs_error_pct")].append(percentage_error)
                    drift_by_cycle[
                        (scenario, iteration, cycle_id, "voltage_abs_error_pct")
                    ].append(percentage_error)
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
    first_cycle = {}
    for scenario, iteration, cycle_id, metric in drift_by_cycle:
        key = (scenario, iteration, metric)
        first_cycle[key] = min(cycle_id, first_cycle.get(key, cycle_id))

    drift_by_time: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    for (scenario, iteration, cycle_id, metric), values in drift_by_cycle.items():
        t = cycle_id - first_cycle[(scenario, iteration, metric)]
        drift_by_time[(scenario, metric, t)].append(statistics.fmean(values))

    drift_rows = []
    for (scenario, metric, t), values in sorted(drift_by_time.items()):
        _title, unit = TELEMETRY_METRICS[metric]
        drift_rows.append(
            {
                "scenario": scenario,
                "metric": metric,
                "unit": unit,
                "t": t,
                "iteration_count": len(values),
                **numeric_summary(values),
            }
        )
    return rows, drift_rows


def iteration_number(path: Path) -> int:
    try:
        return int(path.name.split("_", 1)[1])
    except (IndexError, ValueError):
        return 0


def read_first_cycle_timestamps(path: Path, column: str) -> dict[int, float]:
    timestamps = {}
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            try:
                cycle_id = int(row["cycle_id"])
                timestamp = float(row[column])
            except (KeyError, TypeError, ValueError):
                continue
            timestamps[cycle_id] = min(timestamps.get(cycle_id, timestamp), timestamp)
    return timestamps


def read_cycle_timestamp_lists(path: Path, column: str) -> dict[int, list[float]]:
    timestamps: dict[int, list[float]] = defaultdict(list)
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            try:
                cycle_id = int(row["cycle_id"])
                timestamp = float(row[column])
            except (KeyError, TypeError, ValueError):
                continue
            timestamps[cycle_id].append(timestamp)
    return {
        cycle_id: sorted(set(values))
        for cycle_id, values in timestamps.items()
    }


def read_aoi_summary(
    root: Path,
    consumed: set[Path],
    threshold_s: float = AOI_THRESHOLD_S,
) -> list[dict]:
    iteration_rows = []
    for _scenario_dir, run_root in iter_run_roots(root):
        host_csv_root = run_root / "host_csv"
        if not host_csv_root.is_dir():
            continue
        for field_path in sorted(host_csv_root.rglob("h1.csv")):
            lower_parts = [part.lower() for part in field_path.parts]
            if "data_plane" not in lower_parts:
                continue
            iteration_dir = field_path.parent.parent
            if iteration_number(iteration_dir) <= 0:
                continue
            dt_path = field_path.with_name("h4.csv")
            if not dt_path.is_file():
                continue
            scenario = scenario_from_path(field_path, root)
            if scenario not in SCENARIO_ORDER:
                continue

            sent_by_cycle = read_first_cycle_timestamps(field_path, "ts_sent")
            received_by_cycle = read_cycle_timestamp_lists(dt_path, "ts_received")
            if not sent_by_cycle:
                continue
            consumed.update((field_path, dt_path))

            aoi_values = []
            fresh_count = 0
            stale_count = 0
            missing_count = 0
            for cycle_id, sent_time in sorted(sent_by_cycle.items()):
                received_time = next(
                    (
                        timestamp
                        for timestamp in received_by_cycle.get(cycle_id, [])
                        if timestamp >= sent_time
                    ),
                    None,
                )
                if received_time is None:
                    missing_count += 1
                    continue
                aoi = received_time - sent_time
                aoi_values.append(aoi)
                if aoi <= threshold_s:
                    fresh_count += 1
                else:
                    stale_count += 1

            total_count = len(sent_by_cycle)
            iteration_rows.append(
                {
                    "scenario": scenario,
                    "aoi_mean_s": statistics.fmean(aoi_values) if aoi_values else 0.0,
                    "aoi_max_s": max(aoi_values) if aoi_values else 0.0,
                    "fresh_pct": fresh_count / total_count * 100.0,
                    "stale_pct": stale_count / total_count * 100.0,
                    "missing_pct": missing_count / total_count * 100.0,
                }
            )

    rows = []
    for scenario in SCENARIO_ORDER:
        scenario_rows = [row for row in iteration_rows if row["scenario"] == scenario]
        if not scenario_rows:
            continue

        def values(column: str) -> list[float]:
            return [float(row[column]) for row in scenario_rows]

        def mean_std(column: str) -> tuple[float, float]:
            items = values(column)
            return (
                statistics.fmean(items),
                statistics.stdev(items) if len(items) > 1 else 0.0,
            )

        aoi_mean, aoi_std = mean_std("aoi_mean_s")
        fresh_mean, fresh_std = mean_std("fresh_pct")
        stale_mean, stale_std = mean_std("stale_pct")
        missing_mean, missing_std = mean_std("missing_pct")
        rows.append(
            {
                "scenario": scenario,
                "aoi_mean_s": aoi_mean,
                "aoi_std_s": aoi_std,
                "aoi_max_s": max(values("aoi_max_s")),
                "fresh_mean_pct": fresh_mean,
                "fresh_std_pct": fresh_std,
                "stale_mean_pct": stale_mean,
                "stale_std_pct": stale_std,
                "missing_mean_pct": missing_mean,
                "missing_std_pct": missing_std,
            }
        )
    return rows


def read_mitm_decision_errors(root: Path, consumed: set[Path]) -> list[dict]:
    grouped: dict[tuple[str, int], list[int]] = defaultdict(list)

    for scenario_dir, run_root in iter_run_roots(root):
        if scenario_dir != "mitm":
            continue
        host_csv_root = run_root / "host_csv"
        if not host_csv_root.is_dir():
            continue

        for control_path in sorted(host_csv_root.rglob("h4.csv")):
            lower_parts = [part.lower() for part in control_path.parts]
            if "control_plane" not in lower_parts:
                continue
            iteration_dir = control_path.parent.parent
            if iteration_number(iteration_dir) <= 0:
                continue
            field_path = iteration_dir / "data_plane" / "h1.csv"
            if not field_path.is_file():
                continue

            field_rows = read_csv_index(field_path, ("cycle_id", "bus"))
            iteration = f"{run_root.name}/{iteration_dir.relative_to(host_csv_root).as_posix()}"
            consumed.update((field_path, control_path))
            with control_path.open("r", newline="", encoding="utf-8-sig") as handle:
                for row in csv.DictReader(handle):
                    origin_cycle = row.get("origin_cycle")
                    bus = row.get("bus")
                    if origin_cycle is None or bus is None:
                        continue
                    field_row = field_rows.get((origin_cycle, bus))
                    if field_row is None:
                        continue
                    try:
                        line = int(bus)
                        field_actual = int(field_row["breaker_actual"])
                        dt_command = int(row["breaker_DT"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    grouped[(iteration, line)].append(int(dt_command != field_actual))

    rates_by_line: dict[int, list[float]] = defaultdict(list)
    matched_by_line: dict[int, int] = defaultdict(int)
    false_by_line: dict[int, int] = defaultdict(int)
    for (_iteration, line), values in grouped.items():
        matched_count = len(values)
        false_count = sum(values)
        rates_by_line[line].append(false_count / matched_count * 100.0)
        matched_by_line[line] += matched_count
        false_by_line[line] += false_count

    rows = []
    for line in sorted(rates_by_line):
        rates = rates_by_line[line]
        rows.append(
            {
                "line": line,
                "iteration_count": len(rates),
                "matched_decisions_sum": matched_by_line[line],
                "false_control_count_sum": false_by_line[line],
                "decision_error_rate_mean_pct": statistics.fmean(rates),
                "decision_error_rate_std_dev_pct": (
                    statistics.stdev(rates) if len(rates) > 1 else 0.0
                ),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def write_aoi_final_table(path: Path, rows: list[dict]) -> None:
    columns = [
        "Skenario",
        "Mean AoI (s)",
        "Max AoI (s)",
        "Fresh (%)",
        "Stale (%)",
        "Missing (%)",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "Skenario": SCENARIO_LABELS.get(row["scenario"], row["scenario"]),
                    "Mean AoI (s)": f"{row['aoi_mean_s']:.2f} ± {row['aoi_std_s']:.2f}",
                    "Max AoI (s)": f"{row['aoi_max_s']:.2f}",
                    "Fresh (%)": (
                        f"{row['fresh_mean_pct']:.1f} ± {row['fresh_std_pct']:.1f}"
                    ),
                    "Stale (%)": (
                        f"{row['stale_mean_pct']:.1f} ± {row['stale_std_pct']:.1f}"
                    ),
                    "Missing (%)": (
                        f"{row['missing_mean_pct']:.1f} ± {row['missing_std_pct']:.1f}"
                    ),
                }
            )


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


def route_label(row: dict) -> str:
    layer = str(row.get("layer", "unknown")).replace("_", " ").title()
    return f"{layer} ({row.get('source', '')} -> {row.get('destination', '')})"


def plot_network_bars(rows: list[dict], metric: str, output: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    selected = [
        row
        for row in rows
        if row["metric"] == metric and row["scenario"] in SCENARIO_ORDER
    ]
    if not selected:
        return

    scenarios = sorted({row["scenario"] for row in selected}, key=scenario_sort_key)
    routes = sorted(
        {
            (row["layer"], row["source"], row["destination"])
            for row in selected
        }
    )
    indexed = {
        (row["scenario"], row["layer"], row["source"], row["destination"]): row
        for row in selected
    }
    positions = list(range(len(scenarios)))
    width = min(0.72 / max(1, len(routes)), 0.32)
    title, ylabel, value_format = NETWORK_PLOT_LABELS.get(
        metric,
        (f"{metric} Comparison", f"{metric} ({selected[0]['unit']})", "{:.2f}"),
    )

    figure, axis = plt.subplots(figsize=(11, 6.2), dpi=160)
    figure.patch.set_facecolor("#F8FAFC")
    axis.set_facecolor("#FFFFFF")
    bar_groups = []

    for index, route in enumerate(routes):
        means = []
        errors = []
        sample = None
        for scenario in scenarios:
            row = indexed.get((scenario, *route))
            means.append(float(row["mean"]) if row else 0.0)
            errors.append(float(row["std_dev"]) if row else 0.0)
            sample = sample or row

        x_values = [
            position + (index - (len(routes) - 1) / 2) * width
            for position in positions
        ]
        bars = axis.bar(
            x_values,
            means,
            width,
            yerr=errors,
            capsize=5,
            color=PLOT_COLORS[index % len(PLOT_COLORS)],
            edgecolor="#334155",
            linewidth=0.7,
            error_kw={"elinewidth": 1.2, "ecolor": "#475569", "capthick": 1.2},
            label=route_label(sample or {
                "layer": route[0],
                "source": route[1],
                "destination": route[2],
            }),
        )
        bar_groups.append((bars, means, errors))

    max_value = max(
        (mean + error for _bars, means, errors in bar_groups for mean, error in zip(means, errors)),
        default=0.0,
    )
    y_top = max(1.0, max_value * 1.32)
    axis.set_ylim(0, y_top)
    label_offset = y_top * 0.012
    for bars, means, errors in bar_groups:
        for bar, mean, error in zip(bars, means, errors):
            center = bar.get_x() + bar.get_width() / 2
            mean_y = mean * 0.5 if mean > 0 else label_offset
            error_y = mean + error + label_offset
            if mean == 0 and error == 0:
                error_y = label_offset * 3
            axis.text(
                center,
                mean_y,
                f"$\\mu$={value_format.format(mean)}",
                ha="center",
                va="center",
                fontsize=8.2,
                fontweight="semibold",
                color="#0F172A",
            )
            axis.text(
                center,
                error_y,
                f"$\\sigma$={value_format.format(error)}",
                ha="center",
                va="bottom",
                fontsize=8,
                color="#334155",
            )

    axis.set_xticks(positions)
    axis.set_xticklabels([SCENARIO_LABELS.get(name, name) for name in scenarios])
    axis.set_xlabel("Test Scenario", fontsize=11, fontweight="semibold", color="#334155")
    axis.set_ylabel(ylabel, fontsize=11, fontweight="semibold", color="#334155")
    axis.set_title(title, fontsize=15, fontweight="bold", color="#0F172A", pad=14)
    axis.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.45, color="#94A3B8")
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.spines["left"].set_color("#CBD5E1")
    axis.spines["bottom"].set_color("#CBD5E1")
    axis.tick_params(axis="both", colors="#334155")
    axis.legend(
        title="Network Segment",
        frameon=True,
        facecolor="#FFFFFF",
        edgecolor="#CBD5E1",
        fontsize=9,
        title_fontsize=10,
        loc="upper left",
    )
    figure.text(
        0.01,
        0.015,
        "Bars show mean values ($\\mu$); error bars and labels show standard deviation ($\\sigma$).",
        fontsize=9,
        color="#475569",
    )
    figure.tight_layout(rect=(0, 0.035, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def plot_mitm_decision_errors(rows: list[dict], output: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    if not rows:
        return

    labels = [f"Line {row['line']}" for row in rows]
    means = [float(row["decision_error_rate_mean_pct"]) for row in rows]
    errors = [float(row["decision_error_rate_std_dev_pct"]) for row in rows]
    positions = list(range(len(rows)))

    figure, axis = plt.subplots(figsize=(10.5, 6), dpi=160)
    figure.patch.set_facecolor("#F8FAFC")
    axis.set_facecolor("#FFFFFF")
    bars = axis.bar(
        positions,
        means,
        yerr=errors,
        capsize=6,
        color="#69AFA5",
        edgecolor="#334155",
        linewidth=0.8,
        error_kw={"elinewidth": 1.4, "ecolor": "#475569", "capthick": 1.4},
    )

    y_top = max(10.0, max(mean + error for mean, error in zip(means, errors)) + 12.0)
    axis.set_ylim(0, y_top)
    for bar, mean, error in zip(bars, means, errors):
        axis.text(
            bar.get_x() + bar.get_width() / 2,
            mean + error + y_top * 0.018,
            f"$\\mu$={mean:.1f}%\n$\\sigma$={error:.1f}%",
            ha="center",
            va="bottom",
            fontsize=9,
            color="#0F172A",
            fontweight="semibold",
        )

    axis.set_title(
        "MITM Decision Error Rate per Line",
        fontsize=16,
        fontweight="bold",
        color="#0F172A",
        pad=14,
    )
    axis.set_xlabel("Line", fontsize=11, fontweight="semibold", color="#334155")
    axis.set_ylabel(
        "Decision Error Rate (%)",
        fontsize=11,
        fontweight="semibold",
        color="#334155",
    )
    axis.set_xticks(positions)
    axis.set_xticklabels(labels)
    axis.grid(axis="y", color="#CBD5E1", linewidth=0.8, alpha=0.7)
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.spines["left"].set_color("#94A3B8")
    axis.spines["bottom"].set_color("#94A3B8")
    axis.tick_params(axis="both", colors="#334155")
    figure.text(
        0.01,
        0.015,
        "Decision error rate = false control actions / matched decisions x 100. Error bars show standard deviation across iterations.",
        fontsize=8.5,
        color="#475569",
    )
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


def plot_voltage_drift(rows: list[dict], metric: str, output: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    selected = [
        row
        for row in rows
        if row["metric"] == metric and row["scenario"] in SCENARIO_ORDER
    ]
    if not selected:
        return

    scenarios = sorted({row["scenario"] for row in selected}, key=scenario_sort_key)
    positive_values = [float(row["mean"]) for row in selected if float(row["mean"]) > 0]
    floor_value = min(positive_values) * 0.5 if positive_values else 1e-9

    figure, axis = plt.subplots(figsize=(11.5, 6.1), dpi=160)
    figure.patch.set_facecolor("#F8FAFC")
    axis.set_facecolor("#FFFFFF")
    axis.set_yscale("log")

    for scenario in scenarios:
        scenario_rows = sorted(
            (row for row in selected if row["scenario"] == scenario),
            key=lambda row: row["t"],
        )
        x_values = [row["t"] for row in scenario_rows]
        y_values = [
            float(row["mean"]) if float(row["mean"]) > 0 else floor_value
            for row in scenario_rows
        ]
        axis.plot(
            x_values,
            y_values,
            marker=SCENARIO_MARKERS.get(scenario, "o"),
            markevery=max(1, len(x_values) // 12),
            markersize=5.5,
            linewidth=2.2,
            color=SCENARIO_COLORS.get(scenario, "#64748B"),
            label=SCENARIO_LABELS.get(scenario, scenario),
        )

    unit = selected[0]["unit"]
    axis.set_title(
        "Mean DT Voltage Drift: Baseline vs MITM vs DoS",
        fontsize=15,
        fontweight="bold",
        color="#0F172A",
        pad=14,
    )
    axis.set_xlabel("t", fontsize=12, fontweight="semibold", color="#334155")
    axis.set_ylabel(
        f"Mean |V_DT - V_Field| ({unit})",
        fontsize=11,
        fontweight="semibold",
        color="#334155",
    )
    axis.grid(axis="both", linestyle="--", linewidth=0.8, alpha=0.45, color="#94A3B8")
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.spines["left"].set_color("#CBD5E1")
    axis.spines["bottom"].set_color("#CBD5E1")
    axis.tick_params(axis="both", colors="#334155")
    axis.legend(
        title="Scenario",
        frameon=True,
        facecolor="#FFFFFF",
        edgecolor="#CBD5E1",
        fontsize=10,
        title_fontsize=10,
        loc="best",
    )
    axis.set_ylim(
        bottom=(min(positive_values) * 0.45 if positive_values else floor_value * 0.45),
        top=(max(positive_values) * 1.8 if positive_values else floor_value * 1.8),
    )
    figure.text(
        0.01,
        0.015,
        "Each t is cycle_id normalized to start at 0 per iteration. Values are averaged across Lines 1-4, then across iterations. The Y-axis uses a log scale.",
        fontsize=8.7,
        color="#475569",
    )
    figure.tight_layout(rect=(0, 0.04, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, bbox_inches="tight")
    plt.close(figure)


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
    for _, run_root in iter_run_roots(root):
        path = run_root / "meta.json"
        if not path.is_file():
            continue
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
    telemetry_rows, drift_rows = read_telemetry(root, consumed)
    aoi_rows = read_aoi_summary(root, consumed)
    decision_error_rows = read_mitm_decision_errors(root, consumed)
    if not network_rows and not telemetry_rows and not aoi_rows and not decision_error_rows:
        raise SystemExit(f"No supported raw CSV data found under {root}")

    network_csv = output_path / "network_summary.csv"
    telemetry_csv = output_path / "telemetry_summary.csv"
    drift_csv = output_path / "voltage_drift_timeseries.csv"
    aoi_csv = output_path / "aoi_final_table.csv"
    decision_error_csv = output_path / "mitm_decision_error_rate_per_line.csv"
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
    write_csv(
        drift_csv,
        drift_rows,
        [
            "scenario",
            "metric",
            "unit",
            "t",
            "iteration_count",
            "n",
            "mean",
            "std_dev",
            "min",
            "max",
        ],
    )
    write_csv(
        decision_error_csv,
        decision_error_rows,
        [
            "line",
            "iteration_count",
            "matched_decisions_sum",
            "false_control_count_sum",
            "decision_error_rate_mean_pct",
            "decision_error_rate_std_dev_pct",
        ],
    )
    write_aoi_final_table(aoi_csv, aoi_rows)
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
        plot_network_bars(route_rows, metric, output_path / "figures" / filename)
    for metric in sorted({row["metric"] for row in drift_rows}):
        plot_voltage_drift(
            drift_rows,
            metric,
            output_path / "figures" / f"{metric}.png",
        )
    plot_mitm_decision_errors(
        decision_error_rows,
        output_path / "figures" / "mitm_decision_error_rate_per_line.png",
    )
    obsolete_aoi_figure = output_path / "figures" / "aoi_s.png"
    if obsolete_aoi_figure.is_file():
        obsolete_aoi_figure.unlink()

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
    print(f"Wrote voltage drift time series: {drift_csv}")
    print(f"Wrote AoI final table: {aoi_csv}")
    print(f"Wrote MITM decision error summary: {decision_error_csv}")
    print(f"Wrote figures: {output_path / 'figures'}")
    print(f"Wrote analysis manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
