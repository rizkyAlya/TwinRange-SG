# TwinRange-SG

This directory is the standalone software distribution for the paper. The generator creates
the Mininet topology and host applications, the experiment engine records raw data, and the
analysis command creates summary tables and figures.

## Directory structure

```text
src/                     Core Python package
  generator/             Templates and deterministic code generator
  logger/                CSV and PCAP collectors
  orchestrator.py        Mininet experiment engine
configs/
  topology.yaml          Network topology
  experiments/           Baseline, MITM, and DoS recipes
scripts/                  Public run and analysis commands
```

The generated `script/` and runtime `results/` directories are created automatically and are
not tracked by Git.

## Platform and installation

Use Linux with Python 3.10 or 3.11. Mininet requires root privileges and Linux network
namespaces; it cannot run natively on Windows.

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch iperf tcpdump hping3 iproute2 net-tools iptables
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run experiments

Each command validates its YAML config, generates `script/topology.py`, all files under
`script/apps/`, and `script/mitm/modbus_proxy.py`, then runs the complete scenario. Use the
virtual environment's Python explicitly with `sudo` so the installed packages remain visible.

```bash
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/baseline.yaml
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/mitm.yaml
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/dos.yaml
```

Validate a config without Mininet or root access:

```bash
python scripts/run_experiment.py --config configs/experiments/baseline.yaml --dry-run
```

Raw CSV, metadata, and optional PCAP files are written under `results/raw/`. Every run's
`meta.json` embeds the experiment config, its SHA-256 hash, generator hashes, seeds, and runtime
platform information.

## Analyze results

Run analysis without `sudo` after one or more scenarios have completed:

```bash
python scripts/analyze_results.py --input results/ --output results/summary/
```

The command creates network and Field–Digital Twin telemetry summaries, figures for RTT,
packet loss, throughput, voltage error, and Age of Information, a run inventory, and an
`analysis_manifest.json` containing hashes of all consumed inputs and produced outputs.
