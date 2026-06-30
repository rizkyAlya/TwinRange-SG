# TwinRange-SG

## Overview

TwinRange-SG is a reproducible co-simulation cyber range for smart grid cybersecurity research. It integrates Mininet-based communication network emulation, configurable cyberattack scenarios, field-device applications, and Field–Digital Twin telemetry analysis. The software is designed to support controlled experiments for evaluating how cyberattacks affect both communication metrics and physical-impact indicators in a smart grid cyber-physical system.

## Main features

* Deterministic generation of Mininet topology and host applications from YAML configuration files.
* Predefined baseline, Man-in-the-Middle, and Denial-of-Service experiment recipes.
* Automated experiment orchestration with raw CSV logging and optional PCAP capture.
* Field–Digital Twin telemetry analysis for network and physical-impact metrics.
* Reproducibility metadata, including configuration hashes, generator hashes, random seeds, and runtime platform information.
* Dry-run validation mode for checking experiment configurations without root access or Mininet execution.

## Requirements

TwinRange-SG is intended to run on Linux with Python 3.10 or 3.11. Mininet requires root privileges and Linux network namespaces, so the software cannot run natively on Windows.

The main system dependencies are:

* Mininet
* Open vSwitch
* iperf
* tcpdump
* hping3
* iproute2
* net-tools
* iptables

Python dependencies are listed in `requirements.txt`.

## Directory structure

```text
src/                     Core Python package
  generator/             Templates and deterministic code generator
  logger/                CSV and PCAP collectors
  orchestrator.py        Mininet experiment engine

configs/
  topology.yaml          Network topology
  experiments/           Baseline, MITM, and DoS experiment recipes

scripts/                 Public run and analysis commands
```

The generated `generated/` directory and runtime `results/` directory are created automatically and are not tracked by Git. The `scripts/` directory contains user-facing commands, while `generated/` contains generated runtime files such as the Mininet topology, host applications, and MITM proxy code.

## Quick start

Clone the repository:

```bash
git clone https://github.com/rizkyAlya/TwinRange-SG.git
cd TwinRange-SG
```

Install system dependencies:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch iperf tcpdump hping3 iproute2 net-tools iptables
```

Create and activate the Python virtual environment:

```bash
python3 -m venv --system-site-packages .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the baseline experiment:

```bash
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/baseline.yaml
```

Analyze the results:

```bash
python scripts/analyze_results.py --input results/ --output results/summary/
```

## Run experiments

Each experiment is defined by a YAML configuration file under `configs/experiments/`. The run command validates the selected configuration, generates the Mininet topology and host applications, and executes the complete scenario.

Run the predefined scenarios:

```bash
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/baseline.yaml
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/mitm.yaml
sudo .venv/bin/python scripts/run_experiment.py --config configs/experiments/dos.yaml
```

Run every recipe under `configs/experiments/` sequentially:

```bash
sudo .venv/bin/python scripts/run_experiment.py --all
```

Validate a configuration without Mininet or root access:

```bash
python scripts/run_experiment.py --config configs/experiments/baseline.yaml --dry-run
python scripts/run_experiment.py --all --dry-run
```

## Output files

Raw experiment outputs are written under `results/raw/`. Each run contains CSV logs, metadata, and optional PCAP files depending on the selected configuration.

Typical output structure:

```text
results/
  raw/
    <scenario_name>/
      <run_id>/
        meta.json
        *.csv
        *.pcap

  summary/
    run_inventory.csv
    network_summary.csv
    telemetry_summary.csv
    analysis_manifest.json
    figures/
```

Each `meta.json` file embeds the experiment configuration, configuration SHA-256 hash, generator hashes, random seeds, and runtime platform information.

## Analyze results

Run the analysis command after one or more scenarios have completed:

```bash
python scripts/analyze_results.py --input results/ --output results/summary/
```

The analysis command creates network and Field–Digital Twin telemetry summaries, figures for RTT, packet loss, throughput, voltage error, and Age of Information, a run inventory, and an `analysis_manifest.json` containing hashes of all consumed inputs and produced outputs.

## Metrics

TwinRange-SG supports analysis of communication-level and Field–Digital Twin metrics, including:

* Round-trip time
* Packet loss
* Throughput
* Age of Information
* Voltage error
* Field–Digital Twin telemetry deviation
* Scenario-level run inventory and reproducibility metadata

## Reproducibility

TwinRange-SG records reproducibility metadata for each experiment run. The metadata includes the full experiment configuration, configuration hash, generator hashes, random seeds, and runtime platform information. The analysis pipeline also produces an `analysis_manifest.json` file containing hashes of consumed inputs and produced outputs.

These files are intended to help users inspect, validate, and reproduce experiment results.

## Troubleshooting

Clean previous Mininet state:

```bash
sudo mn -c
```

Restart Open vSwitch:

```bash
sudo systemctl restart openvswitch-switch
```

Check whether Python packages are visible under `sudo`:

```bash
sudo .venv/bin/python -c "import yaml; print('OK')"
```

Validate a configuration without running Mininet:

```bash
python scripts/run_experiment.py --config configs/experiments/baseline.yaml --dry-run
```

## Ethical use

TwinRange-SG is intended only for cybersecurity research, education, and controlled cyber-range experiments. The included attack scenarios must only be executed inside isolated laboratory environments or authorized testbeds. The software must not be used against real systems, public networks, or third-party infrastructure without explicit permission.

## Known limitations

* Mininet experiments require Linux and root privileges.
* The software cannot run natively on Windows because Mininet depends on Linux network namespaces.
* Runtime performance and timing measurements may vary depending on host machine load.
* The predefined scenarios are intended for isolated cyber-range environments.
* The current release focuses on the provided smart grid test case and predefined baseline, MITM, and DoS scenarios.

## License

This project is released under the Apache License 2.0. See `LICENSE.txt` for details.
