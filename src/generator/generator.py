# Generator membaca topology.yaml dan membuat script/topology.py serta app host dari template Jinja.
# Folder templates sengaja tidak diberi komentar sesuai permintaan.
import os
import yaml
import argparse
import json
import hashlib
from jinja2 import Environment, FileSystemLoader

PACKAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(PACKAGE_DIR, ".."))
TEMPLATE_DIR = os.path.join(PACKAGE_DIR, "generator", "templates")
STATIC_DIR = os.path.join(PACKAGE_DIR, "generator", "static")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "script")

# Environment Jinja diarahkan hanya ke generator/templates.
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), keep_trailing_newline=True)

ROLE_TEMPLATE = {
    "field": "field.j2",
    "rtu": "rtu.j2",
    "gateway": "gateway.j2",
    "dt": "dt.j2",
    "attacker": "attacker.j2",
}

def load_config(path):
    """Baca konfigurasi topologi YAML."""
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if not isinstance(config, dict):
        raise ValueError(f"Configuration must be a YAML mapping: {path}")
    return config


def sha256_file(path):
    """Hitung SHA-256 untuk provenance artefak eksperimen."""
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text_file(path, content):
    """Tulis file secara atomik agar artefak lama tidak menjadi setengah-tertulis."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary_path = f"{path}.tmp"
    with open(temporary_path, "w", encoding="utf-8", newline="\n") as output_file:
        output_file.write(content)
    os.replace(temporary_path, path)

def parse_topology(config):
    """Ubah config zona menjadi daftar host, IP, link, dan indeks role."""
    zones = config["topology"]["zones"]
    bandwidth = config.get("network", {}).get("bandwidth", 5)
    links = config.get("topology", {}).get("links", [])

    all_hosts = []
    zone_map = {}
    hosts_by_name = {}
    hosts_by_role = {}

    for zone_name, zone in zones.items():
        subnet_base = zone["subnet"].split("/")[0].rsplit(".", 1)[0]

        zone_hosts = []

        for i, host in enumerate(zone["hosts"]):
            host_data = {
                "name": host["name"],
                "role": host["role"],
                "ip": f"{subnet_base}.{i+2}",
                "zone": zone_name,
            }
            all_hosts.append(host_data)
            zone_hosts.append(host_data)
            hosts_by_name[host_data["name"]] = host_data
            hosts_by_role.setdefault(host_data["role"], []).append(host_data)

        zone_map[zone_name] = zone_hosts

    return all_hosts, zone_map, links, bandwidth, hosts_by_name, hosts_by_role

def generate_apps(hosts, app_mode="host"):
    """Render app host dari template berdasarkan role dan simpan app_map.json."""
    app_dir = os.path.join(OUTPUT_DIR, "apps")
    os.makedirs(app_dir, exist_ok=True)
    app_map = {}
    role_counts = {}

    for host in hosts:
        role = host["role"]
        template_name = ROLE_TEMPLATE[role]
        template = env.get_template(template_name)

        # Template diberi konteks host, daftar host, dan map role untuk resolve endpoint.
        output = template.render(
            host=host,
            all_hosts=hosts,
            hosts_by_name=generate_apps.hosts_by_name,
            hosts_by_role=generate_apps.hosts_by_role,
        )

        if app_mode == "role":
            role_counts[role] = role_counts.get(role, 0) + 1
            idx = role_counts[role]
            script_name = f"{role}.py" if idx == 1 else f"{role}_{idx}.py"
        else:
            script_name = f"{host['name']}.py"

        app_map[host["name"]] = script_name
        write_text_file(os.path.join(app_dir, script_name), output)

    # app_map dipakai orchestrator untuk menemukan file app walau mode nama berubah.
    app_map_json = json.dumps(app_map, indent=2, sort_keys=True) + "\n"
    write_text_file(os.path.join(app_dir, "app_map.json"), app_map_json)
    return app_map

def generate_topology(hosts, zone_map, links, bandwidth, hosts_by_role):
    """Render file topology.py dan pastikan minimal ada satu attacker."""
    template = env.get_template("topology.j2")
    attacker_hosts = hosts_by_role.get("attacker", [])
    if not attacker_hosts:
        raise ValueError(
            "Topology requires at least one host with role 'attacker' (Control foothold + optional Field link)."
        )
    attacker_name = attacker_hosts[0]["name"]

    output = template.render(
        hosts=hosts,
        zones=zone_map,
        links=links,
        bandwidth=bandwidth,
        attacker_name=attacker_name,
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    write_text_file(os.path.join(OUTPUT_DIR, "topology.py"), output)


def generate_static_assets():
    """Salin aset runtime non-template ke output generator."""
    generated = []
    for current_dir, dirnames, filenames in os.walk(STATIC_DIR):
        dirnames.sort()
        for filename in sorted(filenames):
            source = os.path.join(current_dir, filename)
            relative = os.path.relpath(source, STATIC_DIR)
            destination = os.path.join(OUTPUT_DIR, relative)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with open(source, "rb") as source_file, open(destination, "wb") as output_file:
                output_file.write(source_file.read())
            generated.append(relative)
    return generated


def generate_project(config_path, app_mode="host"):
    """Bangkitkan seluruh artefak runtime dan tulis manifest hash deterministik."""
    config_path = os.path.abspath(config_path)
    config = load_config(config_path)
    hosts, zone_map, links, bandwidth, hosts_by_name, hosts_by_role = parse_topology(config)

    generate_apps.hosts_by_name = hosts_by_name
    generate_apps.hosts_by_role = hosts_by_role
    app_map = generate_apps(hosts, app_mode=app_mode)
    generate_topology(hosts, zone_map, links, bandwidth, hosts_by_role)
    static_files = generate_static_assets()

    generated_files = ["topology.py", "apps/app_map.json"]
    generated_files.extend(f"apps/{name}" for name in sorted(app_map.values()))
    generated_files.extend(static_files)
    template_files = sorted(
        name for name in os.listdir(TEMPLATE_DIR) if name.endswith(".j2")
    )
    manifest = {
        "app_mode": app_mode,
        "config": {
            "file": os.path.basename(config_path),
            "sha256": sha256_file(config_path),
        },
        "templates": {
            name: sha256_file(os.path.join(TEMPLATE_DIR, name))
            for name in template_files
        },
        "static_assets": {
            name.replace(os.sep, "/"): sha256_file(os.path.join(STATIC_DIR, name))
            for name in static_files
        },
        "generated_files": {
            name.replace(os.sep, "/"): sha256_file(os.path.join(OUTPUT_DIR, name))
            for name in generated_files
        },
    }
    manifest_path = os.path.join(OUTPUT_DIR, "generation_manifest.json")
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    write_text_file(manifest_path, manifest_json)
    return manifest

def main():
    """Entry point CLI generator."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-C", "--config", required=True)
    parser.add_argument(
        "--app-mode",
        choices=["host", "role"],
        default="host",
        help="Generated app filename mode: host (h1.py) or role (field.py, dt.py, ...)",
    )
    args = parser.parse_args()

    generate_project(args.config, app_mode=args.app_mode)

    print("Generation complete!")
    print(f"Output directory: {OUTPUT_DIR}")
    print(f"App filename mode: {args.app_mode}")
    print(f"App mapping file: {os.path.join(OUTPUT_DIR, 'apps', 'app_map.json')}")

if __name__ == "__main__":
    main()
