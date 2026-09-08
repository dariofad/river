from pathlib import Path

import yaml


ACTIVE_MANIFEST = Path(__file__).parent.parent / "simulator" / "manifest.yaml"


def read_active_manifest() -> dict:
    with ACTIVE_MANIFEST.open(encoding="utf-8") as file:
        manifest = yaml.safe_load(file)
    if not isinstance(manifest, dict):
        raise ValueError(f"{ACTIVE_MANIFEST} does not contain a manifest")
    return manifest


def active_cycles() -> int:
    settings = read_active_manifest().get("settings", {})
    return int(settings["cycles"])
