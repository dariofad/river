import os
import subprocess
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
ACTIVE_MANIFEST = REPOSITORY_ROOT / "simulator" / "manifest.yaml"
MANIFEST_TOOL = Path(
    os.environ.get("RIVER_MANIFEST_TOOL", REPOSITORY_ROOT / "river-manifest")
).expanduser()
DEFAULT_MODELS_DIR = REPOSITORY_ROOT.parent / "sim2cpp"


def read_active_manifest_text() -> str:
    models_dir = os.environ.get("MODELS_DIR") or str(DEFAULT_MODELS_DIR)
    try:
        result = subprocess.run(
            [
                str(MANIFEST_TOOL),
                "repair",
                "--manifest",
                str(ACTIVE_MANIFEST),
                "--models-dir",
                models_dir,
                "--output",
                "-",
            ],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError(f"Could not run {MANIFEST_TOOL}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or "Manifest repair failed."
        raise RuntimeError(detail)
    return result.stdout


def read_active_manifest() -> dict:
    with ACTIVE_MANIFEST.open(encoding="utf-8") as file:
        manifest = yaml.safe_load(file)
    if not isinstance(manifest, dict):
        raise ValueError(f"{ACTIVE_MANIFEST} does not contain a manifest")
    return manifest


def active_cycles() -> int:
    settings = read_active_manifest().get("settings", {})
    return int(settings["cycles"])
