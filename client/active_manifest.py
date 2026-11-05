import os
import subprocess
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEMOS_DIR = REPOSITORY_ROOT / "simulator" / "demos"
MANIFEST_TOOL = Path(
    os.environ.get("RIVER_MANIFEST_TOOL", REPOSITORY_ROOT / "river-manifest")
).expanduser()
DEFAULT_MODELS_DIR = REPOSITORY_ROOT.parent / "sim2cpp"


def demo_manifest_path(model: str, config: str) -> Path:
    return DEMOS_DIR / f"m{model}_c{config}.river.yaml"


def read_manifest_text(model: str, config: str) -> str:
    manifest_path = demo_manifest_path(model, config)
    models_dir = os.environ.get("MODELS_DIR") or str(DEFAULT_MODELS_DIR)
    try:
        result = subprocess.run(
            [
                str(MANIFEST_TOOL),
                "repair",
                "--manifest",
                str(manifest_path),
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


def read_manifest(model: str, config: str) -> dict:
    manifest_path = demo_manifest_path(model, config)
    with manifest_path.open(encoding="utf-8") as file:
        manifest = yaml.safe_load(file)
    if not isinstance(manifest, dict):
        raise ValueError(f"{manifest_path} does not contain a manifest")
    return manifest


def manifest_cycles(model: str, config: str) -> int:
    settings = read_manifest(model, config).get("settings", {})
    return int(settings["cycles"])
