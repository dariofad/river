from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import streamlit as st
import yaml
from scenarios import SCENARIOS, SUPPORTED_BINARIES
from scenarios.common import clear_results, launch

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_TOOL = Path(
    os.environ.get("RIVER_MANIFEST_TOOL", REPOSITORY_ROOT / "river-manifest")
).expanduser()
ACTIVE_MANIFEST = REPOSITORY_ROOT / "simulator" / "manifest.yaml"


def generate_manifest(binary: Path) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="river-dashboard-") as temp_dir:
        output = Path(temp_dir) / "manifest.yaml"
        try:
            result = subprocess.run(
                [
                    str(MANIFEST_TOOL),
                    "generate",
                    "--binary",
                    str(binary),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError as exc:
            raise RuntimeError(f"Could not run the manifest generator: {exc}") from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(detail or "Manifest generation failed.")
        try:
            manifest_text = output.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Could not read generated manifest: {exc}") from exc

    warnings = "\n".join(
        line for line in result.stderr.splitlines() if line.startswith("warning:")
    )
    return manifest_text, warnings


def activate_manifest(text: str) -> None:
    try:
        ACTIVE_MANIFEST.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Could not activate the manifest: {exc}") from exc


st.title("2. Review the manifest")

uploaded_binary_path = st.session_state.get("uploaded_binary_path")
if not uploaded_binary_path:
    st.warning("Upload a model binary before generating a manifest.")
    st.page_link("pages/upload.py", label="Go to binary upload")
    st.stop()

uploaded_binary_name = st.session_state["uploaded_binary_name"]
binary = Path(uploaded_binary_path)
st.caption(f"Generated from uploaded binary `{uploaded_binary_name}`")

manifest_text = st.session_state.get("manifest_text", "")
warnings = ""
if st.session_state.get("manifest_binary") != uploaded_binary_path:
    try:
        with st.spinner("Generating manifest…"):
            manifest_text, warnings = generate_manifest(binary)
    except RuntimeError as exc:
        st.error(str(exc))
        st.stop()
    st.session_state.manifest_text = manifest_text
    st.session_state.manifest_binary = uploaded_binary_path
    if warnings:
        st.warning(warnings)

manifest_text = st.text_area(
    "Editable YAML manifest",
    key="manifest_text",
    height=600,
    help="Edit hook selections, settings, and signals before starting the simulation.",
)

available_scenarios = {
    name: scenario
    for name, scenario in SCENARIOS.items()
    if uploaded_binary_name in SUPPORTED_BINARIES[name]
}
if not available_scenarios:
    st.error(f"No client scenarios are available for `{uploaded_binary_name}`.")
    st.stop()

scenario_name = st.selectbox(
    "Scenario",
    list(available_scenarios),
    format_func=lambda name: available_scenarios[name].LABEL,
)
scenario = available_scenarios[scenario_name]

if st.button("Simulate", type="primary"):
    try:
        manifest = yaml.safe_load(manifest_text)
        request = scenario.build_request(uploaded_binary_name, manifest)
        if scenario.RESULTS == "redis":
            clear_results()
        activate_manifest(manifest_text)
        run = launch(scenario.PORT, request, scenario.run)
    except RuntimeError as exc:
        st.error(str(exc))
    else:
        st.session_state.parsed_manifest = manifest
        st.session_state.simulation_run = run
        st.session_state.scenario_name = scenario_name
        st.switch_page("pages/results.py")
