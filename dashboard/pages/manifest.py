from __future__ import annotations

import os
import subprocess
from pathlib import Path

import streamlit as st
import yaml
from scenarios import SCENARIOS, SUPPORTED_BINARIES
from scenarios.common import clear_results, launch

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_TOOL = Path(
    os.environ.get("RIVER_MANIFEST_TOOL", REPOSITORY_ROOT / "river-manifest")
).expanduser()


def generate_manifest(binary: Path) -> tuple[str, str]:
    try:
        result = subprocess.run(
            [
                str(MANIFEST_TOOL),
                "generate",
                "--binary",
                str(binary),
                "--output",
                "-",
            ],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError(f"Could not run the manifest generator: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Manifest generation failed.")

    warnings = "\n".join(
        line for line in result.stderr.splitlines() if line.startswith("warning:")
    )
    return result.stdout, warnings


st.title("2. Review the manifest")

uploaded_binary_path = st.session_state.get("uploaded_binary_path")
if not uploaded_binary_path:
    st.warning("Upload a model binary before generating a manifest.")
    st.page_link("pages/upload.py", label="Go to binary upload")
    st.stop()

uploaded_binary_name = st.session_state["uploaded_binary_name"]
binary = Path(uploaded_binary_path)
st.caption(f"Generated from uploaded binary `{uploaded_binary_name}`")

if st.session_state.get("manifest_binary") != uploaded_binary_path:
    for key in ("manifest_text", "manifest_binary", "manifest_warnings"):
        st.session_state.pop(key, None)
    try:
        with st.spinner("Generating manifest…"):
            manifest_text, warnings = generate_manifest(binary)
    except RuntimeError as exc:
        st.error(str(exc))
        st.stop()
    st.session_state.manifest_text = manifest_text
    st.session_state.manifest_binary = uploaded_binary_path
    st.session_state.manifest_warnings = warnings

warnings = st.session_state.get("manifest_warnings", "")
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
        if not isinstance(manifest, dict):
            raise RuntimeError("The manifest must be a YAML mapping.")
        request = scenario.build_request(uploaded_binary_name, manifest)
        if scenario.RESULTS == "redis":
            clear_results()
        run = launch(scenario.PORT, request, scenario.run, manifest_text)
    except (RuntimeError, yaml.YAMLError, KeyError, TypeError) as exc:
        st.error(str(exc))
    else:
        st.session_state.parsed_manifest = manifest
        st.session_state.simulation_run = run
        st.session_state.scenario_name = scenario_name
        st.switch_page("pages/results.py")
