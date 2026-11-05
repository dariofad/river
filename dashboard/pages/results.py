from typing import Any, cast

import plotly.express as px
import streamlit as st
from scenarios import SCENARIOS
from scenarios.common import ScenarioRun, read_redis_results, read_response_results

st.title("3. Simulation results")

manifest = st.session_state.get("parsed_manifest")
scenario_name = st.session_state.get("scenario_name")
run = st.session_state.get("simulation_run")
cli_mode = manifest is None or scenario_name is None or run is None

if cli_mode:
    st.caption("Live Redis monitor")
else:
    active_manifest = cast(dict[str, Any], manifest)
    active_run = cast(ScenarioRun, run)
    scenario = SCENARIOS[cast(str, scenario_name)]
    st.caption(f"Scenario: {scenario.LABEL}")


@st.fragment(run_every=0.25)
def live_results() -> None:
    if not cli_mode:
        status, message = active_run.state
        if status == "running":
            st.info(message)
        elif status == "complete":
            st.success(message)
        else:
            st.error(message)

    try:
        if cli_mode:
            dataframe = read_redis_results()
        elif scenario.RESULTS == "redis":
            dataframe = read_redis_results(active_manifest)
        else:
            dataframe = read_response_results(active_run)
    except RuntimeError as exc:
        st.error(str(exc))
        return

    if dataframe.empty:
        st.info("Waiting for simulation data…")
        return

    signal_columns = [column for column in dataframe.columns if column != "time"]
    figure = px.line(
        dataframe,
        x="time",
        y=signal_columns,
        title=f"Time series ({len(signal_columns)} signals detected)",
        labels={"value": "Signal value", "variable": "Signals"},
    )
    figure.update_layout(xaxis_title="Loop cycle", uirevision="constant")
    st.plotly_chart(figure, width="stretch", key="live-results")

    st.subheader("Latest data")
    st.dataframe(dataframe, width="stretch", hide_index=True)
    st.download_button(
        "Export to CSV",
        data=dataframe.to_csv(index=False),
        file_name="river-simulation.csv",
        mime="text/csv",
    )


live_results()
