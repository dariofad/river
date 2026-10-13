import tempfile
from pathlib import Path

import streamlit as st

st.title("River simulation")
st.subheader("1. Upload a model binary")
st.caption("The uploaded filename is preserved for manifest generation.")

uploaded_file = st.file_uploader("Model binary", accept_multiple_files=False)

if st.button("Use this binary", type="primary", disabled=uploaded_file is None):
    if uploaded_file is None:
        st.stop()

    filename = Path(uploaded_file.name).name
    try:
        if filename != uploaded_file.name or not filename:
            raise RuntimeError("The uploaded binary has an invalid filename.")

        contents = uploaded_file.getvalue()
        if not contents.startswith(b"\x7fELF"):
            raise RuntimeError(f"`{filename}` is not an ELF binary.")

        upload_dir = Path(tempfile.mkdtemp(prefix="river-dashboard-upload-"))
        binary = upload_dir / filename
        binary.write_bytes(contents)
        binary.chmod(0o700)
    except (OSError, RuntimeError) as exc:
        st.error(str(exc))
        st.stop()
    st.session_state.pop("manifest_text", None)
    st.session_state.pop("manifest_binary", None)
    st.session_state.pop("parsed_manifest", None)
    st.session_state.pop("simulation_run", None)
    st.session_state.pop("scenario_name", None)
    st.session_state.uploaded_binary_path = str(binary)
    st.session_state.uploaded_binary_name = uploaded_file.name
    st.switch_page("pages/manifest.py")
