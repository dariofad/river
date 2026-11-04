import sys

import streamlit as st


def main() -> None:
    st.set_page_config(page_title="River Dashboard", layout="wide")
    results_only = "--results-only" in sys.argv[1:]
    pages = (
        [st.Page("pages/results.py", title="Results", default=True)]
        if results_only
        else [
            st.Page("pages/upload.py", title="Upload", default=True),
            st.Page("pages/manifest.py", title="Manifest"),
            st.Page("pages/results.py", title="Results"),
        ]
    )
    page = st.navigation(pages, position="hidden")
    page.run()


if __name__ == "__main__":
    main()
