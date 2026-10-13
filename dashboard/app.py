import streamlit as st


def main() -> None:
    st.set_page_config(page_title="River Dashboard", layout="wide")
    page = st.navigation(
        [
            st.Page("pages/upload.py", title="Upload", default=True),
            st.Page("pages/manifest.py", title="Manifest"),
            st.Page("pages/results.py", title="Results"),
        ],
        position="hidden",
    )
    page.run()


if __name__ == "__main__":
    main()
