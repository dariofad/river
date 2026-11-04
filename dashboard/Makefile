.DEFAULT_GOAL := run

.PHONY: run plot dash

run:
	@ uv run streamlit run app.py

plot:
	@ uv run streamlit run app.py -- --results-only

dash: plot

