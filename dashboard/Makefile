.DEFAULT_GOAL := dash

dash:
	@test -n "$(RIVER_MANIFEST)" || (echo "RIVER_MANIFEST=/path/to/model.river.yaml is required"; exit 2)
	@RIVER_MANIFEST="$(RIVER_MANIFEST)" uv run dashboard.py
