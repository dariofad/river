# Demos

This folder collects the demos.
Use them to test the simulation server and analyze the approach.

## Quickstart

- Install all Python dependencies and development tools with `uv sync --locked`
  from this directory or the repository root. Both use the root `.venv` and
  `pyproject.toml`, shared with the dashboard.
- Make sure the server is up and running (`make` from the repository root), which
  also builds `./river-manifest`.
- Check the list of available demos with `make`
- Use the Makefile variables `HOST`, `MODELS_DIR`, `m` and `c` to customize your
  test. By default, `MODELS_DIR` resolves to `../../sim2cpp` (sibling to the `river`
  repository). Before each demo sends its request to the server, it invokes
  `river-manifest repair` in memory to replace `$MODELS_DIR` and `$BUILD_ID` in the
  demo manifest template for your local environment and architecture.
- Run a demo, for example with `make monit m=1 c=1` or
  `make monit m=1 c=1 MODELS_DIR=/path/to/models` (default `HOST` is 127.0.0.1)
- To view live plots of CLI demo runs in the browser, run `make plot` (or
  `make dash`) from `../dashboard`.

For the live state perturbation demos, perturbations can reference variables by
their full catalog path (`NAME`) from the manifest, or specify a raw ELF virtual
address (`ADDR`) valid for your local environment (see `../simulator/README.md`).

