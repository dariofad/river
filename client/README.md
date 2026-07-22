# Demos

This folder collects the demos.
Use them to test the simulation server and analyze the approach.

## Quickstart

- Install the workspace dependencies from the repository root with
  `uv sync`
- If you also need the Python development tools, use
  `uv sync --dev`
- Generate and edit a model manifest, then start the server with
  `-manifest`; see `../simulator/README.md`
- Check the list of available demos with `make`
- Use the Makefile variables `HOST`, `M` and `C` to customize your
  test
- Run a demo, for example with `make monit M=1 C=1` (default `HOST`
  is 127.0.0.1)

Live state perturbations use manifest-qualified `STATE` names. Raw addresses
are no longer accepted.
