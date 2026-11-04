# Demos

This folder collects the demos.
Use them to test the simulation server and analyze the approach.

## Quickstart

- Install all Python dependencies and development tools with `uv sync --locked`
  from this directory or the repository root. Both use the root `.venv` and
  `pyproject.toml`, shared with the dashboard.
- Make sure the server is up and running, and the demo configuration
  files have been adapted to your local environment (see
  `../simulator/README.md`)
- Check the list of available demos with `make`
- Use the Makefile variables `HOST`, `m` and `c` to customize your
  test
- Run a demo, for example with `make monit m=1 c=1` (default `HOST`
  is 127.0.0.1)

For the live state perturbation demos, make sure the address of the
state variables `ADDR` is valid for your local environment (again, see
`../simulator/README.md`)
