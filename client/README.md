# Demos

This folder collects the demos.
Use them to test the simulation server and analyze the approach.

## Quickstart

- Install the workspace dependencies from the repository root with
  `uv sync`
- If you also need the Python development tools, use
  `uv sync --dev`
- Make sure the server is up and running, and the demo configuration
  files have been adapted to your local environment (see
  `../simulation/readme.md`)
- Check the list of available demos with `make`
- Use the Makefile variables `HOST`, `M` and `C` to customize your
  test
- Run a demo, for example with `make monit M=1 C=1` (default `HOST`
  is 127.0.0.1)

For the live state perturbation demos, make sure the address of the
state variables `ADDR` is valid for your local environment (again, see
`../simulation/README.md`)
