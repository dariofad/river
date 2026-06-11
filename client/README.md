# Demos

This folder collects the demos.
Use them to test the simulation server and analyze the approach.

## Quickstart

- Create a local virtual environment `python3 -m venc .venv` (only
  once)
- Activate the virtual environment `source .venv/bin/activate`
- Install the dependencies `pip install -r requirements.txt` (every
  time dependencies are updated)
- Make sure the server is up and running, and the demo configuration
  files have been adapted to your local environment (see
  `../simulation/readme.md`)
- Check the list of available demos with `make`
- Use the Makefile variables `HOST`, `M` and `C` to customize your
  test
- Run a demo, for example with `make monit M=1 C=1` (default `HOST`
  is 127.0.0.1)
- Deactivate the virtual environment with `deactivate`

For the live state perturbation demos, make sure the address of the
state variables `ADDR` is valid for your local environment (again, see
`../simulation/README.md`)
