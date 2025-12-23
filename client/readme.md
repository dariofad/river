# Demos

This folder collects the demos available.
Use them to test the simulation server.

## Quickstart

1. Create a local virtual environment `python3 -m venc .venv` (only once)
2. Install the dependencies `pip install -r requirements.txt` (every time dependencies are updated)
3. Activate the virtual environment `source .venv/bin/activate`
4. Make sure the server is up and running, and the demo configuration
   files have been adapted to your local environment
5. Check the list of available demos with `make list`
6. Use the Makefile variables `HOST`, `M` and `C` to customize your
   test
7. Run a demo, for example with `make monit M=1 C=1` (default `HOST`
   127.0.0.1)
8. Deactivate the virtual environment with `deactivate`
