# Demos

This folder contains manifest-only demo scenario templates. Each template uses
`$MODELS_DIR` in `artifact.binary` so it is independent of any developer's local
filesystem.

Client Make targets copy `mx_cy.river.yaml` to `simulator/manifest.yaml` and run
`river-manifest repair` in memory (using `MODELS_DIR`, defaulting to `../../sim2cpp`)
just before sending the simulation request to the server.

