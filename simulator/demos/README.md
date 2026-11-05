# Demos

This folder contains manifest-only demo scenario templates. Each template uses
`$MODELS_DIR` in `artifact.binary` and `$BUILD_ID` in `artifact.build_id` so it is
independent of any developer's local filesystem and target architecture.

Client Make targets read `mx_cy.river.yaml` directly and run `river-manifest repair`
in memory (using `MODELS_DIR`, defaulting to `../../sim2cpp`) just before sending
the simulation request to the server.

