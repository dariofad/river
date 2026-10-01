# Demos

This folder contains manifest-only demo scenarios. Client Make targets select
`mx_cy.river.yaml` as `simulator/manifest.yaml` before a run. Each manifest is
validated against its declared binary, so regenerate/update it when rebuilding
or relocating a model.
