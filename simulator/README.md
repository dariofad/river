# Simulator manifests

River is configured exclusively through `simulator/manifest.yaml`. Before a
simulation starts, River reads that YAML file, validates its binary fingerprint,
resolves hooks and data addresses, and constructs its runtime configuration in
memory. It never reads or creates a JSON configuration file.

The client demo targets select one checked-in scenario manifest atomically:

```bash
cd client
make monit m=3 c=1
```

The active-manifest workflow supports one selected demo at a time. Do not
replace `simulator/manifest.yaml` while a simulation is running.

## Creating and editing a manifest

Generate an editable manifest for a model binary:

```bash
./river-manifest generate --binary /path/to/model --output model.river.yaml
```

Use `--output -` to write the YAML to standard output without creating a
manifest file. Warnings and errors are written to standard error, so callers
can capture the generated YAML directly in memory.

Set `artifact.binary`, review `settings`, select model-local hooks and their
phases, then select inputs, outputs, and states in each hook's `data` list.
The manifest is the complete customization surface: no separate JSON
translation or manually maintained runtime addresses are needed for discovered
model data.

```yaml
artifact:
  binary: /path/to/model
settings:
  cycles: 100
  sample_every: 1
  timer:
    model: Controller
    hook: step
models:
  - name: Controller
    enabled: true
    available_hooks:
      - id: step
    hooks:
      - id: step
        phase: entry
        action: write
        data: [Controller.Controller_U.setpoint]
      - id: step
        phase: post_outputs
        action: read
        data: [Controller.Controller_Y.value]
```

Use `entry`, `return`, or (for discovered Simulink `step`) `post_outputs`.
`return` creates a native uretprobe. Use `custom` only for a manually selected
instruction boundary and give it a prefixed hexadecimal `offset`.

Manual models define a hook `symbol` and custom data with an ELF virtual
`address`; addresses and offsets always retain their `0x` prefix. River checks
the binary build ID, hook boundaries, data ranges, and writable segments before
the model starts. It supports `bool`, signed and unsigned 8/16/32/64-bit
integers, `float32`, and `float64` scalar data.

Signal perturbations add numeric values at their native width and toggle
booleans. State perturbation messages must specify `TYPE`, matching
`VALUE_SIZE`, and an ELF virtual `ADDR` (not an ASLR runtime address).

## Demo manifests

`simulator/demos/mx_cy.river.yaml` contains the demo manifest templates for each
client and dashboard scenario. Their `artifact.binary` field uses the `$MODELS_DIR`
placeholder (for example, `$MODELS_DIR/DualACC/dualACC`).

When running demos from `client/` (e.g. `make monit m=1 c=1 MODELS_DIR=/path/to/models`)
or selecting a demo template in the dashboard, `river-manifest repair` is invoked
automatically in memory before sending the request to the server:

```bash
./river-manifest repair --manifest simulator/demos/m1_c1.river.yaml --models-dir /path/to/models --output -
```

This resolves `artifact.binary` against `MODELS_DIR` (or an explicit `--binary`
override) and recomputes `artifact.build_id` for the local binary without
modifying the checked-in template files.

