# Simulator manifests

River is configured exclusively through `simulator/manifest.yaml`. Before a
simulation starts, River reads that YAML file, validates its binary fingerprint,
resolves hooks and data addresses, and constructs its runtime configuration in
memory. It never reads or creates a JSON configuration file.

The client demo targets select one checked-in scenario manifest atomically:

```bash
cd client
make monit M=3 C=1
```

The active-manifest workflow supports one selected demo at a time. Do not
replace `simulator/manifest.yaml` while a simulation is running.

## Creating and editing a manifest

Generate an editable manifest for a model binary:

```bash
./river-manifest generate --binary /path/to/model --output model.river.yaml
```

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
  timer_model: Controller
  timer_hook: step
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

`simulator/demos/Mx_Cy.river.yaml` replaces the former JSON demo
configuration. Each contains the binary, timing, hook selection, and selected
signals for its client scenario. The `client` Make targets atomically install
the chosen one as `simulator/manifest.yaml` before contacting River.
