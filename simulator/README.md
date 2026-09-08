# Simulator configuration

The simulator reads `simulator/config.json`. Demo templates live in
`simulator/demos/`; copy the chosen template to `simulator/config.json` before
starting a run.

```bash
cp simulator/demos/M2_C2_config.json simulator/config.json
```

The templates describe the binaries available in the companion `sim2cpp`
repository. Update `MODEL_PATH`, symbols, offsets, and addresses whenever you
use a different build of a model.

For a new C++ model, `river-manifest` can discover a Simulink model and
produce an editable YAML manifest:

```bash
go run ./cmd/river-manifest generate \
  --binary /path/to/model \
  --output model.river.yaml
```

The generated manifest selects supported inputs for writing at `step.entry`,
then selects supported inputs and outputs for reading at `step.post_outputs`
when DWARF/source mapping identifies the first instruction after the last
output assignment. If that proof is unavailable it conservatively uses
`step.return` and emits a warning. States are available but not selected by
default. Each model owns its own
`available_hooks` and `hooks`: hook IDs are therefore model-local. Review
`cycles`, `sample_every`, `timer_model`, `timer_hook`, data names, and hook selections. The
compiler resolves each selected hook's phase to the target binary's symbol and
instruction offset, so the manifest remains independent of its machine code.

For generated continuous models, `sample_every` is inferred from the actual
number of `step()` calls in the generated fixed-step solver source (rather
than assuming that an ODE method's name equals its stage count). Discrete,
implicit, variable-step, or unproven solver code uses `1` and emits a warning.

```yaml
models:
  - name: ToyModel
    available_hooks:
      - id: step
    hooks:
      - id: step
        phase: entry
        action: write
        data: [ToyModel.ToyModel_U.x]
      - id: step
        phase: post_outputs
        action: read
        data: [ToyModel.ToyModel_U.x, ToyModel.ToyModel_Y.y]
```

Compile the refined manifest against the target binary:

```bash
go run ./cmd/river-manifest compile \
  --manifest model.river.yaml \
  --binary /path/to/model \
  --output simulator/config.json
```

Compilation verifies the binary fingerprint, resolves semantic hook IDs to
symbols and instruction boundaries, verifies static model instances, data
types and addresses, then atomically writes the existing JSON format. Every
selected `read` or `write` hook becomes one JSON group. Selections may include
fixed-width scalar `bool`, signed and unsigned 8/16/32/64-bit integers, and
`float32` or `float64` inputs, outputs, and states. States include
continuous (`*_X`) and block (`*_DW`) state; static model parameters are
available for reads and, when their ELF load segment is writable, writes. The
simulator supports at most 16 signals in each direction.

Use `entry`, `return`, or (for `step`) `post_outputs` to select a compiler-
resolved phase. `return` compiles to a native uretprobe (`"RETPROBE": true`)
at the function and therefore uses offset `0x0`. For a manually chosen probe
site, use `phase: custom` and a hexadecimal `offset`; compilation verifies that it
is an instruction boundary:

```yaml
- id: step
  phase: custom
  offset: 0x37
  action: read
  data: [ToyModel.ToyModel_Y.y]
```

Hand-written JSON groups may use `"RETPROBE": true` to request the same
native return probe. The field is omitted or `false` for normal uprobes; a
retprobe must use offset `"0x0"`.

## Manual models and data

When a binary is not recognized as a Simulink model, `generate` writes a
fingerprinted skeleton and warns that its model definition must be supplied
manually. Define each hook with its exact ELF function symbol and each custom
data item with its ELF virtual address. Custom entries remain in the normal
`inputs`, `outputs`, or `states` lists; `address` makes their location
explicit. The runtime supports all fixed-width scalar types listed above.
Signal perturbations add numeric values at their native width (wrapping on
integer overflow); boolean perturbations toggle their value. State
perturbations must include `TYPE` and the matching native `VALUE_SIZE`.

```yaml
settings:
  cycles: 100
  sample_every: 1
  timer_model: Controller
  timer_hook: tick
models:
  - name: Controller
    enabled: true
    available_hooks:
      - id: tick
        symbol: controller_tick
    inputs:
      - name: SETPOINT
        path: controller.setpoint
        type: float64
        address: 0x4040
    outputs:
      - name: VALUE
        path: controller.value
        type: float64
        address: 0x4048
    states:
      - name: INTEGRAL
        path: controller.integral
        type: float64
        address: 0x4050
    hooks:
      - id: tick
        phase: entry
        action: write
        data: [controller.setpoint]
      - id: tick
        phase: return
        action: read
        data: [controller.value, controller.integral]
```

Custom hooks support `entry`, `return`, and `custom`; `post_outputs` needs
Simulink DWARF/source information and is unavailable to manual hooks. Manual
compilation does not require DWARF, but hook symbols must be available in the
ELF. Addresses are validated against its loadable segments and writes require
a writable segment.

## Address model and ASLR

`ADDR` values are **ELF virtual addresses**, not addresses from a running
process. They are stable for one particular model binary and are written as
prefixed hexadecimal strings, for example `"0x4048"`. Hook `OFFSET` values
use the same representation.

ASLR must remain enabled. At startup River launches the model in a temporary
post-`exec` ptrace stop, reads `/proc/<pid>/maps`, calculates the load bias,
and writes the corresponding runtime addresses to the eBPF map. It then
detaches from the model before normal simulation begins.

Do not use an address copied from a running process, such as
`0x5555...` or `0xaaaa...`; that value includes a particular run's ASLR bias
and will be wrong for the next run. State perturbation `ADDR` values follow the
same rule.

## JSON format

```json
{
  "MODEL_PATH": "/absolute/path/to/model",
  "TIMER_SYMBOL": "mangled_or_exported_timer_symbol",
  "MINOR_TO_MAJOR_RATIO": "1",
  "NOF_CYCLES": "20",
  "WRITES": [
    {
      "SYMBOL": "hook_symbol",
      "OFFSET": "0x4a",
      "SIGNALS": [
        {"NAME": "INPUT", "TYPE": "float64", "ADDR": "0x4048"}
      ]
    }
  ],
  "READS": [
    {
      "SYMBOL": "hook_symbol",
      "OFFSET": "0x4f",
      "SIGNALS": [
        {"NAME": "OUTPUT", "TYPE": "float64", "ADDR": "0x4058"}
      ]
    }
  ]
}
```

Each `READS` or `WRITES` item is an independently attached uprobe group. Its
`OFFSET` is a hexadecimal byte offset relative to that group's `SYMBOL`; it is not
an absolute ELF address. A configuration can contain at most 16 read signals
and 16 write signals. A single group can contain all 16: its size minus one is
encoded in the lower four bits of the eBPF attach cookie.

Place write hooks before the model consumes the configured inputs and read
hooks after it has produced the configured outputs. The last read group flushes
each sampled record and drives the configured-cycle termination condition.

## Deriving or refining probe sites manually

1. Identify the model entry point and its ELF address:

   ```bash
   nm -C --defined-only /path/to/model | rg '::step|rt_OneStep'
   ```

2. Obtain static addresses for global/model fields. GDB can inspect the ELF
   without running it:

   ```bash
   gdb -q /path/to/model
   (gdb) p/x &Simulink2Code_Obj.Simulink2Code_U.x
   ```

   Record the result with its `0x` prefix as `ADDR`. Confirm it belongs to a loadable
   ELF segment with `readelf -lW /path/to/model`.

3. Disassemble the hook function and choose an instruction boundary:

   ```bash
   objdump -d -C --disassemble='rt_OneStep()' /path/to/model
   ```

   Subtract the symbol's start address from the selected instruction address;
   convert that difference to hexadecimal and put it in `OFFSET`. Do not use an offset in the middle
   of an x86 instruction. Source-line information is useful for locating the
   relevant code, but validate the final location in the disassembly:

   ```bash
   addr2line -e /path/to/model -f -C 0x1238
   ```

4. Validate the JSON before running a simulation:

   ```bash
   jq . simulator/config.json > /dev/null
   ```

## Existing demo probe sites

In `simulator/demos/` there are examples of offsets and all `ADDR` values for
the binaries reported in the companion repository. Recalculate them after
recompiling a model or switching to another executable. See below as an example.

### Model 1

```bash
nm -C --defined-only dualACC | rg 'egoCar::step()' # 4a14
gdb -q dualACC
p/x &ego.egoCar_Y.d_rel # 30328
info line egoCar.cpp:2301 # 0x4b48 (symbol + 308)
p/x &ego.egoCar_Y.a_ego # 30340
p/x &ego.egoCar_Y.v_ego # 30338
p/x &ego.egoCar_Y.v_rel # 30330
p/x &ego.egoCar_U.d_lead # 30318
p/x &ego.egoCar_X.Integrator1_CSTATE # 30470
info line egoCar.cpp:2551 # 0x5974 (symbol + 3936)
```

### Model 2

```bash
nm -C --defined-only Simulink2Code | rg '::step()' # 1888
gdb -q Simulink2Code
info line main.cpp:61 # 80
info line main.cpp:64 # 92
p/x &Simulink2Code_Obj.Simulink2Code_U.x # 20020
p/x &Simulink2Code_Obj.Simulink2Code_U.y # 20028
p/x &Simulink2Code_Obj.Simulink2Code_Y.result # 20030
p/x &Simulink2Code_Obj.model_offset # 20018
```

### Model 3

```bash
nm -C --defined-only fuel_control  | grep -i "::step()" # 30f0
gdb -q fuel_control
p/x &model.AbstractFuelControl_M1_U.PedalAngle # 30698
p/x &model.AbstractFuelControl_M1_U.EngineSpeed # 306a0
p/x &model.AbstractFuelControl_M1_Y.AF # 306b0
p/x &model.AbstractFuelControl_M1_Y.controller_mode # 306b8
p/x &AbstractFuelControl_M1::AbstractFuelControl_M1_P.Baseopeningangle_Value # 30278
info line AbstractFuelControl_M1.cpp:1065 # 4428
```

### Model 4

```bash
nm -C --defined-only Tester  | grep -i "::step()" # 17fc
gdb -q Tester
info line Tester.cpp:34 # 52
info line Tester.cpp:36 # 80
info line Tester.cpp:26 # 12
info line Tester.cpp:32 # 36
info line Tester.cpp:37 # 120
p/x &m.extU.x # 20018
p/x &m.extU.y # 20020
p/x &m.extU.z # 20028
p/x &m.offset # 20038
```
