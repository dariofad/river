# Manifest-based model discovery

River does not accept instruction offsets or absolute userspace addresses.
Build the Simulink C++ executable unstripped with debug information and create
a manifest:

```bash
go run ./cmd/river-manifest generate \
  --binary /path/to/model \
  --output model.river.yaml
```

If the build directory contains `codedescriptor.dmr` and MATLAB is available,
enrich the manifest with authoritative Simulink names, SIDs and categories.
Repeat `--codedescriptor` for each Simulink model linked into one executable:

```bash
go run ./cmd/river-manifest generate \
  --binary /path/to/model \
  --codedescriptor /path/to/model_ert_rtw/codedescriptor.dmr \
  --output model.river.yaml
```

For example, a DualACC executable can use both generated descriptors:

```bash
go run ./cmd/river-manifest generate \
  --binary /path/to/dualACC \
  --codedescriptor /path/to/egoCar_ert_rtw/codedescriptor.dmr \
  --codedescriptor /path/to/leadCar_ert_rtw/codedescriptor.dmr \
  --output dualacc.river.yaml
```

Inputs and outputs are enabled by default; internal states are listed but
disabled. Edit selections and settings, then start River with:

```bash
sudo ./river -manifest model.river.yaml
```

River verifies the executable fingerprint and translates semantic paths into
typed `this`-relative descriptors. ASLR must remain enabled. Regenerate the
manifest after rebuilding the executable.
