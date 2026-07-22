# Demo manifests

Generate manifests directly from the corresponding demo ELF rather than
copying address-based JSON templates. For example:

```bash
go run ./cmd/river-manifest generate \
  --binary ../sim2cpp/ToyModel/Simulink2Code_ert_rtw/Simulink2Code \
  --output simulator/demos/toy.river.yaml
```

The output is tied to the ELF fingerprint and is therefore intentionally not
checked in as a reusable binary-independent configuration.
