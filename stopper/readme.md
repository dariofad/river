# Instructions

This example uses the `AdaptiveCruiseControlExample` from this
[repo](https://github.com/lyudeyun/sim2cpp).

## Setup

- Build the kernel type definitions with `make vmlinux`
- Setup the go module with `make mod_init`
- Clone the `sim2cpp`repo in another directory, make sure you have the
  changes in [PR #1](https://github.com/lyudeyun/sim2cpp/pull/1)
- Build the `AdaptiveCruiseControlExample` running `make` (in its
  directory)
- create a local file named `.BIN_PATH` containing the path of the
  `AdaptiveCruiseControlExample` binary you just built (e.g.,
  `/home/user/sim2cpp/AdaptiveCruiseControlExample/mpcACCsystem_ert_rtw/mpcACCsystem`)
- create a local file named `.BIN_SYM` containing the mangled name of
  the `mpcACCsystem::step()` function of the
  `AdaptiveCruiseControlExample` (e.g., `_ZN12mpcACCsystem4stepEv`),
  you can get the name by looking at the binary symbols with `objdump -t mpcACCsystem`
- create a local file named `.ADDRS.json` listing the base addresses we are monitoring, it should look like the following
```
{
    "ADDR_BASE": "555555554000",
    "ADDR_OBJ": "19060",
    "ADDR_DREL": "8",
    "OFFSET": "434"
}
```
To get obtain these addresses you can use GDB:
1. Disable ASLR with `make aslr_off`
2. Go to the `AdaptiveCruiseControlExample` folder
3. Run `gdb mpcACCsystem`, then follow the next steps
4. `b main`
5. `r`
6. `info address mpcACCsystem_Obj`, the value you get is `ADDR_BASE`+`ADDR_OBJ`
7. `p &mpcACCsystem_Obj.mpcACCsystem_Y.d_rel`, the value you get is `ADDR_BASE`+`ADDR_OBJ`+`ADDR_DREL`
8. `q`
9. To get the value of `ADDR_BASE`, run the `AdaptiveCruiseControlExample`, get its PID,
    inspect the process memory: it will be the first address you see,
    feel free to use this one liner `pmap $(ps -aux | grep "mpcACCsystem" | awk 'NR==1{ print $2}')`
10. To get the offset, run `info line mpcACCsystem.cpp:2311`	

## Reproduce

1. Disable ASLR with `make aslr_off`
2. Run the `AdaptiveCruiseControlExample` with `./mpcACCsystem` (do this in another terminal)
3. Run `make generate` to rebuild the Go scaffolding (at the beginning, or every time the eBPF probe is updated)
4. Run `make` to rebuild the Go wrapper and run it
5. You can get additional feedback from the eBPF probe if you look at `/sys/kernel/tracing/trace_pipe`
