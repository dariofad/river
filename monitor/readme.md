# Instructions

This example uses the `ToyModel` from this
[repo](https://github.com/lyudeyun/sim2cpp).

## Setup

- Build the kernel type definitions with `make vmlinux`
- Setup the go module with `make mod_init`
- Clone the `sim2cpp`repo in another directory, checkout at commit
  `7117506`
- Build the `ToyModel` running `make` (in its directory)
- create a local file named `.BIN_PATH` containing the path of the
  `ToyModel` binary you just built (e.g.,
  `/home/user/sim2cpp/ToyModel/Simulink2Code_ert_rtw/Simulink2Code`)
- create a local file named `.BIN_SYM` containing the mangled name of
  the `rt_OneStep()` function of the `ToyModel` (e.g.,
  `_Z10rt_OneStepv`), you can get the name by looking at the binary
  symbols with `objdump -t Simulink2Code`
- create a local file named `.ADDRS.json` listing the base addresses we are monitoring, it should look like the following
```
{
    "ADDR_BASE": "555555554000",
    "ADDR_OBJ": "4020",
    "ADDR_X": "0",
    "ADDR_Y": "4"
}
```
To get obtain these addresses you can use GDB:
1. Disable ASLR with `make aslr_off`
2. Go to the `ToyModel` folder
3. Run `gdb Simulink2Code`, then follow the next steps
4. `b main`
5. `r`
6. `info address Simulink2Code_Obj`, the value you get is `ADDR_BASE`+`ADDR_OBJ`
7. `p &Simulink2Code_Obj.Simulink2Code_U.x`, the value you get is `ADDR_BASE`+`ADDR_OBJ`+`ADDR_X`
8. `p &Simulink2Code_Obj.Simulink2Code_U.y`, the value you get is `ADDR_BASE`+`ADDR_OBJ`+`ADDR_Y`
9. `q`
10. To get the value of `ADDR_BASE`, run the `ToyModel`, get its PID,
    inspect the process memory: it will be the first address you see,
    feel free to use this one liner `pmap $(ps -aux | grep "Simulink2Code" | awk 'NR==1{ print $2}')`


## Reproduce

1. Disable ASLR with `make aslr_off`
2. Run the `ToyModel` with `./Simulink2Code` (do this in another terminal)
3. Run `make generate` to rebuild the Go scaffolding (at the beginning, or every time the eBPF probe is updated)
4. Run `make` to rebuild the Go wrapper and run it
5. You can get additional feedback from the eBPF probe if you look at `/sys/kernel/tracing/trace_pipe`
