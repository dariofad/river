## Quickstart

Copy the demo configuration files to this folder with `cp
   demos/*config.json `, then use GDB to obtain the correct addresses
   and offset of any signal/internal state variable. Follow these
   steps:
1. Disable ASLR (`make aslr_off` from the parent folder)
2. Go to the `model` folder
3. Run `gdb model`, then follow the next steps
4. `b main`
5. `r`
6. `p &signal`, the value you get is `ADDR_SIGNAL`
7. or `info line source_file:line_number`, to check the value of offsets
8. `q`, to quit GDB
