# Quickstart

Copy the demo configuration files to this folder with `cp
   demos/*config.json .`, then use GDB to obtain the correct addresses
   and offset of any signal/internal state variable. Follow these
   generic steps:
1. Disable ASLR (`make aslr_off` from the parent folder)
2. Go to the `model` folder
3. Run `gdb model`, then follow the next steps
4. `b main`
5. `r`
6. `p &signal`, the value you get is `ADDR_SIGNAL`
7. or `info line source_file:line_number`, to check the value of offsets
8. `q`, to quit GDB

## How the templates have been generated?

In general, `objdump` (with the `--demangle` option) can be used to
retrieve the symbol associated with the model `::step()` function.
For the addresses, see the following.

### Model 1: EgoCar

Input:
 ```bash
 p &ego.egoCar_Y.d_rel
 offset: info line egoCar.cpp:2301
 ```
 Output:
  ```bash
 p &ego.egoCar_Y.d_rel  
p &ego.egoCar_Y.a_ego
p &ego.egoCar_Y.v_ego
offset: info line egoCar.cpp:2551
 ```

### Model 2: Signal Addition

Input:
 ```bash
 p &Simulink2Code_Obj.Simulink2Code_U.x
 p &Simulink2Code_Obj.Simulink2Code_U.y
 offset 1: info line main.cpp:61
 offset 2: info line main.cpp:62
 ```
 Output:
  ```bash
p &Simulink2Code_Obj.Simulink2Code_Y.result
p &Simulink2Code_Obj.model_offset
offset: offset 2: info line main.cpp:64
 ```
State:
```bash
p &Simulink2Code_Obj.model_offset
```

### Model 3: Abstract Fuel Control

Input:
 ```bash
p &model.AbstractFuelControl_M1_U.PedalAngle
p &model.AbstractFuelControl_M1_U.EngineSpeed 
offset: 0, the beginning of the ::step() function
 ```
 Output:
  ```bash
p &model.AbstractFuelControl_M1_Y.AF
p &model.AbstractFuelControl_M1_Y.controller_mode
offset: info line AbstractFuelControl_M1.cpp:1065
 ```
State:
```bash
p &AbstractFuelControl_M1::AbstractFuelControl_M1_P.Baseopeningangle_Value
```
