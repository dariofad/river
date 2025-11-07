# Setup

Configure a local file `config.json` with all the information required
to run the simulation. An example based on the `DualACC` model
follows.

```json
{
	"MODEL_PATH": "path_to_model/binary",
	"TIMER_SYMBOL": "_ZN6egoCar4stepEv",
    "MINOR_TO_MAJOR_RATIO": "3",
    "NOF_CYCLES": "801",
    "WRITE_TIMING_I": {
		"SYMBOL": "_ZN6egoCar4stepEv",
		"OFFSET":  "418",
		"SIGNALS": [
			{
				"SIGN_NAME": "DREL",
				"SIGN_TYPE": "float64",
				"SIGN_ADDR": "55555556e350"
			}
		]
		}, 
    "READ_TIMING_I": null,
    "READ_TIMING_O": {
		"SYMBOL": "_ZN6egoCar4stepEv",
		"OFFSET":  "188",
		"SIGNALS": [
			{
				"SIGN_NAME": "AEGO",
				"SIGN_TYPE": "float64",
				"SIGN_ADDR": "55555556e368"
			},
			{
				"SIGN_NAME": "VEGO",
				"SIGN_TYPE": "float64",
				"SIGN_ADDR": "55555556e360"
			}
		]
    }
}
```

Use GDB to obtain the correct addresses and offset. Follow these
steps:
1. Disable ASLR
2. Go to the `DualACC` folder
3. Run `gdb dualACC`, then follow the next steps
4. `b main`
5. `r`
6. `p &ego.egoCar_Y.d_rel`, the value you get is `ADDR_DREL`
7. `p &ego.egoCar_Y.a_ego`, the value you get is `ADDR_AEGO`
8. `p &ego.egoCar_Y.v_ego`, the value you get is `ADDR_VEGO`
9. `info line egoCar.cpp:2300`, this is the value of `OFFSET_STEP`
10. `info line main.cpp:28`, this is the value of `OFFSET_MAIN`
11. `q`, to quit GDB
