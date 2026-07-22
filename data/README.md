# process.py

1. Start the server with `make bench`
2. Run the simulation with the client (for example `make state M=3 C=3`)
3. Wait until the end of the simulation and then extract the stats 
Example 
```bash
./process.py --filename=stats --manifest=../model.river.yaml
```
4. Press <enter> on the server terminal window to release the maps
5. Start a new simulation (step 1)
