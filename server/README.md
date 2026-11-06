# Notes

The server permits to run eBPF-controlled model simulations via
TCP/IP.

It can be executed within a VM, provided that a host-only network is
created.

Data serialization is performed via MessagePack using length-prefixed frames
(4-byte big-endian length followed by a MessagePack payload) in both directions.

Every server response is a MessagePack map with:
- `status`: `"started"`, `"ack"`, `"completed"`, or `"error"`
- `category` *(optional)*: error category when `status == "error"` (`"request_error"`, `"manifest_error"`, `"trajectory_error"`, `"perturbation_error"`, `"ebpf_error"`, `"target_error"`, or `"redis_error"`)
- `message` *(optional)*: human-readable status or error description
- `OUT_SIGNALS` *(optional)*: output trace array returned upon completion in `falsification` mode

The server also maintains the current simulation status and any error details in Redis under `simulation:0:status` (cleared and updated automatically on each new simulation run).

For MATLAB clients, a native external MessagePack implementation (MEX file) is required (see the following).

## Prerequisites and build notes

1. Install MessagePack

```bash
git clone https://github.com/msgpack/msgpack-c.git
cd msgpack-c
git checkout c_master
cmake -DBUILD_SHARED_LIBS=ON .
make
sudo make install
```

2. Ensure installed libraries are available system-wide 

```bash
echo "/local/lib" | sudo tee /etc/ld.so.conf.d/msgpack.conf
sudo ldconfig
```

3. Get MessagePack bindings for Matlab

```bash
git clone https://github.com/RandallPittmanOrSt/msgpack-matlab2.git
```

4. Build the MEX file

```matlab
addpath('path-to/msgpack-matlab2');
savepath;
setenv('LD_LIBRARY_PATH', [getenv('LD_LIBRARY_PATH'), ':/local/lib']);
cd('path-to/msgpack-matlab2');
mex -O msgpack.cc -lmsgpack-c -L/usr/local/lib -I/usr/include
% this produces a file named msgpack.mexa*  
```
