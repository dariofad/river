# Notes

This material demonstrates how to connect a Matlab script and a Go
server via TCP/IP.

The server can naturally be executed within a VM, provided that a
host-only network is created.

Matlab code is slow to serialize data, hence a MEX file is used to
improve performance. The selected format is the efficient binary
MessagePack.

## Howto

0. Check the [prerequisites](##prerequisites-and-build-notes)
1. Start the server `go run bridge.go`
2. Open Matlab and run the script specifying the number of data points

## Prerequisites and build notes

Get a MessagePack implementation

```bash
git clone https://github.com/msgpack/msgpack-c.git
cd msgpack-c
git checkout c_master
cmake -DBUILD_SHARED_LIBS=ON .
make
sudo make install
```

Ensure installed libraries are available system-wide 

```bash
echo "/local/lib" | sudo tee /etc/ld.so.conf.d/msgpack.conf
sudo ldconfig
```

Get MessagePack bindings for Matlab

```bash
git clone https://github.com/RandallPittmanOrSt/msgpack-matlab2.git
```

Build the MEX file

```matlab
addpath('path-to/msgpack-matlab2');
savepath;
setenv('LD_LIBRARY_PATH', [getenv('LD_LIBRARY_PATH'), ':/local/lib']);
cd('path-to/msgpack-matlab2');
mex -O msgpack.cc -lmsgpack-c -L/usr/local/lib -I/usr/include
% this produces a file named msgpack.mexa*  
```
