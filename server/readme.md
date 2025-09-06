# Notes

The server bridges a Matlab client application and a Go simulator via
TCP/IP.

It can be executed within a VM, provided that a host-only network is
created.

Data serialization is performed via MessagePack using a native
external implementation, hence a MEX file is required (see the
following).

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
