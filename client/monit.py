#!/usr/bin/env python3

import socket
import sys
import argparse
from typing import Sized
import msgpack
import demos_config

PORT = 8080
HOST = None
MODEL = None
CONFIG = None

def srv_connect(host: str, model: int, config: int) -> bytearray:

    # get the model-configuration-based trajectory 
    demo_fname = f"M{model}_C{config}_trajectory"
    demo_func = getattr(demos_config, demo_fname)
    trajectory = demo_func()
    # serialize the trajectory with msgpack
    payload = msgpack.packb(trajectory)

    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Connecting to {host}:{PORT}...", file=sys.stderr)
        # Connect to server
        sock.connect((host, PORT))
        print(f"[+] Connected successfully!", file=sys.stderr)
        # Send the trajectory to the server
        if isinstance(payload, Sized):
            sock.sendall(len(payload).to_bytes(4, 'big'))
            sock.sendall(payload)
        else:
            print("Error with payload type")
            exit(1)
        response = sock.recv(4096)
        # Close the socket
        sock.close()
        return bytearray(response)
    except ConnectionRefusedError:
        return bytearray(f"ERROR: Connection refused by {host}:{PORT}".encode('utf-8'))
    except socket.gaierror as e:
        return bytearray(f"ERROR: Could not resolve hostname '{host}': {e}".encode('utf-8'))
    except Exception as e:
        return bytearray(f"ERROR: {type(e).__name__}: {e}".encode('utf-8'))

def main():
    parser = argparse.ArgumentParser(
        description="Connect to the simulation server via TCP",
    )
    parser.add_argument('host', help='Server hostname or IP address')
    parser.add_argument('model', help='Model id')
    parser.add_argument('config', help='Config id')        
    
    args = parser.parse_args()
    HOST = args.host
    MODEL = args.model
    CONFIG = args.config
        
    print(f"host:\t{HOST}")
    print(f"model:\t{MODEL}")
    print(f"config:\t{CONFIG}")
    
    print(srv_connect(HOST, MODEL, CONFIG).decode('utf-8'))    

if __name__ == "__main__":
    main()
