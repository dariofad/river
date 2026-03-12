#!/usr/bin/env python3

from typing import Sized
import argparse
import demos_config
import json
import msgpack
import socket
import sys
import time

CYCLES : int = 0
with open("../simulator/config.json", 'r', encoding='utf-8') as file:
        CYCLES = int(json.load(file)["NOF_CYCLES"])
INJECTIONS : int = 0

PORT = 8082
HOST = None
MODEL = None
CONFIG = None

def srv_connect(host: str, model: int, config: int) -> bytearray:
    global MODEL
    global CONFIG
    # get the model-configuration-based trajectory 
    demo_fname = f"state_M{model}_C{config}_trajectory"
    demo_func = getattr(demos_config, demo_fname)
    trajectory = demo_func(CYCLES)
    payload = msgpack.packb(trajectory)    # prepare the trace
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Connecting to {host}:{PORT}...", file=sys.stderr)
        # Connect to server
        sock.connect((host, PORT))
        print(f"[+] Connected successfully!", file=sys.stderr)
        # Send the initial trajectory
        if isinstance(payload, Sized):
            sock.sendall(len(payload).to_bytes(4, 'big'))
            sock.sendall(payload)
        else:
            print("Error with payload type")
            exit(1)
        # wait for simulation started ack
        response = sock.recv(64)
        print(response.decode('utf-8'))
        # send a state perturbation
        demo_fname = f"state_M{model}_C{config}_perturbation"
        demo_func = getattr(demos_config, demo_fname)
        perturbations = demo_func(None, None)
        if perturbations is not None:
                if MODEL == "2" and CONFIG == "1":
                        time.sleep(3)
                payload = msgpack.packb(perturbations)
                if isinstance(payload, Sized):
                        sock.sendall(len(payload).to_bytes(4, 'big'))
                        sock.sendall(payload)
                else:
                        print("Error with payload type")
                        exit(1)
                # wait for ack
                response = sock.recv(64)
                print(response.decode('utf-8'))
        # wait for the end of the simulation
        response = sock.recv(64)        
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
    global MODEL
    global CONFIG
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

    global INJECTIONS
    match int(MODEL):
        case 1:
                INJECTIONS = 2
        case 2:
                INJECTIONS = 0
        case 3:
                INJECTIONS = 1
    print(f"cycles:\t{CYCLES}")
    print(f"injections:\t{INJECTIONS}")
    
    result = srv_connect(HOST, MODEL, CONFIG)
    print(result.decode('utf-8'))


if __name__ == "__main__":
    main()
