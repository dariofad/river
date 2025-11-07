#!/usr/bin/env python3

import socket
import sys
import argparse
from typing import Sized
import numpy as np
import msgpack

PORT = 8081

def srv_connect(host: str) -> bytearray:

    # create a test trajectory and serialize it with msgpack
    single_trajectory = np.array([float(i)/1000 for i in range(801)], dtype=np.float64)
    trajectory = dict()
    trajectory["DREL"] = single_trajectory.tolist()
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
        # Receive response size
        response = sock.recv(4)
        resp_len = int.from_bytes(response, byteorder='big')
        print(f"[*] Receiving a {resp_len}-byte response")
        data = bytearray()
        bytes_received = 0
        while bytes_received < resp_len:
            chunk = sock.recv(resp_len - bytes_received)
            if not chunk:  # Peer closed the connection
                raise EOFError("Socket connection closed before all bytes were received")
            data.extend(chunk)
            bytes_received += len(chunk)
        # Close the socket
        sock.close()
        return data
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
    
    args = parser.parse_args()
    
    result = srv_connect(args.host)
    unpacked_res = msgpack.unpackb(result)
    print("(...first 25 output trace records)")
    for sign in unpacked_res['OUT_SIGNALS']:
        print(sign['SIGN_NAME'])
        print(*(sign['VALUES'][:25]), "...")        

if __name__ == "__main__":
    main()
