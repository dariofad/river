#!/usr/bin/env python3

import socket
import sys
import argparse

PORT = 8083

def srv_connect(host: str) -> bytearray:

    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[*] Connecting to {host}:{PORT}...", file=sys.stderr)
        # Connect to server
        sock.connect((host, PORT))
        print(f"[+] Connected successfully!", file=sys.stderr)
        # todo: implement signal perturbation
        
        # wait for end of simulation
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
    
    args = parser.parse_args()
    
    print(srv_connect(args.host).decode('utf-8'))

if __name__ == "__main__":
    main()
