import socket

import msgpack
import numpy as np

SUPPORTED_TYPES = {
    "bool": np.bool_,
    "int8": np.int8,
    "int16": np.int16,
    "int32": np.int32,
    "int64": np.int64,
    "uint8": np.uint8,
    "uint16": np.uint16,
    "uint32": np.uint32,
    "uint64": np.uint64,
    "float32": np.float32,
    "float64": np.float64,
}


def ebpf_format(array, dtype_str: str) -> list:
    """Casts any numpy/pandas array to a supported eBPF type and converts to list."""
    if dtype_str not in SUPPORTED_TYPES:
        raise ValueError(f"Unsupported eBPF type: {dtype_str}")
    return np.asarray(array).astype(SUPPORTED_TYPES[dtype_str]).tolist()


def get_time_array(cycles: int, step: float = 1.0) -> np.ndarray:
    """Generates a standard time array for trajectory calculations."""
    return np.arange(cycles, dtype=np.float64) * step


class RiverSession:
    """Handles communication with the River eBPF server."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

    def send_payload(self, data: dict | list):
        """Packs and sends a dictionary payload."""
        if not self.sock:
            raise RuntimeError("Socket not connected.")
        payload = msgpack.packb(data)
        if not isinstance(payload, bytes):
            raise TypeError("msgpack returned non-bytes")
        self.sock.sendall(len(payload).to_bytes(4, "big"))
        self.sock.sendall(payload)

    def wait_for_ack(self, bufsize: int = 64) -> str:
        """Waits for a standard string ACK (e.g., in demo_sign.py or demo_state.py)."""
        if not self.sock:
            raise RuntimeError("Socket not connected.")
        return self.sock.recv(bufsize).decode("utf-8")

    def receive_data(self) -> bytes:
        """Receives length-prefixed data (e.g., in demo_fals.py or demo_monit.py)."""
        if not self.sock:
            raise RuntimeError("Socket not connected.")
        resp_size_bytes = self.sock.recv(4)
        if not resp_size_bytes:
            return b""
        resp_len = int.from_bytes(resp_size_bytes, byteorder="big")

        data = bytearray()
        bytes_received = 0
        while bytes_received < resp_len:
            chunk = self.sock.recv(resp_len - bytes_received)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
