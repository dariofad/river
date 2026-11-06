import socket
from typing import Any

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


class RiverServerError(RuntimeError):
    """Raised when the River server returns an error status."""

    def __init__(self, message: str, category: str = ""):
        self.category = category
        self.detail = message
        prefix = f"[{category}] " if category else ""
        super().__init__(f"{prefix}{message}")


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
        """Packs and sends a dictionary or list payload."""
        if not self.sock:
            raise RuntimeError("Socket not connected.")
        payload = msgpack.packb(data)
        if not isinstance(payload, bytes):
            raise TypeError("msgpack returned non-bytes")
        self.sock.sendall(len(payload).to_bytes(4, "big"))
        self.sock.sendall(payload)

    def _receive_exact(self, size: int) -> bytes:
        if not self.sock:
            raise RuntimeError("Socket not connected.")
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise RuntimeError(
                    "The server closed the connection during the response."
                )
            data.extend(chunk)
        return bytes(data)

    def receive_data(self) -> bytes:
        """Receives length-prefixed raw bytes from the server."""
        resp_size_bytes = self._receive_exact(4)
        resp_len = int.from_bytes(resp_size_bytes, byteorder="big")
        return self._receive_exact(resp_len)

    def receive_response(
        self, expected_status: str | tuple[str, ...] | None = None
    ) -> dict[str, Any]:
        """Receives and unpacks a structured ServerResponse dictionary."""
        raw = self.receive_data()
        response = msgpack.unpackb(raw, raw=False)
        if not isinstance(response, dict):
            raise RuntimeError(f"Unexpected server response format: {response!r}")
        status = str(response.get("status", ""))
        if status == "error":
            raise RiverServerError(
                str(response.get("message", "Unknown simulation error")),
                str(response.get("category", "")),
            )
        if expected_status is not None:
            allowed = (
                (expected_status,)
                if isinstance(expected_status, str)
                else expected_status
            )
            if status not in allowed:
                raise RuntimeError(
                    f"Unexpected server status {status!r} (expected {allowed}): "
                    f"{response.get('message', '')}"
                )
        return response

    def wait_for_ack(self, expected_status: str | tuple[str, ...] | None = None) -> str:
        """Waits for a server response and returns its human-readable message."""
        response = self.receive_response(expected_status=expected_status)
        return str(response.get("message") or response.get("status", ""))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
