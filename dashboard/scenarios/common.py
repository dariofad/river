from __future__ import annotations

import os
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import msgpack
import pandas as pd
import redis

REDIS_HOST = os.environ.get("RIVER_REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("RIVER_REDIS_PORT", "6379"))
REDIS_DB = int(os.environ.get("RIVER_REDIS_DB", "0"))
ZSET_KEY = "simulation:0"


@dataclass
class ScenarioRun:
    state: tuple[str, str] = ("running", "Simulation is running.")
    result: dict[str, Any] | None = None


def send_payload(sock: socket.socket, data: dict | list) -> None:
    payload = cast(bytes, msgpack.packb(data))
    sock.sendall(len(payload).to_bytes(4, "big"))
    sock.sendall(payload)


def receive_ack(sock: socket.socket) -> str:
    return sock.recv(64).rstrip(b"\x00").decode("utf-8")


def receive_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("The server closed the connection during the response.")
        data.extend(chunk)
    return bytes(data)


def receive_payload(sock: socket.socket) -> bytes:
    size = int.from_bytes(receive_exact(sock, 4), "big")
    return receive_exact(sock, size)


def launch(
    port: int,
    request: dict[str, Any],
    worker: Callable[[socket.socket, dict[str, Any], ScenarioRun], None],
) -> ScenarioRun:
    host = os.environ.get("RIVER_SERVER_HOST", "127.0.0.1")
    try:
        sock = socket.create_connection((host, port), timeout=2.0)
    except OSError as exc:
        raise RuntimeError(f"Cannot reach the server at {host}:{port}: {exc}") from exc
    sock.settimeout(None)

    run = ScenarioRun()

    def execute() -> None:
        try:
            worker(sock, request, run)
        except Exception as exc:
            run.state = ("error", str(exc))
        finally:
            sock.close()

    threading.Thread(target=execute, daemon=True).start()
    return run


def clear_results() -> None:
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    try:
        client.delete("simulation", ZSET_KEY)
    except redis.RedisError as exc:
        raise RuntimeError(
            f"Could not clear Redis at {REDIS_HOST}:{REDIS_PORT}: {exc}. "
            "Ensure Redis is running before starting a simulation."
        ) from exc
    finally:
        client.close()


def read_signal_names(manifest: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for model in manifest["models"]:
        if not model.get("enabled", False):
            continue
        catalog = {
            datum["path"]: datum["name"]
            for category in ("inputs", "outputs", "states")
            for datum in model.get(category, [])
        }
        for hook in model["hooks"]:
            if hook["action"] != "read":
                continue
            names.extend(catalog[path] for path in hook["data"])
    return names


def read_redis_results(manifest: dict[str, Any]) -> pd.DataFrame:
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
    try:
        raw_data = cast(list[bytes], client.zrange(ZSET_KEY, 0, -1))
    except redis.RedisError as exc:
        raise RuntimeError(
            f"Could not read Redis at {REDIS_HOST}:{REDIS_PORT}: {exc}"
        ) from exc
    finally:
        client.close()

    rows: list[list[Any]] = []
    for item in raw_data:
        record = msgpack.unpackb(item, raw=False)
        rows.append([record["TIME"], *record["VALUES"]])
    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows, columns=["time", *read_signal_names(manifest)])


def read_response_results(run: ScenarioRun) -> pd.DataFrame:
    if run.result is None:
        return pd.DataFrame()
    signals = run.result["OUT_SIGNALS"]
    columns = {signal["NAME"]: signal["VALUES"] for signal in signals}
    columns = {"time": range(len(signals[0]["VALUES"])), **columns}
    return pd.DataFrame(columns)
