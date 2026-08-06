#!/usr/bin/env python3
"""Minimal authenticated API around the NSPanel ADB updater."""

from __future__ import annotations

import json
import secrets
import subprocess
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DATA = Path("/data")
STATE_FILE = DATA / "state.json"
OPTIONS_FILE = DATA / "options.json"
TOOL = "/app/nspanel_updater.py"
MAX_BODY = 16 * 1024
LOCK = threading.Lock()


def read_json(path: Path, fallback: dict) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else fallback
    except (OSError, json.JSONDecodeError):
        return fallback


OPTIONS = read_json(OPTIONS_FILE, {})
STATE = read_json(STATE_FILE, {})
STATE.setdefault("id", secrets.token_hex(8))
STATE.setdefault("name", "NSPanel Companion Updater")
STATE.setdefault("token", "")
PAIR_CODE = f"{secrets.randbelow(1_000_000):06d}"
STATE_FILE.write_text(json.dumps(STATE))


def run_tool(arguments: list[str], timeout: int) -> tuple[int, str, str]:
    result = subprocess.run(
        ["python3", TOOL, *arguments], text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "NSPanelUpdater/0.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"updater-api: {fmt % args}", flush=True)

    def json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BODY:
            raise ValueError("Request is too large")
        value = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self) -> bool:
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(STATE["token"]) and secrets.compare_digest(token, STATE["token"])

    def do_GET(self) -> None:
        if self.path == "/api/status":
            self.send_json(HTTPStatus.OK, {
                "id": STATE["id"], "name": STATE["name"],
                "paired": bool(STATE["token"]), "version": "0.1.1",
            })
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        try:
            if self.path == "/api/pair":
                body = self.json_body()
                if str(body.get("code", "")) != PAIR_CODE:
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid pairing code"})
                    return
                STATE["token"] = secrets.token_urlsafe(32)
                STATE_FILE.write_text(json.dumps(STATE))
                self.send_json(HTTPStatus.OK, {
                    "id": STATE["id"], "name": STATE["name"], "token": STATE["token"]
                })
                return
            if not self.authorized():
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
                return
            if self.path == "/api/discover":
                body = self.json_body()
                subnet = str(body.get("subnet") or OPTIONS.get("subnet") or "")
                code, stdout, stderr = run_tool(["discover", "--subnet", subnet, "--json"], 90)
                if code:
                    raise RuntimeError(stderr or "Discovery failed")
                self.send_json(HTTPStatus.OK, {"devices": json.loads(stdout)})
                return
            if self.path == "/api/update":
                body = self.json_body()
                address = str(body.get("address", ""))
                classification = str(body.get("classification", ""))
                if classification not in {"nspanel-companion", "probable-nspanel"}:
                    raise ValueError("Refusing to modify an unverified Android device")
                repository = str(OPTIONS.get("repository") or "dmitrogajduk/ha-companion")
                channel = str(OPTIONS.get("channel") or "stable")
                with LOCK:
                    code, stdout, stderr = run_tool([
                        "update", address, "--github", "--repository", repository,
                        "--channel", channel, "--yes", "--set-home",
                    ], 300)
                if code:
                    raise RuntimeError(stderr or stdout or "Update failed")
                self.send_json(HTTPStatus.OK, {"ok": True, "message": stdout})
                return
            if self.path == "/api/unpair":
                STATE["token"] = ""
                STATE_FILE.write_text(json.dumps(STATE))
                self.send_json(HTTPStatus.OK, {"unpaired": True})
                return
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except subprocess.TimeoutExpired:
            self.send_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "ADB operation timed out"})
        except Exception as error:
            self.send_json(HTTPStatus.BAD_GATEWAY, {"error": str(error)})


if __name__ == "__main__":
    print(f"NSPanel Updater pairing code: {PAIR_CODE}", flush=True)
    print("Open NSPanel Companion in Home Assistant to pair this updater.", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8098), Handler).serve_forever()
