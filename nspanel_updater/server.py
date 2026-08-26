#!/usr/bin/env python3
"""Minimal authenticated API around the NSPanel ADB updater."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Overridable so the module can be imported in tests without touching /data.
DATA = Path(os.environ.get("NSPANEL_UPDATER_DATA", "/data"))
STATE_FILE = DATA / "state.json"
OPTIONS_FILE = DATA / "options.json"
TOOL = "/app/nspanel_updater.py"
# Stamped into the image from the add-on version at build time. Typing a
# version in here instead let it drift three releases behind config.yaml,
# which made a running add-on indistinguishable from an old one.
VERSION = os.environ.get("NSPANEL_UPDATER_VERSION") or "unknown"
MAX_BODY = 16 * 1024
LOCK = threading.Lock()


def read_json(path: Path, fallback: dict) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else fallback
    except (OSError, json.JSONDecodeError):
        return fallback


def options() -> dict:
    """The add-on options as they are now.

    Read per request rather than once at import: Home Assistant rewrites this
    file when the user saves the configuration, and caching it meant a channel
    changed in the UI kept resolving against the value the container started
    with, with nothing to say so.
    """
    return read_json(OPTIONS_FILE, {})


STATE = read_json(STATE_FILE, {})
STATE.setdefault("id", secrets.token_hex(8))
STATE.setdefault("name", "NSPanel Companion Updater")
STATE.setdefault("token", "")
# Persisted rather than regenerated per start: a restart during pairing would
# otherwise silently invalidate the code Home Assistant is about to send.
STATE.setdefault("pair_code", f"{secrets.randbelow(1_000_000):06d}")
PAIR_CODE = STATE["pair_code"]
STATE_FILE.write_text(json.dumps(STATE))


def is_loopback(address: str) -> bool:
    """Return whether a request originated on this host.

    The pairing code authorises pairing, so it is only ever disclosed to the
    host itself. A LAN client cannot forge this: it would have to complete a
    TCP handshake from a spoofed source address.
    """
    return address in {"127.0.0.1", "::1"}


def startup_lines() -> list[str]:
    """Return what to print at start.

    The pairing code is only printed while unpaired. It is persisted now, so a
    code left in a log stays valid, and add-on logs are routinely pasted into
    issue reports.
    """
    if STATE["token"]:
        return ["Updater paired with Home Assistant."]
    return [
        f"NSPanel Updater pairing code: {PAIR_CODE}",
        "Open NSPanel Companion in Home Assistant to pair this updater.",
    ]


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
        if self.path == "/api/pair-code":
            # Disclosed to the host only, so Home Assistant can pair without a
            # human copying the code out of the add-on log.
            if not is_loopback(self.client_address[0]):
                self.send_json(HTTPStatus.FORBIDDEN, {
                    "error": "The pairing code is only available on the local host"
                })
                return
            self.send_json(HTTPStatus.OK, {
                "id": STATE["id"], "name": STATE["name"], "code": PAIR_CODE,
            })
            return
        if self.path == "/api/status":
            self.send_json(HTTPStatus.OK, {
                "id": STATE["id"], "name": STATE["name"],
                "paired": bool(STATE["token"]), "version": VERSION,
            })
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        global PAIR_CODE
        try:
            if self.path == "/api/pair":
                body = self.json_body()
                if not secrets.compare_digest(str(body.get("code", "")), PAIR_CODE):
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid pairing code"})
                    return
                STATE["token"] = secrets.token_urlsafe(32)
                # Consume the code. Persisting it means it would otherwise remain
                # a standing key to the updater for anyone who ever saw it.
                PAIR_CODE = STATE["pair_code"] = f"{secrets.randbelow(1_000_000):06d}"
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
                subnet = str(body.get("subnet") or options().get("subnet") or "")
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
                source = str(body.get("source") or "github")
                settings = options()
                with LOCK:
                    if source == "local":
                        release_directory = str(settings.get("local_release_directory") or "")
                        arguments = ["update", address, "--local-release", release_directory, "--yes", "--set-home"]
                        if body.get("migrate_debug"):
                            arguments.append("--migrate-debug")
                    elif source == "github":
                        repository = str(settings.get("repository") or "hestiaworks/nspanel-companion-app")
                        channel = str(settings.get("channel") or "prerelease")
                        arguments = [
                            "update", address, "--github", "--repository", repository,
                            "--channel", channel, "--yes", "--set-home",
                        ]
                    else:
                        raise ValueError("Unknown release source")
                    code, stdout, stderr = run_tool(arguments, 300)
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
    for line in startup_lines():
        print(line, flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8098), Handler).serve_forever()
