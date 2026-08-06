#!/usr/bin/env python3
"""Container-local, dependency-free NSPanel network ADB updater."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen

PACKAGE = "dev.hacompanion.panel"
PINNED_CERTIFICATE_SHA256 = "3567e430a196e39a4b21045757c98d83756569777cff2bb3d2835fa6e813e5e7"


def run(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)


def shell(serial: str, command: str, timeout: int = 10) -> str:
    result = run(["adb", "-s", serial, "shell", command], timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


def private_subnet(value: str) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(value, strict=False)
    if not isinstance(network, ipaddress.IPv4Network) or not network.is_private:
        raise ValueError("Only private IPv4 subnets are supported")
    if network.num_addresses > 1024:
        raise ValueError("Use /22 or a smaller subnet")
    return network


def open_port(address: str) -> bool:
    try:
        with socket.create_connection((address, 5555), timeout=.35):
            return True
    except OSError:
        return False


def inspect(address: str) -> dict:
    serial = address if ":" in address else f"{address}:5555"
    state = None
    connection_output = ""
    for attempt in range(4):
        connection = run(["adb", "connect", serial], 7)
        connection_output += connection.stdout + connection.stderr
        state = run(["adb", "-s", serial, "get-state"], 5)
        combined = (connection_output + state.stdout + state.stderr).lower()
        if "unauthorized" in combined:
            return {"address": serial, "adb_state": "unauthorized", "classification": "unknown-android"}
        if state.returncode == 0 and state.stdout.strip() == "device":
            break
        if attempt < 3:
            time.sleep(.75)
    if state is None or state.returncode or state.stdout.strip() != "device":
        return {"address": serial, "adb_state": "offline", "classification": "unknown-android"}
    values = {
        "manufacturer": shell(serial, "getprop ro.product.manufacturer"),
        "model": shell(serial, "getprop ro.product.model"),
        "device": shell(serial, "getprop ro.product.device"),
        "fingerprint": shell(serial, "getprop ro.build.fingerprint"),
    }
    screen = shell(serial, "wm size").removeprefix("Physical size: ").strip()
    package = shell(serial, f"dumpsys package {PACKAGE}", 15)
    version = re.search(r"versionName=([^\s]+)", package)
    version_code = re.search(r"versionCode=(\d+)", package)
    identity = " ".join(values.values()).lower()
    installed = version is not None
    probable = "nspanel" in identity or "ewelink" in identity or "480x480" in screen.replace(" ", "")
    return {
        "address": serial, "adb_state": "device", "screen_size": screen,
        "app_version": version.group(1) if version else None,
        "app_version_code": int(version_code.group(1)) if version_code else None,
        "classification": "nspanel-companion" if installed else "probable-nspanel" if probable else "unknown-android",
        **values,
    }


def discover(subnet: str) -> list[dict]:
    network = private_subnet(subnet)
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        addresses = [address for address, found in zip(
            (str(item) for item in network.hosts()),
            pool.map(open_port, (str(item) for item in network.hosts())),
        ) if found]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(inspect, addresses))


def fetch_json(url: str) -> object:
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "nspanel-updater"})
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read(256 * 1024))


def release_apk(repository: str, channel: str) -> tuple[Path, dict]:
    releases = fetch_json(f"https://api.github.com/repos/{repository}/releases")
    release = next((item for item in releases if not item.get("draft") and (channel == "prerelease" or not item.get("prerelease"))), None)
    if not release:
        raise RuntimeError(f"No {channel} release is available")
    assets = {item["name"]: item for item in release.get("assets", [])}
    metadata_asset = assets.get("release.json")
    if not metadata_asset:
        raise RuntimeError("Release metadata is missing")
    metadata = fetch_json(metadata_asset["browser_download_url"])
    if metadata.get("application_id") != PACKAGE or metadata.get("abi") != "arm64-v8a":
        raise RuntimeError("Release metadata is not for this app/device ABI")
    if metadata.get("certificate_sha256") != PINNED_CERTIFICATE_SHA256:
        raise RuntimeError("Release metadata has the wrong signing certificate")
    name = str(metadata.get("apk", ""))
    digest = str(metadata.get("sha256", ""))
    if not re.fullmatch(r"nspanel-companion-[A-Za-z0-9._-]+-arm64\.apk", name) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("Release metadata is invalid")
    asset = assets.get(name)
    if not asset:
        raise RuntimeError("Release APK is missing")
    destination = Path(tempfile.gettempdir()) / name
    with urlopen(Request(asset["browser_download_url"], headers={"User-Agent": "nspanel-updater"}), timeout=60) as response:
        payload = response.read(100 * 1024 * 1024 + 1)
    if len(payload) > 100 * 1024 * 1024 or hashlib.sha256(payload).hexdigest() != digest:
        raise RuntimeError("Release APK failed verification")
    destination.write_bytes(payload)
    keytool = shutil.which("keytool")
    if not keytool:
        raise RuntimeError("keytool is required to verify the APK signer")
    certificate = run([keytool, "-printcert", "-jarfile", str(destination)], 30)
    match = re.search(r"SHA256:\s*([0-9A-F:]{95})", certificate.stdout, re.IGNORECASE)
    fingerprint = match.group(1).replace(":", "").lower() if certificate.returncode == 0 and match else ""
    if fingerprint != PINNED_CERTIFICATE_SHA256:
        destination.unlink(missing_ok=True)
        raise RuntimeError("Release APK has the wrong signing certificate")
    return destination, metadata


def default_home(serial: str) -> str:
    output = shell(serial, "cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME")
    return next((line for line in reversed(output.splitlines()) if "/" in line and "=" not in line), "")


def update(address: str, repository: str, channel: str) -> str:
    panel = inspect(address)
    if panel["adb_state"] != "device" or panel["classification"] not in {"nspanel-companion", "probable-nspanel"}:
        raise RuntimeError("ADB target is not a verified NSPanel")
    apk, metadata = release_apk(repository, channel)
    current = panel.get("app_version_code")
    if current is not None and int(metadata["version_code"]) <= current:
        return f"No update needed; {panel['address']} already has version code {current}."
    serial = panel["address"]
    restore_home = default_home(serial).startswith(f"{PACKAGE}/")
    command = ["adb", "-s", serial, "install"]
    if panel.get("app_version"):
        command.append("-r")
    result = run([*command, str(apk)], 240)
    if result.returncode or "Success" not in result.stdout:
        raise RuntimeError((result.stdout + result.stderr).strip() or "ADB installation failed")
    if restore_home or not panel.get("app_version"):
        home = run(["adb", "-s", serial, "shell", "cmd", "package", "set-home-activity", f"{PACKAGE}/.MainActivity"])
        if home.returncode:
            raise RuntimeError("App installed but could not be restored as Home")
    start = run(["adb", "-s", serial, "shell", "am", "start", "-n", f"{PACKAGE}/.MainActivity"])
    if start.returncode:
        raise RuntimeError("App installed but could not be started")
    for _ in range(5):
        if shell(serial, f"pidof {PACKAGE}"):
            break
        time.sleep(1)
    else:
        raise RuntimeError("App installed but did not remain running")
    return f"Updated {serial} to {metadata['version']}; Home app restored."


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("discover")
    scan.add_argument("--subnet", required=True)
    scan.add_argument("--json", action="store_true")
    install = commands.add_parser("update")
    install.add_argument("address")
    install.add_argument("--github", action="store_true")
    install.add_argument("--repository", required=True)
    install.add_argument("--channel", choices=["stable", "prerelease"], required=True)
    install.add_argument("--yes", action="store_true")
    install.add_argument("--set-home", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "discover":
            print(json.dumps(discover(args.subnet)))
        else:
            print(update(args.address, args.repository, args.channel))
        return 0
    except Exception as error:
        print(f"Error: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
