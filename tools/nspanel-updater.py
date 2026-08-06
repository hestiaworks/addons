#!/usr/bin/env python3
"""Discover, inspect, install, and update NSPanel Companion over network ADB."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

PACKAGE = "dev.hacompanion.panel"
DEFAULT_ADB_PORT = 5555


@dataclass
class Panel:
    address: str
    adb_state: str
    manufacturer: str = ""
    model: str = ""
    device: str = ""
    fingerprint: str = ""
    screen_size: str = ""
    app_version: str | None = None
    app_version_code: int | None = None
    classification: str = "unknown-android"


def run(command: list[str], timeout: float = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def adb_path() -> str:
    path = shutil.which("adb")
    if not path:
        raise RuntimeError("adb was not found. Install Android platform-tools and ensure adb is on PATH.")
    return path


def default_subnet() -> ipaddress.IPv4Network:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        address = sock.getsockname()[0]
    finally:
        sock.close()
    return ipaddress.ip_network(f"{address}/24", strict=False)


def parse_subnet(value: str | None) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(value, strict=False) if value else default_subnet()
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 subnets are supported")
    if not network.is_private:
        raise ValueError("Refusing to scan a non-private subnet")
    if network.num_addresses > 1024:
        raise ValueError("Subnet is too large; use /22 or a smaller explicit range")
    return network


def port_open(address: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan(network: ipaddress.IPv4Network, port: int, timeout: float) -> list[str]:
    addresses = [str(address) for address in network.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, max(1, len(addresses)))) as pool:
        checks = {pool.submit(port_open, address, port, timeout): address for address in addresses}
        return sorted((checks[future] for future in concurrent.futures.as_completed(checks) if future.result()), key=ipaddress.ip_address)


def shell(adb: str, serial: str, command: str, timeout: float = 8) -> str:
    result = run([adb, "-s", serial, "shell", command], timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


def inspect(adb: str, address: str, port: int) -> Panel:
    serial = f"{address}:{port}"
    try:
        connection = run([adb, "connect", serial], 6)
    except subprocess.TimeoutExpired:
        return Panel(serial, "connection-timeout")
    output = f"{connection.stdout}\n{connection.stderr}".lower()
    if "unauthorized" in output:
        return Panel(serial, "unauthorized")
    try:
        state = run([adb, "-s", serial, "get-state"], 4)
    except subprocess.TimeoutExpired:
        return Panel(serial, "connection-timeout")
    if state.returncode != 0 or state.stdout.strip() != "device":
        return Panel(serial, "offline")
    props = {
        "manufacturer": shell(adb, serial, "getprop ro.product.manufacturer"),
        "model": shell(adb, serial, "getprop ro.product.model"),
        "device": shell(adb, serial, "getprop ro.product.device"),
        "fingerprint": shell(adb, serial, "getprop ro.build.fingerprint"),
    }
    screen = shell(adb, serial, "wm size")
    package = shell(adb, serial, f"dumpsys package {PACKAGE}", 12)
    version = re.search(r"versionName=([^\s]+)", package)
    version_code = re.search(r"versionCode=(\d+)", package)
    identity = " ".join(props.values()).lower()
    app_installed = version is not None
    likely_nspanel = "nspanel" in identity or "ewelink" in identity or "480x480" in screen.replace(" ", "")
    classification = "nspanel-companion" if app_installed else "probable-nspanel" if likely_nspanel else "unknown-android"
    return Panel(
        address=serial,
        adb_state="device",
        screen_size=screen.removeprefix("Physical size: ").strip(),
        app_version=version.group(1) if version else None,
        app_version_code=int(version_code.group(1)) if version_code else None,
        classification=classification,
        **props,
    )


def discover(args: argparse.Namespace) -> list[Panel]:
    adb = adb_path()
    network = parse_subnet(args.subnet)
    if not args.json:
        print(f"Scanning {network} for ADB on TCP {args.port}…", file=sys.stderr)
    addresses = scan(network, args.port, args.timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(addresses)))) as pool:
        return list(pool.map(lambda address: inspect(adb, address, args.port), addresses))


def print_panels(panels: list[Panel], as_json: bool) -> None:
    if as_json:
        print(json.dumps([asdict(panel) for panel in panels], indent=2, sort_keys=True))
        return
    if not panels:
        print("No network ADB devices found.")
        return
    for panel in panels:
        version = panel.app_version or "not installed"
        name = " ".join(part for part in (panel.manufacturer, panel.model) if part) or "Unknown Android device"
        print(f"{panel.address:<22} {panel.adb_state:<20} {panel.classification:<20} {version:<16} {name}")


def install(args: argparse.Namespace) -> int:
    adb = adb_path()
    apk = Path(args.apk).expanduser().resolve()
    if not apk.is_file():
        raise RuntimeError(f"APK does not exist: {apk}")
    address, _, port_text = args.address.partition(":")
    port = int(port_text or args.port)
    panel = inspect(adb, address, port)
    if panel.adb_state != "device":
        raise RuntimeError(f"ADB device is not ready: {panel.adb_state}")
    if panel.classification == "unknown-android" and not args.allow_unknown:
        raise RuntimeError("Refusing to modify an unknown Android device; use --allow-unknown only after verifying it manually")
    action = "Update" if panel.app_version else "Install"
    if not args.yes:
        answer = input(f"{action} {apk.name} on {panel.address} ({panel.model or 'unknown model'})? [y/N] ")
        if answer.strip().lower() not in {"y", "yes"}:
            print("Cancelled.")
            return 1
    command = [adb, "-s", panel.address, "install"]
    if panel.app_version:
        command.append("-r")
    command.append(str(apk))
    result = run(command, args.install_timeout)
    if result.returncode != 0 or "Success" not in result.stdout:
        raise RuntimeError((result.stdout + result.stderr).strip() or "ADB installation failed")
    updated = inspect(adb, address, port)
    print(f"Success: {updated.address} now has {PACKAGE} {updated.app_version or '(version unavailable)'}." )
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser("discover", help="scan a private subnet and inspect network ADB devices")
    discovery.add_argument("--subnet", help="private IPv4 CIDR; defaults conservatively to the current /24")
    discovery.add_argument("--port", type=int, default=DEFAULT_ADB_PORT)
    discovery.add_argument("--timeout", type=float, default=0.35, help="TCP probe timeout in seconds")
    discovery.add_argument("--json", action="store_true", help="emit machine-readable output for the future HA add-on")
    installation = commands.add_parser("install", aliases=["update"], help="install or update a local signed APK")
    installation.add_argument("address", help="panel IP or IP:port")
    installation.add_argument("--apk", required=True)
    installation.add_argument("--port", type=int, default=DEFAULT_ADB_PORT)
    installation.add_argument("--install-timeout", type=float, default=180)
    installation.add_argument("--yes", action="store_true")
    installation.add_argument("--allow-unknown", action="store_true")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "discover":
            print_panels(discover(args), args.json)
            return 0
        return install(args)
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
