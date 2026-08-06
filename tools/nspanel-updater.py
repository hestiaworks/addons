#!/usr/bin/env python3
"""Discover, inspect, install, and update NSPanel Companion over network ADB."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PACKAGE = "dev.hacompanion.panel"
DEFAULT_ADB_PORT = 5555
DEFAULT_REPOSITORY = "dmitrogajduk/ha-companion"
DEFAULT_CACHE = Path.home() / ".cache" / "nspanel-companion"
MAX_METADATA_BYTES = 128 * 1024
MAX_APK_BYTES = 100 * 1024 * 1024


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


def github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "nspanel-companion-updater"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def read_url(url: str, maximum: int) -> bytes:
    request = Request(url, headers=github_headers())
    try:
        with urlopen(request, timeout=30) as response:
            declared = int(response.headers.get("Content-Length", "0") or 0)
            if declared > maximum:
                raise RuntimeError(f"Download is larger than the allowed {maximum} bytes")
            data = response.read(maximum + 1)
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"Download failed: {error}") from error
    if len(data) > maximum:
        raise RuntimeError(f"Download is larger than the allowed {maximum} bytes")
    return data


def fetch_json(url: str) -> object:
    try:
        return json.loads(read_url(url, MAX_METADATA_BYTES))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise RuntimeError(f"Invalid JSON from {url}") from error


def resolve_release(releases: list[dict], channel: str) -> dict:
    candidates = [release for release in releases if not release.get("draft")]
    if channel == "stable":
        candidates = [release for release in candidates if not release.get("prerelease")]
    if not candidates:
        raise RuntimeError(f"No {channel} release is available")
    return candidates[0]


def release_asset(release: dict, name: str) -> dict:
    for asset in release.get("assets", []):
        if asset.get("name") == name and asset.get("browser_download_url"):
            return asset
    raise RuntimeError(f"Release asset is missing: {name}")


def validate_release_metadata(metadata: object) -> dict:
    if not isinstance(metadata, dict):
        raise RuntimeError("Release metadata must be an object")
    if metadata.get("application_id") != PACKAGE:
        raise RuntimeError("Release metadata has the wrong application ID")
    if metadata.get("abi") != "arm64-v8a":
        raise RuntimeError("Release metadata has the wrong ABI")
    if not isinstance(metadata.get("version_code"), int) or metadata["version_code"] <= 0:
        raise RuntimeError("Release metadata has an invalid version code")
    digest = str(metadata.get("sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("Release metadata has an invalid SHA-256 digest")
    apk = str(metadata.get("apk", ""))
    if not re.fullmatch(r"nspanel-companion-[A-Za-z0-9._-]+-arm64\.apk", apk):
        raise RuntimeError("Release metadata has an invalid APK name")
    return metadata


def download_github_release(repository: str, channel: str, cache: Path) -> tuple[Path, dict]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise RuntimeError("GitHub repository must look like owner/name")
    releases = fetch_json(f"https://api.github.com/repos/{repository}/releases")
    if not isinstance(releases, list):
        raise RuntimeError("GitHub releases response must be a list")
    release = resolve_release(releases, channel)
    metadata_asset = release_asset(release, "release.json")
    metadata = validate_release_metadata(fetch_json(metadata_asset["browser_download_url"]))
    apk_asset = release_asset(release, metadata["apk"])
    destination = cache / str(metadata["version"]) / metadata["apk"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and hashlib.sha256(destination.read_bytes()).hexdigest() == metadata["sha256"]:
        return destination, metadata
    payload = read_url(apk_asset["browser_download_url"], MAX_APK_BYTES)
    if hashlib.sha256(payload).hexdigest() != metadata["sha256"]:
        raise RuntimeError("Downloaded APK checksum does not match release metadata")
    temporary = destination.with_suffix(".apk.part")
    temporary.write_bytes(payload)
    temporary.replace(destination)
    (destination.parent / "release.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return destination, metadata


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


def default_home(adb: str, serial: str) -> str:
    output = shell(
        adb,
        serial,
        "cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME",
    )
    components = [line.strip() for line in output.splitlines() if "/" in line and "=" not in line]
    return components[-1] if components else ""


def recover_application(adb: str, serial: str, restore_home: bool) -> None:
    if restore_home:
        result = run([adb, "-s", serial, "shell", "cmd", "package", "set-home-activity", f"{PACKAGE}/.MainActivity"], 8)
        if result.returncode != 0 or "Success" not in result.stdout:
            raise RuntimeError("APK installed, but HA Companion could not be restored as the Home app")
    started = run([adb, "-s", serial, "shell", "am", "start", "-n", f"{PACKAGE}/.MainActivity"], 10)
    if started.returncode != 0:
        raise RuntimeError("APK installed, but HA Companion could not be launched")
    for _ in range(5):
        process = shell(adb, serial, f"pidof {PACKAGE}", 4)
        if process:
            return
        time.sleep(1)
    raise RuntimeError("APK installed, but the HA Companion process did not start")


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


def resolve_apk(args: argparse.Namespace) -> tuple[Path, dict | None]:
    if args.apk:
        apk = Path(args.apk).expanduser().resolve()
        if not apk.is_file():
            raise RuntimeError(f"APK does not exist: {apk}")
        return apk, None
    return download_github_release(args.repository, args.channel, Path(args.cache).expanduser())


def download_command(args: argparse.Namespace) -> int:
    apk, metadata = download_github_release(args.repository, args.channel, Path(args.cache).expanduser())
    if args.json:
        print(json.dumps({"apk": str(apk), "metadata": metadata}, indent=2, sort_keys=True))
    else:
        print(f"Downloaded NSPanel Companion {metadata['version']} ({metadata['version_code']}) to {apk}")
    return 0


def install(args: argparse.Namespace) -> int:
    adb = adb_path()
    apk, metadata = resolve_apk(args)
    address, _, port_text = args.address.partition(":")
    port = int(port_text or args.port)
    panel = inspect(adb, address, port)
    if panel.adb_state != "device":
        raise RuntimeError(f"ADB device is not ready: {panel.adb_state}")
    if panel.classification == "unknown-android" and not args.allow_unknown:
        raise RuntimeError("Refusing to modify an unknown Android device; use --allow-unknown only after verifying it manually")
    if metadata and panel.app_version_code is not None and metadata["version_code"] <= panel.app_version_code and not args.reinstall:
        print(f"No update needed: {panel.address} has version code {panel.app_version_code}; release is {metadata['version_code']}.")
        return 0
    was_home = default_home(adb, panel.address).startswith(f"{PACKAGE}/")
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
    recover_application(adb, panel.address, was_home or args.set_home)
    updated = inspect(adb, address, port)
    home = " · Home restored" if was_home or args.set_home else ""
    print(f"Success: {updated.address} now has {PACKAGE} {updated.app_version or '(version unavailable)'}{home}." )
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser("discover", help="scan a private subnet and inspect network ADB devices")
    discovery.add_argument("--subnet", help="private IPv4 CIDR; defaults conservatively to the current /24")
    discovery.add_argument("--port", type=int, default=DEFAULT_ADB_PORT)
    discovery.add_argument("--timeout", type=float, default=0.35, help="TCP probe timeout in seconds")
    discovery.add_argument("--json", action="store_true", help="emit machine-readable output for the future HA add-on")
    download = commands.add_parser("download", help="download and verify an APK from GitHub Releases")
    download.add_argument("--repository", default=DEFAULT_REPOSITORY)
    download.add_argument("--channel", choices=["stable", "prerelease"], default="stable")
    download.add_argument("--cache", default=str(DEFAULT_CACHE))
    download.add_argument("--json", action="store_true")
    installation = commands.add_parser("install", aliases=["update"], help="install or update a local signed APK")
    installation.add_argument("address", help="panel IP or IP:port")
    source = installation.add_mutually_exclusive_group(required=True)
    source.add_argument("--apk", help="local APK path")
    source.add_argument("--github", action="store_true", help="download the selected GitHub release")
    installation.add_argument("--repository", default=DEFAULT_REPOSITORY)
    installation.add_argument("--channel", choices=["stable", "prerelease"], default="stable")
    installation.add_argument("--cache", default=str(DEFAULT_CACHE))
    installation.add_argument("--port", type=int, default=DEFAULT_ADB_PORT)
    installation.add_argument("--install-timeout", type=float, default=180)
    installation.add_argument("--yes", action="store_true")
    installation.add_argument("--allow-unknown", action="store_true")
    installation.add_argument("--reinstall", action="store_true", help="install even when the selected version is not newer")
    installation.add_argument("--set-home", action="store_true", help="make HA Companion the default Home app after installation")
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "discover":
            print_panels(discover(args), args.json)
            return 0
        if args.command == "download":
            return download_command(args)
        return install(args)
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
