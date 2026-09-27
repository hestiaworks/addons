#!/usr/bin/env python3
"""Authenticated API that turns panel microphone audio into doorbell talk.

The panel already sends 16 kHz mono PCM, which is exactly what the camera
wants, so nothing here resamples. What it does is encode to ADPCM and carry
it over Baichuan — Reolink's own protocol — because the camera's ONVIF
backchannel buffers two to three seconds and Baichuan does not.

Video is not this add-on's business. Scrypted keeps serving it, prebuffered,
and keeps HomeKit working. Only the microphone's route changes.
"""

from __future__ import annotations

import json
import logging
import math
import os
import secrets
import struct
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import adpcm
from baichuan import BaichuanError, bcmedia_adpcm
from client import Camera

LOG = logging.getLogger("talkback")

DATA = Path(os.environ.get("NSPANEL_TALKBACK_DATA", "/data"))
OPTIONS_FILE = DATA / "options.json"
STATE_FILE = DATA / "state.json"
VERSION = os.environ.get("NSPANEL_TALKBACK_VERSION") or "unknown"
PORT = int(os.environ.get("NSPANEL_TALKBACK_PORT", "8099"))

SAMPLE_RATE = 16000
MAX_BODY = 16 * 1024
# A talk that never ends would hold the channel against everyone else. The
# camera frees it on disconnect anyway; this is the belt to that's braces.
MAX_TALK_SECONDS = 300
# Below this peak, a block is silence and the camera never sees it.
#
# A panel opens its talkback session as soon as the camera page appears and
# fills the wait with zero-filled frames, so the first thing to arrive is
# always silence - seconds of it. Forwarding that fills the camera's playout
# buffer before anyone speaks, and since the buffer drains in real time, every
# word then arrives that far behind. Measured at four to five seconds, with
# the overflow clipping the end off what was said.
#
# Dropping it costs nothing: silence carries no information, and the panel's
# is literal zeros rather than a quiet room.
SILENCE_PEAK = 32

STATE: dict = {"id": "", "name": "NSPanel Talkback", "token": ""}
PAIR_CODE = f"{secrets.randbelow(1000000):06d}"
TALK_LOCK = threading.Lock()


def load_options() -> dict:
    try:
        return json.loads(OPTIONS_FILE.read_text())
    except (OSError, ValueError):
        return {}


def load_state() -> None:
    try:
        STATE.update(json.loads(STATE_FILE.read_text()))
    except (OSError, ValueError):
        pass
    if not STATE.get("id"):
        STATE["id"] = secrets.token_hex(8)
        save_state()


def save_state() -> None:
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(STATE))
    except OSError as err:
        LOG.warning("could not persist state: %s", err)


def is_loopback(address: str) -> bool:
    return address in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def camera_from_options() -> Camera:
    options = load_options()
    host = str(options.get("camera_host", "")).strip()
    if not host:
        raise RuntimeError("no camera_host configured")
    return Camera(
        host=host,
        username=str(options.get("camera_username", "")),
        password=str(options.get("camera_password", "")),
        port=int(options.get("camera_port", 9000)),
        channel=int(options.get("camera_channel", 0)),
    )


def check_ability(cam: Camera) -> dict:
    """Read what the camera accepts and complain loudly if it has moved.

    The camera fails silently on a format it dislikes — 200 OK, every packet
    acknowledged, no sound — so this comparison is the only early warning
    there is that a firmware update has changed the rules.
    """
    ability = cam.talk_ability()
    if ability["audio_type"] != "adpcm":
        LOG.error("camera now wants %r, not adpcm — talk will be silent",
                  ability["audio_type"])
    if ability["sample_rate"] != SAMPLE_RATE:
        LOG.error("camera now wants %s Hz, not %s — talk will be silent",
                  ability["sample_rate"], SAMPLE_RATE)
    return ability


def stream_pcm(cam: Camera, read_chunk, ability: dict) -> dict:
    """Encode 16-bit PCM into ADPCM blocks and push them at the camera.

    The reader paces this: a panel sends in real time, so blocking until a
    whole block exists keeps us in step without a clock of our own.
    """
    length_per_encoder = ability["length_per_encoder"]
    n_code = adpcm.code_bytes(length_per_encoder)
    per_block = adpcm.samples_per_block(length_per_encoder)
    need = per_block * 2

    encoder = adpcm.Encoder()
    blocks = 0
    dropped = 0
    talking = False
    opened = time.monotonic()
    started = None
    while True:
        if started is None:
            if time.monotonic() - opened > MAX_TALK_SECONDS:
                break
        elif time.monotonic() - started > MAX_TALK_SECONDS:
            break
        raw = read_chunk(need)
        if len(raw) < need:
            break
        samples = struct.unpack(f"<{per_block}h", raw)

        if not talking:
            if max(samples) < SILENCE_PEAK and min(samples) > -SILENCE_PEAK:
                # Read it, drop it, and read the next. This drains whatever
                # queued up before anyone spoke, at whatever speed it arrives,
                # so the camera's buffer is empty when the first word reaches
                # it.
                dropped += 1
                continue
            # The talk channel is claimed here rather than when the request
            # opened, so the camera is not holding it - against a phone, or
            # another panel - through a silence nobody is listening to.
            cam.start_talk(ability["sample_rate"], length_per_encoder)
            talking = True
            started = time.monotonic()

        # Past the first word, silence is part of speech - the gap between
        # words - and dropping it would tighten the pauses out of a sentence.
        cam.send_audio(bcmedia_adpcm(encoder.block(samples, n_code)))
        blocks += 1

    if not talking:
        LOG.info("talk request carried no speech: %s silent blocks dropped", dropped)
    return {
        "blocks": blocks,
        "seconds": round(blocks * per_block / ability["sample_rate"], 2),
        "dropped_silent_blocks": dropped,
    }


def two_tone(ability: dict, seconds: float):
    """A synthetic signal for verification, with no microphone involved."""
    rate = ability["sample_rate"]
    per_block = adpcm.samples_per_block(ability["length_per_encoder"])
    total = int(seconds * rate / per_block)
    sample = 0
    for index in range(total):
        freq = 800 if (index // 8) % 2 == 0 else 1200
        block = [int(math.sin(2 * math.pi * freq * (sample + i) / rate) * 20000)
                 for i in range(per_block)]
        sample += per_block
        yield block


class BodyReader:
    """Reads a request body that may be chunked, and stops at its end.

    Two reasons this cannot be `rfile.read`. A panel streams with no
    Content-Length, so the body arrives chunked and `BaseHTTPRequestHandler`
    does not decode that. And on a keep-alive connection a plain read blocks
    waiting for the *next* request rather than returning short, so a talk
    that had ended would never be noticed.
    """

    def __init__(self, rfile, headers) -> None:
        self._rfile = rfile
        self._chunked = "chunked" in headers.get("Transfer-Encoding", "").lower()
        self._remaining = None if self._chunked else int(headers.get("Content-Length") or 0)
        self._buffer = b""
        self._ended = False

    def _fill(self) -> None:
        if self._ended:
            return
        try:
            if self._chunked:
                line = self._rfile.readline().strip()
                if not line:
                    self._ended = True
                    return
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    self._rfile.readline()          # the trailing blank line
                    self._ended = True
                    return
                chunk = b""
                while len(chunk) < size:
                    part = self._rfile.read(size - len(chunk))
                    if not part:
                        self._ended = True
                        break
                    chunk += part
                self._rfile.read(2)                 # CRLF after every chunk
                self._buffer += chunk
            else:
                if not self._remaining:
                    self._ended = True
                    return
                part = self._rfile.read(min(self._remaining, 65536))
                if not part:
                    self._ended = True
                    return
                self._remaining -= len(part)
                self._buffer += part
        except (OSError, ValueError):
            self._ended = True

    def read_exactly(self, count: int) -> bytes:
        """Up to `count` bytes, returning short only at the end of the body."""
        while len(self._buffer) < count and not self._ended:
            self._fill()
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out


class Handler(BaseHTTPRequestHandler):
    server_version = f"NSPanelTalkback/{VERSION}"

    def log_message(self, fmt: str, *args) -> None:
        LOG.debug("%s - %s", self.client_address[0], fmt % args)

    # -- helpers ---------------------------------------------------------

    def send_json(self, status: HTTPStatus, body: dict) -> None:
        payload = json.dumps(body).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def authorized(self) -> bool:
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return bool(STATE["token"]) and secrets.compare_digest(token, STATE["token"])

    def read_body(self) -> dict:
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except ValueError:
            return {}

    def _talk(self, produce) -> None:
        """Hold the camera for one talk, whoever is producing the audio."""
        if not TALK_LOCK.acquire(blocking=False):
            self.send_json(HTTPStatus.CONFLICT,
                           {"error": "This add-on is already talking"})
            return
        try:
            with camera_from_options() as cam:
                ability = check_ability(cam)
                result = produce(cam, ability)
            self.send_json(HTTPStatus.OK, {"ok": True, **result})
        except BaichuanError as err:
            if err.busy:
                # Someone else already has the channel — a phone on HomeKit,
                # or another panel. Say so rather than retrying into a wall.
                self.send_json(HTTPStatus.CONFLICT,
                               {"error": "Someone else is talking to the door"})
            else:
                self.send_json(HTTPStatus.BAD_GATEWAY,
                               {"error": f"Camera refused: status {err.status}"})
        except (RuntimeError, ConnectionError, OSError, TimeoutError) as err:
            LOG.warning("talk failed: %s", err)
            self.send_json(HTTPStatus.BAD_GATEWAY, {"error": str(err)})
        finally:
            TALK_LOCK.release()

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:
        if self.path == "/api/pair-code":
            # Host-only, so Home Assistant can pair without a human copying
            # a code out of the add-on log.
            if not is_loopback(self.client_address[0]):
                self.send_json(HTTPStatus.FORBIDDEN,
                               {"error": "The pairing code is only available on the local host"})
                return
            self.send_json(HTTPStatus.OK,
                           {"id": STATE["id"], "name": STATE["name"], "code": PAIR_CODE})
            return

        if self.path == "/api/info":
            options = load_options()
            self.send_json(HTTPStatus.OK, {
                "id": STATE["id"],
                "name": STATE["name"],
                "version": VERSION,
                "paired": bool(STATE["token"]),
                "camera_host": options.get("camera_host", ""),
                "sample_rate": SAMPLE_RATE,
            })
            return

        if self.path == "/api/ability":
            if not self.authorized():
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credential"})
                return
            try:
                with camera_from_options() as cam:
                    self.send_json(HTTPStatus.OK, check_ability(cam))
            except (RuntimeError, ConnectionError, OSError, TimeoutError,
                    BaichuanError) as err:
                self.send_json(HTTPStatus.BAD_GATEWAY, {"error": str(err)})
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "No such endpoint"})

    def do_POST(self) -> None:
        if self.path == "/api/pair":
            body = self.read_body()
            if str(body.get("code", "")) != PAIR_CODE:
                self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid pairing code"})
                return
            STATE["token"] = secrets.token_urlsafe(32)
            save_state()
            self.send_json(HTTPStatus.OK, {"token": STATE["token"], "id": STATE["id"]})
            return

        if not self.authorized():
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credential"})
            return

        if self.path == "/api/talk":
            reader = self._body_reader()

            def produce(cam, ability):
                return stream_pcm(cam, reader.read_exactly, ability)
            self._talk(produce)
            return

        if self.path == "/api/test-tone":
            seconds = 3.0
            def produce(cam, ability):
                cam.start_talk(ability["sample_rate"], ability["length_per_encoder"])
                encoder = adpcm.Encoder()
                n_code = adpcm.code_bytes(ability["length_per_encoder"])
                per_block = adpcm.samples_per_block(ability["length_per_encoder"])
                blocks = 0
                for block in two_tone(ability, seconds):
                    cam.send_audio(bcmedia_adpcm(encoder.block(block, n_code)))
                    blocks += 1
                    time.sleep(per_block / ability["sample_rate"])
                return {"blocks": blocks, "seconds": seconds}
            self._talk(produce)
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "No such endpoint"})

    def _body_reader(self) -> "BodyReader":
        return BodyReader(self.rfile, self.headers)


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_state()
    options = load_options()
    LOG.info("NSPanel Talkback %s starting on port %s (camera %s)", VERSION, PORT,
             options.get("camera_host") or "not configured")
    if not STATE["token"]:
        LOG.info("Not paired yet. Pairing code: %s", PAIR_CODE)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
