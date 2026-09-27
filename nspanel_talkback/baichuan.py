#!/usr/bin/env python3
"""The slice of Reolink's Baichuan protocol needed to talk to a doorbell.

Baichuan is Reolink's own protocol on TCP 9000 — the one their app uses. It
matters because the camera's *other* audio path, the ONVIF RTSP backchannel,
carries a large fixed buffer: measured 2-3 seconds against well under one for
this. See the design record in the private hub for the measurements.

Only the talk path is here. Reolink's HTTP API and the event subscriptions
live elsewhere and are somebody else's problem.

Credit where it is due: the framing, the encryption and the login handshake
were read from `reolink_aio`, and the talk messages from `neolink`. Neither
is a dependency — reolink_aio does not implement talk at all, so the talk
layer had to be written regardless, and vendoring the rest would have cost a
pip stage and an async framework to use a twentieth of a package.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import threading
import xml.etree.ElementTree as ET
from typing import NamedTuple

HEADER_MAGIC = bytes.fromhex("f0debc0a")
# The XOR key is published, the AES IV is hard-coded in the firmware. Neither
# is a secret; this is obfuscation, not security. Treat the link as plaintext.
XML_KEY = (0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF)
AES_IV = b"0123456789abcdef"

DEFAULT_PORT = 9000

CMD_LOGIN = 1
CMD_TALK_ABILITY = 10
CMD_TALK_RESET = 11
CMD_TALK_CONFIG = 201
CMD_TALK = 202

# The camera answers 422 when another client already holds the talk channel.
STATUS_BUSY = 422



class BaichuanError(RuntimeError):
    """A camera reply that was not 200."""

    def __init__(self, cmd_id: int, status: int) -> None:
        super().__init__(f"cmd {cmd_id} returned status {status}")
        self.cmd_id = cmd_id
        self.status = status

    @property
    def busy(self) -> bool:
        """Whether someone else is talking to the door right now."""
        return self.status == STATUS_BUSY


def md5_hash(text: str) -> str:
    """Baichuan's MD5: hex, truncated to 31 characters, upper-cased.

    The truncation is not a typo — it is what the firmware expects, and a
    full 32-character hash fails the login.
    """
    return hashlib.md5(text.encode("utf8")).hexdigest()[0:31].upper()


def xor_crypt(data: bytes, offset: int) -> bytes:
    """Baichuan's pre-login obfuscation. Symmetric: the same call decrypts.

    Used for the nonce exchange and the login itself. Everything after login
    must be AES — the camera answers 421 to an XOR-encrypted talk message.
    """
    if offset > 255:
        raise ValueError(f"encryption offset {offset} does not fit a byte")
    return bytes(b ^ XML_KEY[(offset + i) % len(XML_KEY)] ^ offset
                 for i, b in enumerate(data))


def aes_crypt(key: bytes, data: bytes, encrypt: bool = True) -> bytes:
    """AES-128-CFB with a full 128-bit segment and the firmware's fixed IV.

    Imported here rather than at module scope so every pure function above
    stays importable — and testable — on a machine without the library.
    """
    if not data:
        return b""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    # CFB moved to `decrepit` in cryptography 43 and leaves the old location
    # in 49. Alpine already ships 47, so take the new path when it exists.
    try:
        from cryptography.hazmat.decrepit.ciphers import modes
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import modes

    cipher = Cipher(algorithms.AES(key), modes.CFB(AES_IV))
    ctx = cipher.encryptor() if encrypt else cipher.decryptor()
    return ctx.update(data) + ctx.finalize()


# Message classes, and how long their header is. The class sits at bytes
# 18:20 and is the only thing that says whether a payload offset follows.
CLASS_LOGIN = "1465"      # legacy, 20 bytes — what we send to ask for a nonce
CLASS_REPLY = "1466"      # modern, 20 bytes — what the camera answers with
CLASS_NORMAL = "1464"     # modern, 24 bytes — neolink's 0x6414, same bytes
LONG_CLASSES = ("1464", "0000")

# A status only exists on a 24-byte header. On a 20-byte one those same two
# bytes are the encryption type, and reading them as a status yields 56594.
STATUS_OK = (200, 201, 300)

# Encryption markers found at bytes 16:18 of a 20-byte reply.
ENC_XOR = ("01dd", "12dd")
ENC_AES = ("02dd", "03dd")
ENC_NONE = "00dd"


class Message(NamedTuple):
    cmd_id: int
    length: int
    ch_id: int
    enc_type: str
    message_class: str
    status: "int | None"
    payload_offset: int
    body: bytes = b""

    @property
    def ok(self) -> bool:
        """A 20-byte reply carries no status, so absence is not failure."""
        return self.status is None or self.status in STATUS_OK


def header_length(head: bytes) -> int:
    """20 bytes, unless the class says a payload offset follows."""
    return 24 if head[18:20].hex() in LONG_CLASSES else 20


def build_header(cmd_id: int, mess_len: int, ch_id: int, mess_id: int,
                 message_class: str = CLASS_NORMAL, payload_offset: int = 0) -> bytes:
    """One Baichuan message header.

    `mess_len` and `payload_offset` count the bytes actually on the wire, so
    for an encrypted body they are the *encrypted* lengths. AES-CFB is a
    stream mode and preserves length, so in practice they match the
    plaintext — but computing them from the ciphertext is what is correct.
    """
    head = (HEADER_MAGIC
            + cmd_id.to_bytes(4, "little")
            + mess_len.to_bytes(4, "little")
            + ch_id.to_bytes(1, "little") + mess_id.to_bytes(3, "little"))
    if message_class == CLASS_LOGIN:
        return head + bytes.fromhex("12dc" + CLASS_LOGIN)
    if message_class in LONG_CLASSES:
        return (head + bytes.fromhex("0000" + message_class)
                + payload_offset.to_bytes(4, "little"))
    raise ValueError(f"cannot build a header for message class {message_class!r}")


def parse_header(head: bytes) -> Message:
    """Read a header, without inventing a status the wire does not carry."""
    if len(head) < 20 or head[0:4] != HEADER_MAGIC:
        raise ValueError("not a baichuan header")
    message_class = head[18:20].hex()
    long_header = message_class in LONG_CLASSES
    return Message(
        cmd_id=int.from_bytes(head[4:8], "little"),
        length=int.from_bytes(head[8:12], "little"),
        ch_id=head[12],
        enc_type=head[16:18].hex(),
        message_class=message_class,
        status=int.from_bytes(head[16:18], "little") if long_header else None,
        payload_offset=(int.from_bytes(head[20:24], "little")
                        if long_header and len(head) >= 24 else 0),
    )


def bcmedia_adpcm(block: bytes) -> bytes:
    """Wrap one ADPCM block as a BcMedia record.

    The payload size is written twice, identically; the firmware wants both.
    The last field is the block size *halved*, which is neither the code
    byte count nor the sample count and has to be taken on faith.
    """
    pad = (-len(block)) % 8
    return (struct.pack("<IHHHH",
                        0x62773130,              # "01wb"
                        len(block) + 4,
                        len(block) + 4,
                        0x0100,
                        (len(block) - 4) // 2)
            + block + b"\x00" * pad)


def talk_config_xml(channel: int, sample_rate: int, length_per_encoder: int,
                    duplex: str = "FDX",
                    audio_stream_mode: str = "followVideoStream") -> str:
    """The format negotiation sent as cmd 201."""
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        "<body>\n"
        '<TalkConfig version="1.1">\n'
        f"<channelId>{channel}</channelId>\n"
        f"<duplex>{duplex}</duplex>\n"
        f"<audioStreamMode>{audio_stream_mode}</audioStreamMode>\n"
        "<audioConfig>\n"
        "<priority>0</priority>\n"
        "<audioType>adpcm</audioType>\n"
        f"<sampleRate>{sample_rate}</sampleRate>\n"
        "<samplePrecision>16</samplePrecision>\n"
        f"<lengthPerEncoder>{length_per_encoder}</lengthPerEncoder>\n"
        "<soundTrack>mono</soundTrack>\n"
        "</audioConfig>\n"
        "</TalkConfig>\n"
        "</body>\n"
    )


def binary_extension_xml(channel: int) -> str:
    """The extension on a cmd 202: the payload behind it is binary, not XML."""
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<Extension version="1.1">\n'
        f"<channelId>{channel}</channelId>\n"
        "<binaryData>1</binaryData>\n"
        "</Extension>\n"
    )


def channel_extension_xml(channel: int) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<Extension version="1.1">\n'
        f"<channelId>{channel}</channelId>\n"
        "</Extension>\n"
    )


def parse_talk_ability(xml_text: str) -> dict:
    """What the camera says it accepts, from a cmd 10 reply.

    Read at startup and compared against what is being sent. The camera
    fails silently on a format it dislikes, so this is the only early
    warning available if a firmware update moves the goalposts.
    """
    root = ET.fromstring(xml_text)
    config = root.find(".//audioConfig")
    if config is None:
        raise ValueError("no audioConfig in TalkAbility")

    def text(tag: str, default: str = "") -> str:
        node = config.find(tag)
        return node.text.strip() if node is not None and node.text else default

    return {
        "duplex": [d.text for d in root.findall(".//duplexList/duplex") if d.text],
        "audio_stream_modes": [m.text for m in
                               root.findall(".//audioStreamModeList/audioStreamMode") if m.text],
        "audio_type": text("audioType"),
        "sample_rate": int(text("sampleRate", "0")),
        "length_per_encoder": int(text("lengthPerEncoder", "0")),
        "sound_track": text("soundTrack"),
    }
