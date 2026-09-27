#!/usr/bin/env python3
"""A Baichuan connection to one camera, and the talk session on it."""

from __future__ import annotations

import logging
import socket
import threading

from baichuan import (
    CLASS_LOGIN, CLASS_NORMAL, CMD_LOGIN, CMD_TALK, CMD_TALK_ABILITY,
    CMD_TALK_CONFIG, CMD_TALK_RESET, ENC_NONE, ENC_XOR, BaichuanError,
    Message, aes_crypt, binary_extension_xml, build_header,
    channel_extension_xml, header_length, md5_hash, parse_header,
    parse_talk_ability, talk_config_xml, xor_crypt,
)

LOG = logging.getLogger("talkback.client")

CH_HOST = 250          # 0/251 push, 1-100 a channel, 250 the host itself
CMD_KEEPALIVE = 93     # reolink_aio uses LinkType for this
CONNECT_TIMEOUT = 10
REPLY_TIMEOUT = 10


class Camera:
    """One TCP connection, logged in, able to hold the talk channel.

    Not thread safe for concurrent talk sessions, which is fine: the camera
    permits exactly one talker anyway and answers 422 to the second.
    """

    def __init__(self, host: str, username: str, password: str,
                 port: int = 9000, channel: int = 0) -> None:
        self.host = host
        self.port = port
        self.channel = channel
        self._username = username
        self._password = password
        self._sock: socket.socket | None = None
        self._aes_key: bytes | None = None
        self._mess_id = 0
        self._send_lock = threading.Lock()
        self._replies: dict[int, list] = {}
        self._replies_lock = threading.Lock()
        self._reader: threading.Thread | None = None
        self._closing = False
        self.talking = False

    # -- connection ------------------------------------------------------

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), CONNECT_TIMEOUT)
        self._sock.settimeout(None)
        self._closing = False
        self._reader = threading.Thread(target=self._read_loop, name="baichuan-reader",
                                        daemon=True)
        self._reader.start()

    def close(self) -> None:
        self._closing = True
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def __enter__(self) -> "Camera":
        self.connect()
        self.login()
        return self

    def __exit__(self, *_exc) -> None:
        # Dropping the socket is enough on its own: the camera frees the talk
        # channel within a second of a disconnect, so a crash cannot wedge
        # the doorbell. The explicit reset is politeness, not a requirement.
        try:
            if self.talking:
                self.stop_talk()
        finally:
            self.close()

    # -- framing ---------------------------------------------------------

    def _recv_exactly(self, count: int) -> bytes:
        buf = b""
        while len(buf) < count:
            if self._sock is None:
                raise ConnectionError("connection closed")
            chunk = self._sock.recv(count - len(buf))
            if not chunk:
                raise ConnectionError("connection closed by camera")
            buf += chunk
        return buf

    def _read_loop(self) -> None:
        try:
            while not self._closing:
                head = self._recv_exactly(20)
                if header_length(head) == 24:
                    head += self._recv_exactly(4)
                message = parse_header(head)
                body = self._recv_exactly(message.length) if message.length else b""
                with self._replies_lock:
                    self._replies.setdefault(message.cmd_id, []).append(
                        message._replace(body=body))
        except (ConnectionError, OSError):
            pass
        finally:
            with self._replies_lock:
                # Unblock anything waiting, rather than letting it time out.
                for waiting in self._replies.values():
                    waiting.append(None)

    def _take_reply(self, cmd_id: int, timeout: float = REPLY_TIMEOUT) -> Message:
        deadline = threading.Event()
        waited = 0.0
        step = 0.01
        while waited < timeout:
            with self._replies_lock:
                queue = self._replies.get(cmd_id)
                if queue:
                    return queue.pop(0)
            deadline.wait(step)
            waited += step
        raise TimeoutError(f"no reply to cmd {cmd_id} within {timeout}s")

    def _send(self, cmd_id: int, *, extension: str = "", body: str = "",
              binary: bytes = b"", message_class: str = CLASS_NORMAL,
              encrypt: str = "aes", ch_id: int | None = None) -> None:
        if self._sock is None:
            raise ConnectionError("not connected")
        ext_bytes = extension.encode("utf8")
        body_bytes = body.encode("utf8")
        if ch_id is None:
            ch_id = CH_HOST if not extension else self.channel + 1

        if encrypt == "xor":
            enc_ext = xor_crypt(ext_bytes, ch_id)
            enc_body = xor_crypt(body_bytes, ch_id)
        else:
            enc_ext = aes_crypt(self._require_key(), ext_bytes)
            enc_body = aes_crypt(self._require_key(), body_bytes)

        # The binary payload of a talk message is NOT encrypted; only the
        # extension in front of it is.
        payload = enc_ext + enc_body + binary
        with self._send_lock:
            self._mess_id = (self._mess_id + 1) % 16777216
            header = build_header(cmd_id, len(payload), ch_id, self._mess_id,
                                  message_class, len(enc_ext))
            self._sock.sendall(header + payload)

    def _require_key(self) -> bytes:
        if self._aes_key is None:
            raise RuntimeError("log in before sending encrypted messages")
        return self._aes_key

    def _request(self, cmd_id: int, **kwargs) -> str:
        """Send and wait, raising on any status the camera dislikes."""
        with self._replies_lock:
            self._replies.pop(cmd_id, None)
        self._send(cmd_id, **kwargs)
        reply = self._take_reply(cmd_id)
        if reply is None:
            raise ConnectionError(f"connection lost waiting for cmd {cmd_id}")
        if not reply.ok:
            raise BaichuanError(cmd_id, reply.status or 0)
        return self._decrypt(reply)

    def _decrypt(self, reply: Message) -> str:
        """Decrypt a reply the way its own header says it was encrypted.

        The camera picks, not us: a 20-byte reply marks XOR or AES in the
        two bytes where a longer header would put a status.
        """
        if not reply.body:
            return ""
        if reply.enc_type == ENC_NONE:
            plain = reply.body
        elif reply.enc_type in ENC_XOR:
            plain = xor_crypt(reply.body, reply.ch_id)
        else:
            plain = aes_crypt(self._require_key(), reply.body, encrypt=False)
        return plain[reply.payload_offset:].decode("utf8", "replace")

    # -- session ---------------------------------------------------------

    def login(self) -> None:
        """Nonce, then hashes, then the AES key everything after this uses."""
        with self._replies_lock:
            self._replies.pop(CMD_LOGIN, None)
        self._send(CMD_LOGIN, message_class=CLASS_LOGIN, encrypt="xor", ch_id=CH_HOST)
        reply = self._take_reply(CMD_LOGIN)
        if reply is None:
            raise ConnectionError("camera closed the connection during login")
        if not reply.ok:
            raise BaichuanError(CMD_LOGIN, reply.status or 0)
        nonce = _value(self._decrypt(reply), "nonce")
        if not nonce:
            raise RuntimeError("camera returned no nonce")

        self._aes_key = md5_hash(f"{nonce}-{self._password}")[0:16].encode("utf8")
        login_xml = (
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            "<body>\n"
            '<LoginUser version="1.1">\n'
            f"<userName>{md5_hash(self._username + nonce)}</userName>\n"
            f"<password>{md5_hash(self._password + nonce)}</password>\n"
            "<userVer>1</userVer>\n"
            "</LoginUser>\n"
            # LoginNet is not optional. Without it the camera answers 400,
            # having accepted the nonce request immediately before.
            '<LoginNet version="1.1">\n'
            "<type>LAN</type>\n"
            "<udpPort>0</udpPort>\n"
            "</LoginNet>\n"
            "</body>\n"
        )
        self._request(CMD_LOGIN, body=login_xml, encrypt="xor", ch_id=CH_HOST)
        LOG.info("logged in to %s", self.host)

    def keepalive(self) -> None:
        """Keep the connection warm between talks.

        A socket the camera has quietly dropped does not fail on the next
        send — it times out, ten seconds later, which is worse than having
        reconnected in the first place.
        """
        self._request(CMD_KEEPALIVE)

    def talk_ability(self) -> dict:
        """What the camera says it accepts — the firmware-drift canary."""
        xml_text = self._request(CMD_TALK_ABILITY,
                                 extension=channel_extension_xml(self.channel))
        return parse_talk_ability(xml_text)

    def start_talk(self, sample_rate: int, length_per_encoder: int,
                   duplex: str = "FDX",
                   audio_stream_mode: str = "followVideoStream") -> None:
        self._request(CMD_TALK_CONFIG,
                      extension=channel_extension_xml(self.channel),
                      body=talk_config_xml(self.channel, sample_rate,
                                           length_per_encoder, duplex,
                                           audio_stream_mode))
        self.talking = True

    def send_audio(self, record: bytes) -> None:
        """One BcMedia record. Fire and forget — the camera acks every one,
        and waiting for that would pace the stream to the round trip."""
        self._send(CMD_TALK, extension=binary_extension_xml(self.channel),
                   binary=record, ch_id=self.channel + 1)

    def stop_talk(self) -> None:
        self.talking = False
        try:
            self._request(CMD_TALK_RESET,
                          extension=channel_extension_xml(self.channel))
        except (BaichuanError, TimeoutError, ConnectionError) as err:
            LOG.debug("talk reset failed, letting the disconnect free it: %s", err)


def _value(xml_text: str, tag: str) -> str:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return ""
    node = root.find(f".//{tag}")
    return node.text.strip() if node is not None and node.text else ""
