"""Baichuan framing, encryption and the talk messages.

Everything here is pure, so it runs without a camera and without
`cryptography` — the AES primitive is imported lazily for exactly that
reason, and is the one thing these tests do not cover.
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nspanel_talkback"))

import baichuan as bc


class Hashing(unittest.TestCase):
    def test_md5_is_truncated_to_31_and_upper_cased(self):
        # Not a typo in the firmware's favour: a full 32-character hash
        # fails the login outright.
        digest = bc.md5_hash("anything")
        self.assertEqual(len(digest), 31)
        self.assertEqual(digest, digest.upper())


class XorObfuscation(unittest.TestCase):
    def test_round_trips(self):
        self.assertEqual(bc.xor_crypt(bc.xor_crypt(b"<?xml ...", 250), 250), b"<?xml ...")

    def test_offset_changes_the_output(self):
        self.assertNotEqual(bc.xor_crypt(b"abc", 1), bc.xor_crypt(b"abc", 2))

    def test_offset_must_fit_a_byte(self):
        with self.assertRaises(ValueError):
            bc.xor_crypt(b"abc", 256)


class Headers(unittest.TestCase):
    def test_normal_class_carries_a_payload_offset(self):
        head = bc.build_header(bc.CMD_TALK, 100, 1, 7, bc.CLASS_NORMAL, 60)
        self.assertEqual(len(head), 24)
        message = bc.parse_header(head)
        self.assertEqual(message.cmd_id, bc.CMD_TALK)
        self.assertEqual(message.length, 100)
        self.assertEqual(message.ch_id, 1)
        self.assertEqual(message.payload_offset, 60)

    def test_login_class_has_no_payload_offset(self):
        head = bc.build_header(bc.CMD_LOGIN, 0, 250, 1, bc.CLASS_LOGIN)
        self.assertEqual(len(head), 20)
        self.assertEqual(bc.header_length(head), 20)

    def test_the_camera_replies_in_class_1466_with_a_short_header(self):
        """Regression: a real nonce reply, captured from a D340P.

        Treating 1466 as a 24-byte header eats four bytes of the body and
        every decryption after it is garbage. The reply is 178 bytes with a
        declared length of 158, which only adds up at 20.
        """
        head = bytes.fromhex("f0debc0a010000009e000000fa01000012dd1466")
        self.assertEqual(bc.header_length(head), 20)
        message = bc.parse_header(head)
        self.assertEqual(message.cmd_id, bc.CMD_LOGIN)
        self.assertEqual(message.length, 158)
        self.assertEqual(message.ch_id, 250)
        self.assertEqual(message.enc_type, "12dd")
        self.assertIn(message.enc_type, bc.ENC_XOR)

    def test_a_short_header_carries_no_status(self):
        # Those two bytes are the encryption type. Read as a status they
        # say 56594, and every reply looks like a failure.
        head = bytes.fromhex("f0debc0a010000009e000000fa01000012dd1466")
        message = bc.parse_header(head)
        self.assertIsNone(message.status)
        self.assertTrue(message.ok)

    def test_status_is_read_only_from_a_long_header(self):
        head = bc.build_header(bc.CMD_TALK_CONFIG, 0, 1, 1, bc.CLASS_NORMAL)
        self.assertEqual(bc.parse_header(head).status, 0)

    def test_busy_status_is_recognised(self):
        error = bc.BaichuanError(bc.CMD_TALK_CONFIG, bc.STATUS_BUSY)
        self.assertTrue(error.busy)
        self.assertFalse(bc.BaichuanError(bc.CMD_TALK_CONFIG, 400).busy)

    def test_rejects_something_that_is_not_a_header(self):
        with self.assertRaises(ValueError):
            bc.parse_header(b"not a baichuan message at all")


class BcMediaRecord(unittest.TestCase):
    def test_header_fields_match_the_block(self):
        block = bytes(516)                      # 4 predictor + 512 codes
        record = bc.bcmedia_adpcm(block)
        magic, size_a, size_b, data_magic, halved = struct.unpack("<IHHHH", record[:12])
        self.assertEqual(magic, 0x62773130)     # "01wb"
        self.assertEqual(size_a, len(block) + 4)
        self.assertEqual(size_b, size_a, "the firmware wants the size twice")
        self.assertEqual(data_magic, 0x0100)
        self.assertEqual(halved, (len(block) - 4) // 2)

    def test_the_block_is_padded_to_an_eight_byte_boundary(self):
        # The padding applies to the block, not to the whole record: the
        # 12-byte header sits in front of it and is not counted.
        for block_size in (516, 520, 517):
            record = bc.bcmedia_adpcm(bytes(block_size))
            self.assertEqual((len(record) - 12) % 8, 0,
                             f"block of {block_size} was not padded to 8")
        self.assertEqual(len(bc.bcmedia_adpcm(bytes(516))), 12 + 520)

    def test_the_block_survives_verbatim(self):
        block = bytes(range(256)) * 2 + bytes(4)
        record = bc.bcmedia_adpcm(block)
        self.assertEqual(record[12:12 + len(block)], block)


class TalkAbility(unittest.TestCase):
    REPLY = """<?xml version="1.0" encoding="UTF-8" ?>
<body>
<TalkAbility version="1.1">
<duplexList><duplex>FDX</duplex></duplexList>
<audioStreamModeList>
<audioStreamMode>followVideoStream</audioStreamMode>
<audioStreamMode>mixAudioStream</audioStreamMode>
</audioStreamModeList>
<audioConfigList><audioConfig>
<priority>0</priority>
<audioType>adpcm</audioType>
<sampleRate>16000</sampleRate>
<samplePrecision>16</samplePrecision>
<lengthPerEncoder>1024</lengthPerEncoder>
<soundTrack>mono</soundTrack>
</audioConfig></audioConfigList>
</TalkAbility>
</body>
"""

    def test_reads_what_the_camera_accepts(self):
        ability = bc.parse_talk_ability(self.REPLY)
        self.assertEqual(ability["audio_type"], "adpcm")
        self.assertEqual(ability["sample_rate"], 16000)
        self.assertEqual(ability["length_per_encoder"], 1024)
        self.assertEqual(ability["sound_track"], "mono")
        self.assertIn("FDX", ability["duplex"])
        self.assertIn("mixAudioStream", ability["audio_stream_modes"])

    def test_refuses_a_reply_with_no_audio_config(self):
        with self.assertRaises(ValueError):
            bc.parse_talk_ability("<?xml version='1.0'?><body><TalkAbility/></body>")


class TalkConfig(unittest.TestCase):
    def test_carries_the_negotiated_numbers(self):
        xml = bc.talk_config_xml(0, 16000, 1024)
        self.assertIn("<sampleRate>16000</sampleRate>", xml)
        self.assertIn("<lengthPerEncoder>1024</lengthPerEncoder>", xml)
        self.assertIn("<audioType>adpcm</audioType>", xml)
        self.assertIn("<duplex>FDX</duplex>", xml)

    def test_binary_extension_declares_a_binary_payload(self):
        # Without this the camera reads the audio as XML and rejects it.
        self.assertIn("<binaryData>1</binaryData>", bc.binary_extension_xml(0))


if __name__ == "__main__":
    unittest.main()


class BodyReading(unittest.TestCase):
    """Reading a request body that ends, on a connection that does not.

    A panel streams with no Content-Length, so the body is chunked — which
    `BaseHTTPRequestHandler` does not decode — and on a keep-alive socket a
    plain read blocks for the next request instead of returning short.
    """

    def _reader(self, raw, headers):
        import io
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nspanel_talkback"))
        import server
        return server.BodyReader(io.BytesIO(raw), headers)

    def test_reads_a_body_with_a_content_length(self):
        reader = self._reader(b"abcdefghij", {"Content-Length": "10"})
        self.assertEqual(reader.read_exactly(4), b"abcd")
        self.assertEqual(reader.read_exactly(4), b"efgh")

    def test_stops_at_the_end_rather_than_blocking(self):
        reader = self._reader(b"abcdefghij", {"Content-Length": "10"})
        reader.read_exactly(10)
        self.assertEqual(reader.read_exactly(4), b"")

    def test_returns_short_on_a_partial_final_block(self):
        reader = self._reader(b"abcdefghij", {"Content-Length": "10"})
        reader.read_exactly(8)
        self.assertEqual(reader.read_exactly(4), b"ij")

    def test_decodes_a_chunked_body(self):
        raw = b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"
        reader = self._reader(raw, {"Transfer-Encoding": "chunked"})
        self.assertEqual(reader.read_exactly(10), b"helloworld")
        self.assertEqual(reader.read_exactly(1), b"")

    def test_reassembles_across_chunk_boundaries(self):
        # A 20 ms audio block will not line up with the chunks it arrives in.
        raw = b"3\r\nabc\r\n3\r\ndef\r\n3\r\nghi\r\n0\r\n\r\n"
        reader = self._reader(raw, {"Transfer-Encoding": "chunked"})
        self.assertEqual(reader.read_exactly(4), b"abcd")
        self.assertEqual(reader.read_exactly(4), b"efgh")
        self.assertEqual(reader.read_exactly(4), b"i")

    def test_a_truncated_chunked_body_ends_rather_than_hangs(self):
        reader = self._reader(b"5\r\nhel", {"Transfer-Encoding": "chunked"})
        self.assertEqual(reader.read_exactly(10), b"hel")
        self.assertEqual(reader.read_exactly(1), b"")


class LeadingSilence(unittest.TestCase):
    """Silence that arrives before anyone speaks must never reach the camera.

    A panel opens its talkback session when the camera page appears and fills
    the wait with zero-filled frames. Forwarding those fills the camera's
    playout buffer before the first word, and since it drains in real time
    every word then arrives that far behind — measured at four to five
    seconds, with the overflow clipping the end off the sentence.
    """

    def _stream(self, blocks):
        import struct
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nspanel_talkback"))
        import server

        ability = {"sample_rate": 16000, "length_per_encoder": 1024}
        per = 1 + 512 * 2
        body = b"".join(struct.pack(f"<{per}h", *b) for b in blocks)
        pos = {"i": 0}

        def read(count):
            chunk = body[pos["i"]:pos["i"] + count]
            pos["i"] += len(chunk)
            return chunk

        class FakeCamera:
            def __init__(self):
                self.started = False
                self.sent = 0
                self.start_order = None
            def start_talk(self, *_a, **_k):
                self.started = True
                self.start_order = self.sent
            def send_audio(self, _record):
                self.sent += 1

        cam = FakeCamera()
        result = server.stream_pcm(cam, read, ability)
        return cam, result

    def _silence(self, per=1025):
        return [0] * per

    def _speech(self, per=1025):
        return [12000 if i % 2 else -12000 for i in range(per)]

    def test_silent_blocks_never_reach_the_camera(self):
        cam, result = self._stream([self._silence()] * 20)
        self.assertEqual(0, cam.sent)
        self.assertEqual(20, result["dropped_silent_blocks"])

    def test_the_talk_channel_is_not_claimed_for_silence(self):
        # Holding it would refuse a phone or another panel with 422, for a
        # silence nobody is listening to.
        cam, _ = self._stream([self._silence()] * 20)
        self.assertFalse(cam.started)

    def test_speech_is_forwarded_from_its_first_block(self):
        cam, result = self._stream([self._silence()] * 30 + [self._speech()] * 5)
        self.assertEqual(5, cam.sent)
        self.assertEqual(30, result["dropped_silent_blocks"])
        self.assertTrue(cam.started)

    def test_the_channel_is_claimed_exactly_when_speech_starts(self):
        cam, _ = self._stream([self._silence()] * 30 + [self._speech()] * 5)
        self.assertEqual(0, cam.start_order, "start_talk must precede the first block")

    def test_pauses_inside_speech_are_kept(self):
        # Dropping these would tighten the gaps out of a sentence.
        blocks = [self._speech(), self._silence(), self._silence(), self._speech()]
        cam, result = self._stream([self._silence()] * 10 + blocks)
        self.assertEqual(4, cam.sent)
        self.assertEqual(10, result["dropped_silent_blocks"])

    def test_room_noise_counts_as_speech(self):
        # The threshold is for digital zeros, not for a quiet room: a panel
        # with an open microphone should still get through.
        quiet = [40 if i % 2 else -40 for i in range(1025)]
        cam, _ = self._stream([quiet])
        self.assertEqual(1, cam.sent)


class WarmConnection(unittest.TestCase):
    """The camera connection is kept open between talks.

    Connecting, logging in and asking the camera what it accepts is three
    round trips. Per request that is invisible on a camera page, where the
    button is pressed seconds after the page opens — and plainly audible on
    a ring, where it is pressed the instant the screen appears and the first
    words go in while the add-on is still introducing itself.
    """

    def holder(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nspanel_talkback"))
        import server
        return server

    def test_a_reused_connection_does_not_log_in_again(self):
        server = self.holder()
        opened = []

        class FakeCamera:
            talking = False
            def close(self): pass

        holder = server.CameraHolder.__new__(server.CameraHolder)
        holder._camera = None
        holder._ability = None
        import threading
        holder._lock = threading.Lock()
        holder._open = lambda: (opened.append(1), FakeCamera())[1]
        server.check_ability = lambda _cam: {"audio_type": "adpcm"}

        holder.borrow()
        holder.borrow()
        holder.borrow()
        self.assertEqual(1, len(opened), "logged in more than once for three talks")

    def test_a_stale_connection_is_replaced_rather_than_surfaced(self):
        server = self.holder()
        opened = []

        class Stale:
            talking = False
            def close(self): pass

        class Fresh:
            talking = False
            def close(self): pass

        holder = server.CameraHolder.__new__(server.CameraHolder)
        holder._camera = Stale()
        holder._ability = None
        import threading
        holder._lock = threading.Lock()
        holder._open = lambda: (opened.append(1), Fresh())[1]

        calls = {"n": 0}
        def ability(cam):
            calls["n"] += 1
            if isinstance(cam, Stale):
                raise ConnectionError("socket went away while idle")
            return {"audio_type": "adpcm"}
        server.check_ability = ability

        cam, _ = holder.borrow()
        self.assertIsInstance(cam, Fresh, "a stale connection was handed out")
        self.assertEqual(1, len(opened))
