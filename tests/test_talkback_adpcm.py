"""The ADPCM encoder, and the block arithmetic that silence depends on."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nspanel_talkback"))

import adpcm


class BlockArithmetic(unittest.TestCase):
    """`lengthPerEncoder` counts samples, not bytes.

    Reading it as bytes is not a small error: the camera accepts the
    oversized blocks, answers 200 OK, acknowledges every packet and plays
    nothing at all. It cost an afternoon, so it gets a test.
    """

    def test_code_bytes_is_half_the_advertised_length(self):
        self.assertEqual(adpcm.code_bytes(1024), 512)

    def test_a_block_carries_one_sample_more_than_its_codes(self):
        # The extra one lives in the predictor header and is not encoded.
        self.assertEqual(adpcm.samples_per_block(1024), 1025)

    def test_encoded_block_is_the_header_plus_the_codes(self):
        encoder = adpcm.Encoder()
        block = encoder.block([0] * 1025, 512)
        self.assertEqual(len(block), 516)


class Encoding(unittest.TestCase):
    def test_header_holds_the_first_sample_verbatim(self):
        encoder = adpcm.Encoder()
        block = encoder.block([1234] + [0] * 1024, 512)
        predictor, index, reserved = struct.unpack("<hBB", block[:4])
        self.assertEqual(predictor, 1234)
        self.assertEqual(index, 0)
        self.assertEqual(reserved, 0)

    def test_a_demanding_signal_drives_the_step_index_up(self):
        # A constant signal drives it the other way: every code is zero and
        # INDEX_TABLE[0] is -1, so the index sits in its clamp at zero.
        encoder = adpcm.Encoder()
        encoder.block([0] + [30000, -30000] * 512, 512)
        self.assertGreater(encoder.index, 0)

    def test_predictor_state_carries_between_blocks(self):
        # Resetting per block would restart the step index every time, which
        # audibly dulls the opening of each one. Proven by encoding the same
        # block from a continuing encoder and a fresh one: identical input,
        # different output, because only one of them carries state.
        second = [0] + [30000, -30000] * 512

        carrying = adpcm.Encoder()
        carrying.block([0] + [30000, -30000] * 512, 512)
        continued = carrying.block(second, 512)

        fresh = adpcm.Encoder().block(second, 512)
        self.assertNotEqual(continued, fresh)

    def test_a_loud_signal_does_not_wrap_the_predictor(self):
        encoder = adpcm.Encoder()
        encoder.block([32767] + [-32768, 32767] * 512, 512)
        self.assertGreaterEqual(encoder.predictor, -32768)
        self.assertLessEqual(encoder.predictor, 32767)

    def test_wrong_sample_count_is_refused(self):
        encoder = adpcm.Encoder()
        with self.assertRaises(ValueError):
            encoder.block([0] * 1024, 512)

    def test_decodes_back_to_something_close(self):
        """Round-trip through the reference IMA decoder."""
        import math
        original = [int(math.sin(2 * math.pi * 440 * n / 16000) * 12000)
                    for n in range(1025)]
        block = adpcm.Encoder().block(original, 512)

        predictor, index, _ = struct.unpack("<hBB", block[:4])
        decoded = [predictor]
        for byte in block[4:]:
            for code in (byte & 0x0F, byte >> 4):
                step = adpcm.STEP_TABLE[index]
                delta = step >> 3
                if code & 4:
                    delta += step
                if code & 2:
                    delta += step >> 1
                if code & 1:
                    delta += step >> 2
                predictor += -delta if code & 8 else delta
                predictor = max(-32768, min(32767, predictor))
                index = max(0, min(88, index + adpcm.INDEX_TABLE[code]))
                decoded.append(predictor)

        error = sum(abs(a - b) for a, b in zip(original, decoded)) / len(original)
        self.assertLess(error, 500, f"mean absolute error {error:.0f} is too high")


if __name__ == "__main__":
    unittest.main()
