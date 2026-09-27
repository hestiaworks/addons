#!/usr/bin/env python3
"""IMA/DVI-4 ADPCM encoding, in the block layout Reolink asks for.

A block is four bytes of predictor state followed by 4-bit codes, two to a
byte, low nibble first. The camera advertises `lengthPerEncoder`, and that
counts **samples, not bytes** — two codes pack into each byte, so the 1024 a
D340P advertises means 512 code bytes and 1 + 1024 = 1025 samples per block.

Getting that wrong is silent. A camera handed the wrong block size answers
200 OK, acknowledges every packet and plays nothing at all.
"""

from __future__ import annotations

import struct

STEP_TABLE = (
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41,
    45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190,
    209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724,
    796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132,
    7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500,
    20350, 22385, 24623, 27086, 29794, 32767,
)
INDEX_TABLE = (-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8)


def code_bytes(length_per_encoder: int) -> int:
    """Bytes of codes in one block, from what the camera advertises.

    Two 4-bit codes to a byte, so the sample count halves.
    """
    return length_per_encoder // 2


def samples_per_block(length_per_encoder: int) -> int:
    """Samples one block carries, including the one held in the header."""
    return 1 + code_bytes(length_per_encoder) * 2


class Encoder:
    """Carries predictor state across blocks, as a continuous stream must.

    Resetting between blocks would work — each block re-seeds the predictor
    from its header — but the index would restart at zero every time and the
    step size would have to climb again, which audibly dulls the first
    samples of every block.
    """

    def __init__(self) -> None:
        self.predictor = 0
        self.index = 0

    def reset(self) -> None:
        self.predictor = 0
        self.index = 0

    def _code(self, sample: int) -> int:
        step = STEP_TABLE[self.index]
        diff = sample - self.predictor
        code = 0
        if diff < 0:
            code = 8
            diff = -diff
        delta = step >> 3
        if diff >= step:
            code |= 4
            diff -= step
            delta += step
        step >>= 1
        if diff >= step:
            code |= 2
            diff -= step
            delta += step
        step >>= 1
        if diff >= step:
            code |= 1
            delta += step
        self.predictor += -delta if code & 8 else delta
        # Clamping rather than wrapping: a wrapped predictor flips polarity
        # and the decoder follows it, turning a loud passage into noise.
        self.predictor = max(-32768, min(32767, self.predictor))
        self.index = max(0, min(88, self.index + INDEX_TABLE[code]))
        return code

    def block(self, samples: "list[int] | tuple[int, ...]", n_code_bytes: int) -> bytes:
        """Encode exactly one block.

        Expects `1 + n_code_bytes * 2` samples. The first is stored verbatim
        in the header and is what the decoder starts from, so it is not
        encoded.
        """
        expected = 1 + n_code_bytes * 2
        if len(samples) != expected:
            raise ValueError(f"need {expected} samples for {n_code_bytes} code bytes, got {len(samples)}")
        self.predictor = max(-32768, min(32767, int(samples[0])))
        out = bytearray(struct.pack("<hBB", self.predictor, self.index, 0))
        for i in range(1, expected, 2):
            low = self._code(int(samples[i]))
            high = self._code(int(samples[i + 1]))
            out.append((high << 4) | low)
        return bytes(out)
