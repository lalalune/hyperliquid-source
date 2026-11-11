"""Synthetic integration of selected #115 checkpoint and replay contracts.

Synthetic contract composition for the RE-017 restore/replay boundary.
The checkpoint row scan follows RE-017-restore-checkpoint-exact-match-115.
The queue probe follows RE-017-node115-replay-segmented-probe.
Record validation follows RE-017-node115-replay-record-identity.
PRs #3875, #3877 and #3878 establish the explicit expected-word and
receiver projections. This fixture supplies their values independently.
The captured binary is read for byte checks only.
"""
import hashlib
from pathlib import Path
import unittest

from tools.elf_index import sections

SENTINEL = 1 << 63
MARKER = SENTINEL | 1
ROOT = Path(__file__).resolve().parents[1]


def first_replay(rows, checkpoint_key, segments, index, expected_word):
    """Return the selected row and first accepted pair, or a stage failure."""
    selected = next(
        (row for row in rows if row[3] == checkpoint_key and row[0] != SENTINEL),
        None,
    )
    if selected is None:
        return "checkpoint_rejected", None, index
    segment = segments
    while segment is not None and segment["base"] != (index & ~31):
        segment = segment["next"]
    if segment is None:
        return "segment_missing", None, index
    slot = index & 31
    if not segment["ready"] & (1 << slot):
        return "not_ready", None, index
    record = segment["slots"][slot]
    # Probe consumption precedes worker validation.
    index = (index + 1) & ((1 << 64) - 1)
    field = 0x60 if record[0x28] == MARKER else (
        0x58 if record[0xb8] == MARKER else 0xe8
    )
    if record[field] != expected_word:
        return "record_mismatch", None, index
    return "accepted", (selected, record), index


class FirstReplayIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
        if hashlib.sha256(data).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
            raise ValueError("wrong #115 artifact")
        table = sections(data)
        # Bind the composed model to the existing packets' selection,
        # probe consumption, and worker equality gates.
        for address, raw in {
            0x25d49cf: "483968f8",
            0x25d49ad: "0f85da000000",
            0x581a27d: "83e21f",
            0x581a280: "c1e204",
            0x581a292: "48ffc1",
            0x581a295: "48894e10",
            0x5a6e3e2: "483b842468010000",
        }.items():
            expected = bytes.fromhex(raw)
            section, = (
                s for s in table if s["type"] != 8
                and s["address"] <= address
                and address + len(expected) <= s["address"] + s["size"]
            )
            offset = section["offset"] + address - section["address"]
            if data[offset:offset + len(expected)] != expected:
                raise ValueError(f"changed contract at {address:#x}")

    def setUp(self):
        self.row = (8, 0x1230, 1, 42)
        self.record = {0x28: MARKER, 0xb8: 0, 0x60: 900, 0x58: 11, 0xe8: 12}
        tail = {"base": 32, "ready": 1 << 3, "slots": {3: self.record}, "next": None}
        self.segments = {"base": 0, "ready": 0, "slots": {}, "next": tail}

    def test_success_uses_explicit_expected_not_checkpoint_successor(self):
        rows = [(SENTINEL, 0, 0, 42), (1, 2, 3, 41), self.row]
        status, result, index = first_replay(rows, 42, self.segments, 35, 900)
        self.assertEqual((status, index), ("accepted", 36))
        self.assertEqual(result, (self.row, self.record))
        self.assertNotEqual(900, 42 + 1)

    def test_no_eligible_checkpoint_does_not_consume(self):
        result = first_replay([(SENTINEL, 0, 0, 42)], 42, self.segments, 35, 900)
        self.assertEqual(result, ("checkpoint_rejected", None, 35))

    def test_missing_segment_does_not_consume(self):
        result = first_replay([self.row], 42, None, 35, 900)
        self.assertEqual(result, ("segment_missing", None, 35))

    def test_mismatched_record_has_already_been_consumed(self):
        result = first_replay([self.row], 42, self.segments, 35, 901)
        self.assertEqual(result, ("record_mismatch", None, 36))
