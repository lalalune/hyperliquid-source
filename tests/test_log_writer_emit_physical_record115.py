"""Tests for the node #115 log::Writer::EmitPhysicalRecord model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the legacy /
recyclable gate, the header layout, the CRC chain (Value + Combine +
Mask), the length/log-number truncations, the two-Append flow with
the status move byte rules, and the live engine check (a real WAL
file written by the model parses back with all CRCs valid).
"""

import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import log_writer_emit_physical_record115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-log-writer-emit-physical-record-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _ok_append():
    return m.Status.ok()


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"header_build": 600, "crc_combine": 600,
                                  "append_flow": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")

    def test_check_vector_row(self):
        rows = _read_cases()
        row = [r for r in rows if r["id"] == "crc-0000"][0]
        exp = json.loads(row["expected"])
        self.assertEqual(exp["payload_crc"], 0xE3069283)
        self.assertTrue(exp["combine_matches_direct"])


class GateTests(unittest.TestCase):
    def test_gate_boundaries(self):
        for t in range(5):
            self.assertFalse(m.is_recyclable(t), t)
        for t in (5, 6, 7, 8):
            self.assertTrue(m.is_recyclable(t), t)
        self.assertFalse(m.is_recyclable(9))
        for t in (10, 11, 15):
            self.assertTrue(m.is_recyclable(t), t)

    def test_header_sizes(self):
        for t in (0, 1, 2, 3, 4, 9):
            self.assertEqual(len(m.build_header(t, 0, 0, 0)), 7, t)
        for t in (5, 6, 7, 8):
            self.assertEqual(len(m.build_header(t, 0, 0, 0)), 11, t)

    def test_header_layout(self):
        h = m.build_header(5, 9, 0x12345678, 0xAABBCCDD)
        self.assertEqual(h, bytes.fromhex("ddccbbaa09000578563412"))
        h = m.build_header(1, 9, 0x12345678, 0xAABBCCDD)
        self.assertEqual(h, bytes.fromhex("ddccbbaa090001"))

    def test_length_truncates_to_16_bits(self):
        # The n <= 0xffff assert is compiled out; the binary stores
        # only the low 16 bits of the length in the header.
        h = m.build_header(1, 0x10000, 0, 0)
        self.assertEqual(struct.unpack_from("<H", h, 4)[0], 0)
        h = m.build_header(1, 0x10001, 0, 0)
        self.assertEqual(struct.unpack_from("<H", h, 4)[0], 1)

    def test_log_number_truncates_to_32_bits(self):
        h = m.build_header(5, 0, 0x100000000, 0)
        self.assertEqual(struct.unpack_from("<I", h, 7)[0], 0)
        h = m.build_header(5, 0, 0x123456789, 0)
        self.assertEqual(struct.unpack_from("<I", h, 7)[0], 0x23456789)


class CrcTests(unittest.TestCase):
    def test_check_vector(self):
        self.assertEqual(m.crc32c_value(b"123456789"), 0xE3069283)

    def test_mask_unmask_roundtrip(self):
        for v in (0, 1, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF):
            self.assertEqual(m.crc32c_unmask(m.crc32c_mask(v)), v)

    def test_combine_equals_direct_extend(self):
        for typ in range(10):
            for lognum in (0, 1, 0x12345678, 0xFFFFFFFF):
                payload = bytes(range(typ + 1)) * 3
                seed = m.type_crc_seeds()[typ]
                if m.is_recyclable(typ):
                    seed = m.crc32c_extend(
                        seed, struct.pack("<I", lognum))
                combined = m.crc32c_combine(
                    seed, m.crc32c_value(payload), len(payload))
                direct = m.crc32c_extend(
                    0, bytes([typ])
                    + (struct.pack("<I", lognum)
                       if m.is_recyclable(typ) else b"") + payload)
                self.assertEqual(combined, direct, (typ, lognum))

    def test_combine_degenerate_len_zero(self):
        # No len2 == 0 early return in the binary: crc1 ^ crc2.
        self.assertEqual(m.crc32c_combine(0x11111111, 0x22222222, 0),
                         0x33333333)

    def test_type_crc_seeds_are_single_byte_values(self):
        for i, seed in enumerate(m.type_crc_seeds()):
            self.assertEqual(seed, m.crc32c_value(bytes([i])))


class AppendFlowTests(unittest.TestCase):
    def _run(self, typ=1, payload=b"abc", priority=4,
             header_status=None, payload_status=None, log_number=0,
             block_offset=0):
        writer = m.Writer(log_number=log_number,
                          block_offset=block_offset)
        script = [header_status or m.Status.ok(),
                  payload_status or m.Status.ok()]
        calls = []

        def append_fn(slice_bytes, crc_arg, prio):
            calls.append((slice_bytes, crc_arg, prio))
            return script.pop(0)

        final, events = m.emit_physical_record(
            writer, typ, payload, priority, append_fn)
        return writer, final, events, calls

    def test_both_appends_called_with_right_crc_args(self):
        _, _, _, calls = self._run(payload=b"hello")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1], 0)  # header: crc arg 0
        self.assertEqual(calls[1][1],
                         m.crc32c_value(b"hello"))  # payload: its CRC
        self.assertEqual(calls[0][2], 4)
        self.assertEqual(calls[1][2], 4)

    def test_header_failure_skips_payload_but_advances_offset(self):
        writer, final, events, calls = self._run(
            payload=b"hello",
            header_status=m.Status(5, 1, 0, 0, 0, 0, 0, 4242))
        self.assertEqual(len(calls), 1)
        self.assertEqual(final.code, 5)
        self.assertEqual(final.state, 4242)
        self.assertEqual(writer.block_offset, 7 + 5)

    def test_payload_failure_returns_payload_status(self):
        _, final, _, _ = self._run(
            payload=b"hello",
            payload_status=m.Status(5, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(final.code, 5)

    def test_move_preserves_first_status_b2_and_b67(self):
        # The move at 0x5f03cb3 copies bytes 0-1, 3-4, 5, 8-15 only.
        _, final, events, _ = self._run(
            payload=b"hello",
            header_status=m.Status(0, 0, 9, 0, 0, 0, 0xABCD, 0),
            payload_status=m.Status(2, 3, 4, 5, 6, 7, 0x1234, 999))
        self.assertEqual(final.code, 2)
        self.assertEqual(final.subcode, 3)
        self.assertEqual(final.b2, 9)       # kept from header status
        self.assertEqual(final.b67, 0xABCD)  # kept from header status
        self.assertEqual(final.b3, 5)
        self.assertEqual(final.b4, 6)
        self.assertEqual(final.b5, 7)
        self.assertEqual(final.state, 999)
        self.assertEqual(final.out_bytes(),
                         bytes([2, 3, 9, 5, 6, 7]) + struct.pack(
                             "<H", 0xABCD) + struct.pack("<Q", 999))

    def test_header_state_freed_on_move(self):
        _, _, events, _ = self._run(
            payload=b"hello",
            header_status=m.Status(0, 0, 0, 0, 0, 0, 0, 4242))
        self.assertIn(["free_old_state", 4242], events)

    def test_block_offset_advances_on_both_arms(self):
        writer, _, _, _ = self._run(typ=5, payload=b"x" * 100)
        self.assertEqual(writer.block_offset, 11 + 100)
        writer, _, _, _ = self._run(
            typ=1, payload=b"x" * 100,
            header_status=m.Status(5, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(writer.block_offset, 7 + 100)


class BindingTests(unittest.TestCase):
    def test_census_hashes(self):
        got = m._check_binding(
            {"check": "body_hash", "start": "0x5f03b80",
             "end": "0x5f03d26"})
        self.assertEqual(
            got["sha256"],
            "f82927be6afb1e677d0cd26f44020f7973672cc1f5f05b92495fa9469a41bcc5")
        got = m._check_binding(
            {"check": "body_hash", "start": "0x5f03b50",
             "end": "0x5f03b7b"})
        self.assertEqual(
            got["sha256"],
            "60c6dbfbbdb2a6e95a79122d5de806e56274ef09cb06fe810147da0a406f20cf")

    def test_source_hashes_reproduced(self):
        got = m._check_binding(
            {"check": "source_hash", "start": "0x5f03b80",
             "end": "0x5f03d26"})
        self.assertEqual(
            got["sha256"],
            "94892536b8e99b6850f59d281f9719ae3b31988f149b8c1b170d0de0b2995d26")
        got = m._check_binding(
            {"check": "source_hash", "start": "0x5f03b50",
             "end": "0x5f03b7b"})
        self.assertEqual(
            got["sha256"],
            "32fea398535e1b55f0a636de9ac46ca62ac0f9843d4806271e55f50b8c98c81c")

    def test_append_call_sites(self):
        for site in (0x5F03C2A, 0x5F03CAE):
            got = m._check_binding(
                {"check": "call_site", "site": hex(site)})
            self.assertEqual(got["target"], "0x6054680")
            self.assertEqual(got["opcode"], "0xe8")

    def test_cold_jump(self):
        got = m._check_binding(
            {"check": "call_site", "site": "0x5f03d21"})
        self.assertEqual(got["target"], "0x5f03b50")
        self.assertEqual(got["opcode"], "0xe9")

    def test_relocation_targets(self):
        # The 9 main-FDE relocations pin the callees.
        expected = {
            0: 0x61C25F0, 1: 0x61C2600, 2: 0x6054680, 3: 0x61C25F0,
            4: 0x6054680, 5: 0x63F0DC0, 6: 0x63F0DC0, 7: 0x63F0D70,
            8: 0x5F03B50,
        }
        for idx, target in expected.items():
            got = m._check_binding(
                {"check": "reloc_target", "start": "0x5f03b80",
                 "reloc_index": idx})
            self.assertEqual(got["target"], hex(target), idx)


class LiveCheckTests(unittest.TestCase):
    def test_live_check(self):
        result = m.live_check()
        for key in ("crc_check_vector", "mask_roundtrip",
                    "callsite_header_append", "callsite_payload_append",
                    "cold_jump", "census_body_hash", "wal_all_crc_ok",
                    "wal_consumed_all"):
            self.assertTrue(result[key], key)
        self.assertEqual(result["wal_bytes"], 56)
        self.assertEqual(result["wal_block_offset"], 56)
        self.assertEqual([r["type"] for r in result["wal_records"]],
                         [1, 5, 9])


if __name__ == "__main__":
    unittest.main()
