"""Tests for the node #115 log::Reader::ReadPhysicalRecord model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the header parse
(recyclable gate, log_num check, zero-record arm, bad-record-len),
the CRC check (masked stored CRC vs Extend over type+payload), the
decompress loop (single-shot, multi-chunk, kBlockSize continuation,
engine error, type-9 bypass, hash-state creation and digest check),
and the live engine check (CRC32C vector, XXH3 empty vector, and a
real ZSTD round trip through the model).
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import log_reader_read_physical_record115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-log-reader-read-physical-record-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _run(buf, **kw):
    p = {"buffer": buf.hex(), "end_of_buffer_offset": 100,
         "log_number": 7, "checksum": False, "uncompress": 0,
         "fragment_checksum": None}
    p.update(kw)
    return m._run_scenario(p)


def _header(type_byte, length, payload, log_num=None):
    return m._build_header(type_byte, length, payload, log_num=log_num)


class ReplayTests(unittest.TestCase):
    def test_case_count(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"header_parse": 600, "crc": 600,
                                  "decompress": 600, "bindings": 600})

    def test_all_cases_replay(self):
        bad = []
        for r in _read_cases():
            ok, detail = m.replay_case(r)
            if not ok:
                bad.append((r["id"], detail))
        self.assertEqual(bad, [], f"{len(bad)} cases failed: {bad[:5]}")


class HeaderParseTests(unittest.TestCase):
    def test_type_sweeps_all_256_bytes(self):
        # The first 256 header rows are the one-per-type-byte sweep:
        # every type 0..255 returns itself (as u32) for a valid record.
        rets = set()
        for r in _read_cases():
            if r["id"].startswith("header-") and \
                    int(r["id"][7:]) < 256:
                rets.add(json.loads(r["expected"])["return"])
        self.assertEqual(rets, {t if t < 0x80 else (t - 256) & 0xFFFFFFFF
                                for t in range(256)})

    def test_full_record_returns_type_and_payload(self):
        out = _run(_header(1, 3, b"abc"))
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["result"], b"abc".hex())
        self.assertEqual(out["buffer_after"], "")
        self.assertEqual(out["drop_size"], 0)

    def test_recyclable_needs_matching_log_num(self):
        out = _run(_header(5, 3, b"abc", log_num=7))
        self.assertEqual(out["return"], 5)
        out = _run(_header(5, 3, b"abc", log_num=8))
        self.assertEqual(out["return"], m.K_OLD_RECORD)
        self.assertEqual(out["result"], None)

    def test_recycled_set_only_at_offset_zero(self):
        out = _run(_header(6, 3, b"abc", log_num=7),
                   end_of_buffer_offset=14)
        self.assertTrue(out["recycled_after"])
        out = _run(_header(6, 3, b"abc", log_num=7),
                   end_of_buffer_offset=100)
        self.assertFalse(out["recycled_after"])
        # Non-recyclable types never set it, even at offset 0.
        out = _run(_header(1, 3, b"abc"), end_of_buffer_offset=10)
        self.assertFalse(out["recycled_after"])

    def test_zero_type_zero_length_is_bad_record(self):
        out = _run(_header(0, 0, b""))
        self.assertEqual(out["return"], m.K_BAD_RECORD)
        self.assertEqual(out["drop_size"], 0)  # no drop_size write
        out = _run(_header(0, 5, b"hello"))
        self.assertEqual(out["return"], 0)
        self.assertEqual(out["result"], b"hello".hex())

    def test_short_buffer_goes_to_bad_record_len(self):
        full = _header(1, 3, b"abc")
        out = _run(full[:-1])
        self.assertEqual(out["return"], m.K_BAD_RECORD_LEN)
        self.assertEqual(out["drop_size"], len(full) - 1)
        self.assertEqual(out["buffer_after"], "")

    def test_impossible_length_is_bad_record_len(self):
        out = _run(_header(1, 65535, b""))
        self.assertEqual(out["return"], m.K_BAD_RECORD_LEN)

    def test_read_more_refill_then_parse(self):
        full = _header(1, 3, b"abc")
        out = _run(full[:3], read_more_script=[
            {"refill": full.hex(), "end_offset": 110}])
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["result"], b"abc".hex())
        self.assertEqual(out["read_more_calls"], 1)

    def test_read_more_fail_returns_its_error(self):
        full = _header(1, 3, b"abc")
        out = _run(full[:3], read_more_script=[
            {"fail": m.K_EOF, "drop_size": None}])
        self.assertEqual(out["return"], m.K_EOF)
        out = _run(full[:3], read_more_script=[
            {"fail": m.K_BAD_HEADER, "drop_size": 3}])
        self.assertEqual(out["return"], m.K_BAD_HEADER)
        self.assertEqual(out["drop_size"], 3)

    def test_type_byte_ge_0x80_returns_sign_extended(self):
        # type 0x80 is a signed -128 in r15d; the return is 0xFFFFFF80.
        out = _run(_header(0x80, 3, b"abc"))
        self.assertEqual(out["return"], 0xFFFFFF80)
        out = _run(_header(0xFF, 3, b"abc"))
        self.assertEqual(out["return"], 0xFFFFFFFF)

    def test_trailing_bytes_stay_in_buffer(self):
        full = _header(1, 3, b"abc")
        out = _run(full + b"\xde\xad")
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["buffer_after"], b"\xde\xad".hex())


class CrcTests(unittest.TestCase):
    def test_crc32c_known_vector(self):
        self.assertEqual(m.crc32c_value(b"123456789"), 0xE3069283)
        self.assertEqual(m.crc32c_value(b""), 0)

    def test_mask_unmask_round_trip(self):
        for v in (0, 1, 0xDEADBEEF, 0xFFFFFFFF, 0x12345678):
            self.assertEqual(m.crc32c_unmask(m.crc32c_mask(v)), v)

    def test_correct_crc_returns_raw(self):
        out = _run(_header(1, 3, b"abc"), checksum=True)
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["result"], b"abc".hex())

    def test_corrupt_stored_crc_is_bad_checksum(self):
        buf = m._build_header(1, 3, b"abc", corrupt="stored_bit0")
        out = _run(buf, checksum=True)
        self.assertEqual(out["return"], m.K_BAD_RECORD_CHECKSUM)
        self.assertEqual(out["drop_size"], len(buf))
        self.assertEqual(out["buffer_after"], "")

    def test_corrupt_payload_is_bad_checksum(self):
        buf = m._build_header(1, 3, b"abc", corrupt="payload_byte")
        out = _run(buf, checksum=True)
        self.assertEqual(out["return"], m.K_BAD_RECORD_CHECKSUM)

    def test_corrupt_type_byte_is_bad_checksum(self):
        buf = m._build_header(1, 3, b"abc", corrupt="type_byte")
        out = _run(buf, checksum=True)
        self.assertEqual(out["return"], m.K_BAD_RECORD_CHECKSUM)

    def test_recyclable_log_num_gate_fires_before_crc(self):
        # Flipping a log_num byte breaks the CRC too (bytes 7..10 are
        # inside the covered range header+6 .. header_size+length-6),
        # but the log_num gate runs first: the binary returns
        # kOldRecord (13), not kBadRecordChecksum.
        buf = bytearray(_header(5, 3, b"abc", log_num=7))
        buf[7] ^= 0x01
        out = _run(bytes(buf), checksum=True)
        self.assertEqual(out["return"], m.K_OLD_RECORD)

    def test_crc_skipped_when_checksum_off(self):
        buf = m._build_header(1, 3, b"abc", corrupt="stored_bit0")
        out = _run(buf, checksum=False)
        self.assertEqual(out["return"], 1)


class DecompressTests(unittest.TestCase):
    def _decomp(self, type_byte, payload, script, frag=False,
                hash_state=0, checksum=False):
        buf = _header(type_byte, len(payload), payload,
                      log_num=7 if 5 <= type_byte <= 8 else None)
        return _run(buf, checksum=checksum, uncompress=42,
                    uncompressed_buffer=77,
                    uncompress_hash_state=hash_state,
                    fragment_checksum="present" if frag else None,
                    uncompress_script=script)

    def test_single_shot_identity(self):
        out = self._decomp(1, b"hello",
                           [{"remaining": 0, "produced": b"hello".hex()}])
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["result"], b"hello".hex())
        self.assertEqual(out["uncompress_calls"], 1)

    def test_multi_chunk_remaining(self):
        payload = b"0123456789"
        out = self._decomp(1, payload, [
            {"remaining": 5, "produced": payload[:5].hex()},
            {"remaining": 0, "produced": payload[5:].hex()}])
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["result"], payload.hex())
        self.assertEqual(out["uncompress_calls"], 2)

    def test_type_9_bypasses_decompression(self):
        out = self._decomp(9, b"\x01\x02\x03", [], frag=True)
        self.assertEqual(out["return"], 9)
        self.assertEqual(out["result"], b"\x01\x02\x03".hex())
        self.assertEqual(out["uncompress_calls"], 0)
        self.assertFalse(out["hash_state_created"])

    def test_uncompress_absent_is_raw_path(self):
        out = _run(_header(1, 3, b"abc"))
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["uncompress_calls"], 0)

    def test_engine_error_clears_buffer_and_returns_bad_record(self):
        out = self._decomp(1, b"0123456789",
                           [{"remaining": -1, "produced": ""}])
        self.assertEqual(out["return"], m.K_BAD_RECORD)
        self.assertEqual(out["buffer_after"], "")
        self.assertEqual(out["result"], None)

    def test_error_on_second_call(self):
        out = self._decomp(1, b"0123456789", [
            {"remaining": 5, "produced": b"01234".hex()},
            {"remaining": -1, "produced": ""}])
        self.assertEqual(out["return"], m.K_BAD_RECORD)
        self.assertEqual(out["buffer_after"], "")

    def test_fragment_checksum_written_and_matches_xxh3(self):
        payload = b"checksum me please"
        out = self._decomp(1, payload,
                           [{"remaining": 0, "produced": payload.hex()}],
                           frag=True)
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["fragment_checksum"],
                         m.xxh3_64bits(payload))
        self.assertTrue(out["hash_state_created"])
        self.assertTrue(out["hash_state_present_after"])

    def test_hash_state_reused_when_present(self):
        payload = b"reuse the state"
        out = self._decomp(1, payload,
                           [{"remaining": 0, "produced": payload.hex()}],
                           frag=True, hash_state=55)
        self.assertFalse(out["hash_state_created"])
        self.assertEqual(out["fragment_checksum"],
                         m.xxh3_64bits(payload))

    def test_length_error_guard(self):
        # Shrink max_size so the append guard trips on a small
        # produce: the binary throws length_error "basic_string::append"
        # when produced > max_size - current size.
        old = m.MAX_STRING_SIZE
        m.MAX_STRING_SIZE = 10
        try:
            with self.assertRaises(m.LengthError_):
                self._decomp(1, b"0123456789AB",
                             [{"remaining": 0,
                               "produced": b"0123456789AB".hex()}])
        finally:
            m.MAX_STRING_SIZE = old

    def test_zero_produce_then_done(self):
        out = self._decomp(1, b"", [{"remaining": 0, "produced": ""}])
        self.assertEqual(out["return"], 1)
        self.assertEqual(out["result"], "")
        self.assertEqual(out["uncompressed_record_after"], "")


class BindingsTests(unittest.TestCase):
    def test_functions_tsv_matches_binary_and_census(self):
        rows = list(open(PACKET / "functions.tsv"))[1:]
        self.assertEqual(len(rows), 1)
        data = m._read_binary()
        for row in rows:
            cols = row.rstrip("\n").split("\t")
            start, end = int(cols[1], 16), int(cols[2], 16)
            body = data[m._va_to_off(start):m._va_to_off(end)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), cols[4])
            self.assertEqual(cols[4],
                             "9c5b6dcbcbc0f4017ab39d2a4c19d2132e1bdede3cb4c874"
                             "ace33b9eb39787bd")

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 2)
        self.assertEqual(census["targets"]["0x5f01a30"]["calls"], 2)
        self.assertEqual(census["targets"]["0x5f01a30"]["jumps"], 0)
        self.assertEqual(census["targets"]["0x5f01a30"]["lea_refs"], 0)
        sites = [l.split("\t") for l in
                 open(PACKET / "callers.tsv").read().splitlines()[1:]]
        by_site = {row[3]: row for row in sites}
        self.assertEqual(by_site["0x5f01ff6"][4], "0x5f01f10")
        self.assertEqual(by_site["0x5f024f9"][4], "0x5f01f10")

    def test_reader_layout_pins_the_observed_fields(self):
        layout = {n: (o, s) for n, o, s in m.READER_LAYOUT}
        self.assertEqual(layout["checksum_"], (0x28, 1))
        self.assertEqual(layout["buffer_"], (0x38, 16))
        self.assertEqual(layout["end_of_buffer_offset_"], (0x60, 8))
        self.assertEqual(layout["log_number_"], (0x68, 8))
        self.assertEqual(layout["recycled_"], (0x70, 1))
        self.assertEqual(layout["uncompress_"], (0x78, 8))
        self.assertEqual(layout["uncompressed_buffer_"], (0x80, 8))
        self.assertEqual(layout["uncompressed_record_"], (0x88, 32))
        self.assertEqual(layout["uncompress_hash_state_"], (0xB0, 8))
        self.assertEqual(layout["size"], (0x00, 0xF0))

    def test_reloc_targets_pin_the_engine_callees(self):
        data = m._read_binary()
        by_start = {r["start"]: r for r in m._read_census()}
        rec = by_start[0x5F01A30]
        targets = {}
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            site = 0x5F01A30 + o
            disp = struct.unpack_from("<i", data,
                                      m._va_to_off(site))[0]
            targets[o] = site + w + disp
        self.assertEqual(targets[124], 0x5F018D0)   # ReadMore
        self.assertEqual(targets[760], 0x61C25F0)   # crc32c thunk
        self.assertEqual(targets[398], 0x61DC480)   # XXH3 reset
        self.assertEqual(targets[1049], 0x61DC410)  # XXH3 createState

    def test_live_engine_check(self):
        crc_ok, xxh3_empty, round_trip_ok = m.live_engine_check()
        self.assertTrue(crc_ok)
        self.assertTrue(xxh3_empty)
        self.assertTrue(round_trip_ok)


if __name__ == "__main__":
    unittest.main()
