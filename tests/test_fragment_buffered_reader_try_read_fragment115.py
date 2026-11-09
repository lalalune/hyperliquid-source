"""Tests for the node #115 log::FragmentBufferedReader::TryReadFragment
model.

Replays all 2,400 cases in cases.tsv through the tool's replay_case,
then checks the model's key behaviours directly: the header parse
(recyclable gate, log_num check, zero-record arm, no kBadRecordLen
arm -- a short body refills instead), the three TryReadMore loops
(refill, fail, and the no-progress arm that returns false without
writing *fragment_type_or_err), the CRC check (masked stored CRC vs
Extend over type+payload), the decompress loop (single-shot,
multi-chunk, kBlockSize continuation, engine error, type-9 bypass,
types 10/11 decompressed like the binary does), and the live engine
check (CRC32C vector and real ZSTD round trips through the model).
"""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import fragment_buffered_reader_try_read_fragment115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-fragment-buffered-reader-try-read-fragment-115")


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


def _run(buf, **kw):
    p = {"buffer": buf.hex(), "end_of_buffer_offset": 100,
         "log_number": 7, "checksum": False, "uncompress": 0}
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
        # every type 0..255 returns true with frag_type = itself (u32).
        rets = set()
        for r in _read_cases():
            if r["id"].startswith("header-") and \
                    int(r["id"][7:]) < 256:
                exp = json.loads(r["expected"])
                self.assertTrue(exp["ok"])
                rets.add(exp["frag_type"])
        self.assertEqual(rets, {t if t < 0x80 else (t - 256) & 0xFFFFFFFF
                                for t in range(256)})

    def test_full_record_returns_type_and_payload(self):
        out = _run(_header(1, 3, b"abc"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], b"abc".hex())
        self.assertEqual(out["buffer_after"], "")
        self.assertEqual(out["drop_size"], 0)

    def test_recyclable_needs_matching_log_num(self):
        out = _run(_header(5, 3, b"abc", log_num=7))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 5)
        out = _run(_header(5, 3, b"abc", log_num=8))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], m.K_OLD_RECORD)
        self.assertEqual(out["fragment"], None)
        # Buffer is NOT cleared on the old-record arm.
        self.assertEqual(out["buffer_after"],
                         _header(5, 3, b"abc", log_num=8).hex())

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
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], m.K_BAD_RECORD)
        self.assertEqual(out["drop_size"], 0)  # no drop_size write
        self.assertEqual(out["fragment"], None)
        self.assertEqual(out["buffer_after"], "")
        out = _run(_header(0, 5, b"hello"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 0)
        self.assertEqual(out["fragment"], b"hello".hex())

    def test_short_body_refills_instead_of_bad_record_len(self):
        # Unlike ReadPhysicalRecord there is NO kBadRecordLen arm: a
        # short body refills through TryReadMore until it fits.
        full = _header(1, 3, b"abc")
        out = _run(full[:-1], try_read_more_script=[
            {"refill": full.hex(), "end_offset": 110}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], b"abc".hex())
        # With no refill available the call fails with TryReadMore's
        # code, not kBadRecordLen.
        out = _run(full[:-1])
        self.assertFalse(out["ok"])
        self.assertEqual(out["frag_type"], m.K_EOF)

    def test_try_read_more_refill_then_parse(self):
        full = _header(1, 3, b"abc")
        out = _run(full[:3], try_read_more_script=[
            {"refill": full.hex(), "end_offset": 110}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], b"abc".hex())
        self.assertEqual(out["try_read_more_calls"], 1)

    def test_try_read_more_fail_returns_its_error(self):
        full = _header(1, 3, b"abc")
        out = _run(full[:3], try_read_more_script=[
            {"fail": m.K_EOF, "drop_size": None}])
        self.assertFalse(out["ok"])
        self.assertEqual(out["frag_type"], m.K_EOF)
        out = _run(full[:3], try_read_more_script=[
            {"fail": m.K_BAD_HEADER, "drop_size": 3}])
        self.assertFalse(out["ok"])
        self.assertEqual(out["frag_type"], m.K_BAD_HEADER)
        self.assertEqual(out["drop_size"], 3)

    def test_no_progress_returns_false_without_writing_type(self):
        # TryReadMore returns true but the buffer does not grow: the
        # binary returns false and leaves *fragment_type_or_err
        # untouched (None here -- the caller sees its old value).
        full = _header(1, 3, b"abc")
        out = _run(full[:3], try_read_more_script=[{"noop": True}])
        self.assertFalse(out["ok"])
        self.assertEqual(out["frag_type"], None)
        self.assertEqual(out["fragment"], None)

    def test_type_byte_ge_0x80_returns_sign_extended(self):
        # type 0x80 is a signed -128 in the parse; the out-param is
        # 0xFFFFFF80.
        out = _run(_header(0x80, 3, b"abc"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 0xFFFFFF80)
        out = _run(_header(0xFF, 3, b"abc"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 0xFFFFFFFF)

    def test_trailing_bytes_stay_in_buffer(self):
        full = _header(1, 3, b"abc")
        out = _run(full + b"\xde\xad")
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
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
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], b"abc".hex())

    def test_corrupt_stored_crc_is_bad_checksum(self):
        buf = m._build_header(1, 3, b"abc", corrupt="stored_bit0")
        out = _run(buf, checksum=True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], m.K_BAD_RECORD_CHECKSUM)
        self.assertEqual(out["drop_size"], len(buf))
        self.assertEqual(out["buffer_after"], "")
        self.assertEqual(out["fragment"], None)

    def test_corrupt_payload_is_bad_checksum(self):
        buf = m._build_header(1, 3, b"abc", corrupt="payload_byte")
        out = _run(buf, checksum=True)
        self.assertEqual(out["frag_type"], m.K_BAD_RECORD_CHECKSUM)

    def test_corrupt_type_byte_is_bad_checksum(self):
        buf = m._build_header(1, 3, b"abc", corrupt="type_byte")
        out = _run(buf, checksum=True)
        self.assertEqual(out["frag_type"], m.K_BAD_RECORD_CHECKSUM)

    def test_recyclable_log_num_gate_fires_before_crc(self):
        # Flipping a log_num byte breaks the CRC too (bytes 7..10 are
        # inside the covered range header+6 .. header_size+length-6),
        # but the log_num gate runs first: the binary returns
        # kOldRecord (13), not kBadRecordChecksum.
        buf = bytearray(_header(5, 3, b"abc", log_num=7))
        buf[7] ^= 0x01
        out = _run(bytes(buf), checksum=True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], m.K_OLD_RECORD)

    def test_crc_skipped_when_checksum_off(self):
        buf = m._build_header(1, 3, b"abc", corrupt="stored_bit0")
        out = _run(buf, checksum=False)
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)


class DecompressTests(unittest.TestCase):
    def _decomp(self, type_byte, payload, script, checksum=False):
        buf = _header(type_byte, len(payload), payload,
                      log_num=7 if 5 <= type_byte <= 8 else None)
        return _run(buf, checksum=checksum, uncompress=42,
                    uncompressed_buffer=77, uncompress_script=script)

    def test_single_shot_identity(self):
        out = self._decomp(1, b"hello",
                           [{"remaining": 0, "produced": b"hello".hex()}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], b"hello".hex())
        self.assertEqual(out["uncompress_calls"], 1)

    def test_multi_chunk_remaining(self):
        payload = b"0123456789"
        out = self._decomp(1, payload, [
            {"remaining": 5, "produced": payload[:5].hex()},
            {"remaining": 0, "produced": payload[5:].hex()}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], payload.hex())
        self.assertEqual(out["uncompress_calls"], 2)

    def test_type_9_bypasses_decompression(self):
        out = self._decomp(9, b"\x01\x02\x03", [])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 9)
        self.assertEqual(out["fragment"], b"\x01\x02\x03".hex())
        self.assertEqual(out["uncompress_calls"], 0)

    def test_types_10_and_11_are_decompressed_not_raw(self):
        # The binary has no bypass for the user-defined-timestamp
        # types: with uncompress_ set they go through the engine.
        for t in (10, 11):
            out = self._decomp(t, b"ts-size",
                               [{"remaining": 0,
                                 "produced": b"ts-size".hex()}])
            self.assertTrue(out["ok"])
            self.assertEqual(out["frag_type"], t)
            self.assertEqual(out["fragment"], b"ts-size".hex())
            self.assertEqual(out["uncompress_calls"], 1)

    def test_uncompress_absent_is_raw_path(self):
        out = _run(_header(1, 3, b"abc"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["uncompress_calls"], 0)

    def test_engine_error_clears_buffer_and_returns_bad_record(self):
        out = self._decomp(1, b"0123456789",
                           [{"remaining": -1, "produced": ""}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], m.K_BAD_RECORD)
        self.assertEqual(out["buffer_after"], "")
        self.assertEqual(out["fragment"], None)
        self.assertEqual(out["uncompressed_record_after"], "")

    def test_error_on_second_call_keeps_partial_record(self):
        out = self._decomp(1, b"0123456789", [
            {"remaining": 5, "produced": b"01234".hex()},
            {"remaining": -1, "produced": ""}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], m.K_BAD_RECORD)
        self.assertEqual(out["buffer_after"], "")
        # *fragment is untouched, but the partial record stays in the
        # reader (it is cleared only by the next decompress entry).
        self.assertEqual(out["fragment"], None)
        self.assertEqual(out["uncompressed_record_after"],
                         b"01234".hex())

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
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], "")
        self.assertEqual(out["uncompressed_record_after"], "")

    def test_block_size_continuation(self):
        # A full 0x8000-byte produce forces another Uncompress call
        # even with nothing left to consume.
        big = bytes((j * 5 + 1) % 256 for j in range(0x8000 + 13))
        out = self._decomp(1, big[:100], [
            {"remaining": 0, "produced": big[:0x8000].hex()},
            {"remaining": 0, "produced": big[0x8000:].hex()}])
        self.assertTrue(out["ok"])
        self.assertEqual(out["frag_type"], 1)
        self.assertEqual(out["fragment"], big.hex())
        self.assertEqual(out["uncompress_calls"], 2)


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
                             "e7cefc65de0773da8a7779b9e3f67387702971ce9969d"
                             "ba96511ee470387cf01")
            self.assertEqual(cols[5],
                             "e550ea549e3ce44cac368f1b8883321e2ef4bf65632781"
                             "2b95dabe4b2a59c389")

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 1)
        self.assertEqual(census["targets"]["0x5f02b40"]["calls"], 1)
        self.assertEqual(census["targets"]["0x5f02b40"]["jumps"], 0)
        self.assertEqual(census["targets"]["0x5f02b40"]["lea_refs"], 0)
        sites = [l.split("\t") for l in
                 open(PACKET / "callers.tsv").read().splitlines()[1:]]
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0][3], "0x5f02fdc")
        self.assertEqual(sites[0][4], "0x5f02f20")
        self.assertEqual(sites[0][5], "0x5f034f2")

    def test_reader_layout_pins_the_observed_fields(self):
        layout = {n: (o, s) for n, o, s in m.FRAGMENT_LAYOUT}
        self.assertEqual(layout["checksum_"], (0x28, 1))
        self.assertEqual(layout["buffer_"], (0x38, 16))
        self.assertEqual(layout["end_of_buffer_offset_"], (0x60, 8))
        self.assertEqual(layout["log_number_"], (0x68, 8))
        self.assertEqual(layout["recycled_"], (0x70, 1))
        self.assertEqual(layout["uncompress_"], (0x78, 8))
        self.assertEqual(layout["uncompressed_buffer_"], (0x80, 8))
        self.assertEqual(layout["uncompressed_record_"], (0x88, 32))
        self.assertEqual(layout["fragments_"], (0xB8, 32))
        self.assertEqual(layout["in_fragmented_record_"], (0xD8, 1))

    def test_reloc_targets_pin_the_engine_callees(self):
        data = m._read_binary()
        by_start = {r["start"]: r for r in m._read_census()}
        rec = by_start[0x5F02B40]
        targets = {}
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            site = 0x5F02B40 + o
            disp = struct.unpack_from("<i", data,
                                      m._va_to_off(site))[0]
            targets[o] = site + w + disp
        self.assertEqual(targets[108], 0x5F02980)   # TryReadMore (loop 1)
        self.assertEqual(targets[280], 0x5F02980)   # TryReadMore (loop 2)
        self.assertEqual(targets[375], 0x5F02980)   # TryReadMore (loop 3)
        self.assertEqual(targets[658], 0x63F0F40)   # _M_append
        self.assertEqual(targets[729], 0x4376FD)    # empty literal
        self.assertEqual(targets[761], 0x4376FD)    # empty literal
        self.assertEqual(targets[823], 0x61C25F0)   # crc32c thunk
        self.assertEqual(targets[847], 0x4376FD)    # empty literal
        self.assertEqual(targets[902], 0x63F0D70)   # __stack_chk_fail
        self.assertEqual(targets[925], 0x4474D2)    # length_error literal
        self.assertEqual(targets[930], 0x63F0DE0)   # __throw_length_error

    def test_live_engine_check(self):
        crc_ok, rt_decomp, rt_raw, rt_rec = m.live_engine_check()
        self.assertTrue(crc_ok)
        self.assertTrue(rt_decomp)
        self.assertTrue(rt_raw)
        self.assertTrue(rt_rec)


if __name__ == "__main__":
    unittest.main()
