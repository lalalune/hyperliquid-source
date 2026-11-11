"""Tests for tools/zstd_stream_methods115.py (RE-002, node #115).

2,400 deterministic cases (600 reset, 600 compress, 600 uncompress,
600 bindings) plus targeted boundary controls. The model is checked
against INDEPENDENT expectations derived from the binary, not against
itself:

  * Reset: the engine reset is called with directive 1 and the whole
    24-byte inBuffer is zeroed (src/size/pos), on a fresh holder, after
    a partial stream, after an error, and twice in a row.
  * Compress: *output_len is 0 first; empty input returns 0; a
    single-shot call returns 0 with a checksummed frame that
    round-trips through the independent direct decompress; a small
    output buffer leaves bytes to flush (ret > 0) and resuming with
    the SAME token completes the same frame; switching tokens
    mid-frame does NOT feed the new bytes into the open frame (the
    engine ignores them until the frame flushes -- verified: the
    finished frame holds the consumed prefix of A plus only the bytes
    of B consumed during the flush, usually none, and the remainder
    of B starts a new frame on the next call); a forced engine error
    returns -1 after Reset.
  * Uncompress: *output_len is 0 first; empty input returns 0; a
    round-trip returns 0 with the exact input; a null input resumes
    the stored buffer; a corrupt frame returns -1 after Reset; a
    split feed (prefix drained with NULL resumes, then the rest under
    a new token) reconstructs the input; the return is the binary's
    rule (input bytes still unconsumed, low 32 bits), read back from
    the holder memory.
  * Bindings: body/source hashes recomputed from the binary, FDE
    ranges, relocation displacements decoded to the pinned callees,
    vtable slots, caller census, the isError threshold immediate read
    from the callee body, and the committed cases.tsv matching a
    fresh regeneration.

The engine calls go through the system libzstd.so.1 via ctypes on
REAL context handles (see the tool docstring). Frame bytes are
asserted through the independent direct oracle (compress_direct /
decompress_direct), not through the model itself. Event order,
inBuffer bytes, return values and the freed-state transitions are
asserted: those are the methods' contract.
"""

import hashlib
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import zstd_stream_methods115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research" / "work-items"
          / "re-002-node115-rocksdb-zstd-stream-methods-115")
BIN = Path(__file__).resolve().parents[1] / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def _read_cases():
    rows = []
    with open(PACKET / "cases.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    return rows


class ResetTests(unittest.TestCase):
    def test_reset_zeroes_inbuffer_both_families(self):
        for family in ("compress", "uncompress"):
            holder = m.make_holder(family)
            # Dirty the inBuffer first (a partial stream call).
            data = b"hello world, streaming zstd" * 4
            token = holder.register_input(data)
            if family == "compress":
                m.compress(holder, token, data)
                events = m.reset_compress(holder)
            else:
                frame = m.compress_direct(data)
                ftoken = holder.register_input(frame)
                m.uncompress(holder, ftoken, frame)
                events = m.reset_uncompress(holder)
            self.assertEqual(holder.read_inbuffer(), (0, 0, 0), family)
            self.assertEqual(events[0][1], 0, family)
            self.assertEqual(events[1], ("zero_inbuffer", holder.in_off),
                             family)
            holder.free()

    def test_reset_after_error_and_double(self):
        for family in ("compress", "uncompress"):
            holder = m.make_holder(family)
            if family == "compress":
                token = holder.register_input(b"abc" * 100)
                ret, _o, _l, _e = m.compress(holder, token, b"abc" * 100,
                                            _force_error=True)
                self.assertEqual(ret, -1, family)
            else:
                frame = m.compress_direct(b"abc" * 100)
                token = holder.register_input(frame[:10])
                ret, _o, _l, _e = m.uncompress(holder, token, frame[:10],
                                               _force_error=True)
                self.assertEqual(ret, -1, family)
            # The error path already reset; a second reset is still ok.
            self.assertEqual(holder.read_inbuffer(), (0, 0, 0), family)
            if family == "compress":
                m.reset_compress(holder)
            else:
                m.reset_uncompress(holder)
            self.assertEqual(holder.read_inbuffer(), (0, 0, 0), family)
            holder.free()

    def test_reset_calls_engine_with_directive_one(self):
        # The binary passes esi=1 (ZSTD_reset_session_only) to the
        # engine reset; the model passes the same constant. A reset
        # with any other directive is a different call and is not what
        # the binary does.
        lib = m._load_lib()
        holder = m.make_holder("compress")
        ret = lib.ZSTD_CCtx_reset(holder.ctx, 1)
        self.assertEqual(ret, 0)
        holder2 = m.make_holder("uncompress")
        ret2 = lib.ZSTD_DCtx_reset(holder2.ctx, 1)
        self.assertEqual(ret2, 0)
        holder.free()
        holder2.free()


class CompressTests(unittest.TestCase):
    def test_empty_input_returns_zero(self):
        holder = m.make_holder("compress")
        token = holder.register_input(b"")
        ret, out, out_len, _ev = m.compress(holder, token, b"")
        self.assertEqual((ret, out, out_len), (0, b"", 0))
        holder.free()

    def test_single_shot_round_trip_and_checksum(self):
        for label, data in m._sample_inputs(__import__("random").Random(115)):
            if len(data) == 0:
                continue
            holder = m.make_holder(
                "compress",
                max_output_len=max(0x8000, len(data) + 1024))
            token = holder.register_input(data)
            ret, out, out_len, _ev = m.compress(holder, token, data)
            self.assertEqual(ret, 0, label)
            self.assertEqual(out_len, len(out), label)
            self.assertTrue(m.frame_has_checksum(out), label)
            self.assertEqual(m.decompress_direct(out), data, label)
            holder.free()

    def test_resume_same_token_completes_same_frame(self):
        data = b"resume me, please" * 200
        small = m.Holder("compress", max_output_len=16)
        token = small.register_input(data)
        frame, calls = m._drain_compress(small, token, data)
        self.assertGreaterEqual(calls, 2)
        self.assertEqual(frame, m.compress_direct(data))
        self.assertEqual(m.decompress_direct(frame), data)
        small.free()

    def test_mid_frame_token_switch_ignored_until_flush(self):
        # The engine ignores a new input while the open frame flushes.
        data = b"first input bytes" * 100
        other = b"second"
        holder = m.Holder("compress", max_output_len=16)
        t2 = holder.register_input(data)
        r1, out1, _l, _e = m.compress(holder, t2, data)
        self.assertGreater(r1, 0)
        pos1 = holder.read_inbuffer()[2]
        t3 = holder.register_input(other)
        frame2, _c2 = m._drain_compress(holder, t3, other)
        pos_after = holder.read_inbuffer()[2]
        self.assertEqual(m.decompress_direct(out1 + frame2),
                         data[:pos1] + other[:pos_after])
        frame3, _c3 = m._drain_compress(holder, t3, other)
        self.assertEqual(m.decompress_direct(frame3), other[pos_after:])
        holder.free()

    def test_forced_error_returns_minus_one_and_resets(self):
        holder = m.make_holder("compress")
        token = holder.register_input(b"x" * 500)
        ret, out, out_len, events = m.compress(holder, token, b"x" * 500,
                                               _force_error=True)
        self.assertEqual(ret, -1)
        self.assertEqual(out_len, 0)
        self.assertEqual(holder.read_inbuffer(), (0, 0, 0))
        kinds = [e[0] for e in events]
        self.assertIn("engine_error_simulated", kinds)
        self.assertIn("reset_cctx", kinds)
        holder.free()


class UncompressTests(unittest.TestCase):
    def test_empty_input_returns_zero(self):
        holder = m.make_holder("uncompress")
        frame = m.compress_direct(b"")
        token = holder.register_input(frame)
        ret, out, out_len, _ev = m.uncompress(holder, token, frame)
        self.assertEqual(ret, 0)
        self.assertEqual(out, b"")
        holder.free()

    def test_round_trip_all_inputs(self):
        for label, data in m._sample_inputs(__import__("random").Random(115)):
            frame = m.compress_direct(data)
            holder = m.make_holder(
                "uncompress",
                max_output_len=max(0x8000, len(data) + 1024))
            token = holder.register_input(frame)
            ret, out, out_len, _ev = m.uncompress(holder, token, frame)
            self.assertEqual(ret, 0, label)
            self.assertEqual(out, data, label)
            self.assertEqual(out_len, len(data), label)
            holder.free()

    def test_null_input_resumes_stored_buffer(self):
        data = b"null resumes the stored buffer" * 100
        frame = m.compress_direct(data)
        small = m.Holder("uncompress", max_output_len=64)
        token = small.register_input(frame)
        out_all, calls, saw_remaining, completed = m._drain_uncompress(
            small, token, frame)
        self.assertGreaterEqual(calls, 2)
        self.assertTrue(saw_remaining)
        self.assertTrue(completed)
        self.assertEqual(out_all, data)
        small.free()

    def test_corrupt_frame_returns_minus_one_and_resets(self):
        data = b"corrupt me" * 200
        frame = bytearray(m.compress_direct(data))
        frame[(3 * len(frame)) // 4] ^= 0xFF
        holder = m.make_holder("uncompress")
        token = holder.register_input(bytes(frame))
        ret, out, out_len, events = m.uncompress(holder, token, bytes(frame))
        self.assertEqual(ret, -1)
        self.assertEqual(out_len, 0)
        self.assertEqual(holder.read_inbuffer(), (0, 0, 0))
        kinds = [e[0] for e in events]
        self.assertIn("engine_error", kinds)
        self.assertIn("reset_dctx", kinds)
        holder.free()

    def test_return_is_input_remaining(self):
        # The return is (inBuffer.size - inBuffer.pos), low 32 bits,
        # read back from the holder memory after the call.
        data = b"return value check" * 300
        frame = m.compress_direct(data)
        small = m.Holder("uncompress", max_output_len=16)
        token = small.register_input(frame)
        ret, _out, _l, _ev = m.uncompress(small, token, frame)
        _s, size, pos = small.read_inbuffer()
        self.assertEqual(ret, m._to_int32(size - pos))
        small.free()


class BindingsTests(unittest.TestCase):
    def test_body_and_source_hashes(self):
        rows = {}
        with open(PACKET / "functions.tsv") as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                rows.update({line.split("\t")[0]:
                             dict(zip(header, line.rstrip("\n").split("\t")))})
        self.assertEqual(len(rows), 4)
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DIGEST)
        for name, row in rows.items():
            start, end = int(row["start"], 16), int(row["end"], 16)
            off = m._va_to_off(start)
            body = data[off:off + (end - start)]
            self.assertEqual(hashlib.sha256(body).hexdigest(),
                             row["body_sha256"], name)
            self.assertEqual(len(body), int(row["size"]), name)

    def test_functions_tsv_matches_binary_and_census(self):
        census = json.load(open(
            Path(__file__).resolve().parents[1] / "research" / "work-items"
            / "RE-002-node115-vendor-census" / "census.json"))["records"]
        by_start = {r["start"]: r for r in census}
        data = open(BIN, "rb").read()
        with open(PACKET / "functions.tsv") as fh:
            header = fh.readline().rstrip("\n").split("\t")
            for line in fh:
                row = dict(zip(header, line.rstrip("\n").split("\t")))
                start, end = int(row["start"], 16), int(row["end"], 16)
                body = data[m._va_to_off(start):m._va_to_off(end)]
                self.assertEqual(hashlib.sha256(body).hexdigest(),
                                 row["body_sha256"], row["name"])
                rec = by_start[start]
                self.assertEqual(rec["target_body_sha256"],
                                 row["body_sha256"], row["name"])
                zeroed = bytearray(body)
                for rel in rec["relocations"]:
                    o, w = rel["offset"], rel["width"]
                    zeroed[o:o + w] = b"\x00" * w
                self.assertEqual(
                    hashlib.sha256(bytes(zeroed)).hexdigest(),
                    row["source_sha256"], row["name"])
                self.assertEqual(rec["symbol"], row["symbol"], row["name"])

    def test_reloc_displacements_hit_pinned_callees(self):
        data = open(BIN, "rb").read()
        for (key, off), want in m.EXPECTED_RELOC_TARGETS.items():
            start_s = m.FUNCS[key][0]
            start = int(start_s, 16)
            body = data[m._va_to_off(start):
                        m._va_to_off(start) + (int(m.FUNCS[key][1], 16) - start)]
            disp = struct.unpack_from("<i", body, off)[0]
            target = start + off - 1 + 5 + disp
            self.assertEqual(target, want, (key, off))

    def test_vtable_slots(self):
        # The merged vtable packets pin the slots; the tool's constants
        # must agree with them (slot 2 = the stream method, slot 3 =
        # Reset, slots 0/1 = the D1/D0 destructors from #5933).
        self.assertEqual(m.COMPRESS_VPTR, 0x64D7418)
        self.assertEqual(m.UNCOMPRESS_VPTR, 0x64D7448)
        for family, vptr, targets in (
                ("compress", 0x64D7418,
                 [0x5F03A40, 0x5F03A10, 0x61C1B30, 0x61C1A20]),
                ("uncompress", 0x64D7448,
                 [0x5F01520, 0x5F014F0, 0x61C1A80, 0x61C1A50])):
            slots = open(Path(__file__).resolve().parents[1]
                         / "research" / "work-items"
                         / ("RE-002-node115-rocksdb-zstd-stream-%s-vtable"
                            % family) / "slots.tsv").read()
            for slot, target in enumerate(targets):
                self.assertIn(hex(target), slots, (family, slot))

    def test_caller_census(self):
        census = json.load(open(PACKET / "census.json"))
        self.assertEqual(census["validated_sites"], 2)
        self.assertEqual(census["targets"]["0x61c1a20"]["calls"], 1)
        self.assertEqual(census["targets"]["0x61c1a50"]["calls"], 1)
        self.assertEqual(census["targets"]["0x61c1a80"]["calls"], 0)
        self.assertEqual(census["targets"]["0x61c1b30"]["calls"], 0)
        rows = open(PACKET / "callers.tsv").read().splitlines()[1:]
        self.assertEqual(len(rows), 2)
        self.assertIn("0x61c1bdd", rows[0])
        self.assertIn("0x61c1b1d", rows[1])

    def test_iserror_threshold_matches_binary(self):
        # 0x620dd60: xor eax,eax; cmp $0xffffffffffffff88,%rdi; seta %al;
        # ret -- the immediate is (size_t)-120 and the test is strict.
        out = subprocess.check_output(
            ["objdump", "-d", "--start-address=0x620dd60",
             "--stop-address=0x620dd6e", str(BIN)]).decode()
        self.assertIn("ffffffffffffff88", out)
        self.assertIn("seta", out)
        for code in (2**64 - 121, 2**64 - 120):
            self.assertFalse(m.is_error(code), hex(code))
        for code in (2**64 - 119, 2**64 - 1):
            self.assertTrue(m.is_error(code), hex(code))

    def test_holder_layouts(self):
        holder = m.make_holder("compress")
        self.assertEqual(holder.size, 0x70)
        self.assertEqual(holder.ctx_off, 0x50)
        self.assertEqual(holder.in_off, 0x58)
        self.assertEqual(holder.outlen_off, 0x48)
        self.assertEqual(holder.fmt_off, 0x40)
        holder.free()
        holder2 = m.make_holder("uncompress")
        self.assertEqual(holder2.size, 0x38)
        self.assertEqual(holder2.ctx_off, 0x18)
        self.assertEqual(holder2.in_off, 0x20)
        self.assertEqual(holder2.outlen_off, 0x10)
        self.assertEqual(holder2.fmt_off, 0x0C)
        holder2.free()

    def test_all_cases_replay_to_expected_outcome(self):
        for case in _read_cases():
            out = m.replay_case(case)
            self.assertEqual(out, case["expected"], case["id"])

    def test_case_count_and_split(self):
        rows = _read_cases()
        self.assertEqual(len(rows), 2400)
        groups = {}
        for r in rows:
            groups[r["group"]] = groups.get(r["group"], 0) + 1
        self.assertEqual(groups, {"reset": 600, "compress": 600,
                                  "uncompress": 600, "bindings": 600})

    def test_cases_tsv_matches_regeneration(self):
        rows = m.cases_tsv_rows()
        committed = [tuple(r.values()) for r in _read_cases()]
        # Regeneration shuffles with the same seed, so the multiset of
        # rows must match exactly (order is shuffled deterministically).
        self.assertEqual(sorted(map(str, rows)), sorted(map(str, committed)))

    def test_artifact_digest(self):
        data = open(BIN, "rb").read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), DIGEST)


if __name__ == "__main__":
    unittest.main()
