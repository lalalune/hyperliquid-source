import hashlib
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import rmp_vec_writers_115 as tool  # noqa: E402


class RmpVecWriterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.new_image()

    def both(self, spec):
        expected, got, spec, seen = tool.compare(spec, self.image)
        self.assertEqual(expected, got, tool.spec_text(spec))
        return got, seen

    @staticmethod
    def spec(fn, arg, cap=0, length=0, fail=(), data=b""):
        return {"fn": fn, "cap": cap, "len": length, "fail_at": fail, "arg": arg, "data": data}

    def body_digest(self, expected_bytes):
        return hashlib.sha256(expected_bytes).hexdigest()[:16]

    def test_binary_digest(self):
        self.assertEqual(hashlib.sha256(tool.BINARY.read_bytes()).hexdigest(), tool.SHA256)

    def test_map_len_known_answers(self):
        # MessagePack: fixmap 0x80|n, map16 0xde + be16, map32 0xdf + be32.
        for n, wire in [(0, b"\x80"), (3, b"\x83"), (15, b"\x8f"), (16, b"\xde\x00\x10"),
                        (0xffff, b"\xde\xff\xff"), (0x10000, b"\xdf\x00\x01\x00\x00"),
                        (0xffffffff, b"\xdf\xff\xff\xff\xff")]:
            got, _ = self.both(self.spec("map_len", (n,)))
            self.assertEqual(got[4], len(wire))
            self.assertEqual(got[5], self.body_digest(wire), n)

    def test_uint_known_answers(self):
        for v, wire in [(0, b"\x00"), (0x7f, b"\x7f"), (0x80, b"\xcc\x80"), (0xff, b"\xcc\xff"),
                        (0x100, b"\xcd\x01\x00"), (0xffff, b"\xcd\xff\xff"),
                        (0x10000, b"\xce\x00\x01\x00\x00"), (0xffffffff, b"\xce\xff\xff\xff\xff"),
                        (0x100000000, b"\xcf\x00\x00\x00\x01\x00\x00\x00\x00"),
                        (tool.M64, b"\xcf" + b"\xff" * 8)]:
            got, _ = self.both(self.spec("uint", (v,)))
            self.assertEqual(got[5], self.body_digest(wire), hex(v))

    def test_str_known_answers(self):
        for n in (0, 5, 31, 32, 255, 256, 65535, 65536):
            data = bytes((i * 31 + 7) & 0xff for i in range(n))
            if n < 32:
                head = bytes([0xa0 | n])
            elif n < 256:
                head = bytes([0xd9, n])
            elif n < 65536:
                head = b"\xda" + n.to_bytes(2, "big")
            else:
                head = b"\xdb" + n.to_bytes(4, "big")
            got, _ = self.both(self.spec("str", (n,), data=data))
            self.assertEqual(got[1], (2, 0))
            self.assertEqual(got[5], self.body_digest(head + data), n)

    def test_str_length_above_32_bits_is_classified_by_low_word(self):
        # Length 2**32 + 5 is classified as a fixstr by its low 32 bits; the copy then wants 4 GiB,
        # which the stub allocator refuses: the data write fails with tag 1 after the marker landed.
        got, _ = self.both(self.spec("str", (0x1_0000_0005,), cap=8, length=0))
        self.assertEqual(got[1], (1, tool.ERR))
        self.assertEqual(got[4], 1)

    def test_marker_failure_and_success_words(self):
        got, _ = self.both(self.spec("marker", (0xcc, 0), cap=0, length=0, fail=(0,)))
        self.assertEqual(got[1], (tool.ERR,))
        got, _ = self.both(self.spec("marker", (0xcc, 0), cap=0, length=0))
        self.assertEqual(got[1], (0,))

    def test_marker_payload_folding(self):
        for marker, payload, byte in [(0x00, 0x7a, 0x7a), (0x01, 0xff, 0x8f), (0x90, 0xff, 0x9f),
                                      (0xa0, 0xff, 0xbf), (0xc0, 0x55, 0xc0), (0xe0, 0x66, 0x66),
                                      (0xa1, 0x12, 0x12)]:
            got, _ = self.both(self.spec("marker", (marker, payload)))
            self.assertEqual(got[5], self.body_digest(bytes([byte])), hex(marker))

    def test_reserve_error_calls(self):
        got, _ = self.both(self.spec("reserve", (3, 1, 1, 0), cap=4, length=3))
        self.assertEqual(got[0], "halt")
        self.assertEqual(got[7][-1], ("handle_error", 0, 3))
        got, _ = self.both(self.spec("reserve", (3, tool.M64, 1, 1), cap=4, length=3))
        self.assertEqual(got[7][-1], ("handle_error", 0, 3))

    def test_reserve_growth_floor_by_element_size(self):
        for elem, floor in [(1, 8), (2, 4), (1024, 4), (1025, 1)]:
            got, _ = self.both(self.spec("reserve", (0, 1, 1, elem), cap=0, length=0))
            self.assertEqual(got[2], floor, elem)

    def test_finish_grow_layout_limit(self):
        spec = tool.fix_spec({"fn": "finish_grow", "cap": 0, "len": 0, "fail_at": (), "fix_ptr": True,
                              "arg": (0, 0, 1 << 63, 1, 1)})
        got, _ = self.both(spec)
        self.assertEqual(got[6][:16], "0100000000000000")  # tag 1 = layout error, no allocator call
        self.assertEqual(got[7], ())

    def test_grow_one32_doubles_with_minimum_four(self):
        for cap, new in [(0, 4), (1, 4), (2, 4), (3, 6), (10, 20)]:
            got, _ = self.both(self.spec("grow_one32", (), cap=cap, length=cap))
            self.assertEqual(got[2], new, cap)

    def test_probe_set_has_no_false_positive(self):
        self.assertFalse(tool.detects(self.image))

    def test_model_mutations_are_detected(self):
        for name, value in tool.MODEL_MUTATIONS[:12]:
            self.assertTrue(tool.detects(self.image, (name, value)), name)

    def test_binary_corruptions_are_detected(self):
        rows = tool.binary_patches(self.image)
        for label, va, off, value in rows[:10]:
            self.assertTrue(tool.detects(tool.new_image([(off, value)])), label)

    def test_out_of_range_patch_offset_does_not_pass_silently(self):
        with self.assertRaises(IndexError):
            tool.new_image([(10 ** 12, 1)])

    def test_unexecuted_code_is_only_reserve_fallback_pads(self):
        executed = set()
        for spec in tool.probe_specs():
            _, _, _, seen = tool.compare(spec, self.image)
            executed.update(seen)
        rows = {name: runs for name, _, _, _, _, runs in tool.coverage_rows(self.image, executed)}
        for name in ("finish_grow", "reserve", "grow_one32"):
            self.assertEqual(rows[name], [], name)
        for name in ("marker", "map_len", "uint", "str"):
            self.assertTrue(rows[name], name)
            for run in rows[name]:
                self.assertEqual(run[2], "reserve-pad", (name, run))

    def test_case_generation_is_deterministic(self):
        first = [tool.spec_text(s) for _, s in zip(range(300), tool.gen_cases())]
        second = [tool.spec_text(s) for _, s in zip(range(300), tool.gen_cases())]
        self.assertEqual(first, second)

    def test_wrong_model_constant_makes_a_case_fail(self):
        spec = self.spec("uint", (0x100,))
        saved = tool.K["uint16"]
        try:
            tool.K["uint16"] = 0xce
            expected, got, _, _ = tool.compare(spec, self.image)
            self.assertNotEqual(expected, got)
        finally:
            tool.K["uint16"] = saved


def decode_header(blob):
    """Independent MessagePack reader for the three kinds the writers emit.

    Returns (kind, value, consumed): ('uint', v), ('map', n) or ('str', bytes).
    """
    head = blob[0]
    if head < 0x80:
        return "uint", head, 1
    if 0x80 <= head <= 0x8f:
        return "map", head & 0xf, 1
    if 0xa0 <= head <= 0xbf:
        n = head & 0x1f
        return "str", blob[1:1 + n], 1 + n
    widths = {0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8}
    if head in widths:
        w = widths[head]
        return "uint", int.from_bytes(blob[1:1 + w], "big"), 1 + w
    if head in (0xde, 0xdf):
        w = 2 if head == 0xde else 4
        return "map", int.from_bytes(blob[1:1 + w], "big"), 1 + w
    if head in (0xd9, 0xda, 0xdb):
        w = {0xd9: 1, 0xda: 2, 0xdb: 4}[head]
        n = int.from_bytes(blob[1:1 + w], "big")
        return "str", blob[1 + w:1 + w + n], 1 + w + n
    raise ValueError(hex(head))


class RoundTripTests(unittest.TestCase):
    """The bytes the real code appends must decode, with an independent reader, to the input."""

    @classmethod
    def setUpClass(cls):
        cls.image = tool.new_image()

    def append(self, fn, arg, cap, length, data=b"", image=None):
        spec = {"fn": fn, "cap": cap, "len": length, "fail_at": (), "arg": arg, "data": data}
        blob = tool.machine_bytes(spec, image or self.image)
        prefix = bytes((i * 7 + 3) & 0xff for i in range(length))
        self.assertEqual(blob[:length], prefix)
        return blob[length:]

    def test_uint_round_trip_over_growth_states(self):
        rng = tool.Lcg(99)
        for _ in range(120):
            value = rng.next(1 << (1 + rng.next(64)))
            cap = rng.next(20)
            length = rng.next(cap + 1)
            tail = self.append("uint", (value,), cap, length)
            self.assertEqual(decode_header(tail), ("uint", value, len(tail)), hex(value))

    def test_map_len_round_trip(self):
        rng = tool.Lcg(98)
        for _ in range(120):
            n = rng.next(1 << (1 + rng.next(32)))
            cap = rng.next(20)
            length = rng.next(cap + 1)
            tail = self.append("map_len", (n,), cap, length)
            self.assertEqual(decode_header(tail), ("map", n, len(tail)), hex(n))

    def test_str_round_trip(self):
        rng = tool.Lcg(97)
        for _ in range(80):
            n = rng.next(1 + rng.next(70000 if rng.next(10) == 0 else 400))
            cap = rng.next(20)
            length = rng.next(cap + 1)
            data = bytes((i * 13 + 1) & 0xff for i in range(n))
            tail = self.append("str", (n,), cap, length, data)
            self.assertEqual(decode_header(tail), ("str", data, len(tail)), n)

    def test_two_outputs_form_a_decodable_stream(self):
        stream = self.append("uint", (0x1234,), 0, 0) + self.append("map_len", (300,), 0, 0)
        kind, value, used = decode_header(stream)
        self.assertEqual((kind, value), ("uint", 0x1234))
        self.assertEqual(decode_header(stream[used:])[:2], ("map", 300))

    def test_decoder_rejects_unknown_marker(self):
        with self.assertRaises(ValueError):
            decode_header(b"\xc1")

    def test_corrupted_binary_breaks_round_trip(self):
        off = self.image.file_offset(0x4778a48) + 3
        broken = tool.new_image([(off, 0xcc)])
        tail = self.append("uint", (0x1234,), 0, 0, image=broken)
        self.assertNotEqual(decode_header(tail)[:2], ("uint", 0x1234))


if __name__ == "__main__":
    unittest.main()
