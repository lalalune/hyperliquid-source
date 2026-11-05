"""Tests for the node #115 MessagePack string writer model
(tools/msgpack_write_str_cf5d0_115.py, routine 0x57cf5d0,
RE-001)."""
import unittest

from tools.msgpack_write_str_cf5d0_115 import (
    RETURN_PAIR,
    Buffer,
    header_bytes,
    pinned_growth,
    write_str,
)


def run(payload, capacity=0, contents=b""):
    buf = Buffer(capacity=capacity, contents=contents)
    out = write_str(buf, payload, pinned_growth(buf))
    return buf, out


class TestHeaderBytes(unittest.TestCase):
    def test_fixstr_tier(self):
        self.assertEqual(header_bytes(0), b"\xa0")
        self.assertEqual(header_bytes(1), b"\xa1")
        self.assertEqual(header_bytes(0x1F), b"\xbf")

    def test_str8_tier(self):
        self.assertEqual(header_bytes(0x20), b"\xd9\x20")
        self.assertEqual(header_bytes(0xFF), b"\xd9\xff")

    def test_str16_tier(self):
        self.assertEqual(header_bytes(0x100), b"\xda\x01\x00")
        self.assertEqual(header_bytes(0xFFFF), b"\xda\xff\xff")

    def test_str32_tier(self):
        self.assertEqual(header_bytes(0x10000), b"\xdb\x00\x01\x00\x00")
        self.assertEqual(
            header_bytes(0xFFFFFFFF), b"\xdb\xff\xff\xff\xff")

    def test_decision_reads_low_32_bits(self):
        # The header compares are 32-bit (%ebx/%ebp): a length
        # above 2**32 is decided by its low word. The payload
        # step still uses the full length (see the model docstring);
        # only the header function can be exercised at this size.
        self.assertEqual(header_bytes((1 << 32) + 5), b"\xa5")
        self.assertEqual(
            header_bytes((1 << 32) + 0x100), b"\xda\x01\x00")


class TestWriteStr(unittest.TestCase):
    def test_return_pair_is_constant(self):
        _, out = run(b"abc")
        self.assertEqual(out, RETURN_PAIR)
        self.assertEqual(out, (2, 0))

    def test_empty_string_into_empty_buffer(self):
        buf, _ = run(b"")
        self.assertEqual(buf.bytes(), b"\xa0")
        self.assertEqual(buf.length, 1)
        # One growth request: the single header byte, from an
        # empty buffer (additional = 1, at length 0). The empty
        # payload triggers no request and no copy.
        self.assertEqual(buf.grow_requests, [(0, 1)])
        self.assertEqual(buf.capacity, 8)

    def test_short_string_no_payload_growth(self):
        buf, _ = run(b"hello")
        self.assertEqual(buf.bytes(), b"\xa5hello")
        self.assertEqual(buf.grow_requests, [(0, 1)])

    def test_preexisting_contents_are_kept(self):
        buf, _ = run(b"xy", capacity=16, contents=b"PRE")
        self.assertEqual(buf.bytes(), b"PRE\xa2xy")
        self.assertEqual(buf.grow_requests, [])

    def test_full_buffer_grows_for_header_then_payload(self):
        # Capacity exactly full at length 10: the fixstr marker
        # byte needs a 1-byte growth, then the 5 payload bytes
        # fit in the doubled allocation without another request.
        buf, _ = run(b"hello", capacity=10, contents=b"0123456789")
        self.assertEqual(buf.bytes(), b"0123456789\xa5hello")
        self.assertEqual(buf.grow_requests, [(10, 1)])
        self.assertEqual(buf.capacity, 20)

    def test_str8_header_stores_are_separate(self):
        # Length 0x20 enters the str 8 tier: the marker store
        # and the length-byte store are separate 1-byte appends.
        # With an exact-fit growth step (capacity becomes
        # length + additional, nothing more) a full buffer
        # therefore grows twice, once per store.
        def exact_fit(buf):
            def grow(length, additional):
                new_data = bytearray(length + additional)
                new_data[:buf.length] = buf.data[:buf.length]
                buf.data = new_data
                buf.capacity = length + additional

            return grow

        buf = Buffer(capacity=1, contents=b"Q")
        out = write_str(buf, b"z" * 0x20, exact_fit(buf))
        self.assertEqual(out, (2, 0))
        self.assertEqual(buf.grow_requests[:2], [(1, 1), (2, 1)])
        self.assertEqual(buf.bytes()[:3], b"Q\xd9\x20")
        self.assertEqual(buf.bytes()[3:], b"z" * 0x20)

    def test_str16_length_store_grows_by_two(self):
        # Fill the buffer so exactly one byte is free after the
        # marker: the 2-byte big-endian length store must grow
        # with additional = 2, not 1.
        payload = b"a" * 0x100
        buf = Buffer(capacity=4, contents=b"xyz")
        write_str(buf, payload, pinned_growth(buf))
        self.assertEqual(buf.bytes()[:6], b"xyz\xda\x01\x00")
        self.assertIn((4, 2), buf.grow_requests)

    def test_str32_length_store_grows_by_four(self):
        payload = b"b" * 0x10000
        buf = Buffer(capacity=2, contents=b"")
        write_str(buf, payload, pinned_growth(buf))
        self.assertEqual(buf.bytes()[:5], b"\xdb\x00\x01\x00\x00")
        self.assertEqual(buf.bytes()[5:], payload)
        self.assertIn((1, 4), buf.grow_requests)

    def test_payload_grows_by_full_length(self):
        # The payload capacity decision asks for the whole
        # string length as the additional count, one request.
        payload = bytes(range(256)) * 2
        buf = Buffer(capacity=8, contents=b"")
        write_str(buf, payload, pinned_growth(buf))
        self.assertEqual(buf.bytes(), b"\xda\x02\x00" + payload)
        payload_requests = [r for r in buf.grow_requests
                            if r[1] == len(payload)]
        self.assertEqual(len(payload_requests), 1)

    def test_tier_boundaries_end_to_end(self):
        for n, header in ((0x1F, b"\xbf"), (0x20, b"\xd9\x20"),
                          (0xFF, b"\xd9\xff"),
                          (0x100, b"\xda\x01\x00"),
                          (0xFFFF, b"\xda\xff\xff")):
            buf, _ = run(b"s" * n)
            self.assertEqual(buf.bytes(), header + b"s" * n)

    def test_existing_bytes_beyond_length_are_not_output(self):
        buf = Buffer(capacity=8, contents=b"ab")
        buf.data[2:8] = b"ZZZZZZ"
        write_str(buf, b"c", pinned_growth(buf))
        self.assertEqual(buf.bytes(), b"ab\xa1c")
        self.assertEqual(buf.length, 4)


if __name__ == "__main__":
    unittest.main()
