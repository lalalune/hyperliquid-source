"""Tests for the node #115 Ip variant JSON writer model
(tools/ip_variant_json_2ff40_115.py, routine 0x5a2ff40, RE-001)."""
import unittest

from tools.ip_variant_json_2ff40_115 import Buffer, write_ip_variant


def writer_returning(payload, status=0):
    def write(value, ctx):
        if payload:
            ctx[0].append_bytes(payload)
        return status

    return write


class TestIpVariantJson(unittest.TestCase):
    def test_framing_with_room(self):
        buf = Buffer(capacity=64)
        status = write_ip_variant(None, [buf], writer_returning(b'"10.0.0.1"'))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'{"Ip":"10.0.0.1"}')
        self.assertEqual(buf.grow_calls, [])

    def test_empty_payload(self):
        buf = Buffer(capacity=64)
        status = write_ip_variant(None, [buf], writer_returning(b""))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'{"Ip":}')

    def test_key_goes_through_append_helper(self):
        buf = Buffer(capacity=64)
        write_ip_variant(None, [buf], writer_returning(b"X"))
        self.assertEqual(buf.append_log[0], b"Ip")

    def test_zero_capacity_grows_five_times(self):
        # One pinned grow call per inline append point, in order:
        # '{', '"', '"', ':', '}'. The key append is the helper's
        # own business and is not a grow call.
        buf = Buffer(capacity=0)
        status = write_ip_variant(None, [buf], writer_returning(b""))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'{"Ip":}')
        self.assertEqual(buf.grow_calls, [(1, 1, 1)] * 5)

    def test_prefilled_buffer_single_closing_grow(self):
        # "[" plus the 8-byte object exactly fills capacity 8 after
        # the payload, so only the closing brace grows.
        buf = Buffer(capacity=8, initial=b"[")
        status = write_ip_variant(None, [buf], writer_returning(b"1"))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'[{"Ip":1}')
        self.assertEqual(buf.grow_calls, [(1, 1, 1)])

    def test_full_buffer_grows_before_open_brace(self):
        buf = Buffer(capacity=2, initial=b"ab")
        status = write_ip_variant(None, [buf], writer_returning(b""))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'ab{"Ip":}')
        self.assertEqual(buf.grow_calls[0], (1, 1, 1))

    def test_payload_failure_propagates_without_closing_brace(self):
        buf = Buffer(capacity=64)
        status = write_ip_variant(None, [buf], writer_returning(b'"10.', 7))
        self.assertEqual(status, 7)
        self.assertEqual(buf.bytes(), b'{"Ip":"10.')

    def test_failure_status_returned_verbatim(self):
        buf = Buffer(capacity=64)
        status = write_ip_variant(None, [buf], writer_returning(b"", 0xDEAD))
        self.assertEqual(status, 0xDEAD)
        self.assertEqual(buf.bytes(), b'{"Ip":')

    def test_longer_payload_with_room(self):
        buf = Buffer(capacity=16)
        status = write_ip_variant(None, [buf], writer_returning(b"12345678"))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'{"Ip":12345678}')
        self.assertEqual(buf.grow_calls, [])

    def test_closing_grow_triggered_at_exact_capacity(self):
        # Prefix {"Ip": is 6 bytes. Capacity 14 with an 8-byte
        # payload leaves length == capacity before '}'.
        buf = Buffer(capacity=14)
        status = write_ip_variant(None, [buf], writer_returning(b"12345678"))
        self.assertEqual(status, 0)
        self.assertEqual(buf.bytes(), b'{"Ip":12345678}')
        self.assertEqual(buf.grow_calls, [(1, 1, 1)])

    def test_value_forwarded_untouched(self):
        seen = []

        def write(value, ctx):
            seen.append(value)
            return 0

        marker = object()
        buf = Buffer(capacity=64)
        write_ip_variant(marker, [buf], write)
        self.assertEqual(seen, [marker])

    def test_capacity_below_initial_rejected(self):
        with self.assertRaises(ValueError):
            Buffer(capacity=1, initial=b"ab")


if __name__ == "__main__":
    unittest.main()
