import json
import unittest

import blake3
import msgpack

from audit import audit_line

LEAF_A = "0x" + "12" * 32
LEAF_B = "0x" + "34" * 32
LEAF_BYTES = b"\xd9\x42" + LEAF_A.encode("ascii")
NESTED = [[3, LEAF_A], [128, [[0, LEAF_B]]]]
NESTED_BYTES = (
    b"\x92\x92\x03" + LEAF_BYTES
    + b"\x92\xcc\x80\x91\x92\x00\xd9\x42" + LEAF_B.encode("ascii")
)


def line(tree, digest):
    return json.dumps({"height": 42, "abci_digest": digest, "exchange_abci_hash": tree})


def root(preimage):
    return "0x" + blake3.blake3(preimage).hexdigest()


class TreeAudit(unittest.TestCase):
    def test_leaf_and_nested_forms_match_independent_preimages(self):
        for value, preimage in [(LEAF_A, LEAF_BYTES), (NESTED, NESTED_BYTES)]:
            self.assertEqual(msgpack.packb(value, use_bin_type=True), preimage)
            comparison = audit_line(line(value, root(preimage)))
            self.assertTrue(comparison.matches)
            self.assertEqual(comparison.height, 42)

    def test_row_order_and_digest_kind_remain_observable(self):
        self.assertFalse(audit_line(line(NESTED[::-1], root(NESTED_BYTES))).matches)
        self.assertFalse(audit_line(line(NESTED, LEAF_A)).matches)

    def test_unsupported_tree_and_invalid_digest_are_errors(self):
        for invalid in ([[0]], [[True, LEAF_A]], [[-1, LEAF_A]], {"leaf": LEAF_A}):
            with self.assertRaisesRegex(ValueError, "tree row|digest string"):
                audit_line(line(invalid, root(LEAF_BYTES)))
        with self.assertRaisesRegex(ValueError, "digest string"):
            audit_line(line(NESTED, "0x00"))


if __name__ == "__main__":
    unittest.main()
