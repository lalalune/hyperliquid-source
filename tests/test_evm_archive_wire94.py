"""Static controls for the authenticated node 94 archive serializer evidence."""

from contextlib import contextmanager
import itertools
import mmap
import unittest

from tools import evm_archive_wire94 as archive


class ArchiveWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.handle = archive.BINARY.open("rb")
        cls.data = mmap.mmap(cls.handle.fileno(), 0, access=mmap.ACCESS_COPY)
        cls.image = archive.Image(cls.data)
        (cls.schema, cls.functions, cls.anchors, cls.calls,
         cls.branches, cls.cases) = archive.facts(cls.image)

    @classmethod
    def tearDownClass(cls):
        cls.data.close()
        cls.handle.close()

    @contextmanager
    def altered(self, va, byte_xor=1):
        off = self.image.offset(va)
        original = self.data[off]
        self.data[off] = original ^ byte_xor
        try:
            yield
        finally:
            self.data[off] = original

    def test_identity_is_checked_before_parsing(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            archive.Image(self.data, expected_digest="0" * 64)
        with self.altered(0x45a1200):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                archive.Image(self.data)

    def test_fde_and_body_corruption_are_rejected_independently(self):
        start = 0x45a1200
        with self.altered(start + 9):
            with self.assertRaisesRegex(ValueError, "body digest"):
                self.image.check_function(start)
        old = self.image.fdes[start]
        self.image.fdes[start] = dict(old, end=old["end"] + 1)
        try:
            with self.assertRaisesRegex(ValueError, "FDE extent"):
                self.image.check_function(start)
        finally:
            self.image.fdes[start] = old
        self.assertEqual(len(self.functions), len(archive.FUNCTIONS))
        self.assertEqual(len({row["fde"] for row in self.functions}), len(self.functions))

    def test_unmapped_cross_section_and_nobits_are_rejected(self):
        with self.assertRaises(ValueError):
            self.image.offset(-1)
        with self.assertRaises(ValueError):
            self.image.offset(0xffffffffffffffff)
        with self.assertRaises(ValueError):
            self.image.offset(0, 0)
        text = next(s for s in self.image.sections if s["name"] == ".text")
        with self.assertRaises(ValueError):
            self.image.offset(text["address"] + text["size"] - 1, 2, executable=True)
        bss = next(s for s in self.image.sections if s["name"] == ".bss")
        self.assertEqual(bss["type"], 8)
        with self.assertRaises(ValueError):
            self.image.offset(bss["address"])

    def test_fixed_call_and_branch_targets_reject_changes(self):
        extract = archive.Extract(self.image)
        with self.altered(0x459c5a4):
            with self.assertRaises(ValueError):
                extract.call(0x459c5a4, 0x45a1200, "test")
        with self.altered(0x459c5a5):
            with self.assertRaises(ValueError):
                extract.call(0x459c5a4, 0x45a1200, "test")
        with self.altered(0x47afac7):
            with self.assertRaises(ValueError):
                extract.call(0x47afac6, 0x4595c30, "test", opcode=0xe9)
        with self.altered(0x45a1499):
            with self.assertRaises(ValueError):
                extract.branch(0x45a1499, 0x45a14dc, "test")
        with self.altered(0x45a149a):
            with self.assertRaises(ValueError):
                extract.branch(0x45a1499, 0x45a14dc, "test")

    def test_outer_names_and_classifier(self):
        names = ["block", "receipts", "system_txs", "read_precompile_calls",
                 "highest_precompile_address"]
        self.assertEqual([row["name"] for row in self.schema["outer_fields"]], names)
        self.assertEqual([row["name"] for row in self.schema["json_shaped_fields"]], names)
        classifier = self.schema["field_classifier"]
        for expected, name in enumerate(names):
            self.assertEqual(archive.classify(classifier, name.encode()), expected)
        for bad in (b"", b"Block", b"block\x00", b"receipt", b"system-txs", b"unknown"):
            self.assertEqual(archive.classify(classifier, bad), 5)
        self.assertEqual(classifier["outer_tag"], 9)

    def test_every_single_byte_key_substitution_is_unknown(self):
        classifier = self.schema["field_classifier"]
        substitutions = 0
        for row in classifier["fields"]:
            key = row["name"].encode("ascii")
            for index, original in enumerate(key):
                for byte in range(256):
                    if byte == original:
                        continue
                    changed = key[:index] + bytes([byte]) + key[index + 1:]
                    self.assertEqual(archive.classify(classifier, changed), 5)
                    substitutions += 1
        self.assertEqual(substitutions, 17850)

    def test_classifier_table_and_vector_overlap_are_checked(self):
        table = int(self.schema["field_classifier"]["table_va"], 16)
        with self.altered(table):
            with self.assertRaisesRegex(ValueError, "table target"):
                archive.selector(self.image, archive.Extract(self.image))
        # This byte is in the overlapping part of the first 21-byte vector.
        with self.altered(0x2064b0 + 8):
            with self.assertRaisesRegex(ValueError, "overlapping"):
                archive.selector(self.image, archive.Extract(self.image))
        with self.altered(0x1e74a85):
            with self.assertRaisesRegex(ValueError, "condition"):
                archive.selector(self.image, archive.Extract(self.image))
        with self.altered(0x1e74a77):
            with self.assertRaisesRegex(ValueError, "equality reduction"):
                archive.selector(self.image, archive.Extract(self.image))
        # A changed name must not silently be relabeled from the classifier.
        with self.altered(0x20a620):
            with self.assertRaisesRegex(ValueError, "writer names"):
                archive.facts(self.image)

    def test_all_selector_bytes_and_noncanonical_mode_gates(self):
        selection = self.schema["selector"]
        actual = [n for n in range(256)
                  if archive.selector_mode(selection["add_byte"], selection["exclusive_bound"], n)]
        self.assertEqual(actual, [23, 24, 25, 26])
        self.assertEqual(actual, selection["named_codes"])
        self.assertEqual(selection["field_name_bytes"], [0, 1])
        self.assertEqual(selection["human_readable_bytes"], [0, 0])
        self.assertEqual(archive.outer_mode_plan(0),
                         {"container": "array", "name_emitted": [False] * 5})
        self.assertEqual(archive.outer_mode_plan(1),
                         {"container": "map", "name_emitted": [True] * 5})
        self.assertEqual(archive.outer_mode_plan(2),
                         {"container": "map", "name_emitted": [False, False, False, True, True]})
        for bad in (-1, 256):
            with self.assertRaises(ValueError):
                archive.selector_mode(selection["add_byte"], selection["exclusive_bound"], bad)
            with self.assertRaises(ValueError):
                archive.outer_mode_plan(bad)

    def test_block_hierarchy_and_header_order(self):
        self.assertEqual(self.schema["variant"]["name"], "Reth115")
        self.assertEqual([r["name"] for r in self.schema["nested_fields"]],
                         ["header", "hash", "header", "body", "transactions", "ommers", "withdrawals"])
        expected = ["parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot",
                    "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed",
                    "timestamp", "extraData", "mixHash", "nonce", "baseFeePerGas",
                    "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"]
        self.assertEqual([r["name"] for r in self.schema["header_fields"]], expected)
        self.assertEqual([r["source_offset"] for r in self.schema["outer_fields"]],
                         ["0x0", "0x338", "0x350", "0x368", "0x381"])
        self.assertEqual([r["source_offset"] for r in self.schema["header_fields"]],
                         ["0x50", "0x70", "0x258", "0x90", "0xb0", "0xd0", "0xf0", "0x1f0",
                          "0x210", "0x218", "0x220", "0x228", "0x30", "0x230", "0x250",
                          "0x0", "0x26c", "0x10", "0x20", "0x28d", "0x2ae"])

    def test_every_valid_optional_header_mask(self):
        base = self.schema["header_required_count"]
        self.assertEqual(base, 15)
        self.assertEqual(len(self.cases), 64)
        optional = ["baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas",
                    "parentBeaconBlockRoot", "requestsHash"]
        for bits, row in zip(itertools.product((0, 1), repeat=6), self.cases):
            self.assertEqual(row["field_count"], 15 + sum(bits))
            self.assertEqual(archive.header_count(bits, base), row["field_count"])
            self.assertEqual(row["included_optional"], [n for n, b in zip(optional, bits) if b])
        for bad in ((0, 0), (0, 0, 0, 0, 0, 2), (0, 0, 0, 0, 0, True)):
            with self.assertRaises(ValueError):
                archive.header_count(bad, base)

    def test_every_header_child_result_branch_is_pinned(self):
        sites = [0x46bfcaa, 0x46bfce8, 0x46bfd29, 0x46bfd6a, 0x46bfdab,
                 0x46bfdd3, 0x46bfdef, 0x46bfe17, 0x46bfe33, 0x46bfe4f,
                 0x46bfe6b, 0x46bfe87, 0x46bfeac, 0x46bfed4, 0x46bfef0,
                 0x46bff0e, 0x46bff3c, 0x46bff5b, 0x46bff7a, 0x46bffa8,
                 0x46bffd5]
        branches = {int(row["site"], 16): row for row in self.branches}
        self.assertEqual(len(sites), len(self.schema["header_fields"]))
        for field, site in zip(self.schema["header_fields"], sites):
            row = branches[site]
            self.assertIn("child failure", row["label"])
            self.assertGreater(site, int(field["value_call"], 16))
            self.assertLessEqual(site - int(field["value_call"], 16), 16)
            with self.altered(site):
                with self.assertRaises(ValueError):
                    archive.Extract(self.image).branch(site, int(row["destination"], 16), "corrupt")

    def test_collection_strides_and_pair_failure_branch(self):
        rows = self.schema["sequences"]
        self.assertEqual([(r["field"], r["row_stride"]) for r in rows],
                         [("receipts", 40), ("system_txs", 272),
                          ("read_precompile_calls", 16)])
        self.assertEqual(rows[2]["row_element_count"], 2)
        self.assertEqual(rows[2]["direct_header_byte"], 0x92)
        with self.altered(0x4406064):
            with self.assertRaisesRegex(ValueError, "row stride"):
                archive.Extract(self.image).pin(0x4406061, "4883c510", "row stride")
        with self.altered(0x440605b):
            with self.assertRaisesRegex(ValueError, "condition"):
                archive.Extract(self.image).branch(0x440605b, 0x4405f40, "row failure")

    def test_shared_receipt_and_transaction_variant_rows(self):
        self.assertEqual([r["name"] for r in self.schema["system_row"]], ["tx", "receipt"])
        self.assertEqual([r["source_offset"] for r in self.schema["system_row"]], ["0x0", "0xe0"])
        self.assertEqual([r["name"] for r in self.schema["receipt_fields"]],
                         ["tx_type", "success", "cumulative_gas_used", "logs"])
        self.assertEqual([r["source_offset"] for r in self.schema["receipt_fields"]],
                         ["0x21", "0x20", "0x18", "0x0"])
        names = ["Legacy", "Eip2930", "Eip1559", "Eip4844", "Eip7702"]
        for rows in (self.schema["transaction_variants"], self.schema["receipt_variants"]):
            self.assertEqual([archive.variant_name(rows, i) for i in range(5)], names)
            for bad in (-1, 5, 255, True):
                with self.assertRaises(ValueError):
                    archive.variant_name(rows, bad)
        self.assertEqual([row["following_target_in_selected_fde"] for row in
                          self.schema["variant_table_boundaries"]], [False, False])
        marker = self.schema["receipt_boolean_marker_base"]
        self.assertEqual(archive.receipt_boolean(0, marker), 0xc2)
        self.assertEqual(archive.receipt_boolean(1, marker), 0xc3)
        for bad in (-1, 2, True):
            with self.assertRaises(ValueError):
                archive.receipt_boolean(bad, marker)

    def test_changed_variant_table_or_name_is_rejected(self):
        table = int(self.schema["variant_table_boundaries"][0]["table_va"],16)
        with self.altered(table):
            with self.assertRaisesRegex(ValueError, "variant jump table"):
                archive.facts(self.image)
        with self.altered(0x6f70f1):
            with self.assertRaisesRegex(ValueError, "variant names differ"):
                archive.facts(self.image)

    def test_binary_widths_endian_and_length_boundaries(self):
        self.assertEqual({r["kind"]: r["width"] for r in self.schema["fixed_binary"]},
                         {"hash": 32, "address": 20, "bloom": 256, "nonce": 8, "unsigned scalar": 8})
        encoding = self.schema["binary_length_encoding"]
        self.assertEqual(archive.binary_frame((0x0102030405060708).to_bytes(8, "big"), encoding).hex(),
                         "c4080102030405060708")
        self.assertEqual(archive.binary_frame(bytes(20), encoding)[:2], bytes.fromhex("c414"))
        self.assertEqual(archive.binary_frame(bytes(32), encoding)[:2], bytes.fromhex("c420"))
        self.assertEqual(archive.binary_frame(bytes(255), encoding)[:2], bytes.fromhex("c4ff"))
        self.assertEqual(archive.binary_frame(bytes(256), encoding)[:3], bytes.fromhex("c50100"))
        self.assertEqual(archive.binary_frame(bytes(65535), encoding)[:3], bytes.fromhex("c5ffff"))
        self.assertEqual(archive.binary_frame(bytes(65536), encoding)[:5], bytes.fromhex("c600010000"))
        with self.altered(0x4aea845 + 1):
            with self.assertRaisesRegex(ValueError, "marker selection"):
                archive.Extract(self.image).pin(0x4aea83c,
                    "81fa000100000fb6c0bdc40000000f43e8", "marker selection")


if __name__ == "__main__":
    unittest.main()
