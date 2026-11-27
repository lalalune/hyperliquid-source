import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.action_dispatch_callsite_graph_115 import (
    DIGEST,
    EvidenceError,
    TARGET,
    build_rows,
    verify_direct_call,
    write_outputs,
)


class ActionDispatchCallsiteGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = TARGET.read_bytes()

    def test_target_bound_direct_call_crosswalk(self):
        rows, summary = build_rows(self.binary)
        self.assertEqual(hashlib.sha256(self.binary).hexdigest(), DIGEST)
        self.assertEqual(summary["direct_call_site_counts"], {
            "action_decoder": 2,
            "action_router": 5,
            "action_envelope": 2,
            "nested_action_parser": 2,
        })
        self.assertEqual(summary["decoder_router_shared_caller_fdes"], [])
        self.assertEqual(len(rows), 11)

    def test_regeneration_is_byte_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = write_outputs(self.binary, root / "first")
            second = write_outputs(self.binary, root / "second")
            self.assertEqual(first, second)
            for name in ("call-sites.tsv", "summary.json"):
                self.assertEqual((root / "first" / name).read_bytes(), (root / "second" / name).read_bytes())
            self.assertEqual(json.loads((root / "first" / "summary.json").read_text()), first)

    def test_wrong_target_digest_rejected(self):
        altered = bytearray(self.binary)
        altered[-1] ^= 1
        with self.assertRaises(EvidenceError):
            build_rows(bytes(altered))

    def test_corrupted_call_displacement_rejected(self):
        from tools.elf_index import sections
        text = next(section for section in sections(self.binary) if section["name"] == ".text")
        site = 0x20F06D3
        offset = text["offset"] + site - text["address"]
        raw = bytearray(self.binary[offset:offset + 5])
        verify_direct_call(raw, site, 0x2B817D0)
        raw[1] ^= 1
        with self.assertRaises(EvidenceError):
            verify_direct_call(bytes(raw), site, 0x2B817D0)

    def test_router_caller_fde_boundary_is_recorded(self):
        rows, _ = build_rows(self.binary)
        row = next(row for row in rows if row["call_site_va"] == "0x2c719c3")
        self.assertEqual(row["caller_fde_start"], "0x2c71250")
        self.assertEqual(row["caller_fde_end"], "0x2c71ea5")


if __name__ == "__main__":
    unittest.main()
