"""Binary-backed verification for RE-012 node #115 artifact, stream_msg, and abci_latency_sampler."""

import hashlib
import json
import pathlib
import runpy
import struct
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
BIN_PATH = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET_DIR = REPO / "research" / "work-items" / "RE-012-node115-artifact-and-stream-msg"
RECORDS_PATH = PACKET_DIR / "records.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"

EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RELA_DYN_OFF = 0x6BE8
RELA_DYN_SIZE = 0x163CC8
DATA_REL_RO_DELTA = 0x2000


class TestArtifactAndStreamMsg115(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = BIN_PATH.read_bytes()
        cls.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        cls.relas: dict[int, int] = {}
        for off in range(RELA_DYN_OFF, RELA_DYN_OFF + RELA_DYN_SIZE, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", cls.data, off)
            if (r_info & 0xFFFFFFFF) == 8:
                cls.relas[r_offset] = r_addend

    def test_pinned_binary_sha256(self) -> None:
        digest = hashlib.sha256(self.data).hexdigest()
        self.assertEqual(digest, EXPECTED_SHA256)
        self.assertEqual(self.records["target"]["sha256"], EXPECTED_SHA256)

    def test_rodata_anchors_and_poll_constant(self) -> None:
        for name, entry in self.records["rodata_anchors"].items():
            va = int(entry["va"], 16)
            expected = entry["text"].encode("utf-8")
            actual = self.data[va : va + len(expected)]
            self.assertEqual(actual, expected, f"rodata mismatch for {name} at {hex(va)}")

        const = self.records["constants"]["artifact_poll_interval_secs"]
        va = int(const["va"], 16)
        val = struct.unpack_from("<d", self.data, va)[0]
        self.assertEqual(val, const["value"])

    def test_location_structs_and_relocs(self) -> None:
        for loc in self.records["locations"]:
            va = int(loc["va"], 16)
            expected_file_va = int(loc["file_va"], 16)
            self.assertEqual(self.relas.get(va), expected_file_va, f"missing reloc at {hex(va)}")
            file_off = va - DATA_REL_RO_DELTA
            length, line, col = struct.unpack_from("<QII", self.data, file_off + 8)
            file_bytes = self.data[expected_file_va : expected_file_va + length]
            self.assertEqual(file_bytes.decode("utf-8"), loc["file"])
            self.assertEqual(line, loc["line"])
            self.assertEqual(col, loc["col"])

    def test_negative_controls_and_fdes(self) -> None:
        # Negative control: offset +1 must not match artifact dir string
        dir_va = int(self.records["rodata_anchors"]["node_artifact_dir"]["va"], 16)
        self.assertNotEqual(self.data[dir_va + 1 : dir_va + 1 + len(b"node-artifact-2")], b"node-artifact-2")
        for fde in self.records["fdes"]:
            start = int(fde["start_va"], 16)
            end = int(fde["end_va"], 16)
            self.assertEqual(end - start, fde["size_bytes"])
            self.assertGreater(fde["size_bytes"], 0)

    def test_named_archive_writer_evidence(self) -> None:
        compare = runpy.run_path(str(PACKET_DIR / "compare_replicas.py"))
        result = json.loads((PACKET_DIR / "replica-results.json").read_text(encoding="utf-8"))
        self.assertEqual(compare["check_capture"](), result["native"])

    def test_manifest_sha256_integrity(self) -> None:
        lines = [ln.strip() for ln in MANIFEST_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        expected_files = {"README.md", "records.json", "compare_replicas.py", "encode_replicas.rs", "replica-results.json"}
        self.assertEqual(len(lines), len(expected_files))
        seen = set()
        for line in lines:
            expected_hash, rel_name = line.split("  ", 1)
            seen.add(rel_name)
            actual_hash = hashlib.sha256((PACKET_DIR / rel_name).read_bytes()).hexdigest()
            self.assertEqual(actual_hash, expected_hash, f"checksum mismatch for {rel_name}")
        self.assertEqual(seen, expected_files)


if __name__ == "__main__":
    unittest.main()
