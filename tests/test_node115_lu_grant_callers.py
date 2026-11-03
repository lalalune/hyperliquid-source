import hashlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import node115_lu_grant_callers as subject


def _text_off(va):
    return va - 0x1000


class GrantCallersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.DEFAULT_BINARY.read_bytes()

    def test_verify_passes(self):
        record = subject.verify()
        self.assertEqual(record["fde"]["start"], "0x4fb52e0")
        self.assertEqual(record["fde"]["end"], "0x4fb5435")
        self.assertEqual(record["fde"]["bytes"], 341)
        self.assertEqual(record["fde"]["body_sha256"], subject.BODY_SHA256)
        self.assertEqual(record["census"]["e8_callers"], 0)
        self.assertEqual(record["census"]["got_sites"], 66)
        self.assertEqual(record["census"]["got_calls"], 65)
        self.assertEqual(record["census"]["got_jmps"], 1)
        self.assertEqual(record["esi_census"]["sites_with_esi_0"], 66)
        self.assertEqual(record["esi_census"]["sites_with_esi_1"], 0)
        self.assertEqual(record["mov_esi_1_census"]["count"], 58)
        self.assertEqual(record["mov_esi_1_census"]["feeding_grant"], 0)

    def test_digest_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            subject.verify(b"unrelated executable")

    def test_corrupt_jmp_site_xor_rejected(self):
        bad = bytearray(self.data)
        bad[_text_off(0x4FB53DD)] ^= 0xFF
        fde = bytes(bad[_text_off(0x4FB52E0):_text_off(0x4FB52E0) + 341])
        with patch.object(subject, "BINARY_SHA256",
                          hashlib.sha256(bytes(bad)).hexdigest()), \
                patch.object(subject, "BODY_SHA256",
                             hashlib.sha256(fde).hexdigest()):
            with self.assertRaisesRegex(ValueError, "jmp-site xor changed"):
                subject.verify(bytes(bad))

    def test_corrupt_release_cmpxchg_rejected(self):
        bad = bytearray(self.data)
        bad[_text_off(0x4FB53AA)] ^= 0xFF
        fde = bytes(bad[_text_off(0x4FB52E0):_text_off(0x4FB52E0) + 341])
        with patch.object(subject, "BINARY_SHA256",
                          hashlib.sha256(bytes(bad)).hexdigest()), \
                patch.object(subject, "BODY_SHA256",
                             hashlib.sha256(fde).hexdigest()):
            with self.assertRaisesRegex(ValueError, "gate release cmpxchg changed"):
                subject.verify(bytes(bad))

    def test_corrupt_grant_jmp_rejected(self):
        bad = bytearray(self.data)
        bad[_text_off(0x4FB53E8) + 2] ^= 0xFF
        fde = bytes(bad[_text_off(0x4FB52E0):_text_off(0x4FB52E0) + 341])
        with patch.object(subject, "BINARY_SHA256",
                          hashlib.sha256(bytes(bad)).hexdigest()), \
                patch.object(subject, "BODY_SHA256",
                             hashlib.sha256(fde).hexdigest()):
            with self.assertRaisesRegex(ValueError, "grant jmp changed"):
                subject.verify(bytes(bad))

    def test_packet_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            packet = Path(folder) / "packet"
            shutil.copytree(subject.PACKET, packet)
            with patch.object(subject, "PACKET", packet):
                records = packet / "records.json"
                original = records.read_text()
                record = json.loads(original)
                record["fde"]["end"] = "0x4fb5434"
                records.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, "Exact FDE changed"):
                    subject.verify()
                records.write_text(original)
                body = packet / "fde52e0.hex"
                original_body = body.read_text()
                body.write_text("00" + original_body[2:])
                with self.assertRaisesRegex(ValueError, "Body reference changed"):
                    subject.verify()
                body.write_text(original_body)

    def test_objdump_counts_match_records(self):
        text = (subject.PACKET / "fde52e0.objdump.txt").read_text()
        body = tail = nops = 0
        for line in text.splitlines():
            match = re.match(r"\s+(4fb5[0-9a-f]+):", line)
            if not match:
                continue
            va = int(match.group(1), 16)
            if va <= 0x4FB53BA:
                body += 1
            else:
                tail += 1
            if "nop" in line:
                nops += 1
        record = json.loads((subject.PACKET / "records.json").read_text())
        self.assertEqual(body, record["instructions"]["body"])
        self.assertEqual(tail, record["instructions"]["tail"])
        self.assertEqual(body + tail, record["instructions"]["total"])
        self.assertEqual(nops, record["instructions"]["nops"])


if __name__ == "__main__":
    unittest.main()
