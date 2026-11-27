import hashlib
import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV = ROOT / "work" / "index" / "node-115-fde.tsv"
PACKET_DIR = ROOT / "research" / "work-items" / "RE-004-node115-fee-trial-referral-rewards"
EVIDENCE_PATH = PACKET_DIR / "evidence.json"
MANIFEST_PATH = PACKET_DIR / "MANIFEST.sha256"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
RODATA_VA = 0x430400
RODATA_OFF = 0x430400


class TestFeeTrialReferralRewards115(unittest.TestCase):
    def test_manifest_and_target_sha256(self) -> None:
        ev = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            hashlib.sha256(BINARY.read_bytes()).hexdigest(),
            ev["target_sha256"],
        )
        entries = {}
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            digest, rel = line.split(None, 1)
            entries[rel] = digest
        self.assertEqual(set(entries), {"README.md", "evidence.json"})
        for rel, expected in entries.items():
            actual = hashlib.sha256((PACKET_DIR / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, f"manifest mismatch for {rel}")

    def test_fdes_constants_and_jump_table_discriminants_match_node115(self) -> None:
        ev = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        blob = BINARY.read_bytes()

        fdes = {}
        with FDE_TSV.open("r", encoding="utf-8") as fh:
            fh.readline()
            for line in fh:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    fdes[int(parts[0], 16)] = int(parts[1], 16)

        self.assertEqual(len(ev["fdes"]), 5)
        self.assertEqual(sum(f["size"] for f in ev["fdes"]), 7898)
        for item in ev["fdes"]:
            s, e = int(item["start"], 16), int(item["end"], 16)
            self.assertEqual(e - s, item["size"])
            self.assertEqual(fdes.get(s), e)
            body = blob[TEXT_OFF + (s - TEXT_VA) : TEXT_OFF + (e - TEXT_VA)]
            self.assertEqual(hashlib.sha256(body).hexdigest(), item["sha256"])

        for site in ev["instruction_sites"]:
            va = int(site["va"], 16)
            expected = bytes.fromhex(site["hex"])
            actual = blob[TEXT_OFF + (va - TEXT_VA) : TEXT_OFF + (va - TEXT_VA) + len(expected)]
            self.assertEqual(actual, expected, f"instruction mismatch at {site['va']} ({site['note']})")

        jt_va = int(ev["user_error_jump_table"]["va"], 16)
        jt_off = RODATA_OFF + (jt_va - RODATA_VA)
        for disc_entry in ev["user_error_jump_table"]["discriminants"]:
            disc = int(disc_entry["disc"], 16)
            rel = struct.unpack_from("<i", blob, jt_off + disc * 4)[0]
            tgt = jt_va + rel
            self.assertEqual(tgt, int(disc_entry["handler_va"], 16), disc_entry["name"])

        for s_entry in ev["rodata_strings"]:
            va = int(s_entry["va"], 16)
            expected = s_entry["text"].encode("ascii")
            actual = blob[RODATA_OFF + (va - RODATA_VA) : RODATA_OFF + (va - RODATA_VA) + len(expected)]
            self.assertEqual(actual, expected)

        # Negative control: flipping a byte in the first instruction site must break equality
        first = ev["instruction_sites"][0]
        va = int(first["va"], 16)
        good = bytes.fromhex(first["hex"])
        bad = bytes([good[0] ^ 0xFF]) + good[1:]
        actual = blob[TEXT_OFF + (va - TEXT_VA) : TEXT_OFF + (va - TEXT_VA) + len(good)]
        self.assertNotEqual(actual, bad)


if __name__ == "__main__":
    unittest.main()
