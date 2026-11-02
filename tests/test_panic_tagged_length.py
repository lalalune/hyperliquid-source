import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-004-panic-tagged-length-94"
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"


def load_segments():
    rows = []
    for line in (PACKET / "segments.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        rows.append({
            "id": parts[0], "start": int(parts[1], 16),
            "end": int(parts[2], 16), "length": int(parts[3]),
            "file_offset": int(parts[4], 16), "sha256": parts[5],
            "kind": parts[6],
        })
    return rows


def load_thunks():
    rows = []
    lines = (PACKET / "thunks.tsv").read_text().splitlines()[1:]
    for line in lines:
        p = line.split("\t")
        rows.append({"name": p[0], "thunk": p[1], "msg": p[2],
                     "raw": int(p[3]), "true": int(p[4]), "message": p[5]})
    return rows


class TestPanicTaggedLength(unittest.TestCase):
    def test_regeneration_matches_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "regen"
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "panic_tagged_length.py"),
                                "--out", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            for name in ["evidence.json", "thunks.tsv", "chain.tsv",
                         "routes.tsv", "segments.txt"]:
                self.assertEqual((out / name).read_bytes(),
                                 (PACKET / name).read_bytes(), name)

    def test_segments_match_binary(self):
        data = NODE.read_bytes()
        for s in load_segments():
            self.assertEqual(s["end"] - s["start"], s["length"], s["id"])
            chunk = data[s["file_offset"]:s["file_offset"] + s["length"]]
            self.assertEqual(len(chunk), s["length"], s["id"])
            self.assertEqual(hashlib.sha256(chunk).hexdigest(), s["sha256"],
                             s["id"])

    def test_counts(self):
        segs = load_segments()
        self.assertEqual(len(segs), 28)
        self.assertEqual(sum(s["length"] for s in segs), 1184)
        code = sum(s["length"] for s in segs if not s["id"].startswith("msg-"))
        msgs = sum(s["length"] for s in segs if s["id"].startswith("msg-"))
        self.assertEqual(code, 828)
        self.assertEqual(msgs, 356)
        ev = json.loads((PACKET / "evidence.json").read_text())
        self.assertEqual(ev["counts"]["segments"], 28)
        self.assertEqual(ev["counts"]["claim_bytes"], 1184)
        self.assertEqual(ev["counts"]["routes_sites"], 35)
        routes = (PACKET / "routes.tsv").read_text().splitlines()[1:]
        self.assertEqual(sum(int(r.split("\t")[3]) for r in routes), 35)

    def test_tagged_arithmetic(self):
        for t in load_thunks():
            self.assertEqual(t["raw"] % 2, 1, t["name"])
            self.assertEqual((t["raw"] - 1) // 2, t["true"], t["name"])
            self.assertEqual(len(t["message"]), t["true"], t["name"])

    def test_tamper_segment_digest(self):
        segs = load_segments()
        data = NODE.read_bytes()
        s = dict(segs[0])
        bad = ("0" if s["sha256"][0] != "0" else "1") + s["sha256"][1:]
        chunk = data[s["file_offset"]:s["file_offset"] + s["length"]]
        self.assertNotEqual(hashlib.sha256(chunk).hexdigest(), bad)

    def test_tamper_thunk_raw(self):
        thunks = load_thunks()
        t = dict(thunks[0])
        t["raw"] += 1  # breaks oddness and the (raw-1)//2 identity
        self.assertFalse(t["raw"] % 2 == 1 and (t["raw"] - 1) // 2 == t["true"])


if __name__ == "__main__":
    unittest.main()
