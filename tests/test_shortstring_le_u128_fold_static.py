#!/usr/bin/env python3
"""Static checks for packet RE-001-node115-shortstring-le-u128-fold.

Two tiers:

* Binary-INDEPENDENT checks that ALWAYS run over the committed packet, even
  when the materialized node #115 capture is absent: the MANIFEST.sha256 digests
  match every committed packet file, records.json is internally consistent with
  the committed objdump excerpts (including is_leaf and the caller tail-call),
  and the body/caller objdump excerpts contain the opcode bytes the claim rests
  on. These guard against packet drift with no capture present.

* A binary-DEPENDENT check that runs the work-item verifier (which authenticates
  the capture by SHA-256, decodes the 89-byte body, emulates it, and compares
  the emulated u128 against the model and an independent little-endian pack).
  When the capture is missing or its digest mismatches, this single test skips
  with a LOUD, explicit reason printed to stderr -- it never skips silently and
  never skips the binary-independent tier above.

The capture is never executed; the verifier only interprets the pinned body
bytes with its own small decoder/emulator.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research/work-items/RE-001-node115-shortstring-le-u128-fold")
VERIFIER = os.path.join(PACKET, "verify_shortstring_le_u128_fold.py")
MANIFEST = os.path.join(PACKET, "MANIFEST.sha256")
RECORDS = os.path.join(PACKET, "records.json")
BODY_OBJDUMP = os.path.join(PACKET, "15472b0.objdump.txt")
CALLER_OBJDUMP = os.path.join(PACKET, "1546aa0.caller-tailcall.objdump.txt")
BINARY = os.path.join(ROOT, "artifacts/node/115/hl-node")
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

ENTRY = re.compile(r"^([0-9a-f]{64})  (\S.*)$")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class PacketStaticTests(unittest.TestCase):
    """Binary-independent; these ALWAYS run."""

    def test_manifest_matches_committed_files(self):
        with open(MANIFEST, encoding="utf-8") as f:
            rows = [ENTRY.match(line.strip()) for line in f
                    if line.strip() and not line.startswith("#")]
        self.assertTrue(rows and all(rows), "malformed MANIFEST.sha256 line")
        names = [m.group(2) for m in rows]
        self.assertEqual(len(names), len(set(names)), "duplicate MANIFEST entry")
        # Every committed packet file (except the manifest itself) must be listed.
        listed = set(names)
        on_disk = {n for n in os.listdir(PACKET) if n != "MANIFEST.sha256"}
        self.assertEqual(on_disk, listed,
                         f"MANIFEST/dir drift: only_disk={on_disk - listed} "
                         f"only_manifest={listed - on_disk}")
        for m in rows:
            want, rel = m.group(1), m.group(2)
            path = os.path.join(PACKET, rel)
            self.assertTrue(os.path.isfile(path), f"missing {rel}")
            self.assertEqual(_sha256(path), want, f"digest drift: {rel}")

    def test_records_json_consistency(self):
        with open(RECORDS, encoding="utf-8") as f:
            rec = json.load(f)
        fn = rec["function"]
        # The function recurses and calls panics -> it is NOT a leaf. The text
        # and is_leaf must agree with that evidence.
        self.assertFalse(fn["is_leaf"],
                         "records.json is_leaf must be false (function calls)")
        self.assertEqual(fn["va_start"], "0x15472b0")
        self.assertEqual(fn["va_end"], "0x1547309")
        self.assertEqual(fn["length_bytes"], 0x1547309 - 0x15472b0)
        # Callee slots/addends must match the recovered relocations.
        by_slot = {c["got_slot"]: c for c in rec["callees"]}
        self.assertEqual(by_slot["0x64e0fe0"]["addend"], "0x15472b0")
        self.assertEqual(by_slot["0x64df620"]["addend"], "0x1680cbf")
        self.assertEqual(by_slot["0x64df870"]["addend"], "0x1681dc0")
        # The caller claim must cite an excerpt file that exists and is in scope.
        caller = rec["caller_context"]
        self.assertEqual(caller["caller_fde_va"], "0x1546aa0")
        self.assertIn("evidence", caller)
        self.assertTrue(os.path.isfile(os.path.join(PACKET, caller["evidence"])),
                        "caller_context.evidence file missing")
        # Overflow domain must be described as value-dependent, not a length cap.
        dom = rec["claim"]["successful_domain"]
        self.assertIn("value", dom.lower())

    def test_body_objdump_has_key_opcodes(self):
        with open(BODY_OBJDUMP, encoding="utf-8") as f:
            text = f.read()
        # Byte-level anchors for the claim (shld/shl/or and the shr rdx,0x38 test).
        for needle in ("48 0f a4 c1 08", "48 c1 e0 08", "48 09 d0",
                       "48 c1 ea 38", "75 27", "ff 15"):
            self.assertIn(needle, text, f"body objdump missing bytes {needle!r}")

    def test_caller_tailcall_excerpt(self):
        with open(CALLER_OBJDUMP, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("1546aa0", text)
        self.assertIn("cmp    rsi,0x10", text)
        self.assertIn("jbe", text)
        self.assertIn("xor    edx,edx", text)
        # Tail-jmp through the GOT slot that resolves to the leaf (0x64e0fe0).
        self.assertIn("jmp    QWORD PTR [rip", text)
        self.assertIn("64e0fe0", text)


class VerifierTests(unittest.TestCase):
    """Binary-dependent; skips LOUDLY (never silently) when the capture is absent."""

    def test_verifier_passes(self):
        reason = None
        if not os.path.isfile(BINARY):
            reason = ("materialized node115 capture absent at "
                      f"{os.path.relpath(BINARY, ROOT)}; run `git lfs pull` / "
                      "`make fetch`. Binary-independent packet checks still ran.")
        else:
            with open(BINARY, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != BIN_SHA256:
                    reason = "node115 capture digest mismatch; refusing to emulate."
        if reason:
            sys.stderr.write("\n[SKIP] test_verifier_passes: " + reason + "\n")
            sys.stderr.flush()
            self.skipTest(reason)
        r = subprocess.run([sys.executable, "-B", VERIFIER],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-3000:])
        self.assertIn("RESULT: PASS", r.stdout)
        # The emulated-body comparison and reproducible controls must appear.
        self.assertIn("opcode sequence OK", r.stdout)
        self.assertIn("emulated==model==LE", r.stdout)
        self.assertIn("value-dependent domain", r.stdout)
        self.assertIn("re-emulated", r.stdout)


if __name__ == "__main__":
    unittest.main()
