"""Unit tests for the node #115 lu slot-release packet.

Regeneration comparison + tamper control + census spot checks for the
0x63b0780 release helper. Static only; never executes the node binary.
"""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slotrelease")
NODE = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
VERIFIER = os.path.join(REPO, "tools", "node115_lu_slotrelease.py")

RELEASE_START = 0x63B0780
RELEASE_END = 0x63B0980
CALLERS = (0x63B1BC4, 0x63B1C91, 0x63B26F1, 0x63B47CA)
INTERNAL_CALLS = {
    0x63B07A6: 0x63E8BF0,
    0x63B0847: 0x63ACB40,
    0x63B084F: 0x63ABCF0,
    0x63B0912: 0x63ABD00,
}

INSN_RE = re.compile(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)")


def text_off(va):
    return va - 0x1000


def objdump(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", NODE],
        capture_output=True, text=True, check=True).stdout
    return out


class SlotReleaseTests(unittest.TestCase):
    def test_exhibits_regenerate(self):
        with open(NODE, "rb") as f:
            data = f.read()
        with open(os.path.join(PACKET, "records.json")) as f:
            records = json.load(f)
        for name, ex in records["exhibits"].items():
            start = int(ex["range"][0], 16)
            end = int(ex["range"][1], 16)
            with open(os.path.join(PACKET, name + ".hex")) as f:
                hexs = "".join(f.read().split())
            self.assertEqual(bytes.fromhex(hexs), data[text_off(start):text_off(end)])
            self.assertEqual(len(bytes.fromhex(hexs)), ex["bytes"])
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                saved = f.read()
            # The objdump header embeds the path passed on the command
            # line, which differs between generation (relative) and this
            # test (absolute); compare from the disassembly body onward.
            def body(text):
                idx = text.find("Disassembly of section")
                return text[idx:] if idx >= 0 else text
            self.assertEqual(body(saved), body(objdump(start, end)))

    def test_fde_bounds(self):
        out = objdump(RELEASE_START, RELEASE_END)
        self.assertEqual(RELEASE_END - RELEASE_START, 512)
        calls = [l for l in out.splitlines() if re.search(r"\tcall\s", l)]
        rets = [l for l in out.splitlines() if re.search(r"\tret\s*$", l)]
        self.assertEqual(len(calls), 4)
        self.assertEqual(len(rets), 1)
        self.assertIn("63b08cf", rets[0])
        for addr, target in (
                ("63b07a6", "63e8bf0"), ("63b0847", "63acb40"),
                ("63b084f", "63abcf0"), ("63b0912", "63abd00")):
            self.assertTrue(any(addr in l and target in l for l in calls),
                            f"missing call {addr} -> {target}")

    def test_key_bytes(self):
        with open(NODE, "rb") as f:
            data = f.read()
        self.assertEqual(data[text_off(RELEASE_START):text_off(RELEASE_START) + 4],
                         bytes.fromhex("f30f1efa"))
        self.assertEqual(data[text_off(0x63B08CF)], 0xC3)
        self.assertEqual(data[text_off(0x63B0867):text_off(0x63B0867) + 3],
                         bytes.fromhex("49d3c5"))
        self.assertEqual(data[text_off(0x63B086A):text_off(0x63B086A) + 4],
                         bytes.fromhex("4e216cfd"))
        self.assertEqual(data[text_off(0x63B0950):text_off(0x63B0950) + 6],
                         bytes.fromhex("41b998250000"))
        for site, target in INTERNAL_CALLS.items():
            off = text_off(site)
            self.assertEqual(data[off], 0xE8)
            rel = struct.unpack("<i", data[off + 1:off + 5])[0]
            self.assertEqual(site + 5 + rel, target)
        for site in CALLERS:
            off = text_off(site)
            self.assertEqual(data[off], 0xE8)
            rel = struct.unpack("<i", data[off + 1:off + 5])[0]
            self.assertEqual(site + 5 + rel, RELEASE_START)

    def test_manifest_coverage(self):
        with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
            entries = [l.rstrip("\n") for l in f if l.strip()]
        self.assertEqual(len(entries), 15)
        for line in entries:
            digest, _, path = line.partition("  ")
            self.assertNotEqual(path, "MANIFEST.sha256")
            if path.startswith("../../../"):
                full = os.path.join(REPO, path[9:])
            else:
                full = os.path.join(PACKET, path)
            with open(full, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest)

    def test_strict_counts(self):
        with open(os.path.join(PACKET, "records.json")) as f:
            records = json.load(f)
        for name, ex in records["exhibits"].items():
            with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
                count = sum(1 for line in f if INSN_RE.match(line))
            self.assertEqual(count, ex["strict"])

    def test_tamper_control(self):
        tmp = tempfile.mkdtemp(prefix="slotrelease-tamper-")
        try:
            pkt_copy = os.path.join(tmp, "packet")
            shutil.copytree(PACKET, pkt_copy)
            tools_copy = os.path.join(tmp, "tools")
            os.makedirs(tools_copy)
            shutil.copy(VERIFIER, tools_copy)
            # Corrupt one exhibit hex byte; the verifier must fail.
            hex_path = os.path.join(pkt_copy, "sr_entry.hex")
            with open(hex_path) as f:
                hexs = f.read().strip()
            bad = ("00" if hexs[:2] != "00" else "ff") + hexs[2:]
            with open(hex_path, "w") as f:
                f.write(bad + "\n")
            # Point the verifier copy at the tampered packet by patching
            # its PACKET constant (the copy lives outside the repo tree).
            ver_path = os.path.join(tools_copy, "node115_lu_slotrelease.py")
            with open(ver_path) as f:
                src = f.read()
            src = src.replace(
                'os.path.join(REPO, "research", "work-items", "RE-001-node115-lu-slotrelease")',
                repr(pkt_copy))
            with open(ver_path, "w") as f:
                f.write(src)
            proc = subprocess.run([sys.executable, ver_path],
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_verifier_exit_zero(self):
        proc = subprocess.run([sys.executable, VERIFIER],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("all checks passed", proc.stdout)

    def test_census_got(self):
        with open(NODE, "rb") as f:
            data = f.read()
        rela_off, rela_size = 0x6BE8, 0x163CC8
        self.assertEqual(rela_size // 0x18, 60723)
        hits = 0
        for i in range(rela_size // 0x18):
            r_add = struct.unpack(
                "<q", data[rela_off + i * 0x18 + 16:rela_off + i * 0x18 + 24])[0]
            if r_add == RELEASE_START:
                hits += 1
        self.assertEqual(hits, 0)

    def test_bitmap_and_cache_sites(self):
        out = objdump(RELEASE_START, RELEASE_END)
        rols = [l for l in out.splitlines() if re.search(r"\trol\s", l)]
        self.assertEqual(len(rols), 1)
        self.assertIn("63b0867", rols[0])
        movups = [l for l in out.splitlines() if re.search(r"\tmovups\s", l)]
        self.assertEqual(len(movups), 1)
        self.assertIn("63b0920", movups[0])


if __name__ == "__main__":
    unittest.main()
