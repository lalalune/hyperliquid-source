import bisect
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)
BIN = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-009-storage-state-roots"
OUTPUT_SHA256 = "1ac3af0abe3b12e44819f117d3288a2e7e7ae336934cb6927d566142bc8387a8"
SCHEMA_SHA256 = "ae0c6815914486fefb7092a697f3748c39caaad6131a6f93de339814c45429e4"
DATA = BIN.read_bytes() if BIN.exists() else None


def tool(name):
    return shutil.which(name)


@unittest.skipIf(DATA is None, "pinned binary not present")
class StateRootsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = sr.build(DATA)
        cls.text = sr.render(cls.r)
        cls.elf = sr.Elf(DATA)

    def mutated(self, va, new):
        b = bytearray(DATA)
        o = self.elf.off(va)
        b[o:o + len(new)] = new
        b = bytes(b)
        return sr.build(b, expected_sha256=hashlib.sha256(b).hexdigest())

    # --- pinned output --------------------------------------------------
    def test_pinned_counts_and_hashes(self):
        r = self.r
        self.assertEqual(r["fde_count"], 121299)
        self.assertEqual(r["first_party_location_count"], 1186)
        self.assertEqual(r["scoped_location_counts"], {
            "db/src/block_reader.rs": 2, "db/src/db_home.rs": 13, "db/src/db_hub.rs": 7,
            "db/src/dh.rs": 2, "db/src/owned_db_home.rs": 3, "db/src/rocks_db.rs": 2,
            "l1/src/abci/state.rs": 28})
        self.assertEqual(len(r["functions"]), 57)
        self.assertEqual(sum(f["scoped"] for f in r["functions"]), 46)
        self.assertEqual(r["reconstruction_status_counts"],
                         {"fde_start_no_own_location": 3, "fde_start_with_own_location": 17})
        self.assertEqual(hashlib.sha256(self.text).hexdigest(), OUTPUT_SHA256)
        self.assertEqual(hashlib.sha256(sr.render(r["fixture_schema"])).hexdigest(), SCHEMA_SHA256)

    def test_packet_files_match_tool(self):
        self.assertEqual((PACKET / "state-roots.json").read_bytes(), self.text)
        self.assertEqual((PACKET / "fixture-schema.json").read_bytes(), sr.render(self.r["fixture_schema"]))

    def test_literal_owners(self):
        lit = {x["text"]: x["functions"] for x in self.r["literals"]}
        self.assertEqual(lit["/CHECKPOINT_COMPLETE"], [0x15867a0, 0x28d1650, 0x332e0a0, 0x459a7f0])
        self.assertEqual(lit["/lt_hashes.json"], [0x32699c0, 0x3269ae0, 0x332d440])
        self.assertEqual(lit["@@ linked abci state @@"], [0x2208e60, 0x446da60, 0x446e050])
        self.assertEqual(lit["periodic_abci_states"], [])
        self.assertEqual([(d["function"], d["site"]) for d in self.r["dev_null_compares"]],
                         [(0x46cea60, 0x46ceaef), (0x46cfe90, 0x46cff1f)])

    def test_hashseed_invariance(self):
        outs = set()
        for seed in ("0", "7", "99"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/state_roots.py")],
                               env=env, capture_output=True, check=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    # --- tamper / mutation ---------------------------------------------
    def test_wrong_binary_hash_rejected(self):
        with self.assertRaises(sr.EvidenceError):
            sr.build(DATA[:-1] + bytes([DATA[-1] ^ 1]))

    def test_location_line_mutation_changes_output(self):
        loc = next(l for l in self.r["scoped_locations"] if l["file"] == "l1/src/abci/state.rs")
        r = self.mutated(loc["slot"] + 16, struct.pack("<I", loc["line"] + 1))
        got = next(l for l in r["scoped_locations"] if l["slot"] == loc["slot"])
        self.assertEqual(got["line"], loc["line"] + 1)

    def test_location_len_mutation_drops_record(self):
        loc = next(l for l in self.r["scoped_locations"] if l["file"] == "db/src/dh.rs")
        r = self.mutated(loc["slot"] + 8, struct.pack("<Q", 0))
        self.assertNotIn(loc["slot"], [l["slot"] for l in r["scoped_locations"]])
        self.assertEqual(r["scoped_location_counts"]["db/src/dh.rs"], 1)

    def test_lea_retarget_drops_literal_owner(self):
        lit = next(x for x in self.r["literals"] if x["text"] == "@@ linked abci state @@")
        site = lit["anchors"][0]["lea_sites"][0]
        disp = struct.unpack("<i", self.elf.read(site + 3, 4))[0]
        r = self.mutated(site + 3, struct.pack("<i", disp + 0x100))
        got = next(x for x in r["literals"] if x["text"] == "@@ linked abci state @@")
        self.assertEqual(len(got["functions"]), len(lit["functions"]) - 1)

    def test_dev_null_imm_mutation_removed(self):
        r = self.mutated(0x46ceaef + 2, b"/dev/nuX")
        self.assertEqual([d["site"] for d in r["dev_null_compares"]], [0x46cff1f])

    def test_dev_null_without_ninth_byte_check_rejected(self):
        with self.assertRaises(sr.EvidenceError):
            self.mutated(0x46ceaef + 0x12, b"\x90\x90\x90\x90")

    def test_seed_edit_changes_status(self):
        with tempfile.TemporaryDirectory() as d:
            ref = Path(d)
            for f in sr.REF_FILES:
                (ref / f).parent.mkdir(parents=True, exist_ok=True)
                (ref / f).write_bytes((ROOT / sr.REF_DIR / f).read_bytes())
            p = ref / "l1/abci/state.rs"
            p.write_text(p.read_text().replace("0x2208E60", "0x2208E61"))
            r = sr.build(DATA, ref_root=ref)
        st = {c["va"]: c["status"] for c in r["reconstruction_addresses"]}
        self.assertEqual(st[0x2208E61], "inside_fde")
        self.assertNotIn(0x2208E60, st)

    # --- boundaries -----------------------------------------------------
    def test_fde_end_exclusive_and_seed_off_by_one(self):
        starts, ends = sr.fde_index(self.elf)
        j = bisect.bisect_left(starts, 0x2208e60)
        self.assertEqual(starts[j], 0x2208e60)
        e = ends[j]
        self.assertEqual(sr.containing(starts, ends, e - 1), (0x2208e60, e))
        self.assertNotEqual(sr.containing(starts, ends, e), (0x2208e60, e))
        for v in (0x2208e5f, 0x2208e61):
            self.assertFalse(sr.is_fde_start(starts, v))

    def test_template_anchor_is_exact(self):
        leas = sr.lea_targets(self.elf)
        for x in self.r["literals"]:
            for a in x["anchors"]:
                if a["lea_sites"]:
                    self.assertIn(a["anchor"], leas)
                    self.assertNotIn(a["anchor"] - 1, leas)
                    self.assertNotIn(a["anchor"] + 1, leas)
                if x["kind"] == "template":
                    o = self.elf.off(a["anchor"])
                    self.assertEqual(DATA[o - 1], 0)

    def test_negative_control_literal(self):
        relocs = sr.relative_relocs(self.elf)
        leas = sr.lea_targets(self.elf)
        self.assertEqual(sr.literal_anchors(self.elf, "exact", "/no/such/state_root.rmp", leas, relocs), [])
        self.assertEqual(sr.literal_anchors(self.elf, "exact", "state_root", leas, relocs), [])

    def test_non_elf_rejected(self):
        with self.assertRaises(sr.EvidenceError):
            sr.Elf(b"\0" * 64)

    # --- external cross-checks -----------------------------------------
    @unittest.skipIf(tool("readelf") is None, "readelf missing")
    def test_readelf_fde_bounds(self):
        out = subprocess.run(["readelf", "-wf", str(BIN)], capture_output=True, text=True, check=True).stdout
        pairs = sorted({(int(a, 16), int(b, 16)) for a, b in re.findall(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out)})
        starts, ends = sr.fde_index(self.elf)
        self.assertEqual(pairs, sorted(zip(starts, ends)))

    @unittest.skipIf(tool("readelf") is None, "readelf missing")
    def test_readelf_location_slots(self):
        out = subprocess.run(["readelf", "-rW", str(BIN)], capture_output=True, text=True, check=True).stdout
        rel = {int(m.group(1), 16): int(m.group(2), 16)
               for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", out, re.M)}
        for l in self.r["scoped_locations"]:
            self.assertIn(l["slot"], rel)

    @unittest.skipIf(tool("objdump") is None, "objdump missing")
    def test_objdump_literal_leas(self):
        for x in self.r["literals"]:
            for a in x["anchors"]:
                for s in a["lea_sites"]:
                    out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", f"--start-address={s:#x}",
                                          f"--stop-address={s + 7:#x}", str(BIN)],
                                         capture_output=True, text=True, check=True).stdout
                    self.assertRegex(out, rf"{s:x}:\s+lea\s+-?0x[0-9a-f]+\(%rip\),%r\w+\s+# {a['anchor']:x}")



def synthetic_elf(entries):
    """Minimal ELF64 whose .eh_frame_hdr table carries the given (pc, range)
    FDE specs; needs no materialized binary, unlike the pinned-evidence tests."""
    va = 0x400000
    hdr_off = 0x200
    table = bytearray(bytes([1, 0x1B, 0x03, 0x3B, 0, 0, 0, 0]))
    table += struct.pack('<I', len(entries))
    fde_blobs = {}
    for j, (pc, rng) in enumerate(entries):
        fde_va = va + 0x2000 + j * 0x1000
        disp = pc - fde_va - 8
        fde_blobs[fde_va - va] = struct.pack('<8x') + struct.pack('<i', disp) + struct.pack('<I', rng)
        table += struct.pack('<ii', pc - (va + hdr_off), fde_va - (va + hdr_off))
    shstr = b'\x00.eh_frame_hdr\x00.shstrtab\x00'
    shoff = 0x1000
    total = max(shoff + 3 * 64, max(fde_blobs) + 16 if fde_blobs else 0x1000)
    data = bytearray(total)
    data[0:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, 0x3E, 1, 0, 64, shoff, 0,
                     64, 56, 1, 64, 3, 2)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, va, va, len(data), len(data), 0x1000)
    data[hdr_off:hdr_off + len(table)] = table
    for off, blob in fde_blobs.items():
        data[off:off + len(blob)] = blob
    shstr_off = shoff + 3 * 64
    data[shstr_off:shstr_off + len(shstr)] = shstr

    def sh(name_off, typ, flags, addr, off, size):
        return struct.pack('<IIQQQQIIQQ', name_off, typ, flags, addr, off, size, 0, 0, 1, 0)
    secs = b'\x00' * 64
    secs += sh(1, 1, 0, va + hdr_off, hdr_off, len(table))
    secs += sh(15, 3, 0, 0, shstr_off, len(shstr))
    data[shoff:shoff + len(secs)] = secs
    return sr.Elf(bytes(data))


class FdeIndexDuplicateOverlapTests(unittest.TestCase):
    """fde_index() checked only that starts are sorted, so a duplicate
    start or an FDE ending past the next start passed silently and left
    containing() to resolve the overlap by bisect order alone. This is
    the state_roots sibling of open #496 (consensus_wire only) and #522
    (info_request_path only)."""

    def test_duplicate_fde_start_rejected(self):
        with self.assertRaisesRegex(sr.EvidenceError, 'duplicate FDE start'):
            sr.fde_index(synthetic_elf([(0x401000, 0x100), (0x401000, 0x100)]))

    def test_overlapping_fde_ranges_rejected(self):
        with self.assertRaisesRegex(sr.EvidenceError, 'overlapping next start'):
            sr.fde_index(synthetic_elf([(0x401000, 0x200), (0x401100, 0x100)]))

    def test_adjacent_fde_ranges_accepted(self):
        starts, ends = sr.fde_index(synthetic_elf([(0x401000, 0x100), (0x401100, 0x100)]))
        self.assertEqual((starts, ends), ([0x401000, 0x401100], [0x401100, 0x401200]))


if __name__ == "__main__":
    unittest.main()
