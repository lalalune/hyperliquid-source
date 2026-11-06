"""Packet checker for RE-001-fragmented-tombstone-iterator-115.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-tombstone-iterator-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv, and
   every census site is a real call/jump in its containing FDE;
   the generic helpers' in-packet sites are real calls in their FDEs;
7. the model test file passes under plain python3;
8. relocations: the RELATIVE entries pointing at a packet window or
   census target are exactly the vtable/GOT slots recorded in
   records.json; the iterator vtables resolve to the recorded
   typeinfo names and slots (fragmented 24-slot map exact,
   MemTableIterator shared slots, comparator slots 25/26);
9. key literals (the 0x0f type byte, the AppendInternalKey call, the
   paddq constant, the 0x100000001 packed counts, the 0xc8 delete
   size, the GOT slot addresses) are present in the excerpts;
10. model constants: the layout sizes, the key build, the clamp
    (builtin no-op, timestamped cut), the two end variants, and an
    end-to-end seek/key/maxseq/dtor flow match records.json.
Prints ALL CHECKS PASSED or the first failure.
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

EXCERPTS = [
    ("maxseq-5f32900.objdump.txt", "0x5f32900", "0x5f32a0a"),
    ("seek-covering-5f316d0.objdump.txt", "0x5f316d0", "0x5f31973"),
    ("seekforprev-covering-5f31980.objdump.txt", "0x5f31980", "0x5f31c7d"),
    ("scan-forward-5f31c80.objdump.txt", "0x5f31c80", "0x5f31ead"),
    ("seek-top-first-5f31eb0.objdump.txt", "0x5f31eb0", "0x5f32099"),
    ("seek-5f320a0.objdump.txt", "0x5f320a0", "0x5f320e1"),
    ("scan-backward-5f320f0.objdump.txt", "0x5f320f0", "0x5f3230b"),
    ("seek-top-last-5f32310.objdump.txt", "0x5f32310", "0x5f324ea"),
    ("seekforprev-5f324f0.objdump.txt", "0x5f324f0", "0x5f32531"),
    ("topnext-5f32540.objdump.txt", "0x5f32540", "0x5f32719"),
    ("topprev-5f32720.objdump.txt", "0x5f32720", "0x5f328fa"),
    ("dtor-d1-5f32a10.objdump.txt", "0x5f32a10", "0x5f32b7d"),
    ("dtor-d0-5f32b80.objdump.txt", "0x5f32b80", "0x5f32cfd"),
    ("valid-5f2e8f0.objdump.txt", "0x5f2e8f0", "0x5f2e90e"),
    ("seektofirst-5f2e8d0.objdump.txt", "0x5f2e8d0", "0x5f2e8e9"),
    ("seektolast-5f2ee70.objdump.txt", "0x5f2ee70", "0x5f2ee92"),
    ("next-5f2eea0.objdump.txt", "0x5f2eea0", "0x5f2eee4"),
    ("prev-5f2eef0.objdump.txt", "0x5f2eef0", "0x5f2ef60"),
    ("key-5eba980.objdump.txt", "0x5eba980", "0x5ebaa54"),
    ("value-endkey-5eba910.objdump.txt", "0x5eba910", "0x5eba924"),
    ("nextandgetresult-5df7ce0.objdump.txt", "0x5df7ce0", "0x5df7d24"),
    ("slot11-userkey-5df7650.objdump.txt", "0x5df7650", "0x5df7667"),
    ("status-5f2e7b0.objdump.txt", "0x5f2e7b0", "0x5f2e7cc"),
    ("ret1-a-5df7670.objdump.txt", "0x5df7670", "0x5df767a"),
    ("ret1-b-5df7680.objdump.txt", "0x5df7680", "0x5df768a"),
    ("ret0-a-5df7690.objdump.txt", "0x5df7690", "0x5df7697"),
    ("voidret-5d485b0.objdump.txt", "0x5d485b0", "0x5d485b5"),
    ("ret0-b-5f2e790.objdump.txt", "0x5f2e790", "0x5f2e797"),
    ("ret1-c-5f2e7a0.objdump.txt", "0x5f2e7a0", "0x5f2e7aa"),
    ("status-builder-5df7800.objdump.txt", "0x5df7800", "0x5df7871"),
    ("voidret-b-5df76d0.objdump.txt", "0x5df76d0", "0x5df76d5"),
    ("voidret-c-5df76e0.objdump.txt", "0x5df76e0", "0x5df76e5"),
    ("ret0-c-5df7640.objdump.txt", "0x5df7640", "0x5df7647"),
]

WINDOWS = [0x5F32900, 0x5F316D0, 0x5F31980, 0x5F31C80, 0x5F31EB0, 0x5F320A0,
           0x5F320F0, 0x5F32310, 0x5F324F0, 0x5F32540, 0x5F32720, 0x5F32A10,
           0x5F32B80, 0x5F2E8F0, 0x5F2E8D0, 0x5F2EE70, 0x5F2EEA0, 0x5F2EEF0,
           0x5EBA980, 0x5EBA910, 0x5DF7CE0, 0x5DF7650, 0x5F2E7B0, 0x5DF7670,
           0x5DF7680, 0x5DF7690, 0x5D485B0, 0x5F2E790, 0x5F2E7A0, 0x5DF7800,
           0x5DF76D0, 0x5DF76E0, 0x5DF7640]

# The exact 24-slot FragmentedRangeTombstoneIterator vtable map.
FRAGMENTED_SLOTS = [
    0x5F32A10, 0x5F32B80, 0x5F2E8F0, 0x5F2E8D0, 0x5F2EE70, 0x5F320A0,
    0x5F324F0, 0x5F2EEA0, 0x5DF7CE0, 0x5F2EEF0, 0x5EBA980, 0x5DF7650,
    0x5EBA910, 0x5F2E7B0, 0x5DF7670, 0x5DF7680, 0x5DF7690, 0x5D485B0,
    0x5F2E790, 0x5F2E7A0, 0x5DF7800, 0x5DF76D0, 0x5DF76E0, 0x5DF7640,
]
# Slots shared with the MemTableIterator vtable (same addresses).
SHARED_SLOTS = [11, 14, 15, 16, 17, 20, 21, 22, 23]
# MemTableIterator slots that differ from the fragmented map.
MEMTABLE_DIFFERS = {8: 0x5F08790, 10: 0x5F05E10, 12: 0x5F05E80,
                    13: 0x5F05680, 18: 0x5F04E00, 19: 0x5F04E10}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5F32900: "f30f1efa",  # endbr64: MaxCoveringTombstoneSeqnum entry
    0x5F32920: "e8abedffff",  # call SeekToCoveringTombstone 0x5f316d0
    0x5F316D0: "f30f1efa",  # endbr64: SeekToCoveringTombstone entry
    0x5F31980: "f30f1efa",  # endbr64: SeekForPrevToCoveringTombstone entry
    0x5F31C80: "f30f1efa",  # endbr64: ScanForward entry
    0x5F31EB0: "f30f1efa",  # endbr64: SeekToTopFirst entry
    0x5F320A0: "f30f1efa",  # endbr64: Seek entry
    0x5F320F0: "f30f1efa",  # endbr64: ScanBackward entry
    0x5F32310: "f30f1efa",  # endbr64: SeekToTopLast entry
    0x5F324F0: "f30f1efa",  # endbr64: SeekForPrev entry
    0x5F32540: "f30f1efa",  # endbr64: TopNext entry
    0x5F32720: "f30f1efa",  # endbr64: TopPrev entry
    0x5F32A10: "f30f1efa",  # endbr64: D1 entry
    0x5F32A1D: "488d05bca05900",  # lea vtable 0x64ccae0 (D1 reset)
    0x5F32A5F: "48b80100000001000000",  # movabs $0x100000001 (D1 cache release)
    0x5F32B80: "f30f1efa",  # endbr64: D0 entry
    0x5F32B8D: "488d054c9f5900",  # lea vtable 0x64ccae0 (D0 reset)
    0x5F32BCF: "48b80100000001000000",  # movabs $0x100000001 (D0 cache release)
    0x5F2E8F0: "f30f1efa",  # endbr64: Valid entry
    0x5F2E8F4: "488b5768",  # mov 0x68(%rdi),%rdx (Valid list load)
    0x5F2E8D0: "f30f1efa",  # endbr64: SeekToFirst entry
    0x5F2E8D4: "488b4768",  # mov 0x68(%rdi),%rax (SeekToFirst list load)
    0x5F2EE70: "f30f1efa",  # endbr64: SeekToLast entry
    0x5F2EE82: "660fd405564752fa",  # paddq -0x5adb8aa(%rip) (the (-48,-8) constant)
    0x5F2EEA0: "f30f1efa",  # endbr64: Next entry
    0x5F2EEF0: "f30f1efa",  # endbr64: Prev entry
    0x5EBA980: "f30f1efa",  # endbr64: key() entry
    0x5EBA9CA: "c64424180f",  # movb $0xf,0x18(%rsp) (the 0x0f type byte)
    0x5EBA9F7: "e864f6feff",  # call AppendInternalKey 0x5eaa060
    0x5EBA910: "f30f1efa",  # endbr64: value() entry
    0x5DF7CE0: "f30f1efa",  # endbr64: NextAndGetResult entry
    0x5DF7650: "f30f1efa",  # endbr64: slot-11 entry
    0x5F2E7B0: "f30f1efa",  # endbr64: status() entry
    0x5DF7670: "f30f1efa",  # endbr64: ret-1 stub
    0x5DF7690: "f30f1efa",  # endbr64: ret-0 stub
    0x5D485B0: "f30f1efa",  # endbr64: void no-op
    0x5DF7800: "f30f1efa",  # endbr64: Status builder entry
    0x61BDC40: "f30f1efa",  # endbr64: Bytewise CompareWithoutTimestamp entry
    0x61BDC44: "55",  # push %rbp
    0x61BDC90: "f30f1efa",  # endbr64: Reverse CompareWithoutTimestamp entry
    0x5D48400: "f30f1efa",  # endbr64: builtin CompareTimestamp entry
    0x5D48404: "31c0",  # xor %eax,%eax (the builtin returns 0)
    0x5D48410: "f30f1efa",  # endbr64: slot-0xd0 fast-path thunk entry
    0x5D48414: "488b4720",  # mov 0x20(%rdi),%rax (the thunk loads Q)
    0x5EAA060: "f30f1efa",  # endbr64: AppendInternalKey entry
    0x5EAA066: "49bcffffffffffffff3f",  # movabs $0x3fffffffffffffff (wrapped bytes)
}

INSTR_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]*?)\t(.*)$")
CONT_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*$")


def parse_instructions(text):
    """objdump text -> {va: bytes-hex}, joining wrapped byte lines."""
    out = {}
    last = None
    for line in text.splitlines():
        m = INSTR_RE.match(line)
        if m:
            va = int(m.group(1), 16)
            raw = m.group(2).replace(" ", "")
            rest = m.group(3).strip()
            if rest == "" and last is not None:
                out[last] += raw
            else:
                out[va] = raw
                last = va
            continue
        # Wrapped long instruction: address + bytes, no mnemonic tab.
        m2 = CONT_RE.match(line)
        if m2 and last is not None:
            out[last] += m2.group(2).replace(" ", "")
    return out


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.load(open(os.path.join(ROOT, "provenance/artifacts.json")))
    paths = [f for f in prov["files"] if f["path"] == "artifacts/node/115/hl-node"]
    if not paths or paths[0]["sha256"] != DIGEST:
        fail("provenance digest mismatch")

    # 2. Manifest.
    manifest = {}
    with open(os.path.join(HERE, "MANIFEST.sha256")) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            digest, name = line.split(None, 1)
            manifest[name.strip()] = digest
    on_disk = sorted(
        f for f in os.listdir(HERE)
        if f != "MANIFEST.sha256" and f != "__pycache__"
        and os.path.isfile(os.path.join(HERE, f)))
    if sorted(manifest) != on_disk:
        fail("manifest file set mismatch: manifest=%s disk=%s"
             % (sorted(manifest), on_disk))
    for name, digest in manifest.items():
        got = hashlib.sha256(open(os.path.join(HERE, name), "rb").read()).hexdigest()
        if got != digest:
            fail("manifest digest mismatch for " + name)

    # 3. Excerpts regenerate byte-identically.
    excerpt_instrs = {}
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        disk = open(os.path.join(HERE, name)).read()
        if out != disk:
            fail("excerpt mismatch: " + name)
        excerpt_instrs.update(parse_instructions(disk))

    # 4. Fixed samples + 3 seeded random gate spots, vs fresh objdump
    #    and the raw binary.
    def check_sample(va, expected):
        off = va - 0x1000
        raw = data[off:off + len(bytes.fromhex(expected))].hex()
        if raw != expected:
            fail("raw binary mismatch at %#x: %s != %s" % (va, raw, expected))
        if va in excerpt_instrs:
            if excerpt_instrs[va] != expected:
                fail("excerpt bytes mismatch at %#x: %s != %s"
                     % (va, excerpt_instrs[va], expected))
        else:
            # No excerpt covers this address (a census target, not a
            # window): confirm it against a fresh objdump run instead.
            out = subprocess.run(
                ["objdump", "-d",
                 "--start-address=" + hex(va),
                 "--stop-address=" + hex(va + 0x20), BIN],
                cwd=ROOT, capture_output=True, text=True, check=True,
            ).stdout
            if parse_instructions(out).get(va) != expected:
                fail("fresh objdump mismatch at %#x" % va)

    for va, expected in SAMPLES.items():
        check_sample(va, expected)
    rng = random.Random(0x5F32900)
    spots = rng.sample(sorted(excerpt_instrs), 3)
    for va in spots:
        check_sample(va, excerpt_instrs[va])
    print("gate spots checked:", ", ".join(hex(v) for v in spots))

    # 5. Frames.
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    frames_disk = open(os.path.join(HERE, "frames.txt")).read()
    for line in frames_disk.splitlines():
        if re.match(r"^[0-9a-f]{8} \S+ \S+ FDE ", line):
            if line not in frames:
                fail("FDE line missing from fresh frames dump: " + line)

    # 6. Census reproduces records.json and callers.tsv; every site is
    #    a real call/jump in its containing FDE.
    sys.path.insert(0, HERE)
    import census as census_mod
    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, BIN))
    records = json.load(open(os.path.join(HERE, "records.json")))
    if records["artifact_sha256"] != DIGEST:
        fail("records.json digest mismatch")
    for t in census_mod.TARGETS:
        want = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
        if records["census"].get(hex(t)) != want:
            fail("census mismatch in records.json for " + hex(t))
    tsv_lines = open(os.path.join(HERE, "callers.tsv")).read().splitlines()[1:]
    want_rows = set()
    for t in census_mod.TARGETS:
        for v in calls[t]:
            want_rows.add((hex(t), hex(v), "direct_call"))
        for v in tails[t]:
            want_rows.add((hex(t), hex(v), "tail_jump"))
    got_rows = set()
    for line in tsv_lines:
        parts = line.split("\t")
        got_rows.add((parts[0], parts[1], parts[2]))
    if got_rows != want_rows:
        fail("callers.tsv rows mismatch")
    # Site verification: disassemble each distinct containing FDE once
    # and confirm the call/jump instruction at the site.
    fde_cache = {}

    def check_site(tgt, site_hex, kind, fs, fe):
        if fs is None:
            fail("site without containing FDE: " + site_hex)
        key = (fs, fe)
        if key not in fde_cache:
            fde_cache[key] = subprocess.run(
                ["objdump", "-d",
                 "--start-address=" + fs, "--stop-address=" + fe, BIN],
                cwd=ROOT, capture_output=True, text=True, check=True,
            ).stdout
        k = "call" if kind == "direct_call" else "jmp"
        pat = re.compile(
            r"^\s+%x:\t[0-9a-f ]+\t%s\s+%x\b"
            % (int(site_hex, 16), k, tgt), re.M)
        if not pat.search(fde_cache[key]):
            fail("site not a real %s in its FDE: target %#x site %s"
                 % (k, tgt, site_hex))

    for t_hex, row in records["callers"].items():
        tgt = int(t_hex, 16)
        for site in row:
            fs, fe = site["containing_fde"]
            check_site(tgt, site["site"], site["kind"], fs, fe)
    for t_hex, row in records["packet_internal_sites"].items():
        tgt = int(t_hex, 16)
        for site in row:
            fs, fe = site["containing_fde"]
            check_site(tgt, site["site"], site["kind"], fs, fe)

    # 7. Model tests.
    test = subprocess.run(
        ["python3", "tests/test_fragmented_tombstone_iterator_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: the RELATIVE entries pointing at a packet window
    #    or census target are exactly the recorded vtable/GOT slots.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    expected_slots = {}
    for t in census_mod.TARGETS:
        for s in records["census"][hex(t)]["relative_slots"]:
            expected_slots.setdefault(int(s, 16), set()).add(t)
    got_slots = {}
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        if (info & 0xFFFFFFFF) == 8 and add in census_mod.TARGETS:
            got_slots.setdefault(ro, set()).add(add)
    if got_slots != expected_slots:
        fail("RELATIVE slots mismatch: got %s expected %s"
             % (sorted(got_slots), sorted(expected_slots)))
    # Every recorded relative slot is a vtable or GOT slot in
    # vtable_slot_owners, and vice versa.
    for t_hex, owners in records["vtable_slot_owners"].items():
        t = int(t_hex, 16)
        owner_slots = sorted(int(o["slot"], 16) for o in owners)
        if owner_slots != sorted(int(s, 16) for s in
                                 records["census"][t_hex]["relative_slots"]):
            fail("vtable_slot_owners mismatch for " + t_hex)
    # Vtable resolutions: typeinfo names, slot counts, exact maps.
    vt = records["vtables"]
    if vt["fragmented_range_tombstone_iterator"]["typeinfo_name"] != \
            "N7rocksdb32FragmentedRangeTombstoneIteratorE":
        fail("FragmentedRangeTombstoneIterator typeinfo mismatch")
    frag_slots = [int(s["target"], 16)
                  for s in vt["fragmented_range_tombstone_iterator"]["slots"]]
    if frag_slots != FRAGMENTED_SLOTS:
        fail("fragmented vtable slot map mismatch")
    if vt["memtable_iterator"]["typeinfo_name"] != "N7rocksdb16MemTableIteratorE":
        fail("MemTableIterator typeinfo mismatch")
    mem_slots = [int(s["target"], 16)
                 for s in vt["memtable_iterator"]["slots"]]
    if len(mem_slots) != 24:
        fail("MemTableIterator slot count mismatch")
    for i in SHARED_SLOTS:
        if mem_slots[i] != frag_slots[i]:
            fail("shared slot %d differs between the iterator vtables" % i)
    for i, want in MEMTABLE_DIFFERS.items():
        if mem_slots[i] != want:
            fail("MemTableIterator slot %d mismatch" % i)
    if vt["bytewise_comparator"]["typeinfo_name"] != \
            "*N7rocksdb12_GLOBAL__N_122BytewiseComparatorImplE":
        fail("BytewiseComparator typeinfo mismatch")
    bw_slots = [int(s["target"], 16)
                for s in vt["bytewise_comparator"]["slots"]]
    if len(bw_slots) != 29 or bw_slots[25] != 0x5D48400 or bw_slots[26] != 0x61BDC40:
        fail("BytewiseComparator slot map mismatch")
    if vt["reverse_bytewise_comparator"]["typeinfo_name"] != \
            "*N7rocksdb12_GLOBAL__N_129ReverseBytewiseComparatorImplE":
        fail("ReverseBytewiseComparator typeinfo mismatch")
    rv_slots = [int(s["target"], 16)
                for s in vt["reverse_bytewise_comparator"]["slots"]]
    if len(rv_slots) != 29 or rv_slots[25] != 0x5D48400 or rv_slots[26] != 0x61BDC90:
        fail("ReverseBytewiseComparator slot map mismatch")
    if records["vtable"]["slot_count"] != 24:
        fail("records vtable slot count mismatch")
    if records["vtable"]["base"] != "0x64ccae0" or \
            records["vtable"]["stored_pointer"] != "0x64ccaf0":
        fail("records vtable base/stored pointer mismatch")

    # 9. Key literals.
    key_ex = open(os.path.join(HERE, "key-5eba980.objdump.txt")).read()
    if "movb   $0xf,0x18(%rsp)" not in key_ex:
        fail("0x0f type byte missing from key() excerpt")
    if "call   5eaa060" not in key_ex:
        fail("AppendInternalKey call missing from key() excerpt")
    seektolast = open(os.path.join(HERE, "seektolast-5f2ee70.objdump.txt")).read()
    if "paddq" not in seektolast or "4535e0" not in seektolast:
        fail("paddq constant missing from SeekToLast excerpt")
    dtor_d1 = open(os.path.join(HERE, "dtor-d1-5f32a10.objdump.txt")).read()
    if "movabs $0x100000001,%rax" not in dtor_d1:
        fail("0x100000001 packed counts missing from D1 excerpt")
    if "64ccae0" not in dtor_d1:
        fail("iterator vtable missing from D1 excerpt")
    dtor_d0 = open(os.path.join(HERE, "dtor-d0-5f32b80.objdump.txt")).read()
    if "movabs $0x100000001,%rax" not in dtor_d0:
        fail("0x100000001 packed counts missing from D0 excerpt")
    if "mov    $0xc8,%esi" not in dtor_d0:
        fail("0xc8 delete size missing from D0 excerpt")
    seek_covering = open(os.path.join(HERE, "seek-covering-5f316d0.objdump.txt")).read()
    if "64ecfa8" not in seek_covering or "64ecfb0" not in seek_covering:
        fail("comparator GOT slots missing from SeekToCoveringTombstone excerpt")
    valid_ex = open(os.path.join(HERE, "valid-5f2e8f0.objdump.txt")).read()
    if "0x68(%rdi)" not in valid_ex or "0x88(%rdi)" not in valid_ex:
        fail("Valid list/position loads missing from Valid excerpt")

    # 10. Model constants.
    if records["layout"]["iterator_size_bytes"] != 200:
        fail("records iterator size mismatch")
    if records["layout"]["fragment_size_bytes"] != 48:
        fail("records fragment size mismatch")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import fragmented_tombstone_iterator_115 as model
    if model.pack_sequence_and_type(0x1234, 0x0F) != bytes.fromhex("0f34120000000000"):
        fail("model PackSequenceAndType mismatch")
    if model.TYPE_RANGE_DELETION != 0x0F:
        fail("model kTypeRangeDeletion mismatch")
    bw = model.BytewiseComparator()
    ts = model.TimestampedComparator()
    fl = model.FragmentList(
        [model.Fragment(b"b", b"d", 0, 2), model.Fragment(b"d", b"f", 2, 3)],
        [30, 20, 25], [b"o", b"p", b"m"])
    it = model.FragmentedRangeTombstoneIterator(fl, bw, 100, arg6=0)
    it.seek(b"c")
    if (it.frag, it.seq_idx) != (0, 0):
        fail("model seek mismatch")
    if it.key() != b"b" + model.pack_sequence_and_type(30, 0x0F):
        fail("model key() mismatch")
    if it.max_covering_tombstone_seqnum(b"c") != 30:
        fail("model max_covering_tombstone_seqnum mismatch")
    it2 = model.FragmentedRangeTombstoneIterator(fl, bw, 100, arg6=0)
    it2.seek_for_prev_to_covering_tombstone(b"a")
    if (it2.frag, it2.seq_idx) != (None, 0):
        fail("model no-covering end variant mismatch")
    it3 = model.FragmentedRangeTombstoneIterator(
        model.FragmentList([], [], []), bw, 100)
    it3.seek_to_covering_tombstone(b"a")
    if (it3.frag, it3.seq_idx) != (None, 0):
        fail("model empty-list end variant mismatch")
    it4 = model.FragmentedRangeTombstoneIterator(fl, ts, 100, upper_bound=b"n")
    it4.frag, it4.seq_idx = 0, 0
    it4._clamp(0)
    if it4.seq_idx != 2:
        fail("model timestamped clamp mismatch")
    it5 = model.FragmentedRangeTombstoneIterator(fl, bw, 100, upper_bound=b"z")
    it5.frag, it5.seq_idx = 0, 0
    it5._clamp(0)
    if it5.seq_idx != 0:
        fail("model builtin clamp should be a no-op")
    it6 = model.FragmentedRangeTombstoneIterator(fl, bw, 100)
    it6.seek_to_first()
    trace = it6.destroy(delete_self=True)
    if trace[-1] != "operator_delete_this_0xc8":
        fail("model D0 trace mismatch")
    if "MemTable" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
