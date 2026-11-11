"""Packet checker for RE-001-zstd-compress-cache-115.

Run from the repository root:
    python3 research/work-items/RE-001-zstd-compress-cache-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv, and
   every census site is a real call/jump in its containing FDE;
7. the model test file passes under plain python3;
8. relocations: no RELATIVE entry points at a packet window;
   the factory table lea and the template global are present;
9. key literals (calloc size, init pair, setParameter 201, the
   param-201 arm, the template qwords) are present in the excerpts;
10. model constants: the bounds table and the apply arm map match
    records.json, and the jump tables re-decode to the recorded arms.
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
    ("factory-61c1c10.objdump.txt", "0x61c1c10", "0x61c1cc8"),
    ("factory-landing-61c1bee.objdump.txt", "0x61c1bee", "0x61c1c03"),
    ("create-cctx-6218920.objdump.txt", "0x6218920", "0x6218996"),
    ("reset-62188a0.objdump.txt", "0x62188a0", "0x621891a"),
    ("free-cdict-62187a0.objdump.txt", "0x62187a0", "0x621889b"),
    ("setparam-6212010.objdump.txt", "0x6212010", "0x6212101"),
    ("apply-6211a10.objdump.txt", "0x6211a10", "0x621200c"),
    ("range-check-62119e0.objdump.txt", "0x62119e0", "0x6211a08"),
    ("bounds-62117e0.objdump.txt", "0x62117e0", "0x62119d9"),
    ("refresh-5f041d0.objdump.txt", "0x5f041d0", "0x5f0441c"),
]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x61C1C10: "f30f1efa",  # endbr64: factory entry
    0x61C1C20: "4080ff07",  # cmp $0x7,%dil: the kind gate
    0x61C1C3B: "bf70000000",  # mov $0x70,%edi: holder size
    0x61C1C83: "e8986c0500",  # call createCCtx 0x6218920
    0x61C1C94: "bec9000000",  # mov $0xc9,%esi: parameter 201
    0x61C1C99: "e872030500",  # call setParameter 0x6212010
    0x61C1BEE: "4889df",  # mov %rbx,%rdi: landing pad deletes the holder
    0x6218920: "f30f1efa",  # endbr64: create entry
    0x621892A: "bf80140000",  # mov $0x1480,%edi: calloc size
    0x6218934: "e8f7901d00",  # call calloc
    0x6218947: "83f806",  # cmp $0x6,%eax: cpuid leaf gate
    0x621898B: "81e308010000",  # and $0x108,%ebx: BMI1+BMI2 mask
    0x6218968: "c7453c03000000",  # movl $0x3,0x3c(%rbp)
    0x621896F: "c7453001000000",  # movl $0x1,0x30(%rbp)
    0x62188A0: "53",  # push %rbx: reset entry
    0x62188CC: "e8cffeffff",  # call freeCDict 0x62187a0
    0x62187A0: "f30f1efa",  # endbr64: freeCDict entry
    0x6212010: "f30f1efa",  # endbr64: setter entry
    0x621201E: "83fe64",  # cmp $0x64,%esi: param 100 in the flagged gate
    0x621202B: "c7470401000000",  # movl $0x1,0x4(%rdi): dirty flag
    0x6211A10: "f30f1efa",  # endbr64: apply entry
    0x6211A3F: "488d15daf376fa",  # lea jump table 0x980e20
    0x6211F5D: "31c0",  # xor %eax,%eax: param-201 arm entry
    0x6211F65: "894724",  # mov %eax,0x24(%rdi): param-201 store
    0x62119E0: "4883ec08",  # sub $0x8,%rsp: range-check entry
    0x62117E0: "f30f1efa",  # endbr64: bounds entry
    0x6211992: "ba0000feff",  # mov $0xfffe0000,%edx: level lo -131072
    0x5F041D0: "f30f1efa",  # endbr64: refresh entry
    0x5F0430B: "e800d92b00",  # call factory 0x61c1c10
    0x5F042E7: "48b80000000001000000",  # movabs $0x100000000,%rax
    0x6211FC0: "89d6",  # mov %edx,%esi: param-10 arm entry
    0x6211D5F: "bf64000000",  # mov $0x64,%edi: param-100 arm entry
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
        if f != "MANIFEST.sha256" and os.path.isfile(os.path.join(HERE, f)))
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
        if excerpt_instrs.get(va) != expected:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (va, excerpt_instrs.get(va), expected))

    for va, expected in SAMPLES.items():
        check_sample(va, expected)
    rng = random.Random(0x61C1C10)
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
    for t_hex, row in records["callers"].items():
        tgt = int(t_hex, 16)
        for site in row:
            fs, fe = site["containing_fde"]
            if fs is None:
                fail("site without containing FDE: " + site["site"])
            key = (fs, fe)
            if key not in fde_cache:
                fde_cache[key] = subprocess.run(
                    ["objdump", "-d",
                     "--start-address=" + fs, "--stop-address=" + fe, BIN],
                    cwd=ROOT, capture_output=True, text=True, check=True,
                ).stdout
            kind = "call" if site["kind"] == "direct_call" else "jmp"
            pat = re.compile(
                r"^\s+%x:\t[0-9a-f ]+\t%s\s+%x\b"
                % (int(site["site"], 16), kind, tgt), re.M)
            if not pat.search(fde_cache[key]):
                fail("site not a real %s in its FDE: target %#x site %s"
                     % (kind, tgt, site["site"]))

    # 7. Model tests.
    test = subprocess.run(
        ["python3", "tests/test_zstd_compress_cache_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: no RELATIVE entry points at a packet window.
    for t in census_mod.TARGETS:
        if slots[t]:
            fail("unexpected RELATIVE slot for " + hex(t))
    factory = open(os.path.join(HERE, "factory-61c1c10.objdump.txt")).read()
    if "64d7408" not in factory:
        fail("factory table lea missing from factory excerpt")
    refresh = open(os.path.join(HERE, "refresh-5f041d0.objdump.txt")).read()
    if "459aa0" not in refresh:
        fail("template global missing from refresh excerpt")

    # 9. Key literals.
    create = open(os.path.join(HERE, "create-cctx-6218920.objdump.txt")).read()
    if "1480" not in create:
        fail("calloc size missing from create excerpt")
    if "movl   $0x1,0x30(%rbp)" not in create:
        fail("+0x30 = 1 missing from create excerpt")
    if "movl   $0x3,0x3c(%rbp)" not in create:
        fail("+0x3c = 3 missing from create excerpt")
    if "6212010" not in factory:
        fail("setParameter call missing from factory excerpt")
    apply_txt = open(os.path.join(HERE, "apply-6211a10.objdump.txt")).read()
    if "980e20" not in apply_txt or "980fbc" not in apply_txt:
        fail("jump tables missing from apply excerpt")
    if "0x24(%rdi)" not in apply_txt:
        fail("param-201 store missing from apply excerpt")
    if "100000000" not in refresh:
        fail("template 0x100000000 missing from refresh excerpt")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import zstd_compress_cache_115 as model
    if {int(k): tuple(v) for k, v in records["bounds"]["table"].items()} != model.BOUNDS:
        fail("model BOUNDS mismatch vs records.json")
    model_arms = {}
    for p, (off, kind) in model._APPLY_ARMS.items():
        model_arms[str(p)] = {"field": "+0x%02x" % off, "kind": kind}
    for p, arm in model_arms.items():
        rec = records["apply"]["arms"].get(p)
        if rec is None or rec["field"] != arm["field"]:
            fail("model apply arm mismatch for param " + p)
    if model.create_cctx(7, 0x108)["fields"][0x08] != 1:
        fail("model create_cctx feature flag mismatch")
    if model.TEMPLATE_QWORDS != (0x7FFFFFFFFFF2, 0, 0x100000000, 0, 0, 1):
        fail("model template mismatch")
    if model.make_holder(7, model.TEMPLATE_QWORDS, 2, 0x7FF5,
                         lambda: model.create_cctx(7, 0x108),
                         model.set_parameter) is None:
        fail("model make_holder mismatch")
    # Jump tables re-decode to the recorded arms.
    def table_entry(base, idx):
        return base + struct.unpack_from("<i", data, base + 4 * idx)[0]
    if table_entry(0x980E20, 201 - 100) != 0x6211F5D:
        fail("apply table param 201 mismatch")
    if table_entry(0x980E20, 100 - 100) != 0x6211D5F:
        fail("apply table param 100 mismatch")
    if table_entry(0x980E20, 202 - 100) != 0x6211D49:
        fail("apply table param 202 mismatch")
    if table_entry(0x980FBC, 1016 - 1000) != 0x6211AA0:
        fail("apply table param 1016 mismatch")
    if table_entry(0x980C84, 100 - 100) != 0x6211990:
        fail("bounds table param 100 mismatch")
    if table_entry(0x980C84, 130 - 100) != 0x621196E:
        fail("bounds table param 130 mismatch")
    if "StreamingCompress" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
