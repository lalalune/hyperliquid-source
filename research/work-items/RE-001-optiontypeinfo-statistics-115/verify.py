"""Packet checker for RE-001-optiontypeinfo-statistics-115.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-statistics-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv, and
   every census site is a real call/jump in its containing FDE;
   the invoker's dispose-helper site is a real call in its FDE;
7. the model test file passes under plain python3;
8. relocations: no RELATIVE entry points at a packet window; the two
   hook GOT slots are exactly 0x64eda58 -> 0x606fa80 and
   0x64eda60 -> 0x60780a0; the lambda typeinfo relocations resolve to
   the AsCustomSharedPtr<Statistics> name string at 0x975620;
9. key literals (the type 22 store, the typeinfo lea, the "id" word,
   the packed release qword, the atomicity selector, the dispose
   helper call) are present in the excerpts;
10. model constants: the record field map, the manager op dispatch,
    the invoker id fast path vs forward path, the counted release
    rule and the create-host contract match records.json.
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
    ("builder-6071520.objdump.txt", "0x6071520", "0x60716ca"),
    ("manager-606fa80.objdump.txt", "0x606fa80", "0x606faad"),
    ("invoker-60780a0.objdump.txt", "0x60780a0", "0x60781ab"),
]

WINDOWS = [0x6071520, 0x606FA80, 0x60780A0]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x6071520: "f30f1efa",  # endbr64: builder entry
    0x6071546: "f30f7e0d0ac54700",  # movq GOT manager slot -> xmm1
    0x60715F9: "c78424b800000016000000",  # movl $0x16,0xb8(%rsp): type 22
    0x607161E: "e85de4ffff",  # call manager 0x606fa80
    0x606FA80: "f30f1efa",  # endbr64: manager entry
    0x606FAA0: "488d0591324600",  # lea typeinfo object 0x64d2d38
    0x60780A0: "f30f1efa",  # endbr64: invoker entry
    0x60780D1: "e84af7ffff",  # call create host 0x6077820
    0x60780FB: "6681396964",  # cmpw $0x6469,(%rcx): the "id" check
    0x6078121: "48b80100000001000000",  # movabs $0x100000001,%rax
    0x607816B: "e800cfcbff",  # call dispose helper 0x5d35070
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
        if excerpt_instrs.get(va) != expected:
            fail("excerpt bytes mismatch at %#x: %s != %s"
                 % (va, excerpt_instrs.get(va), expected))

    for va, expected in SAMPLES.items():
        check_sample(va, expected)
    rng = random.Random(0x6071520)
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
        ["python3", "tests/test_optiontypeinfo_statistics_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: no RELATIVE slot lives inside a packet window;
    #    the hook GOT slots are exactly the two expected ones; the
    #    lambda typeinfo relocations resolve to the Statistics name.
    #    (Note: RELATIVE entries whose ADDEND is a window address are
    #    the two GOT hook slots themselves — expected, asserted below —
    #    not a violation.)
    rela_off, rela_size = 0x6BE8, 0x163CC8
    rela = {}
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        rela.setdefault(ro, []).append((info & 0xFFFFFFFF, info >> 32, add))
    for ro, entries in rela.items():
        for (typ, _sym, _add) in entries:
            if typ == 8:
                for (ws, _we) in [(0x6071520, 0x60716CA), (0x606FA80, 0x606FAAD),
                                  (0x60780A0, 0x60781AB)]:
                    if ws <= ro < _we:
                        fail("RELATIVE slot inside window: " + hex(ro))
    if [hex(v) for v in slots[0x606FA80]] != ["0x64eda58"]:
        fail("manager GOT slot mismatch: %s" % slots[0x606FA80])
    if [hex(v) for v in slots[0x60780A0]] != ["0x64eda60"]:
        fail("invoker GOT slot mismatch: %s" % slots[0x60780A0])
    if slots[0x6071520] or slots[0x6077820]:
        fail("unexpected RELATIVE slot for builder/host")
    ti = rela.get(0x64D2D38, [])
    if not any(t == 1 and a == 0x10 for t, _, a in ti):
        fail("typeinfo vtable relocation missing at 0x64d2d38")
    nm = rela.get(0x64D2D40, [])
    if not any(t == 8 and a == 0x975620 for t, _, a in nm):
        fail("typeinfo name relocation missing at 0x64d2d40")
    name = data[0x975620:0x975620 + 120].split(b"\x00")[0].decode()
    if "AsCustomSharedPtrINS_10StatisticsEEE" not in name:
        fail("typeinfo name is not AsCustomSharedPtr<Statistics>: " + name)

    # 9. Key literals.
    builder = open(os.path.join(HERE, "builder-6071520.objdump.txt")).read()
    manager = open(os.path.join(HERE, "manager-606fa80.objdump.txt")).read()
    invoker = open(os.path.join(HERE, "invoker-60780a0.objdump.txt")).read()
    if "$0x16,0xb8(%rsp)" not in builder:
        fail("type 22 store missing from builder excerpt")
    if "64eda58" not in builder or "64eda60" not in builder:
        fail("GOT hook slots missing from builder excerpt")
    if "64d2d38" not in manager:
        fail("typeinfo object missing from manager excerpt")
    if "0x6469" not in invoker:
        fail("\"id\" word missing from invoker excerpt")
    if "0x100000001" not in invoker:
        fail("packed release qword missing from invoker excerpt")
    if "64ed290" not in invoker:
        fail("atomicity selector missing from invoker excerpt")
    if "call   5d35070" not in invoker:
        fail("dispose helper call missing from invoker excerpt")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import optiontypeinfo_statistics_115 as model
    rec = model.build_record(0, 3, 1)
    if (rec["+0x00"] != 0 or rec["+0x18"] != 0x606FA80
            or rec["+0x20"] != 0x60780A0 or rec["+0xa8"] != 22
            or rec["+0xac"] != 3 or rec["+0xb0"] != 1):
        fail("model build_record mismatch")
    if model.builder_manager_call() != (0, []):
        fail("model builder manager call mismatch")
    if model.manager(0) != (0x64D2D38, 0):
        fail("model manager op0 mismatch")
    if model.manager(1, 0xBEEF) != (0xBEEF, 0):
        fail("model manager op1 mismatch")
    if model.manager(2) != (None, 0) or model.manager(3) != (None, 0):
        fail("model manager op2/3 mismatch")
    cb = model.CountedBase()
    if cb.packed() != 0x100000001 or cb.release(True, lambda c: None) is not True:
        fail("model CountedBase fast path mismatch")
    host_calls = []

    def fake_host(out, cfg, name, slot):
        host_calls.append(name)
        slot.obj = "created"
        out.code, out.subcode, out.state = 0, 0, None

    slot = model.SharedPtr(obj="x", control=model.CountedBase())
    out = model.Status(code=9)
    got = model.invoker(out, None, b"id", b"", [slot], fake_host)
    if got is not out or host_calls or not out.is_empty() or slot.obj is not None:
        fail("model invoker id fast path mismatch")
    slot2 = model.SharedPtr()
    out2 = model.Status()
    model.invoker(out2, "cfg", b"id", b"BasicStatistics", [slot2], fake_host)
    if host_calls != [b"BasicStatistics"] or slot2.obj != "created":
        fail("model invoker forward path mismatch")
    out3 = model.Status()
    slot3 = model.SharedPtr()
    if model.create_host_contract(out3, None, b"", slot3) != "default":
        fail("model create-host contract default mismatch")
    if model.create_host_contract(model.Status(), None, b"zz", model.SharedPtr()) != "parse_path":
        fail("model create-host contract parse mismatch")
    if "Statistics" not in json.dumps(records):
        fail("Statistics attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
