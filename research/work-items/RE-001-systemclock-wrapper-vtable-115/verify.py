"""Packet checker for RE-001-systemclock-wrapper-vtable-115.

Run from the repository root:
    python3 research/work-items/RE-001-systemclock-wrapper-vtable-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically (including the ctor
   re-shipped from #3352);
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv, and
   every census site is a real call/jump in its containing FDE;
   the generic helpers' in-packet sites are real calls in their FDEs;
7. the model test file passes under pytest;
8. relocations: the RELATIVE entries pointing at a packet window or
   census target are exactly the vtable/GOT slots recorded in
   records.json; the three vtables resolve to the recorded typeinfo
   names and slots (wrapper 26-slot map exact with nulls at 0/1/14,
   emulated shared slots, posix shared/differing slots);
9. key literals (the "id" compare, the chain-walk GOT canonicals,
   the forwarding offsets, the name literals, the vtable-install
   lea, the lock-addl counters) are present in the excerpts;
10. model constants: the wrapper size, the chain-walk rule
    (first-differing level, 9th level, off-the-end), the forwarding,
    GetOption/AreEquivalent/PrepareOptions/GetId and the emulated
    offsets/counters match records.json.
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
    ("getoption-609d760.objdump.txt", "0x609d760", "0x609d954"),
    ("areequivalent-609dc40.objdump.txt", "0x609dc40", "0x609de39"),
    ("slot04-emptystring-5d32560.objdump.txt", "0x5d32560", "0x5d3257b"),
    ("prepareoptions-5fcf590.objdump.txt", "0x5fcf590", "0x5fcf658"),
    ("validateoptions-6096790.objdump.txt", "0x6096790", "0x6096f0c"),
    ("getoptionsptr-5d2e090.objdump.txt", "0x5d2e090", "0x5d2e0de"),
    ("slot08-emptystatus-60956f0.objdump.txt", "0x60956f0", "0x609570c"),
    ("configureoptions-609d0e0.objdump.txt", "0x609d0e0", "0x609d75e"),
    ("parseoption-60986b0.objdump.txt", "0x60986b0", "0x6098a9c"),
    ("optionsareequal-6095710.objdump.txt", "0x6095710", "0x609579a"),
    ("serializeoptions-5fcdae0.objdump.txt", "0x5fcdae0", "0x5fcdf63"),
    ("getoptionname-609d980.objdump.txt", "0x609d980", "0x609dc18"),
    ("getid-5d32a30.objdump.txt", "0x5d32a30", "0x5d32a51"),
    ("slot17-wrapped-5fcc3f0.objdump.txt", "0x5fcc3f0", "0x5fcc3f9"),
    ("nowmicros-5d4d490.objdump.txt", "0x5d4d490", "0x5d4d552"),
    ("nownanos-fwd-5fcc340.objdump.txt", "0x5fcc340", "0x5fcc351"),
    ("cpumicros-fwd-5fcc360.objdump.txt", "0x5fcc360", "0x5fcc371"),
    ("cpunanos-fwd-5fcc380.objdump.txt", "0x5fcc380", "0x5fcc391"),
    ("sleep-5dd41a0.objdump.txt", "0x5dd41a0", "0x5dd4262"),
    ("timetostring-5fcc3a0.objdump.txt", "0x5fcc3a0", "0x5fcc3e7"),
    ("emu-name-60257a0.objdump.txt", "0x60257a0", "0x60257ac"),
    ("emu-nowmicros-60259e0.objdump.txt", "0x60259e0", "0x6025a08"),
    ("emu-nownanos-60259a0.objdump.txt", "0x60259a0", "0x60259d2"),
    ("emu-cpumicros-6025a30.objdump.txt", "0x6025a30", "0x6025a46"),
    ("emu-cpunanos-6025a10.objdump.txt", "0x6025a10", "0x6025a26"),
    ("emu-sleep-6025b40.objdump.txt", "0x6025b40", "0x6025b7f"),
    ("emu-getcurrenttime-6025eb0.objdump.txt", "0x6025eb0", "0x6025feb"),
    ("posix-name-5fe0fe0.objdump.txt", "0x5fe0fe0", "0x5fe0fec"),
    ("posix-slot17-null-5d2ca00.objdump.txt", "0x5d2ca00", "0x5d2ca07"),
    ("posix-slot18-5fe0ff0.objdump.txt", "0x5fe0ff0", "0x5fe0ffc"),
    ("posix-cpumicros-5fe1480.objdump.txt", "0x5fe1480", "0x5fe14e4"),
    ("posix-cpunanos-5fe1430.objdump.txt", "0x5fe1430", "0x5fe147c"),
    ("ctor-5fd0090.objdump.txt", "0x5fd0090", "0x5fd0178"),
]

WINDOWS = [0x609D760, 0x609DC40, 0x5D32560, 0x5FCF590, 0x6096790, 0x5D2E090,
           0x60956F0, 0x609D0E0, 0x60986B0, 0x6095710, 0x5FCDAE0, 0x609D980,
           0x5D32A30, 0x5FCC3F0, 0x5D4D490, 0x5FCC340, 0x5FCC360, 0x5FCC380,
           0x5DD41A0, 0x5FCC3A0, 0x60257A0, 0x60259E0, 0x60259A0, 0x6025A30,
           0x6025A10, 0x6025B40, 0x6025EB0, 0x5FE0FE0, 0x5D2CA00, 0x5FE0FF0,
           0x5FE1480, 0x5FE1430, 0x5FD0090]

# The exact 26-slot SystemClockWrapper vtable map (None = null slot).
WRAPPER_SLOTS = [
    None, None, 0x609D760, 0x609DC40, 0x5D32560, 0x5FCF590, 0x6096790,
    0x5D2E090, 0x60956F0, 0x609D0E0, 0x60986B0, 0x6095710, 0x5FCDAE0,
    0x609D980, None, 0x5D32A30, 0x5D2E770, 0x5FCC3F0, 0x5D2CA10, 0x5D4D490,
    0x5FCC340, 0x5FCC360, 0x5FCC380, 0x5DD41A0, 0x5D4B100, 0x5FCC3A0,
]
# Slots the EmulatedSystemClock vtable shares with the wrapper.
SHARED_WITH_EMULATED = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 18, 25]
# EmulatedSystemClock slots that differ from the wrapper map.
EMULATED_OVERRIDES = {0: 0x6029110, 1: 0x6029620, 14: 0x60257A0,
                      19: 0x60259E0, 20: 0x60259A0, 21: 0x6025A30,
                      22: 0x6025A10, 23: 0x6025B40, 24: 0x6025EB0}
# Slots the PosixClock vtable shares with the wrapper.
SHARED_WITH_POSIX = [2, 3, 4, 6, 7, 8, 9, 10, 11, 13]
# PosixClock slots that differ from the wrapper map.
POSIX_DIFFERS = {0: 0x5FE17D0, 1: 0x5FE18F0, 5: 0x6095E70, 12: 0x609DE80,
                 14: 0x5FE0FE0, 17: 0x5D2CA00, 18: 0x5FE0FF0, 19: 0x5FE1540,
                 20: 0x5FE14F0, 21: 0x5FE1480, 22: 0x5FE1430, 23: 0x5FE1420,
                 24: 0x5FE2230, 25: 0x5FE1340}

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x609D760: "f30f1efa",  # endbr64: GetOption entry
    0x609D7B3: "6681386964",  # cmpw $0x6469,(%rax) (the "id" check)
    0x609D7C0: "ff5078",  # call *0x78(%rax) (slot 15 GetId)
    0x609D78D: "e89eb8ffff",  # call 6099030 (the generic GetOption path)
    0x609DC40: "f30f1efa",  # endbr64: AreEquivalent entry
    0x609DD6E: "e92db9ffff",  # jmp 60996a0 (the deeper equivalence check)
    0x609DD8D: "e80e2d3500",  # call memcmp@plt
    0x609DDDC: "488d0d323d3afa",  # lea # 441b15 ("id")
    0x5D32560: "f30f1efa",  # endbr64: slot-4 entry
    0x5FCF590: "f30f1efa",  # endbr64: PrepareOptions entry
    0x5FCF5AD: "48837e2000",  # cmpq $0x0,0x20(%rsi) (target null check)
    0x5FCF5B7: "e8b4680c00",  # call 6095e70 (base PrepareOptions)
    0x5FCF5E9: "e892300100",  # call 5fe2680 (the default-clock accessor)
    0x5FCF648: "f083450801",  # lock addl $0x1,0x8(%rbp) (refcount bump)
    0x5D32A3E: "ff5070",  # call *0x70(%rax) (slot 14 Name)
    0x5D32A47: "e8f4feffff",  # call 5d32940 (the string build)
    0x5D4D4A2: "483b05d7fa7900",  # cmp *(0x64ecf80) (the slot-19 GOT canonical)
    0x5D4D53F: "ffa098000000",  # jmp *0x98(%rax) (slot 19)
    0x5FCC340: "f30f1efa",  # endbr64: slot-20 forwarder entry
    0x5FCC344: "488b7f20",  # mov 0x20(%rdi),%rdi (load the wrapped clock)
    0x5FCC34B: "ffa0a0000000",  # jmp *0xa0(%rax) (wrapped slot 20)
    0x5FCC3F0: "f30f1efa",  # endbr64: slot-17 entry
    0x5FCC3F4: "488b4720",  # mov 0x20(%rdi),%rax (return the wrapped clock)
    0x5FCC3C3: "ff90c8000000",  # call *0xc8(%rax) (wrapped slot 25)
    0x60257A0: "f30f1efa",  # endbr64: emulated Name entry
    0x60257A4: "488d05031b41fa",  # lea # 4372ae (TimeEmulatedSystemClock)
    0x60259EA: "0fb65748",  # movzbl 0x48(%rdi),%edx (the +0x48 flag)
    0x60259F9: "ff9098000000",  # call *0x98(%rax) (wrapped slot 19)
    0x6025B44: "f083473801",  # lock addl $0x1,0x38(%rdi) (sleep counter)
    0x6025B73: "f048014740",  # lock add %rax,0x40(%rdi) (offset accumulate)
    0x5FE0FE4: "488d051c0045fa",  # lea # 431007 (DefaultClock)
    0x5FE0FF4: "488d05936646fa",  # lea # 44768e (PosixClock)
    0x5D2CA00: "f30f1efa",  # endbr64: PosixClock slot-17 entry
    0x5D2CA04: "31c0",  # xor %eax,%eax (returns null)
    0x5FD0090: "f30f1efa",  # endbr64: ctor entry
    0x5FD00AF: "488d05c2dc4f00",  # lea # 64cdd78 (the vtable install)
    0x5FD0124: "e8b79b0c00",  # call 6099ce0 (the ctor helper)
    0x6096790: "f30f1efa",  # endbr64: ValidateOptions entry
    0x609D0E0: "f30f1efa",  # endbr64: ConfigureOptions entry
    0x60986B0: "f30f1efa",  # endbr64: ParseOption entry
    0x6095710: "f30f1efa",  # endbr64: OptionsAreEqual entry
    0x5FCDAE0: "f30f1efa",  # endbr64: SerializeOptions entry
    0x609D980: "f30f1efa",  # endbr64: GetOptionName entry
    0x5D2E090: "f30f1efa",  # endbr64: GetOptionsPtr entry
    0x60956F0: "f30f1efa",  # endbr64: slot-8 entry
    0x60259E0: "f30f1efa",  # endbr64: emulated NowMicros entry
    0x60259A0: "f30f1efa",  # endbr64: emulated NowNanos entry
    0x6025A30: "f30f1efa",  # endbr64: emulated CPUMicros entry
    0x6025A10: "f30f1efa",  # endbr64: emulated CPUNanos entry
    0x6025B40: "f30f1efa",  # endbr64: emulated Sleep entry
    0x6025EB0: "f30f1efa",  # endbr64: emulated GetCurrentTime entry
    0x5FE0FE0: "f30f1efa",  # endbr64: PosixClock Name entry
    0x5FE0FF0: "f30f1efa",  # endbr64: PosixClock slot-18 entry
    0x5FE1480: "f30f1efa",  # endbr64: PosixClock CPUMicros entry
    0x5FE1430: "f30f1efa",  # endbr64: PosixClock CPUNanos entry
    0x5FCC360: "f30f1efa",  # endbr64: slot-21 forwarder entry
    0x5FCC380: "f30f1efa",  # endbr64: slot-22 forwarder entry
    0x5FCC3A0: "f30f1efa",  # endbr64: TimeToString entry
    # By-contract windows (no excerpt; checked against fresh objdump).
    0x5D2E770: "f30f1efa",  # endbr64: IsInstanceOf entry
    0x5D2CA10: "f30f1efa",  # endbr64: wrapper slot-18 entry
    0x5D2CA14: "488d05e2ac70fa",  # lea # 4376fd (empty string)
    0x5D4B100: "f30f1efa",  # endbr64: GetCurrentTime entry
    0x6029500: "f30f1efa",  # endbr64: wrapper D0 entry
    0x6029504: "488d056d484a00",  # lea # 64cdd78 (D0 installs the wrapper vtable)
    0x6029110: "f30f1efa",  # endbr64: emulated D1 entry
    0x6029114: "488d055d4c4a00",  # lea # 64cdd78 (D1 installs the wrapper vtable)
    0x5FE2680: "f30f1efa",  # endbr64: default-clock accessor entry
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
            # No excerpt covers this address (a census target or a
            # by-contract window): confirm it against a fresh objdump
            # run instead.
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
    rng = random.Random(0x609D760)
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
        ["python3", "-m", "pytest",
         "tests/test_systemclock_wrapper_vtable_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "19 passed" not in test.stdout:
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
    if vt["system_clock_wrapper"]["typeinfo_name"] != \
            "N7rocksdb18SystemClockWrapperE":
        fail("SystemClockWrapper typeinfo mismatch")
    wrap_slots = [int(s["target"], 16) if s["target"] else None
                  for s in vt["system_clock_wrapper"]["slots"]]
    if wrap_slots != WRAPPER_SLOTS:
        fail("wrapper vtable slot map mismatch")
    if vt["emulated_system_clock"]["typeinfo_name"] != \
            "N7rocksdb19EmulatedSystemClockE":
        fail("EmulatedSystemClock typeinfo mismatch")
    emu_slots = [int(s["target"], 16) if s["target"] else None
                 for s in vt["emulated_system_clock"]["slots"]]
    if len(emu_slots) != 26:
        fail("EmulatedSystemClock slot count mismatch")
    for i in SHARED_WITH_EMULATED:
        if emu_slots[i] != wrap_slots[i]:
            fail("shared slot %d differs between wrapper and emulated" % i)
    for i, want in EMULATED_OVERRIDES.items():
        if emu_slots[i] != want:
            fail("EmulatedSystemClock slot %d mismatch" % i)
    if vt["posix_clock"]["typeinfo_name"] != \
            "*N7rocksdb12_GLOBAL__N_110PosixClockE":
        fail("PosixClock typeinfo mismatch")
    pos_slots = [int(s["target"], 16) if s["target"] else None
                 for s in vt["posix_clock"]["slots"]]
    if len(pos_slots) != 26:
        fail("PosixClock slot count mismatch")
    for i in SHARED_WITH_POSIX:
        if pos_slots[i] != wrap_slots[i]:
            fail("shared slot %d differs between wrapper and PosixClock" % i)
    for i, want in POSIX_DIFFERS.items():
        if pos_slots[i] != want:
            fail("PosixClock slot %d mismatch" % i)
    if records["vtable"]["wrapper"]["slot_count"] != 26:
        fail("records vtable slot count mismatch")
    if records["vtable"]["wrapper"]["stored_pointer"] != "0x64cdd88" or \
            records["vtable"]["wrapper"]["itanium_base"] != "0x64cdd78":
        fail("records vtable base/stored pointer mismatch")

    # 9. Key literals.
    getoption = open(os.path.join(HERE, "getoption-609d760.objdump.txt")).read()
    if "cmpw   $0x6469,(%rax)" not in getoption:
        fail("'id' compare missing from GetOption excerpt")
    if "call   *0x78(%rax)" not in getoption:
        fail("GetId virtual call missing from GetOption excerpt")
    if "call   6099030" not in getoption:
        fail("generic path call missing from GetOption excerpt")
    areeq = open(os.path.join(HERE, "areequivalent-609dc40.objdump.txt")).read()
    if "jmp    60996a0" not in areeq:
        fail("deeper-check tail jump missing from AreEquivalent excerpt")
    if "# 441b15" not in areeq:
        fail("'id' literal missing from AreEquivalent excerpt")
    if "call   63f0aa0" not in areeq:
        fail("memcmp call missing from AreEquivalent excerpt")
    getid = open(os.path.join(HERE, "getid-5d32a30.objdump.txt")).read()
    if "call   *0x70(%rax)" not in getid:
        fail("Name virtual call missing from GetId excerpt")
    if "call   5d32940" not in getid:
        fail("string-build call missing from GetId excerpt")
    prep = open(os.path.join(HERE, "prepareoptions-5fcf590.objdump.txt")).read()
    if "call   5fe2680" not in prep:
        fail("accessor call missing from PrepareOptions excerpt")
    if "call   6095e70" not in prep:
        fail("base PrepareOptions call missing from PrepareOptions excerpt")
    if "cmpq   $0x0,0x20(%rsi)" not in prep:
        fail("target null check missing from PrepareOptions excerpt")
    if "lock addl $0x1,0x8(%rbp)" not in prep:
        fail("refcount bump missing from PrepareOptions excerpt")
    nowmicros = open(os.path.join(HERE, "nowmicros-5d4d490.objdump.txt")).read()
    if "# 64ecf80" not in nowmicros:
        fail("slot-19 GOT canonical missing from NowMicros excerpt")
    if "jmp    *0x98(%rax)" not in nowmicros:
        fail("slot-19 dispatch missing from NowMicros excerpt")
    sleep_ex = open(os.path.join(HERE, "sleep-5dd41a0.objdump.txt")).read()
    if "# 64ed5f8" not in sleep_ex:
        fail("slot-23 GOT canonical missing from Sleep excerpt")
    if "jmp    *0xb8(%rax)" not in sleep_ex:
        fail("slot-23 dispatch missing from Sleep excerpt")
    fwd20 = open(os.path.join(HERE, "nownanos-fwd-5fcc340.objdump.txt")).read()
    if "jmp    *0xa0(%rax)" not in fwd20:
        fail("slot-20 forward missing from the forwarder excerpt")
    tts = open(os.path.join(HERE, "timetostring-5fcc3a0.objdump.txt")).read()
    if "call   *0xc8(%rax)" not in tts:
        fail("slot-25 call missing from TimeToString excerpt")
    emu_name = open(os.path.join(HERE, "emu-name-60257a0.objdump.txt")).read()
    if "# 4372ae" not in emu_name:
        fail("TimeEmulatedSystemClock literal missing from emulated Name excerpt")
    posix_name = open(os.path.join(HERE, "posix-name-5fe0fe0.objdump.txt")).read()
    if "# 431007" not in posix_name:
        fail("DefaultClock literal missing from PosixClock Name excerpt")
    posix_s18 = open(os.path.join(HERE, "posix-slot18-5fe0ff0.objdump.txt")).read()
    if "# 44768e" not in posix_s18:
        fail("PosixClock literal missing from PosixClock slot-18 excerpt")
    slot17 = open(os.path.join(HERE, "slot17-wrapped-5fcc3f0.objdump.txt")).read()
    if "mov    0x20(%rdi),%rax" not in slot17:
        fail("wrapped-clock load missing from slot-17 excerpt")
    emu_sleep = open(os.path.join(HERE, "emu-sleep-6025b40.objdump.txt")).read()
    if "lock addl $0x1,0x38(%rdi)" not in emu_sleep:
        fail("sleep counter bump missing from emulated Sleep excerpt")
    if "lock add %rax,0x40(%rdi)" not in emu_sleep:
        fail("offset accumulate missing from emulated Sleep excerpt")
    ctor_ex = open(os.path.join(HERE, "ctor-5fd0090.objdump.txt")).read()
    if "# 64cdd78" not in ctor_ex:
        fail("vtable install missing from ctor excerpt")
    if "call   6099ce0" not in ctor_ex:
        fail("ctor helper call missing from ctor excerpt")
    ser = open(os.path.join(HERE, "serializeoptions-5fcdae0.objdump.txt")).read()
    if "# 431007" not in ser:
        fail("DefaultClock literal missing from SerializeOptions excerpt")
    if "# 64eceb8" not in ser:
        fail("GOT identity-check slot missing from SerializeOptions excerpt")
    if "call   609de80" not in ser:
        fail("base SerializeOptions call missing from SerializeOptions excerpt")

    # 10. Model constants.
    if records["layout"]["wrapper_size_bytes"] != 0x30:
        fail("records wrapper size mismatch")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import systemclock_wrapper_vtable_115 as model
    if model.WRAPPER_VTABLE != 0x64CDD88:
        fail("model wrapper vtable mismatch")
    if model.slot_address(model.WRAPPER_SLOTS, 19) != 0x5D4D490:
        fail("model slot-19 mismatch")
    if model.slot_address(model.WRAPPER_SLOTS, 14) is not None:
        fail("model slot-14 should be null")
    if model.CHAIN_CANONICAL[19] != (0x64ECF80, 0x5D4D490):
        fail("model slot-19 canonical mismatch")
    if model.CHAIN_CANONICAL[23] != (0x64ED5F8, 0x5DD41A0):
        fail("model slot-23 canonical mismatch")
    if model.CHAIN_CANONICAL[24] != (0x64ED3E8, 0x5D4B100):
        fail("model slot-24 canonical mismatch")
    leaf = model.PosixClock(now_micros=4242)
    wrap = model.SystemClockWrapper(target=leaf)
    if wrap.call_slot(19) != 4242:
        fail("model chain-walk mismatch")
    chain = leaf
    for _ in range(8):
        chain = model.SystemClockWrapper(target=chain)
    if chain.call_slot(19) != 4242:
        fail("model 9th-level chain-walk mismatch")
    emu = model.EmulatedSystemClock(target=model.PosixClock(now_micros=100))
    emu.frozen = True
    emu.emulated_offset = 55
    outer = model.SystemClockWrapper(target=emu)
    if outer.call_slot(19) != 55:
        fail("model first-differing-level mismatch")
    if outer.call_slot(20) != 55_000:
        fail("model emulated NowNanos mismatch")
    if emu.call_slot(2, "id")[0] != "TimeEmulatedSystemClock":
        fail("model GetOption id path mismatch")
    a = model.EmulatedSystemClock(target=model.PosixClock())
    a.config_flag = 3
    a.deeper_check = lambda self, other: 0
    if a.call_slot(3, model.EmulatedSystemClock(target=model.PosixClock()))[0] != 0:
        fail("model AreEquivalent deeper-check mismatch")
    bare = model.SystemClockWrapper(target=None)
    bare.call_slot(5, {})
    if not isinstance(bare.target, model.PosixClock):
        fail("model PrepareOptions lazy default mismatch")
    if bare.call_slot(15) != "DefaultClock":
        fail("model GetId mismatch")
    if wrap.call_slot(17) is not leaf:
        fail("model slot-17 mismatch")
    if wrap.call_slot(18) != "":
        fail("model slot-18 mismatch")
    emu2 = model.EmulatedSystemClock(target=model.PosixClock(now_micros=1000, now_nanos=1_000_000))
    emu2.emulated_offset = 40
    if emu2.call_slot(19) != 1040 or emu2.call_slot(20) != 1_040_000:
        fail("model emulated offset mismatch")
    emu2.call_slot(21)
    emu2.call_slot(23, 7)
    if emu2.cpu_count != 1 or emu2.sleep_count != 1 or emu2.emulated_offset != 47:
        fail("model emulated counters mismatch")
    if wrap.call_slot(25, None) != "PosixClock time":
        fail("model TimeToString mismatch")
    if "SystemClockWrapper" not in json.dumps(records):
        fail("catalogue attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
