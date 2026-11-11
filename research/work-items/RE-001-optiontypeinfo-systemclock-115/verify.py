"""Packet checker for RE-001-optiontypeinfo-systemclock-115.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-systemclock-115/verify.py

Checks, all against the digest-verified work binary:
1. binary SHA-256 matches provenance/artifacts.json;
2. MANIFEST.sha256 entries match the packet files;
3. the excerpts regenerate byte-identically;
4. sampled instructions match a fresh objdump run and the raw binary
   (including 3 self-check instructions picked for this packet);
5. frames.txt rows match a fresh objdump frames dump;
6. the caller census reproduces records.json and callers.tsv, and
   every census site is a real call/jump in its containing FDE;
   every packet-internal helper site is a real call in its FDE;
7. the model test file passes under plain python3;
8. relocations: no RELATIVE entry points at a packet window; the
   two hook GOT slots are exactly 0x64ed8d0 -> 0x5fcc660 and
   0x64ed958 -> 0x5fd4c30; the lambda typeinfo relocations resolve
   to the AsCustomSharedPtr<SystemClock> name string at 0x972460;
   the host's sentinel globals resolve to 0x5d2e770 / 0x5d2ca10;
   the PosixClock typeinfo relocations resolve as pinned;
9. key literals (the type 22 store, the GOT hook slots, the
   typeinfo lea, the "id" word, the accessor's packed-counts load,
   the atomicity selector, the "Cannot reset object " literal,
   the default-init's two name literals) are present in the
   excerpts;
10. model constants: the record field map, the copy helper, the
    manager op dispatch, the Status move, the invoker id fast path
    vs forward path, the counted release rule, the create host's
    adopt vs default dispatch, the accessor's combined allocation
    and the default init's registry insert match records.json.
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
    ("builder-5fd0180.objdump.txt", "0x5fd0180", "0x5fd02f2"),
    ("manager-5fcc660.objdump.txt", "0x5fcc660", "0x5fcc68d"),
    ("invoker-5fd4c30.objdump.txt", "0x5fd4c30", "0x5fd4cc1"),
    ("host-5fd46c0.objdump.txt", "0x5fd46c0", "0x5fd4c2e"),
    ("accessor-5fe2680.objdump.txt", "0x5fe2680", "0x5fe2756"),
    ("default-init-5fd20d0.objdump.txt", "0x5fd20d0", "0x5fd241d"),
    ("status-move-5fcdf70.objdump.txt", "0x5fcdf70", "0x5fcdfdf"),
    ("copy-5e332c0.objdump.txt", "0x5e332c0", "0x5e3354f"),
]

WINDOWS = [0x5FD0180, 0x5FCC660, 0x5FD4C30, 0x5FD46C0, 0x5FE2680,
           0x5FD20D0, 0x5FCDF70, 0x5E332C0]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x5FD0180: "f30f1efa",  # endbr64: builder entry
    0x5FD023A: "c78424c800000016000000",  # movl $0x16,0xc8(%rsp): type 22
    0x5FD0266: "e85530e6ff",  # call copy helper 0x5e332c0
    0x5FCC660: "f30f1efa",  # endbr64: manager entry
    0x5FCC680: "488d0579135000",  # lea typeinfo object 0x64cda00
    0x5FD4C30: "f30f1efa",  # endbr64: invoker entry
    0x5FD4C83: "6681396964",  # cmpw $0x6469,(%rcx): the "id" check
    0x5FD4C60: "e85bfaffff",  # call create host 0x5fd46c0
    0x5FD46C0: "f30f1efa",  # endbr64: host entry
    0x5FD46F4: "e887df0000",  # call accessor 0x5fe2680
    0x5FE2680: "f30f1efa",  # endbr64: accessor entry
    0x5FE26DF: "488b153a7447fa",  # mov 0x459b20,%rdx: packed counts
    0x5FD20D0: "f30f1efa",  # endbr64: default-init entry
    0x5FCDF70: "f30f1efa",  # endbr64: status-move entry
    0x5E332C0: "f30f1efa",  # endbr64: copy-helper entry
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
    rng = random.Random(0x5FD0180)
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
        ["python3", "tests/test_optiontypeinfo_systemclock_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: no RELATIVE slot lives inside a packet window;
    #    the hook GOT slots are exactly the two expected ones; the
    #    lambda typeinfo relocations resolve to the SystemClock name.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    rela = {}
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        rela.setdefault(ro, []).append((info & 0xFFFFFFFF, info >> 32, add))
    windows = [(0x5FD0180, 0x5FD02F2), (0x5FCC660, 0x5FCC68D),
               (0x5FD4C30, 0x5FD4CC1), (0x5FD46C0, 0x5FD4C2E),
               (0x5FE2680, 0x5FE2756), (0x5FD20D0, 0x5FD241D),
               (0x5FCDF70, 0x5FCDFDF), (0x5E332C0, 0x5E3354F)]
    for ro, entries in rela.items():
        for (typ, _sym, _add) in entries:
            if typ == 8:
                for (ws, we) in windows:
                    if ws <= ro < we:
                        fail("RELATIVE slot inside window: " + hex(ro))
    if [hex(v) for v in slots[0x5FCC660]] != ["0x64ed8d0"]:
        fail("manager GOT slot mismatch: %s" % slots[0x5FCC660])
    if [hex(v) for v in slots[0x5FD4C30]] != ["0x64ed958"]:
        fail("invoker GOT slot mismatch: %s" % slots[0x5FD4C30])
    if slots[0x5FD0180] or slots[0x5FD46C0] or slots[0x5FE2680] \
            or slots[0x5FD20D0] or slots[0x5FCDF70] or slots[0x5E332C0] \
            or slots[0x5FD4080]:
        fail("unexpected RELATIVE slot for a non-hook window")
    ti = rela.get(0x64CDA00, [])
    if not any(t == 1 and a == 0x10 for t, _, a in ti):
        fail("typeinfo vtable relocation missing at 0x64cda00")
    nm = rela.get(0x64CDA08, [])
    if not any(t == 8 and a == 0x972460 for t, _, a in nm):
        fail("typeinfo name relocation missing at 0x64cda08")
    name = data[0x972460:0x972460 + 200].split(b"\x00")[0].decode()
    if "AsCustomSharedPtrINS_11SystemClockEEE" not in name:
        fail("typeinfo name is not AsCustomSharedPtr<SystemClock>: " + name)
    sentinel80 = rela.get(0x64ECEB8, [])
    if not any(t == 8 and a == 0x5D2E770 for t, _, a in sentinel80):
        fail("slot-0x80 sentinel relocation missing at 0x64eceb8")
    sentinel90 = rela.get(0x64ECEB0, [])
    if not any(t == 8 and a == 0x5D2CA10 for t, _, a in sentinel90):
        fail("slot-0x90 sentinel relocation missing at 0x64eceb0")
    posix_ti = rela.get(0x64CE928, [])
    if not any(t == 8 and a == 0x64CE870 for t, _, a in posix_ti):
        fail("PosixClock typeinfo relocation missing at 0x64ce928")
    ctrl_ti = rela.get(0x64CECF8, [])
    if not any(t == 8 and a == 0x64CE8B8 for t, _, a in ctrl_ti):
        fail("control typeinfo relocation missing at 0x64cecf8")
    posix_name = data[0x972C00:0x972C00 + 120].split(b"\x00")[0].decode()
    if "PosixClock" not in posix_name:
        fail("PosixClock typeinfo name mismatch: " + posix_name)

    # 9. Key literals.
    builder = open(os.path.join(HERE, "builder-5fd0180.objdump.txt")).read()
    manager = open(os.path.join(HERE, "manager-5fcc660.objdump.txt")).read()
    invoker = open(os.path.join(HERE, "invoker-5fd4c30.objdump.txt")).read()
    host = open(os.path.join(HERE, "host-5fd46c0.objdump.txt")).read()
    accessor = open(os.path.join(HERE, "accessor-5fe2680.objdump.txt")).read()
    defaultinit = open(os.path.join(HERE, "default-init-5fd20d0.objdump.txt")).read()
    if "$0x16,0xc8(%rsp)" not in builder:
        fail("type 22 store missing from builder excerpt")
    if "64ed8d0" not in builder or "64ed958" not in builder:
        fail("GOT hook slots missing from builder excerpt")
    if "call   5e332c0" not in builder:
        fail("copy-helper call missing from builder excerpt")
    if "64cda00" not in manager:
        fail("typeinfo object missing from manager excerpt")
    if "0x6469" not in invoker:
        fail("\"id\" word missing from invoker excerpt")
    if "call   5fd46c0" not in invoker:
        fail("create-host call missing from invoker excerpt")
    if "call   5d350c0" not in invoker:
        fail("_M_release call missing from invoker excerpt")
    if "64ed290" not in host:
        fail("atomicity selector missing from host excerpt")
    if "64eceb8" not in host or "64eceb0" not in host:
        fail("sentinel globals missing from host excerpt")
    if "call   5fe2680" not in host:
        fail("accessor call missing from host excerpt")
    if "call   5fd4080" not in host:
        fail("factory-helper call missing from host excerpt")
    if "433f9f" not in host:
        fail("\"Cannot reset object \" literal missing from host excerpt")
    if "459b20" not in accessor:
        fail("packed-counts global missing from accessor excerpt")
    if "4372ae" not in defaultinit or "438369" not in defaultinit:
        fail("default-init name literals missing from default-init excerpt")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import optiontypeinfo_systemclock_115 as model
    rec = model.build_record(0, 1, 0x2000)
    if (rec["+0x00"] != 0 or rec["+0x18"] != 0x5FCC660
            or rec["+0x20"] != 0x5FD4C30 or rec["+0xa8"] != 22
            or rec["+0xac"] != 1 or rec["+0xb0"] != 0x2000
            or "+0x04" in rec):
        fail("model build_record mismatch")
    if model.builder_temp_cleanup() != (0, []):
        fail("model builder temp cleanup mismatch")
    if model.manager(0) != (0x64CDA00, 0):
        fail("model manager op0 mismatch")
    if model.manager(1, 0xBEEF) != (0xBEEF, 0):
        fail("model manager op1 mismatch")
    if model.manager(2) != (None, 0) or model.manager(3) != (None, 0):
        fail("model manager op2/3 mismatch")
    src = {"+0x00": 0, "+0xa8": 22, "+0xac": 1, "+0xb0": 0x2000,
           "+0x08": {"functor": None, "manager": 0x5FCC660,
                     "invoker": 0x5FD4C30}}
    for member in ("+0x28", "+0x48", "+0x68", "+0x88"):
        src[member] = {"functor": None, "manager": None, "invoker": None}
    copied = model.copy_record({}, src)
    if (copied["+0x08"]["manager"] != 0x5FCC660
            or copied["+0x08"]["invoker"] != 0x5FD4C30
            or copied["+0x28"]["manager"] is not None
            or "+0x04" in copied):
        fail("model copy_record mismatch")
    dst = model.Status(code=1, subcode=2, state="old")
    src_st = model.Status(code=3, subcode=4, state="new")
    model.status_move(dst, src_st)
    if (dst.code != 3 or dst.subcode != 4 or dst.state != "new"
            or src_st.subcode != 0 or src_st.state is not None):
        fail("model status_move mismatch")
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
    model.invoker(out2, "cfg", b"id", b"SystemClock", [slot2], fake_host)
    if host_calls != [b"SystemClock"] or slot2.obj != "created":
        fail("model invoker forward path mismatch")
    # Create host: adopt by slot-0x70 name.
    current = model.SharedPtr(
        obj=model.Clock(name_70=b"SystemClock", slot_90_is_default=True),
        control=model.CountedBase())
    dest = model.SharedPtr()
    out3 = model.Status(code=9)
    model.create_host(out3, {"byte_1": False}, b"SystemClock", dest,
                      current, lambda c, n: (model.Status(), b"", None),
                      lambda f, n, s: model.Status(),
                      lambda i, c, o, cu: model.Status())
    if not out3.is_empty() or dest.obj is not current.obj:
        fail("model create-host adopt mismatch")
    # Create host: translator error moves to out.
    current2 = model.SharedPtr(
        obj=model.Clock(name_70=b"Other", slot_90_is_default=True),
        control=model.CountedBase())
    dest2 = model.SharedPtr()
    out4 = model.Status()
    model.create_host(out4, {"byte_1": False}, b"Unknown", dest2, current2,
                      lambda c, n: (model.Status(code=5, state="bad"), b"", None),
                      lambda f, n, s: model.Status(),
                      lambda i, c, o, cu: model.Status())
    if out4.code != 5 or out4.state != "bad":
        fail("model create-host translator error mismatch")
    # Default slot-0x80 predicate and slot-0x90 getter.
    pred_clock = model.Clock(name_70=b"SystemClock", name_90=b"Alt",
                             slot_90_is_default=False)
    if model.default_slot_0x80_predicate(pred_clock, b"") is not False:
        fail("model default predicate empty-name mismatch")
    if model.default_slot_0x80_predicate(pred_clock, b"SystemClock") is not True:
        fail("model default predicate slot-0x70 mismatch")
    if model.default_slot_0x80_predicate(pred_clock, b"Alt") is not True:
        fail("model default predicate slot-0x90 mismatch")
    if model.default_slot_0x80_predicate(pred_clock, b"Nope") is not False:
        fail("model default predicate no-match mismatch")
    if model.default_slot_0x90_name() != b"":
        fail("model default slot-0x90 getter mismatch")
    if model.SENTINEL_SLOT_0X80 != 0x5D2E770 \
            or model.SENTINEL_SLOT_0X90 != 0x5D2CA10:
        fail("model sentinel constants mismatch")
    # Accessor: slow path then fast path.
    acc = model.ClockAccessor()
    control_a, slot_a = acc.current()
    if control_a.packed() != 0x100000001:
        fail("model accessor packed counts mismatch")
    control_b, slot_b = acc.current()
    if control_b is not control_a or slot_b.obj is not slot_a.obj:
        fail("model accessor fast path mismatch")
    # Default init registers SystemClock.
    registry = {}
    if model.default_init(registry) != b"SystemClock" \
            or b"SystemClock" not in registry:
        fail("model default_init mismatch")
    if "SystemClock" not in json.dumps(records):
        fail("SystemClock attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
