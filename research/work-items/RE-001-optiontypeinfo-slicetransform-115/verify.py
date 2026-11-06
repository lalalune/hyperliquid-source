"""Packet checker for RE-001-optiontypeinfo-slicetransform-115.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-slicetransform-115/verify.py

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
   two hook GOT slots are exactly 0x64eda68 -> 0x607d190 and
   0x64edb70 -> 0x60809e0; the lambda typeinfo relocations resolve
   to the AsCustomSharedPtr<const SliceTransform> name string at
   0x976100; the control-block table relocations resolve as
   pinned; the once/TLS relocations resolve as pinned;
9. key literals (the type 22 store, the GOT hook slots, the
   typeinfo lea, the "id" word, the create-host call, the
   _M_release call, the atomicity selector, the translator/find/
   Status-builder calls, the packed-counts global, the control
   table base, the once control, the hash seed, the two movabs
   "SliceTransform" constants, the default-init's two helper
   calls) are present in the excerpts;
10. model constants: the record field map, the copy helper, the
    manager op dispatch, the Status move, the invoker id fast path
    vs forward path, the counted release rule, the create host's
    translator/find/create dispatch with its three code-4 error
    arms, the registry find's type-node match, entry scan, parent
    recursion and miss, and the default init's registry insert
    match records.json.
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
    ("builder-6083a90.objdump.txt", "0x6083a90", "0x6083c83"),
    ("manager-607d190.objdump.txt", "0x607d190", "0x607d1bd"),
    ("invoker-60809e0.objdump.txt", "0x60809e0", "0x6080a71"),
    ("host-61ca3d0.objdump.txt", "0x61ca3d0", "0x61cb3dc"),
    ("find-61c9d70.objdump.txt", "0x61c9d70", "0x61ca265"),
    ("init-61ccfa0.objdump.txt", "0x61ccfa0", "0x61cd01b"),
]

WINDOWS = [0x6083A90, 0x607D190, 0x60809E0, 0x61CA3D0, 0x61C9D70, 0x61CCFA0]

SAMPLES = {
    # VA -> expected instruction bytes (objdump text, lowercased, no spaces)
    0x6083A90: "f30f1efa",  # endbr64: builder entry
    0x6083B4A: "c78424c800000016000000",  # movl $0x16,0xc8(%rsp): type 22
    0x6083B76: "e845f7daff",  # call copy helper 0x5e332c0
    0x607D190: "f30f1efa",  # endbr64: manager entry
    0x607D1B0: "488d05615e4500",  # lea typeinfo object 0x64d3018
    0x60809E0: "f30f1efa",  # endbr64: invoker entry
    0x6080A33: "6681396964",  # cmpw $0x6469,(%rcx): the "id" check
    0x6080A10: "e8bb991400",  # call create host 0x61ca3d0
    0x6080A51: "e86a46cbff",  # call _M_release 0x5d350c0
    0x61CA3D0: "f30f1efa",  # endbr64: host entry
    0x61CA461: "e86a6f2200",  # call pthread_once@plt
    0x61CA53B: "e8d03fedff",  # call translator 0x609e510
    0x61CA580: "e8ebf7ffff",  # call find 0x61c9d70
    0x61C9D70: "f30f1efa",  # endbr64: find entry
    0x61C9DAD: "e8ae6d2200",  # call pthread_mutex_lock@plt
    0x61CCFA0: "f30f1efa",  # endbr64: init entry
    0x61CCFD0: "e88bbb0200",  # call registry-mutex getter 0x61f8b60
    0x61CCFD8: "e873edffff",  # call register helper 0x61cbd50
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
    rng = random.Random(0x6083A90)
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
        ["python3", "tests/test_optiontypeinfo_slicetransform_115.py"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if test.returncode != 0 or "tests passed" not in test.stdout:
        fail("model tests failed: " + test.stdout + test.stderr)

    # 8. Relocations: no RELATIVE slot lives inside a packet window;
    #    the hook GOT slots are exactly the two expected ones; the
    #    lambda typeinfo relocations resolve to the SliceTransform
    #    name; the control-block table relocations resolve as pinned;
    #    the once/TLS relocations resolve as pinned.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    rela = {}
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        rela.setdefault(ro, []).append((info & 0xFFFFFFFF, info >> 32, add))
    windows = [(0x6083A90, 0x6083C83), (0x607D190, 0x607D1BD),
               (0x60809E0, 0x6080A71), (0x61CA3D0, 0x61CB3DC),
               (0x61C9D70, 0x61CA265), (0x61CCFA0, 0x61CD01B)]
    for ro, entries in rela.items():
        for (typ, _sym, _add) in entries:
            if typ == 8:
                for (ws, we) in windows:
                    if ws <= ro < we:
                        fail("RELATIVE slot inside window: " + hex(ro))
    if [hex(v) for v in slots[0x607D190]] != ["0x64eda68"]:
        fail("manager GOT slot mismatch: %s" % slots[0x607D190])
    if [hex(v) for v in slots[0x60809E0]] != ["0x64edb70"]:
        fail("invoker GOT slot mismatch: %s" % slots[0x60809E0])
    if slots[0x6083A90] or slots[0x61CA3D0] or slots[0x61C9D70] \
            or slots[0x61CCFA0]:
        fail("unexpected RELATIVE slot for a non-hook window")
    ti = rela.get(0x64D3018, [])
    if not any(t == 1 and a == 0x10 for t, _, a in ti):
        fail("typeinfo vtable relocation missing at 0x64d3018")
    nm = rela.get(0x64D3020, [])
    if not any(t == 8 and a == 0x976100 for t, _, a in nm):
        fail("typeinfo name relocation missing at 0x64d3020")
    name = data[0x976100:0x976100 + 200].split(b"\x00")[0].decode()
    if "AsCustomSharedPtrIKNS_14SliceTransformEEE" not in name:
        fail("typeinfo name is not AsCustomSharedPtr<const SliceTransform>: "
             + name)
    ctrl_ti_cell = rela.get(0x64D7880, [])
    if not any(t == 8 and a == 0x64D75C0 for t, _, a in ctrl_ti_cell):
        fail("control typeinfo cell relocation missing at 0x64d7880")
    ctrl_ti = rela.get(0x64D75C0, [])
    if not any(t == 1 and a == 0x10 for t, _, a in ctrl_ti):
        fail("control typeinfo vtable relocation missing at 0x64d75c0")
    ctrl_nm = rela.get(0x64D75C8, [])
    if not any(t == 8 and a == 0x97E600 for t, _, a in ctrl_nm):
        fail("control typeinfo name relocation missing at 0x64d75c8")
    ctrl_name = data[0x97E600:0x97E600 + 120].split(b"\x00")[0].decode()
    if "Sp_counted_ptrIPKN7rocksdb14SliceTransformE" not in ctrl_name:
        fail("control typeinfo name mismatch: " + ctrl_name)
    for slot_addr, want_target in ((0x64D7888, 0x61C64D0),
                                   (0x64D7890, 0x61C6580),
                                   (0x64D7898, 0x61C6530),
                                   (0x64D78A0, 0x61C6590)):
        entries = rela.get(slot_addr, [])
        if not any(t == 8 and a == want_target for t, _, a in entries):
            fail("control table slot relocation missing at %#x" % slot_addr)
    once_callable = rela.get(0x64ED818, [])
    if not any(t == 18 for t, _, _ in once_callable):
        fail("__once_callable TPOFF64 relocation missing at 0x64ed818")
    once_call = rela.get(0x64ED820, [])
    if not any(t == 18 for t, _, _ in once_call):
        fail("__once_call TPOFF64 relocation missing at 0x64ed820")
    once_proxy = rela.get(0x64ED828, [])
    if not any(t == 6 for t, _, _ in once_proxy):
        fail("__once_proxy GLOB_DAT relocation missing at 0x64ed828")
    selector = rela.get(0x64ED290, [])
    if not any(t == 6 for t, _, _ in selector):
        fail("__libc_single_threaded GLOB_DAT relocation missing at 0x64ed290")

    # 9. Key literals.
    builder = open(os.path.join(HERE, "builder-6083a90.objdump.txt")).read()
    manager = open(os.path.join(HERE, "manager-607d190.objdump.txt")).read()
    invoker = open(os.path.join(HERE, "invoker-60809e0.objdump.txt")).read()
    host = open(os.path.join(HERE, "host-61ca3d0.objdump.txt")).read()
    find = open(os.path.join(HERE, "find-61c9d70.objdump.txt")).read()
    init = open(os.path.join(HERE, "init-61ccfa0.objdump.txt")).read()
    if "$0x16,0xc8(%rsp)" not in builder:
        fail("type 22 store missing from builder excerpt")
    if "64eda68" not in builder or "64edb70" not in builder:
        fail("GOT hook slots missing from builder excerpt")
    if "call   5e332c0" not in builder:
        fail("copy-helper call missing from builder excerpt")
    if "64d3018" not in manager:
        fail("typeinfo object missing from manager excerpt")
    if "0x6469" not in invoker:
        fail("\"id\" word missing from invoker excerpt")
    if "call   61ca3d0" not in invoker:
        fail("create-host call missing from invoker excerpt")
    if "call   5d350c0" not in invoker:
        fail("_M_release call missing from invoker excerpt")
    if "64ed290" not in host:
        fail("atomicity selector missing from host excerpt")
    if "call   609e510" not in host:
        fail("translator call missing from host excerpt")
    if "call   61c9d70" not in host:
        fail("find call missing from host excerpt")
    if "call   61cf670" not in host:
        fail("Status-builder call missing from host excerpt")
    if "44b556" not in host:
        fail("\"SliceTransform\" literal missing from host excerpt")
    if "459b20" not in host:
        fail("packed-counts global missing from host excerpt")
    if "64d7878" not in host:
        fail("control table base missing from host excerpt")
    if "6508928" not in host:
        fail("once control missing from host excerpt")
    if "c70f6907" not in find:
        fail("hash seed missing from find excerpt")
    if "call   61c9d70" not in find:
        fail("self-recursion call missing from find excerpt")
    if "0x6172546563696c53" not in find:
        fail("\"SliceTra\" movabs missing from find excerpt")
    if "0x6d726f66736e6172" not in find:
        fail("\"ransform\" movabs missing from find excerpt")
    if "call   61f8b60" not in init:
        fail("registry-mutex getter call missing from init excerpt")
    if "call   61cbd50" not in init:
        fail("register helper call missing from init excerpt")

    # 10. Model constants.
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import optiontypeinfo_slicetransform_115 as model
    rec = model.build_record(0x40, 2, 0x1100)
    if (rec["+0x00"] != 0x40 or rec["+0x18"] != 0x607D190
            or rec["+0x20"] != 0x60809E0 or rec["+0xa8"] != 22
            or rec["+0xac"] != 2 or rec["+0xb0"] != 0x1100
            or "+0x04" in rec):
        fail("model build_record mismatch")
    if model.builder_temp_cleanup() != (0, []):
        fail("model builder temp cleanup mismatch")
    if model.manager(0) != (0x64D3018, 0):
        fail("model manager op0 mismatch")
    if model.manager(1, 0xBEEF) != (0xBEEF, 0):
        fail("model manager op1 mismatch")
    if model.manager(2) != (None, 0) or model.manager(3) != (None, 0):
        fail("model manager op2/3 mismatch")
    src = {"+0x00": 0x40, "+0xa8": 22, "+0xac": 2, "+0xb0": 0x1100,
           "+0x08": {"functor": None, "manager": 0x607D190,
                     "invoker": 0x60809E0}}
    for member in ("+0x28", "+0x48", "+0x68", "+0x88"):
        src[member] = {"functor": None, "manager": None, "invoker": None}
    copied = model.copy_record({}, src)
    if (copied["+0x08"]["manager"] != 0x607D190
            or copied["+0x08"]["invoker"] != 0x60809E0
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
    model.invoker(out2, "cfg", b"id", b"prefix_extractor", [slot2], fake_host)
    if host_calls != [b"prefix_extractor"] or slot2.obj != "created":
        fail("model invoker forward path mismatch")
    # Create host: translator error moves to out.
    dest = model.SharedPtr()
    out3 = model.Status()
    model.create_host(
        out3, {"byte_1": False}, b"prefix_extractor", dest,
        lambda c, n, d: (model.Status(code=5, state="bad"), b""),
        model.Registry(), lambda i, c, o, cu: model.Status())
    if out3.code != 5 or out3.state != "bad":
        fail("model create-host translator error mismatch")
    # Create host: empty translated name releases the slot.
    old_cb = model.CountedBase()
    dest2 = model.SharedPtr(obj="old", control=old_cb)
    out4 = model.Status(code=9)
    model.create_host(
        out4, {"byte_1": False}, b"prefix_extractor", dest2,
        lambda c, n, d: (model.Status(), b""),
        model.Registry(), lambda i, c, o, cu: model.Status())
    if dest2.obj is not None or not old_cb.disposed or not out4.is_empty():
        fail("model create-host empty-name mismatch")
    # Create host: find miss gives code 3.
    dest3 = model.SharedPtr()
    out5 = model.Status()
    model.create_host(
        out5, {"byte_1": False}, b"prefix_extractor", dest3,
        lambda c, n, d: (model.Status(), b"prefix_extractor"),
        model.Registry(), lambda i, c, o, cu: model.Status())
    if out5.code != 3 or out5.state != b"Could not load SliceTransform prefix_extractor":
        fail("model create-host find-miss mismatch")
    # Create host: factory success installs with the control table.
    def factory(name, obj_slot, detail):
        obj_slot["obj"] = "created-transform"
        return True

    registry = model.Registry(
        buckets=[(b"SliceTransform", [(lambda k: True, factory)])])
    dest4 = model.SharedPtr()
    out6 = model.Status(code=9)
    model.create_host(
        out6, {"byte_1": False}, b"prefix_extractor", dest4,
        lambda c, n, d: (model.Status(), b"prefix_extractor"),
        registry, lambda i, c, o, cu: model.Status())
    if (not out6.is_empty() or dest4.obj != "created-transform"
            or dest4.control is None
            or dest4.control.packed() != 0x100000001
            or dest4.control.table != 0x64D7888):
        fail("model create-host factory-install mismatch")
    # Create host: factory null with detail gives code 4.
    def factory_detail(name, obj_slot, detail):
        detail["text"] = b"factory said no"
        return False

    registry2 = model.Registry(
        buckets=[(b"SliceTransform", [(lambda k: True, factory_detail)])])
    dest5 = model.SharedPtr()
    out7 = model.Status()
    model.create_host(
        out7, {"byte_1": False}, b"prefix_extractor", dest5,
        lambda c, n, d: (model.Status(), b"prefix_extractor"),
        registry2, lambda i, c, o, cu: model.Status())
    if out7.code != 4 or out7.state != b"factory said no prefix_extractor":
        fail("model create-host factory-detail mismatch")
    # Create host: factory null without detail gives code 4.
    def factory_null(name, obj_slot, detail):
        return False

    registry3 = model.Registry(
        buckets=[(b"SliceTransform", [(lambda k: True, factory_null)])])
    dest6 = model.SharedPtr()
    out8 = model.Status()
    model.create_host(
        out8, {"byte_1": False}, b"prefix_extractor", dest6,
        lambda c, n, d: (model.Status(), b"prefix_extractor"),
        registry3, lambda i, c, o, cu: model.Status())
    if out8.code != 4 or out8.state != b"Could not load SliceTransform prefix_extractor":
        fail("model create-host factory-null mismatch")
    # Create host: unguarded factory gives code 4.
    def factory_unguarded(name, obj_slot, detail):
        return True

    registry4 = model.Registry(
        buckets=[(b"SliceTransform", [(lambda k: True, factory_unguarded)])])
    dest7 = model.SharedPtr()
    out9 = model.Status()
    model.create_host(
        out9, {"byte_1": False}, b"prefix_extractor", dest7,
        lambda c, n, d: (model.Status(), b"prefix_extractor"),
        registry4, lambda i, c, o, cu: model.Status())
    if out9.code != 4 or b"Cannot make a shared SliceTransform" not in out9.state:
        fail("model create-host unguarded mismatch")
    # Registry find: type match, predicate scan, parent recursion, miss.
    registry5 = model.Registry(buckets=[(
        b"SliceTransform",
        [(lambda k: False, "a"), (lambda k: True, "b")])])
    if model.find_registry(registry5, b"prefix_extractor") != "b":
        fail("model find predicate-scan mismatch")
    parent = model.Registry(buckets=[(
        b"SliceTransform", [(lambda k: True, "parent")])])
    child = model.Registry(buckets=[(b"OtherType", [])], parent=parent)
    if model.find_registry(child, b"prefix_extractor") != "parent":
        fail("model find parent-recursion mismatch")
    if model.find_registry(model.Registry(), b"prefix_extractor") is not None:
        fail("model find miss mismatch")
    # Default init registers SliceTransform.
    registry6 = model.Registry()
    if model.default_init(registry6) != b"SliceTransform":
        fail("model default_init mismatch")
    if model.find_registry(registry6, b"prefix_extractor") is None:
        fail("model default_init registry mismatch")
    if "SliceTransform" not in json.dumps(records):
        fail("SliceTransform attribution missing from records.json")

    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
