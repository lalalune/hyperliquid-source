"""Generate records.json for the RE-001-composite-env-wrapper-115
packet from the census outputs and the verbatim excerpts.

Usage (from the repository root):
    python3 research/work-items/RE-001-composite-env-wrapper-115/gen_records.py

The JSON holds semantic records only: builder/install/dtor roles,
slot overrides, the forwarder table, vtable maps, call counts,
relocation rows, string literals and open unknowns.
Instruction-level detail lives only in the verbatim objdump
excerpts. The record-append 0x6099ce0, grow 0x6099790, holder
accessor 0x5fcf430 and CompositeEnv invoker 0x5fcf450 are
re-shipped byte-identical from the RE-001-systemclock-installers-115
packet (open PR #3948); their SHA-256 values are recorded here and
checked by verify.py.
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
PR3948 = ROOT / "research" / "work-items" / "RE-001-systemclock-installers-115"

TARGETS = [
    0x5FD7360, 0x5FCEB20, 0x5FD5CC0, 0x5FD72D0, 0x5FD7510, 0x5FCF4D0,
    0x5FD7560, 0x5FD5E00, 0x5FD4E60, 0x5FD6240, 0x5FD4E70, 0x5FE2860,
    0x5FCC7E0, 0x6025950, 0x6025B90, 0x5FCF390, 0x5FCF430, 0x5FCF450,
    0x6099CE0, 0x6099790, 0x5D35070, 0x5D350C0, 0x60289F0, 0x60029F0,
    0x61D2CA0, 0x61C21B0, 0x5FE2680, 0x60971C0,
    0x5FD4E80, 0x5FD4ED0, 0x5FD4EF0, 0x5FD4F10, 0x5FD4F30, 0x5FD4F70,
    0x5FD4F90, 0x5FD4F50, 0x5FD4FB0, 0x5FD5000, 0x5FD5020, 0x5FD5040,
    0x5FD5090, 0x5FD50B0, 0x5FD50F0, 0x5FD50D0, 0x5FD51D0, 0x5FD5140,
    0x5FD5190, 0x5FD51B0,
]

FORWARDERS = [
    {"slot": 45, "addr": 0x5FD4E80, "form": "call"},
    {"slot": 46, "addr": 0x5FD4ED0, "form": "jmp"},
    {"slot": 47, "addr": 0x5FD4EF0, "form": "jmp"},
    {"slot": 48, "addr": 0x5FD4F10, "form": "jmp"},
    {"slot": 49, "addr": 0x5FD4F30, "form": "jmp"},
    {"slot": 50, "addr": 0x5FD4F70, "form": "jmp"},
    {"slot": 51, "addr": 0x5FD4F90, "form": "jmp"},
    {"slot": 52, "addr": 0x5FD4F50, "form": "jmp"},
    {"slot": 59, "addr": 0x5FD4FB0, "form": "call"},
    {"slot": 63, "addr": 0x5FD5000, "form": "jmp"},
    {"slot": 64, "addr": 0x5FD5020, "form": "jmp"},
    {"slot": 65, "addr": 0x5FD5040, "form": "call"},
    {"slot": 66, "addr": 0x5FD5090, "form": "jmp"},
    {"slot": 67, "addr": 0x5FD50B0, "form": "jmp"},
    {"slot": 68, "addr": 0x5FD50F0, "form": "call"},
    {"slot": 69, "addr": 0x5FD50D0, "form": "jmp"},
    {"slot": 71, "addr": 0x5FD51D0, "form": "call"},
    {"slot": 79, "addr": 0x5FD5140, "form": "call"},
    {"slot": 80, "addr": 0x5FD5190, "form": "jmp"},
    {"slot": 81, "addr": 0x5FD51B0, "form": "jmp"},
]


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def va_to_file_off(data, va):
    """Translate a virtual address to a file offset via LOADs."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    raise SystemExit("no LOAD segment covers %#x" % va)


def relative_records():
    """offset -> addend for every R_X86_64_RELATIVE record."""
    out = subprocess.run(["readelf", "-r", str(BINARY)],
                         capture_output=True, text=True, check=True).stdout
    rel = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            rel[int(parts[0], 16)] = int(parts[3], 16)
    return rel


def census_counts():
    """(calls, jumps, leas) per target, parsed from callers.tsv."""
    counts = {}
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        _site, target, _caller, kind = line.split("\t")
        target = int(target, 16)
        entry = counts.setdefault(target, {"calls": 0, "jumps": 0, "leas": 0})
        entry[{"call": "calls", "tail jump": "jumps",
               "lea": "leas"}[kind]] += 1
    return counts


def qword_hits(data):
    """Raw-binary qword hits per target (8-byte strides)."""
    hits = {t: 0 for t in TARGETS}
    for off in range(0, len(data) - 7, 8):
        val = struct.unpack_from("<Q", data, off)[0]
        if val in hits:
            hits[val] += 1
    return hits


def main():
    data = BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    counts = census_counts()
    for addr in TARGETS:
        counts.setdefault(addr, {"calls": 0, "jumps": 0, "leas": 0})
    hits = qword_hits(data)
    rel = relative_records()
    rel_counts = {}
    for addr in TARGETS:
        rel_counts[addr] = sum(1 for a in rel.values() if a == addr)
    reloc_rows = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        parts = line.split()
        reloc_rows.append({"offset": int(parts[0], 16),
                           "addend": int(parts[3], 16)})

    def vtable_map(base, nslots):
        return ["0x%x" % rel.get(base + i * 8, 0) for i in range(nslots)]

    env_map = vtable_map(0x64CDAD0, 85)
    comp_map = vtable_map(0x64CE2D8, 85)
    wrap_map = vtable_map(0x64CE590, 85)
    mock_map = vtable_map(0x64D1398, 85)
    conf_map = vtable_map(0x64D3430, 8)
    node_map = vtable_map(0x64CDE68, 3)
    cb_map = vtable_map(0x64D1C38, 5)

    def typeinfo_name(header):
        ti = rel.get(header + 8)
        name_ptr = rel.get(ti + 8) if ti else None
        if name_ptr is None:
            return None
        off = va_to_file_off(data, name_ptr)
        end = data.index(b"\x00", off)
        return data[off:end].decode()

    literals = []
    for addr, text in [
            (0x43E762, "CompositeEnv"),
            (0x4496D1, "target="),
            (0x4474D2, "basic_string::append"),
            (0x4429A3, "mutex_init"),
            (0x44A397, "Environment")]:
        off = va_to_file_off(data, addr)
        raw = data[off:off + len(text) + 1]
        assert raw == text.encode() + b"\x00", "%#x literal mismatch" % addr
        literals.append({"addr": addr, "offset": off, "text": text})
    off = va_to_file_off(data, 0x459B20)
    assert data[off:off + 8] == struct.pack("<Q", 0x100000001)
    literals.append({"addr": 0x459B20, "offset": off,
                     "text": "<packed counts 0x100000001>"})
    off = va_to_file_off(data, 0x459E78)
    assert data[off:off + 4] == struct.pack("<f", 1.0)
    literals.append({"addr": 0x459E78, "offset": off,
                     "text": "<float 1.0>"})

    # Pinned SHA-256 of the same excerpts in the
    # RE-001-systemclock-installers-115 packet (open PR #3948,
    # branch fix/systemclock-installers-115); the local copies must
    # match byte-for-byte.
    reshipped = []
    for name, fde, pinned in [
            ("accessor-5fcf430.objdump.txt", "0x5fcf430..0x5fcf439",
             "10e31147166eceeaa845e3b7a597cd6b4dc1307d7b34224fc04c60577e63c2af"),
            ("invoker-composite-5fcf450.objdump.txt",
             "0x5fcf450..0x5fcf4cb",
             "efa108e8d5054cf978e294bb4c13e01ebccbc159ea0e652bca7266d10cdbd24f"),
            ("append-6099ce0.objdump.txt", "0x6099ce0..0x6099e34",
             "f813fd6acf4f8a0b6bc65e7547cc59cbce95e8ae2277d79f688efb4257453817"),
            ("grow-6099790.objdump.txt", "0x6099790..0x6099cad",
             "cd90e710a6e4f14497fcd949703eec743fd7b54c5386b5d17038a187a7538280")]:
        local = sha256_file(PACKET / name)
        assert local == pinned, "%s differs from #3948" % name
        reshipped.append({"file": name, "fde": fde,
                          "sha256": local,
                          "source": "RE-001-systemclock-installers-115"})

    census = {}
    for addr in sorted(TARGETS):
        census["0x%x" % addr] = {
            "calls": counts[addr]["calls"],
            "jumps": counts[addr]["jumps"],
            "leas": counts[addr]["leas"],
            "qwords": hits[addr],
            "relative": rel_counts[addr],
        }

    records = {
        "target": {"artifact": "work/hl-node-115.bin",
                   "sha256": digest, "node": 115},
        "work_item": "RE-001-composite-env-wrapper-115",
        "task": "RE-001",
        "question": (
            "Pin node #115's CompositeEnvWrapper construction and "
            "destruction end-to-end: the builder 0x5fd7360 and "
            "install helper 0x5fceb20, the wrapper D2/D0 and base D2, "
            "the wrapper vtable overrides (slots 5, 12, 14, 16, 17) "
            "and the 20 forwarder slots, the default holder "
            "initializer 0x5fe2860, the FactoryEntry node slot 2, and "
            "the factory control-block dispose/destroy pair. This "
            "resolves the open unknowns carried by PR #3948 (the "
            "CompositeEnv builder, the holder initializer full body, "
            "the factory control-block dispose/destroy, the node "
            "vtable slot 2)."),
        "layout": {
            "size": 0x60,
            "fields": [
                {"offset": 0x00, "what": "vtable pointer"},
                {"offset": 0x08, "what": "options vector "
                 "{begin, end, capacity} of 0x30-byte records"},
                {"offset": 0x28, "what": "shared_ptr A (object, "
                 "control block)"},
                {"offset": 0x38, "what": "shared_ptr B (object, "
                 "control block)"},
                {"offset": 0x48, "what": "wrapped Env*"},
                {"offset": 0x50, "what": "shared_ptr C (object, "
                 "control block)"},
            ],
            "base_size": 0x50,
            "note": "The base (CompositeEnv) object is 0x50 bytes; "
                    "the wrapper adds shared_ptr C at +0x50/+0x58, "
                    "which the wrapper D0 deletes with operator "
                    "delete 0x60.",
        },
        "builder": {
            "addr": 0x5FD7360, "fde": "0x5fd7360..0x5fd7466",
            "signature": "(this, wrapped_env, sp_a_slot, sp_b_slot)",
            "role": "Calls the install helper 0x5fceb20 with "
                    "(sp_a_slot, sp_b_slot), stores the wrapped env "
                    "at +0x48, zeroes shared_ptr C (+0x50/+0x58), "
                    "installs the wrapper vtable 0x64ce590, and "
                    "appends three empty-named records via 0x6099ce0: "
                    "{\"\" , this+0x48, 0x6504c60}, {\"\" , this+0x28, "
                    "0x6504c20}, {\"\" , this+0x38, 0x6504be0}. The "
                    "record third fields are .bss addresses; their "
                    "runtime contents are not statically "
                    "determinable (open unknown).",
            "calls": counts[0x5FD7360]["calls"],
            "callers": ["0x5fcf495 (CompositeEnv invoker 0x5fcf450)",
                        "0x60289f8 (MockEnv ctor 0x60289f0)"],
            "landing_pads": "The builder's three landing pads "
                            "(0x5fd7442/0x5fd744e/0x5fd745a) jump to "
                            "the shared cleanup at 0x5fd730c: dispose "
                            "the temp record string, release +0x58, "
                            "install the CompositeEnv vtable, call "
                            "the base D2 (0x5fd7333), _Unwind_Resume.",
            "excerpt": "builder-5fd7360.objdump.txt",
        },
        "install": {
            "addr": 0x5FCEB20, "fde": "0x5fceb20..0x5fcebb7",
            "signature": "(this, sp_a_slot, sp_b_slot)",
            "role": "Installs the Env vtable 0x64cdad0, zeroes "
                    "+0x08/+0x10/+0x18/+0x20, copies shared_ptr A "
                    "from the caller's slot into +0x28/+0x30 and "
                    "shared_ptr B from the caller's 16-byte slot "
                    "into +0x38/+0x40, each with a selector-gated "
                    "use-count bump (byte at 0x64ed290: 0 selects "
                    "lock addl, non-zero selects plain addl).",
            "calls": counts[0x5FCEB20]["calls"],
            "callers": ["0x5fd7388 (builder 0x5fd7360)",
                        "0x5fe2900 (holder init 0x5fe2860)"],
            "excerpt": "install-5fceb20.objdump.txt",
        },
        "string_init": {
            "addr": 0x5FD5CC0, "fde": "0x5fd5cc0..0x5fd5cd4",
            "role": "std::string default ctor (20 bytes): ptr = "
                    "this+0x10, length 0, SSO nul. Initializes the "
                    "three empty record names in the builder and "
                    "the temp string in slot 12.",
            "calls": counts[0x5FD5CC0]["calls"],
            "callers": ["0x5fd5e63 (slot 12)", "0x5fd73c3",
                        "0x5fd73e2", "0x5fd7408 (builder)"],
            "excerpt": "string-init-5fd5cc0.objdump.txt",
        },
        "destructors": [
            {"name": "CompositeEnvWrapper D2 (slot 0)", "addr": 0x5FD72D0,
             "fde": "0x5fd72d0..0x5fd730b",
             "role": "Installs the wrapper vtable, releases +0x58 "
                     "via _M_release 0x5d350c0 when non-null, "
                     "installs the CompositeEnv vtable, tail-jumps "
                     "to the base D2 0x5fcf4d0.",
             "installed_by": "RELATIVE record at 0x64ce590 "
                             "(wrapper vtable slot 0)",
             "excerpt": "wrapper-d2-5fd72d0.objdump.txt"},
            {"name": "CompositeEnvWrapper D0 (slot 1)", "addr": 0x5FD7510,
             "fde": "0x5fd7510..0x5fd7558",
             "role": "Deleting destructor: installs the wrapper "
                     "vtable, releases +0x58, installs the "
                     "CompositeEnv vtable, CALLS the base D2 (not a "
                     "tail jump), then operator delete 0x60.",
             "installed_by": "RELATIVE record at 0x64ce598 "
                             "(wrapper vtable slot 1)",
             "excerpt": "wrapper-d0-5fd7510.objdump.txt"},
            {"name": "CompositeEnv base D2", "addr": 0x5FCF4D0,
             "fde": "0x5fcf4d0..0x5fcf585",
             "role": "Installs the Env vtable, releases +0x40 then "
                     "+0x30 via _M_release 0x5d350c0 when non-null, "
                     "installs the Configurable vtable 0x64d3430, "
                     "destroys the options vector (string-dispose "
                     "each 0x30-byte record whose string is heap "
                     "allocated, then free the buffer).",
             "calls": counts[0x5FCF4D0]["calls"],
             "jumps": counts[0x5FCF4D0]["jumps"],
             "reached_by": {
                 "calls": ["0x5fd7545 (wrapper D0)",
                           "0x5fd7333 (builder landing pad 0x5fd730c)",
                           "0x5fe281f (PosixClock accessor landing pad "
                           "0x5fe2756..0x5fe285d)",
                           "0x5fe2dab (neighbor routine "
                           "0x5fe2d20..0x5fe2e17)",
                           "0x60290b6 (MockEnv D0 0x6029050)"],
                 "tail_jumps": ["0x5fd7306 (wrapper D2)",
                                "0x5fe2cbf (TSU atexit dtor 0x5fe2c30 — "
                                "the holder cleanup destroys via the "
                                "base D2)",
                                "0x6028ffc (MockEnv D2 0x6028f90)"]},
             "excerpt": "basedtor-5fcf4d0.objdump.txt"},
        ],
        "slots": [
            {"slot": 5, "name": "PrepareOptions", "addr": 0x5FD7560,
             "fde": "0x5fd7560..0x5fd76b1",
             "signature": "(this, target_env, options)",
             "role": "Resolves the target's wrapped env: the "
                     "target's shared_ptr C object if set, else the "
                     "target's +0x48 if set, else the default holder "
                     "from 0x5fe2860; stores it at target+0x48. If "
                     "target+0x28 is null, copies the wrapped env's "
                     "+0x28 shared_ptr in via the helper 0x5fcf390 "
                     "(selector-gated bump, old control-block "
                     "release). If target+0x38 is null, copies the "
                     "wrapped env's +0x38 shared_ptr in via the "
                     "accessor 0x5fcf430 the same way. Then calls "
                     "the base PrepareOptions 0x6095e70 (a plain call, "
                     "not a tail jump) and returns this.",
             "excerpt": "wslot5-5fd7560.objdump.txt"},
            {"slot": 12, "name": "SerializeOptions", "addr": 0x5FD5E00,
             "fde": "0x5fd5e00..0x5fd5f07",
             "signature": "(out_string, env, options, ...)",
             "role": "Calls the base 0x609de80 first (it fills the "
                     "output string); then, if the env's wrapped env "
                     "is non-null and is not the default holder, "
                     "appends \"target=\" plus the wrapped env's "
                     "serialization (via the helper 0x60971c0) to the "
                     "output string. Recorded as observed: the "
                     "first argument is the output string, the "
                     "second the env, the third the options — the "
                     "base 0x609de80 default-initializes its first "
                     "argument as a std::string and reads the env "
                     "from the second.",
             "excerpt": "wslot12-5fd5e00.objdump.txt"},
            {"slot": 14, "name": "Name", "addr": 0x5FD4E60,
             "fde": "0x5fd4e60..0x5fd4e6c",
             "role": "Returns \"CompositeEnv\" (string at 0x43e762).",
             "excerpt": "wslot14-5fd4e60.objdump.txt"},
            {"slot": 16, "name": "IsInstanceOf", "addr": 0x5FD6240,
             "fde": "0x5fd6240..0x5fd6271",
             "role": "Returns 1 iff the arg string has length 12 "
                     "and equals \"CompositeEnv\" (first 8 bytes "
                     "compared as the constant 0x7469736f706d6f43, "
                     "next 4 as 0x766e4565); otherwise falls back to "
                     "the base 0x5d2e770.",
             "excerpt": "wslot16-5fd6240.objdump.txt"},
            {"slot": 17, "name": "wrapped-env accessor",
             "addr": 0x5FD4E70, "fde": "0x5fd4e70..0x5fd4e79",
             "role": "Returns this+0x48 (the wrapped Env*).",
             "excerpt": "wslot17-5fd4e70.objdump.txt"},
        ],
        "forwarders": [
            dict(f, target_offset=hex(f["slot"] * 8),
                 role=("Forwards the wrapped env's same slot: "
                       "jmp-form loads this+0x48 and tail-jumps to "
                       "wrapped->vtable[slot]; call-form loads "
                       "arg+0x48, calls wrapped->vtable[slot], and "
                       "returns this."))
            for f in FORWARDERS
        ],
        "holder_init": {
            "addr": 0x5FE2860, "fde": "0x5fe2860..0x5fe2c2f",
            "role": "Returns the function-local static holder at "
                    "0x6504cc0 (guard byte 0x6504ca8). Calls 0x61d2ca0 "
                    "and 0x61c21b0 unconditionally first (one site "
                    "each, opaque, by contract), then "
                    "__cxa_guard_acquire; on first init it takes the "
                    "PosixClock accessor 0x5fe2680, builds a temp "
                    "shared_ptr via the PosixFileSystem holder "
                    "accessor 0x60029f0, installs the holder via "
                    "0x5fceb20, releases the temp shared_ptr "
                    "(fast path at counts (1, 1), else selector-gated "
                    "decrement plus the 0x5d35070 dispose tail), "
                    "installs the CompositeEnv vtable, builds a "
                    "0x40-byte 4x0x10 record array (vector at "
                    "0x6504d08, entries via the by-contract "
                    "0x61d4570), a mutex at 0x6504d60 named "
                    "\"mutex_init\" with a 4-entry loop (0x61d4740 / "
                    "0x61d4730, by contract), and a 0xd8-byte "
                    "ThreadStatusUpdater at 0x6504ce0 (vtable "
                    "0x64ce8e0; +0x38/+0x70/+0xa8 = 1; float 1.0 at "
                    "+0x50/+0x88/+0xc0 from 0x459e78; self-pointers "
                    "+0x30->+0x60, +0x68->+0x98, +0xa0->+0xd0), "
                    "registers __cxa_atexit with dtor 0x5fe2c30 and "
                    "DSO handle 0x64efa20, releases the guard.",
            "calls": counts[0x5FE2860]["calls"],
            "callers": ["0x5e5da98", "0x5fcd5b8", "0x5fcf46e",
                        "0x5fd34e4", "0x5fd3a7d", "0x5fd576e",
                        "0x5fd5e35", "0x5fd75e9", "0x5fe2c45",
                        "0x5fe2d35", "0x5feab98", "0x6001418",
                        "0x602e67f", "0x60a524d", "0x60b2ded",
                        "0x60bb8e3", "0x60bb8f5"],
            "excerpt": "holder-init-5fe2860.objdump.txt",
        },
        "node_slot2": {
            "addr": 0x5FCC7E0, "fde": "0x5fcc7e0..0x5fcc7ee",
            "role": "FactoryEntry<Env> node vtable slot 2: forwards "
                    "this+0x08's vtable slot 2 (the entry object's "
                    "slot 2). Answers the open unknown carried by "
                    "PR #3948 about that slot's role.",
            "installed_by": "RELATIVE record at 0x64cde78 "
                            "(node vtable slot 2)",
            "excerpt": "node-slot2-5fcc7e0.objdump.txt",
        },
        "control_block": {
            "vtable": 0x64D1C38,
            "typeinfo": typeinfo_name(0x64D1C28),
            "slots": [
                {"slot": 0, "addr": int(cb_map[0], 16),
                 "role": "not excerpted; cited from the RELATIVE record"},
                {"slot": 1, "addr": int(cb_map[1], 16),
                 "role": "not excerpted; cited from the RELATIVE record"},
                {"slot": 2, "addr": 0x6025950, "name": "dispose",
                 "fde": "0x6025950..0x6025964",
                 "role": "Tail-jumps to the managed object's slot 0 "
                         "(D2) with this+0x10.",
                 "installed_by": "RELATIVE record at 0x64d1c48",
                 "excerpt": "cb-dispose-6025950.objdump.txt"},
                {"slot": 3, "addr": 0x6025B90, "name": "destroy",
                 "fde": "0x6025b90..0x6025b9e",
                 "role": "operator delete 0x60.",
                 "installed_by": "RELATIVE record at 0x64d1c50",
                 "excerpt": "cb-destroy-6025b90.objdump.txt"},
                {"slot": 4, "addr": int(cb_map[4], 16),
                 "role": "not excerpted; cited from the RELATIVE record"},
            ],
            "note": "The control-block vtable is "
                    "_Sp_counted_ptr_inplace<EmulatedSystemClock>; "
                    "its dispose/destroy are the slots _M_release "
                    "0x5d350c0 and its dispose tail 0x5d35070 invoke "
                    "via vtable +0x10/+0x18.",
        },
        "shared_ptr_release": {
            "release_addr": 0x5D350C0, "fde": "0x5d350c0..0x5d35145",
            "dispose_tail_addr": 0x5D35070, "fde_tail": "0x5d35070..0x5d350bc",
            "role": "_M_release 0x5d350c0: fast path when the counts "
                    "word is 0x100000001 (use 1, weak 1) — zero the "
                    "counts, dispose via slot 0x10, destroy via slot "
                    "0x18. Otherwise decrement use (lock xadd when "
                    "the byte at 0x64ed290 is 0, plain decrement "
                    "otherwise); when the old use was 1, tail-jump "
                    "to the dispose tail 0x5d35070, which disposes, "
                    "decrements weak at +0x0c (selector-gated), and "
                    "destroys when the old weak count was 1. Direct "
                    "callers of 0x5d35070 are sites that already "
                    "decremented use themselves (e.g. the holder "
                    "init's temp release).",
            "calls": counts[0x5D350C0]["calls"],
            "jumps": counts[0x5D350C0]["jumps"],
            "tail_calls": counts[0x5D35070]["calls"],
            "tail_jumps": counts[0x5D35070]["jumps"],
        },
        "append": {
            "addr": 0x6099CE0, "fde": "0x6099ce0..0x6099e34",
            "role": "Appends one 0x30-byte {std::string, qword, "
                    "qword} record to the vector at owner+0x08..+0x18; "
                    "SSO copy for len<=15, _M_create for longer, "
                    "grows via 0x6099790 at capacity.",
            "calls": counts[0x6099CE0]["calls"],
            "builder_sites": ["0x5fd73cb", "0x5fd73f1", "0x5fd7417"],
            "excerpt": "append-6099ce0.objdump.txt"},
        "grow": {
            "addr": 0x6099790, "fde": "0x6099790..0x6099cad",
            "role": "Doubles the options-vector capacity (bounded "
                    "by the max check), move-constructs the records, "
                    "frees the old buffer.",
            "calls": counts[0x6099790]["calls"],
            "callers": ["0x6099e0a"],
            "excerpt": "grow-6099790.objdump.txt"},
        "accessor": {
            "addr": 0x5FCF430, "fde": "0x5fcf430..0x5fcf439",
            "role": "9 bytes: returns arg+0x38 (the holder's "
                    "shared_ptr B slot).",
            "calls": counts[0x5FCF430]["calls"],
            "excerpt": "accessor-5fcf430.objdump.txt"},
        "helper": {
            "addr": 0x5FCF390, "fde": "0x5fcf390..0x5fcf399",
            "role": "9 bytes: lea 0x28(%rdi),%rax — returns arg+0x28 "
                    "(the shared_ptr A slot). Used by slot 5 and by "
                    "the CompositeEnv invoker.",
            "calls": counts[0x5FCF390]["calls"],
            "excerpt": "helper-5fcf390.objdump.txt"},
        "invoker": {
            "addr": 0x5FCF450, "fde": "0x5fcf450..0x5fcf4cb",
            "role": "CompositeEnv invoker: new(0x60), holder "
                    "accessor 0x5fe2860, 0x5fcf430 (holder+0x38), "
                    "0x5fcf390 (holder+0x28), builder 0x5fd7360 "
                    "(wrapped=holder, sp_a=holder+0x28, "
                    "sp_b=holder+0x38), then swaps the result into "
                    "the caller's cell, D0-deleting the old value.",
            "leas": counts[0x5FCF450]["leas"],
            "lea_sites": ["0x5fd2885"],
            "excerpt": "invoker-composite-5fcf450.objdump.txt"},
        "mock_env": {
            "vtable": 0x64D1398,
            "typeinfo": typeinfo_name(0x64D1388),
            "ctor": 0x60289F0, "fde_ctor": "0x60289f0..0x6028a0d",
            "role": "MockEnv ctor: passes its arguments straight "
                    "through to the builder 0x5fd7360 (its second "
                    "caller), then installs the MockEnv vtable. "
                    "MockEnv's vtable differs from the wrapper's in "
                    "slots 0, 1 and 14 only (its own D2 0x6028f90, "
                    "D0 0x6029050, Name 0x6025790); all 20 forwarder "
                    "slots and the slot 5/12/16/17 overrides are "
                    "shared with the wrapper.",
            "calls": counts[0x60289F0]["calls"],
            "callers": ["0x6028e12"],
        },
        "vtables": {
            "Env": {"header": "0x64cdac0", "vtable": "0x64cdad0",
                    "typeinfo": typeinfo_name(0x64CDAC0),
                    "slots": env_map,
                    "null_slots": [i for i, v in enumerate(env_map)
                                   if v == "0x0"]},
            "CompositeEnv": {"header": "0x64ce2c8",
                             "vtable": "0x64ce2d8",
                             "typeinfo": typeinfo_name(0x64CE2C8),
                             "slots": comp_map,
                             "null_slots": [i for i, v in enumerate(comp_map)
                                            if v == "0x0"]},
            "CompositeEnvWrapper": {"header": "0x64ce580",
                                    "vtable": "0x64ce590",
                                    "typeinfo": typeinfo_name(0x64CE580),
                                    "slots": wrap_map,
                                    "null_slots": []},
            "MockEnv": {"header": "0x64d1388", "vtable": "0x64d1398",
                        "typeinfo": typeinfo_name(0x64D1388),
                        "slots": mock_map,
                        "null_slots": []},
            "Configurable": {"header": "0x64d3420",
                             "vtable": "0x64d3430",
                             "typeinfo": typeinfo_name(0x64D3420),
                             "slots": conf_map},
            "FactoryEntryNode": {"header": "0x64cde58",
                                 "vtable": "0x64cde68",
                                 "typeinfo": typeinfo_name(0x64CDE58),
                                 "slots": node_map},
            "diffs": {
                "env_vs_composite_env": [i for i in range(85)
                                         if env_map[i] != comp_map[i]],
                "composite_env_vs_wrapper": [i for i in range(85)
                                             if comp_map[i] != wrap_map[i]],
                "wrapper_vs_mock_env": [i for i in range(85)
                                        if wrap_map[i] != mock_map[i]],
            },
            "slot_61_note": "Slot 61 (0x5fd5f10, chain-walk on slot "
                            "24 via GOT 0x64ed3e8) is 0x5fd5f10 in "
                            "both CompositeEnv and the wrapper; Env "
                            "has no implementation there (null). "
                            "Cited only, not excerpted.",
        },
        "relocations": reloc_rows,
        "relocation_ranges": [
            {"range": "0x64cdac0..0x64cdad8", "what": "Env vtable header",
             "count": 1},
            {"range": "0x64ce2c8..0x64ce580", "what": "CompositeEnv vtable "
             "header + slots", "count": 78},
            {"range": "0x64ce580..0x64ce840", "what": "wrapper vtable "
             "header + slots", "count": 86},
            {"range": "0x64d3420..0x64d3470", "what": "Configurable "
             "vtable header + slots 0-7", "count": 9},
            {"range": "0x64cde58..0x64cde80", "what": "FactoryEntry node "
             "vtable header + slots", "count": 4},
            {"range": "0x64d1c28..0x64d1c60", "what": "factory "
             "control-block vtable", "count": 6},
            {"range": "0x64d1388..0x64d13a0", "what": "MockEnv vtable "
             "header + slot 0", "count": 2},
        ],
        "literals": literals,
        "census": {
            "targets": census,
            "callers_tsv_rows": 2297,
            "relocation_records": len(reloc_rows),
        },
        "reshipped": reshipped,
        "model": "tools/composite_env_wrapper_115.py",
        "tests": "tests/test_composite_env_wrapper_115.py",
        "test_checks": 246,
        "open_unknowns": [
            "Record third fields 0x6504c60/0x6504c20/0x6504be0 are in "
            ".bss (runtime-initialized); their contents are not "
            "recoverable statically.",
            "Holder-init callees 0x61d2ca0, 0x61c21b0, 0x61d4570, "
            "0x61d4740, 0x61d4730, 0x61d4420 and the PosixFileSystem "
            "holder accessor 0x60029f0 internals are by contract, not "
            "excerpted.",
            "ThreadStatusUpdater methods are not excerpted; only its "
            "construction-time field map is pinned.",
            "The full MockEnv slot map beyond slots 0, 1, 14 (shared "
            "with the wrapper) is open; MockEnv's own D2/D0/Name "
            "bodies are not excerpted.",
            "Configurable vtable slots beyond 0-7 are open.",
            "The preceding vtable's last slot at 0x64ce2c0 -> "
            "0x5fd5360 (forwards this+0x08's slot 5) is a boundary "
            "observation, not in this packet.",
            "Slot 61 (0x5fd5f10) is cited only, not excerpted.",
            "The 'Environment' string at 0x44a397 is part of the "
            "\"Cannot make a shared Environment from a guarded one\" "
            "error text; the Env create-host registry is a separate "
            "work item.",
            "The slot-12 first argument is the output string as "
            "observed in the binary; no C++ signature is asserted "
            "beyond that.",
        ],
    }
    with open(PACKET / "records.json", "w") as handle:
        json.dump(records, handle, indent=2)
        handle.write("\n")
    print("wrote records.json")
    print("targets in census:", len(census))
    print("relocations:", len(reloc_rows))
    print("literals:", len(literals))


if __name__ == "__main__":
    sys.exit(main())
