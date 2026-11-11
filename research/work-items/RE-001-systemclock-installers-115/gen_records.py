"""Generate records.json for the RE-001-systemclock-installers-115
packet from the census outputs and the verbatim excerpts.

Usage (from the repository root):
    python3 research/work-items/RE-001-systemclock-installers-115/gen_records.py

The JSON holds semantic records only: installer roles, call
counts, relocation rows, string literals and open unknowns.
Instruction-level detail lives only in the verbatim objdump
excerpts. The five vtable installers and the three entry
thunks are re-shipped byte-identical from the
RE-001-canonical-lea-sites-115 packet (open PR #3352, now
merged); their SHA-256 values are recorded here and checked
by verify.py.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
RE3352 = ROOT / "research" / "work-items" / "RE-001-canonical-lea-sites-115"


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


def main():
    data = BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    counts = census_counts()
    for addr in (0x5FD0090, 0x6029110, 0x6029230, 0x6029500, 0x6029620,
                 0x6099CE0, 0x6099790, 0x5D35070, 0x6029390, 0x602934C,
                 0x60297A0, 0x5FCF430, 0x5FCC5D0, 0x5FCC600, 0x5FCC630,
                 0x5FD27C0, 0x5FD20D0, 0x5FD24C0, 0x5FCD5B0, 0x5FCD550,
                 0x5FCF450, 0x5FCC700, 0x5FE2860, 0x5FCF390, 0x5FD7360,
                 0x6028D80):
        counts.setdefault(addr, {"calls": 0, "jumps": 0, "leas": 0})
    reloc_rows = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        parts = line.split()
        reloc_rows.append({"offset": int(parts[0], 16),
                           "addend": int(parts[3], 16)})

    literals = []
    for addr, text in [
            (0x447686, "MockEnv"),
            (0x43E762, "CompositeEnv"),
            (0x4372AE, "TimeEmulatedSystemClock"),
            (0x438369, "SystemClock"),
            (0x44A397, "Environment"),
            (0x44A390, "target"),
            (0x4429A3, "mutex_init"),
            (0x4376FD, "")]:
        off = va_to_file_off(data, addr)
        raw = data[off:off + len(text) + 1]
        assert raw == text.encode() + b"\x00", "%#x literal mismatch" % addr
        literals.append({"addr": addr, "offset": off, "text": text})

    reshipped = []
    for name, fde in [
            ("vtable_install_1.txt", "0x5fd0090..0x5fd0178"),
            ("vtable_install_2.txt", "0x6029110..0x602922b"),
            ("vtable_install_3.txt", "0x6029230..0x602934b"),
            ("vtable_install_4.txt", "0x6029500..0x602961b"),
            ("vtable_install_5.txt", "0x6029620..0x602973b"),
            ("entry_install_1.txt", "0x5fcc5d0..0x5fcc5fd"),
            ("entry_install_2.txt", "0x5fcc600..0x5fcc62d"),
            ("entry_install_3.txt", "0x5fcc630..0x5fcc65d")]:
        local = sha256_file(PACKET / name)
        prior = sha256_file(RE3352 / name)
        assert local == prior, "%s differs from #3352" % name
        reshipped.append({"file": name, "fde": fde,
                          "sha256": local,
                          "source": "RE-001-canonical-lea-sites-115"})

    records = {
        "target": {"artifact": "work/hl-node-115.bin",
                   "sha256": digest, "node": 115},
        "work_item": "RE-001-systemclock-installers-115",
        "task": "RE-001",
        "question": (
            "Pin node #115's SystemClockWrapper vtable installers: "
            "the exact roles of the five installer routines "
            "(0x5fd0090, 0x6029110, 0x6029230, 0x6029500, 0x6029620), "
            "the shared record-append and shared_ptr-release helpers "
            "they call, and the three FactoryEntry entry thunks' "
            "mode-1 callers (0x5fcc5d0, 0x5fcc600, 0x5fcc630)."),
        "installers": [
            {"name": "SystemClockWrapper ctor C1", "addr": 0x5FD0090,
             "fde": "0x5fd0090..0x5fd0178",
             "role": "installs the wrapper vtable 0x64cdd88, zeroes "
                     "+0x08..+0x18, copies the wrapped-clock shared_ptr "
                     "into +0x20/+0x28 with a use-count bump, and "
                     "appends record {\"\", this+0x20, 0x6504b80} "
                     "via 0x6099ce0 at 0x5fd0124",
             "calls": counts[0x5FD0090]["calls"],
             "callers": ["0x60293b6"],
             "excerpt": "vtable_install_1.txt"},
            {"name": "EmulatedSystemClock D2 (slot 0)", "addr": 0x6029110,
             "fde": "0x6029110..0x602922b",
             "role": "releases the +0x28 shared_ptr via 0x5d35070, "
                     "installs the base vtable 0x64d3420+0x10, and "
                     "destroys the +0x08 options vector (string-dispose "
                     "each 0x30-byte record, then free the buffer)",
             "calls": counts[0x6029110]["calls"],
             "callers": [],
             "installed_by": "RELATIVE record at 0x64d1650 "
                             "(emulated vtable slot 0)",
             "excerpt": "vtable_install_2.txt"},
            {"name": "SystemClockWrapper D2", "addr": 0x6029230,
             "fde": "0x6029230..0x602934b",
             "role": "byte-identical to the Emulated D2: releases "
                     "+0x28, installs the base vtable, destroys the "
                     "+0x08 vector",
             "calls": counts[0x6029230]["calls"],
             "callers": ["0x6029357"],
             "excerpt": "vtable_install_3.txt"},
            {"name": "SystemClockWrapper D0", "addr": 0x6029500,
             "fde": "0x6029500..0x602961b",
             "role": "deleting destructor: the D2 body plus operator "
                     "delete 0x30. Completely unreferenced: no direct "
                     "caller, no qword hits, no RELATIVE slot. This "
                     "explains why the wrapper vtable slots 0 and 1 "
                     "are null",
             "calls": counts[0x6029500]["calls"],
             "callers": [],
             "excerpt": "vtable_install_4.txt"},
            {"name": "EmulatedSystemClock D0 (slot 1)", "addr": 0x6029620,
             "fde": "0x6029620..0x602973b",
             "role": "deleting destructor: the D2 body plus operator "
                     "delete 0x50",
             "calls": counts[0x6029620]["calls"],
             "callers": [],
             "installed_by": "RELATIVE record at 0x64d1658 "
                             "(emulated vtable slot 1)",
             "excerpt": "vtable_install_5.txt"},
        ],
        "append": {
            "addr": 0x6099CE0, "fde": "0x6099ce0..0x6099e34",
            "role": "appends one 0x30-byte {std::string, qword, qword} "
                    "record to the vector at owner+0x08..+0x18; "
                    "SSO copy for len<=15, _M_create for longer, "
                    "grows via 0x6099790 at capacity",
            "calls": counts[0x6099CE0]["calls"],
            "clock_sites": {
                "0x5fd0124": {"caller": "wrapper ctor 0x5fd0090",
                              "record": "{\"\" , this+0x20, 0x6504b80}"},
                "0x6029454": {"caller": "emulated ctor 0x6029390",
                              "record": "{\"\" , this, 0x6505960}"},
                "0x6029494": {"caller": "emulated ctor 0x6029390",
                              "record": "{\"\" , this, 0x6505920}"},
            },
            "excerpt": "append-6099ce0.objdump.txt"},
        "grow": {
            "addr": 0x6099790, "fde": "0x6099790..0x6099cad",
            "role": "doubles the options-vector capacity "
                    "(0xaaaaaaaaaaaaaaab divide-by-48, max check "
                    "against 0x2aaaaaaaaaaaaaa, overflow allocation "
                    "0x7fffffffffffffe0), move-constructs the records "
                    "(SSO strings copied inline, heap strings moved "
                    "with the source nulled), frees the old buffer",
            "calls": counts[0x6099790]["calls"],
            "callers": ["0x6099e0a"],
            "excerpt": "grow-6099790.objdump.txt"},
        "emu_ctor": {
            "addr": 0x6029390, "fde": "0x6029390..0x60294f5",
            "role": "EmulatedSystemClock ctor C1: calls the wrapper "
                    "ctor, installs the emulated vtable 0x64d1650, "
                    "reads the wrapped clock's slot-24 GetCurrentTime "
                    "(rdi=rsp+0x20 out, rsi=wrapped, rdx=rsp+0x18 "
                    "value_out; rsp+0x18 preloaded with constant "
                    "0x4fb647d0), stores the value at +0x30, "
                    "duplicates the mode byte at +0x48/+0x49, zeroes "
                    "+0x38/+0x40, and appends two records via "
                    "0x6099ce0",
            "calls": counts[0x6029390]["calls"],
            "callers": ["0x5fcd577", "0x6029800"],
            "modes": {"0": "invoker 0x5fcd550 (TimeEmulatedSystemClock), "
                           "wraps the PosixClock",
                      "1": "factory 0x60297a0 (MockEnv), wraps the "
                           "holder's clock"},
            "excerpt": "emu-ctor-6029390.objdump.txt"},
        "last_use_helper": {
            "addr": 0x5D35070, "fde": "0x5d35070..0x5d350bc",
            "role": "shared_ptr last-use helper: control-block slot "
                    "0x10 dispose, weak-count decrement at +0x0c "
                    "(lock xadd iff the byte at 0x64ed290 is 0), "
                    "old weak count 1 tail-jumps to slot 0x18 "
                    "destroy. Shared libstdc++ machinery: 654 direct "
                    "calls and 36 tail jumps binary-wide",
            "calls": counts[0x5D35070]["calls"],
            "jumps": counts[0x5D35070]["jumps"],
            "clock_sites": ["0x6029221", "0x6029341", "0x6029611",
                            "0x6029731", "0x60298d3", "0x5fe295d"],
            "excerpt": "lastuse-5d35070.objdump.txt"},
        "landing_pad": {
            "addr": 0x602934C, "fde": "0x602934c..0x6029383",
            "role": "_M_dispose temp string (r12 = rsp+0x30), calls "
                    "the wrapper D2, checks the stack canary, "
                    "_Unwind_Resume. Jumped to from 0x60294d8 in the "
                    "emulated ctor",
            "jumps": counts[0x602934C]["jumps"],
            "jumpers": ["0x60294d8"],
            "excerpt": "landing-602934c.objdump.txt"},
        "thunks": [
            {"name": "MockEnv entry thunk", "addr": 0x5FCC5D0,
             "fde": "0x5fcc5d0..0x5fcc5fd", "vtable": "0x64cd9d0",
             "leas": counts[0x5FCC5D0]["leas"], "lea_sites": ["0x5fd280c"],
             "excerpt": "entry_install_1.txt"},
            {"name": "CompositeEnv entry thunk", "addr": 0x5FCC600,
             "fde": "0x5fcc600..0x5fcc62d", "vtable": "0x64cd9e0",
             "leas": counts[0x5FCC600]["leas"], "lea_sites": ["0x5fd288f"],
             "excerpt": "entry_install_2.txt"},
            {"name": "TimeEmulatedSystemClock entry thunk",
             "addr": 0x5FCC630, "fde": "0x5fcc630..0x5fcc65d",
             "vtable": "0x64cd9f0",
             "leas": counts[0x5FCC630]["leas"], "lea_sites": ["0x5fd2124"],
             "excerpt": "entry_install_3.txt"},
        ],
        "manager_ops": {
            "signature": "manager(dest rdi, src rsi, op edx)",
            "op_0": {"effect": "install the vtable at (%rdi)",
                     "invoked": False},
            "op_1": {"effect": "store rsi at (%rdi)",
                     "invoked": False,
                     "note": "binary-wide scan found no real manager "
                             "invocation with op 1; the single edx=1 "
                             "candidate at 0x2320375 is a GOT call at "
                             "0x64e00a0, not a manager call"},
            "op_2": {"effect": "clone the 8-byte functor storage",
                     "invoked": True,
                     "sites": ["0x5fd2526 (registry insert 0x5fd24c0)",
                               "0x61c9d70 (registry find, per #3764)"]},
            "op_3": {"effect": "destroy the functor (no-op for a "
                               "plain function pointer)",
                     "invoked": True,
                     "sites": ["0x5fd2874 (reg-sysclocks MockEnv)",
                               "0x5fd28ea (reg-sysclocks CompositeEnv)",
                               "0x5fd22fe (default-init)",
                               "0x5fcc72b (node D2 0x5fcc700)"]},
            "answer": "No caller passes a mode-1 pointer through the "
                      "thunks: the op-0/op-1 arms are never invoked; "
                      "only ops 2 and 3 are exercised. Mode 1 reaches "
                      "the emulated clock through the factory "
                      "0x60297a0, not through a thunk.",
        },
        "registrations": {
            "reg_sysclocks": {
                "addr": 0x5FD27C0, "fde": "0x5fd27c0..0x5fd297f",
                "role": "RegisterBuiltinSystemClocks: builds the "
                        "{manager=thunk1, invoker=0x5fcd5b0} function "
                        "named MockEnv and the {manager=thunk2, "
                        "invoker=0x5fcf450} function named CompositeEnv, "
                        "inserts each via 0x5fd24c0 (0x5fd2848, "
                        "0x5fd28c3), destroys the temps with op 3, "
                        "then calls 0x61f8700",
                "leas": counts[0x5FD27C0]["leas"],
                "lea_sites": ["0x5fd358e", "0x5fd3c3a"],
                "excerpt": "reg-sysclocks-5fd27c0.objdump.txt"},
            "default_init": {
                "addr": 0x5FD20D0, "fde": "0x5fd20d0..0x5fd241d",
                "role": "SystemClock default initializer: builds the "
                        "{manager=thunk3, invoker=0x5fcd550} function "
                        "named TimeEmulatedSystemClock and inserts it "
                        "inline (same shape as insert: new 0x30 "
                        "function node, new 0x70 entry, op-2 clone, "
                        "mutex lock, 0x5fd1da0 at 0x5fd22b4, op-3 "
                        "destroy at 0x5fd22fe, 0x61f8700 at 0x5fd2310)",
                "leas": counts[0x5FD20D0]["leas"],
                "lea_sites": ["0x5fd47c1"],
                "node_vtable_note": "the 0x30-byte function node's "
                                    "vtable pointer is 0x64cde88 "
                                    "(node vtable slot 2, 0x5fcc7e0); "
                                    "that slot's role is an open unknown",
                "excerpt": "default-init-5fd20d0.objdump.txt"},
            "insert": {
                "addr": 0x5FD24C0, "fde": "0x5fd24c0..0x5fd2748",
                "role": "registry insert: new(0x30) function node "
                        "(vtable 0x64cde68), op-2 clone of the caller's "
                        "function, new(0x70) entry (vtable 0x64d8ed0), "
                        "name string copied via 0x5fcd6f0, mutex lock, "
                        "calls 0x5fd1da0 under the lock, frees the temp "
                        "node on failure and destroys the entry on the "
                        "duplicate path",
                "calls": counts[0x5FD24C0]["calls"],
                "callers": ["0x5fd2848", "0x5fd28c3"],
                "excerpt": "insert-5fd24c0.objdump.txt"},
            "node_dtor": {
                "addr": 0x5FCC700, "fde": "0x5fcc700..0x5fcc742",
                "role": "registry node D2: installs the node base "
                        "vtable 0x64cde68, destroys the stored function "
                        "via manager op 3 (0x5fcc72b), then tail-jumps "
                        "to the entry's D0 (slot 1 of the entry object "
                        "at node+0x08)",
                "installed_by": "RELATIVE record at 0x64cde68 "
                                "(node vtable slot 0)",
                "excerpt": "node-dtor-5fcc700.objdump.txt"},
        },
        "invokers": [
            {"name": "TimeEmulatedSystemClock invoker", "addr": 0x5FCD550,
             "fde": "0x5fcd550..0x5fcd5a9",
             "role": "new(0x50) + Emulated C1(mode 0, wrap the "
                     "PosixClock); replaces the *(*rdx) cell, D0-"
                     "deletes the old clock if non-null",
             "leas": counts[0x5FCD550]["leas"], "lea_sites": ["0x5fd211d"],
             "excerpt": "invoker-timeemu-5fcd550.objdump.txt"},
            {"name": "MockEnv invoker", "addr": 0x5FCD5B0,
             "fde": "0x5fcd5b0..0x5fcd5db",
             "role": "holder accessor 0x5fe2860, then the factory "
                     "0x60297a0 (mode-1 emulated clock), stores the "
                     "holder in the cell",
             "leas": counts[0x5FCD5B0]["leas"], "lea_sites": ["0x5fd2805"],
             "excerpt": "invoker-mockenv-5fcd5b0.objdump.txt"},
            {"name": "CompositeEnv invoker", "addr": 0x5FCF450,
             "fde": "0x5fcf450..0x5fcf4cb",
             "role": "new(0x60), holder accessor 0x5fe2860, "
                     "0x5fcf430, 0x5fcf390, builder 0x5fd7360 "
                     "(FDE 0x5fd7360..0x5fd7466; calls append 3x)",
             "leas": counts[0x5FCF450]["leas"], "lea_sites": ["0x5fd2885"],
             "excerpt": "invoker-composite-5fcf450.objdump.txt"},
        ],
        "factory": {
            "addr": 0x60297A0, "fde": "0x60297a0..0x60298f7",
            "role": "make_shared<EmulatedSystemClock>: new(0x60), "
                    "in-place control block (vtable 0x64d1c38, counts "
                    "0x100000001 from 0x459b20), Emulated C1(mode 1, "
                    "wrapped = 0x5fcf430(holder)), installs the "
                    "shared_ptr into the holder via 0x6028d80",
            "calls": counts[0x60297A0]["calls"],
            "callers": ["0x5fcd5c0"],
            "control_block_vtable": "0x64d1c38 (dispose 0x6025950, "
                                    "destroy 0x6025b90, by contract)",
            "excerpt": "factory-60297a0.objdump.txt"},
        "accessor": {
            "addr": 0x5FCF430, "fde": "0x5fcf430..0x5fcf439",
            "role": "9 bytes: returns arg+0x38 (the holder's "
                    "wrapped-clock shared_ptr slot)",
            "calls": counts[0x5FCF430]["calls"],
            "excerpt": "accessor-5fcf430.objdump.txt"},
        "holder": {
            "accessor_addr": 0x5FE2860, "fde": "0x5fe2860..0x5fe2c2f",
            "role": "returns the holder at 0x6504cc0 (guard "
                    "0x6504ca8); first call initializes from the "
                    "PosixClock accessor 0x5fe2680 and builds .bss "
                    "state 0x6504d08..0x6504d78 with "
                    "pthread_mutex_init. Full body is a separate work "
                    "item; cited here by contract",
            "calls": counts[0x5FE2860]["calls"],
            "holder_vtable": "0x64ce2d8 (slot 2 GetOption 0x609d760)",
            "holder_shared_ptr_slot": "+0x38",
            "bss_records": [
                {"addr": 0x6504B80, "note": "third field of the wrapper "
                                            "ctor's record; also lea'd "
                                            "at 0x5fd1bb8 (static "
                                            "initializer 0x5fd19a0.."
                                            "0x5fd1c56); .bss, contents "
                                            "not recoverable statically"},
                {"addr": 0x6505960, "note": "third field of the "
                                            "emulated ctor's first "
                                            "record; also lea'd at "
                                            "0x6029e50 inside the "
                                            "factory; .bss"},
                {"addr": 0x6505920, "note": "third field of the "
                                            "emulated ctor's second "
                                            "record; also lea'd at "
                                            "0x6029fe0 inside the "
                                            "factory; .bss"},
            ]},
        "relocations": reloc_rows,
        "relocation_ranges": [
            {"range": "0x64cd9b8..0x64cda00", "what": "FactoryEntry "
             "vtable headers", "count": 5},
            {"range": "0x64cdd78..0x64cde58", "what": "SystemClockWrapper "
             "vtable header + slots 2..25", "count": 24},
            {"range": "0x64cde58..0x64cde80", "what": "registry node "
             "vtable header + slots", "count": 4},
            {"range": "0x64d1650..0x64d1660", "what": "EmulatedSystemClock "
             "vtable slots 0-1", "count": 2},
            {"range": "0x64d1c28..0x64d1c60", "what": "make_shared "
             "control-block vtable", "count": 6},
            {"range": "0x64ce2c8..0x64ce2f0", "what": "holder vtable "
             "header + slot 2", "count": 2},
            {"range": "0x64d8ec0..0x64d8ee0", "what": "registry entry "
             "vtable header + slots", "count": 3},
            {"range": "0x64ed3e8..0x64ed3f0", "what": "GOT slot for the "
             "canonical GetCurrentTime 0x5d4b100", "count": 1},
        ],
        "literals": literals,
        "census": {
            "targets": {("%#x" % addr): counts.get(addr, {}) for addr in
                        sorted(counts)},
            "callers_tsv_rows": sum(sum(v.values()) for v in counts.values()),
            "relocation_records": len(reloc_rows),
        },
        "reshipped": reshipped,
        "corrections_to_3352": [
            "The canonical-address qwords at file offsets 0x10f9f0 and "
            "0x15d270 are .rela.dyn RELATIVE addends (r_offset "
            "0x64cde48 wrapper slot 24, and 0x64ed3e8 GOT slot), not "
            ".eh_frame data.",
            "Record third fields 0x6504b80/0x6505960/0x6505920 are in "
            ".bss (runtime-initialized); their contents are not "
            "recoverable statically.",
        ],
        "open_unknowns": [
            "Holder class (vtable 0x64ce2d8) and its methods beyond "
            "slot 2 GetOption.",
            "Holder initializer 0x5fe2860 full body (cited by contract).",
            "CompositeEnv builder 0x5fd7360 full body (cited by contract).",
            "Registry helpers 0x5fd1da0, 0x5fd17c0, 0x61f8b60, "
            "0x61f8700 exact signatures and the 'Environment' string's "
            "role in insert.",
            "Node vtable slot 2 (0x5fcc7e0), used as the 0x30-byte "
            "function node's vtable pointer (0x64cde88) in default-init.",
            "Factory control-block dispose 0x6025950 / destroy "
            "0x6025b90 bodies (cited by contract).",
            "Entry D0 0x5ff2150 body (cited by contract).",
            "Wrapper vtable slot 14 stays null; its intended target, "
            "if any, is unknown.",
        ],
        "test_checks": 135,
    }
    with open(PACKET / "records.json", "w") as handle:
        json.dump(records, handle, indent=2)
        handle.write("\n")
    print("wrote records.json")
    print("targets in census:", len(counts))
    print("relocations:", len(reloc_rows))
    print("literals:", len(literals))


if __name__ == "__main__":
    sys.exit(main())
