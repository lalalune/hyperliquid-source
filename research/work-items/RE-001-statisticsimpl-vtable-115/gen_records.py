"""Generate records.json, vtables.tsv and relocations.txt.

Run from the repository root (after census.py):
    python3 research/work-items/RE-001-statisticsimpl-vtable-115/gen_records.py

Everything derived here comes from the digest-verified binary
(work/hl-node-115.bin), from callers.tsv / dispatch.tsv written
by census.py, or from the merged packets credited in
re_shipped_from. The semantic claims are hand-written below from
the disassembly and checked by verify.py. No per-instruction
mnemonic list is emitted: instruction-level detail lives only in
the verbatim excerpts.

Vtable geometry: the "stored pointer" is the value an object
holds in its +0x00 word (the Itanium vtable base + 0x10); slot N
sits at stored + N*8; the typeinfo pointer sits at stored - 0x08
and the offset-to-top at stored - 0x10. The ctor installs the
Itanium base 0x64d2d78, so objects hold 0x64d2d88. The file
content at the vtable offsets is NOT the vtable qwords: the
entries survive only as R_X86_64_RELATIVE addends in .rela.dyn,
which is what this script reads.
"""

import json
import os
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BASE_COMMIT = "7ff06a097"

sys.path.insert(0, str(HERE))
import census as census_mod

# slot offset -> (target, role)
SLOTS = {
    0x00: (0x6070EA0, "D1 destructor"),
    0x08: (0x6071040, "D0 deleting destructor"),
    0x10: (0x609D760, "Customizable::GetOption"),
    0x18: (0x609DC40, "Customizable::AreEquivalent"),
    0x20: (0x5D32560, "returns empty std::string (C++ name open)"),
    0x28: (0x6095E70, "base Configurable::PrepareOptions"),
    0x30: (0x6096790, "Configurable::ValidateOptions"),
    0x38: (0x5D2E090, "Customizable::GetOptionsPtr"),
    0x40: (0x60956F0, "returns empty Status (C++ name open)"),
    0x48: (0x609D0E0, "Configurable::ConfigureOptions"),
    0x50: (0x60986B0, "Configurable::ParseOption"),
    0x58: (0x6095710, "Configurable::OptionsAreEqual"),
    0x60: (0x609DE80, "base Customizable::SerializeOptions"),
    0x68: (0x609D980, "Customizable::GetOptionName"),
    0x70: (0x606FA20, "Name() -> \"BasicStatistics\""),
    0x78: (0x5D32A30, "GetId"),
    0x80: (0x5D2E770, "IsInstanceOf"),
    0x88: (0x606FA30, "delegate getter (returns *(this+0x28))"),
    0x90: (0x5D2CA10, "NickName() -> \"\""),
    0x98: (0x6070490, "locked ticker read (getTickerCount)"),
    0xA0: (0x6070610, "locked histogram percentiles (getHistogramData)"),
    0xA8: (0x6070700, "locked histogram text (getHistogramString)"),
    0xB0: (0x606FBA0, "record tick"),
    0xB8: (0x6070DC0, "locked set ticker (setTickerCount)"),
    0xC0: (0x6070C50, "get-and-reset ticker (getAndResetTickerCount)"),
    0xC8: (0x5D48960, "level-3-only histogram forward (measureTime, inference)"),
    0xD0: (0x606FFD0, "record histogram, devirtualized twin"),
    0xD8: (0x606FEF0, "record histogram"),
    0xE0: (0x6070B30, "reset (Reset)"),
    0xE8: (0x6070810, "StatisticsImpl::ToString"),
    0xF0: (0x6076030, "ticker-map fill (getTickerMap)"),
    0xF8: (0x606FA40, "histogram-id check (HistEnabledForType)"),
}


def load_segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        typ = struct.unpack_from("<I", data, off)[0]
        poff = struct.unpack_from("<Q", data, off + 8)[0]
        pva = struct.unpack_from("<Q", data, off + 16)[0]
        pfilesz = struct.unpack_from("<Q", data, off + 32)[0]
        segs.append((typ, poff, pva, pfilesz))
    return segs


def va2off(segs, va):
    for typ, poff, pva, pfsz in segs:
        if typ == 1 and pva <= va < pva + pfsz:
            return poff + (va - pva)
    return None


def cstr_at_va(data, segs, va):
    off = va2off(segs, va)
    if off is None:
        return None
    end = data.index(b"\0", off)
    return data[off:end].decode(errors="replace")


def load_relocs(data):
    rel = {}
    rela_off, rela_size = 0x6BE8, 0x163CC8
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel[ro] = add
    return rel


def reloc_val(data, segs, rel, va):
    if va in rel:
        return rel[va]
    off = va2off(segs, va)
    if off is None:
        return None
    return struct.unpack_from("<Q", data, off)[0]


def resolve_vtable(data, segs, rel, stored, count):
    """Return (typeinfo_va, typeinfo_name, [(offset, target-or-None)])."""
    ti = reloc_val(data, segs, rel, stored - 8)
    name = cstr_at_va(data, segs, reloc_val(data, segs, rel, ti + 8))
    slots = []
    for n in range(count):
        va = stored + n * 8
        slots.append((hex(n * 8), (hex(rel[va]) if va in rel else None)))
    return ti, name, slots


def qword_hits(data, target):
    needle = struct.pack("<Q", target)
    found = []
    pos = data.find(needle)
    while pos != -1:
        if pos % 8 == 0:
            found.append(pos)
        pos = data.find(needle, pos + 1)
    return found


def read_tsv(path):
    rows = []
    with open(path) as fh:
        header = fh.readline()
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if parts:
                rows.append(parts)
    return rows


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    import hashlib
    assert hashlib.sha256(data).hexdigest() == DIGEST
    segs = load_segments(data)
    rel = load_relocs(data)
    stored = 0x64D2D88
    ti, name, slots = resolve_vtable(data, segs, rel, stored, 32)
    assert name == "N7rocksdb14StatisticsImplE", name
    base_ti = reloc_val(data, segs, rel, 0x64D2CE0)
    base_name = cstr_at_va(data, segs, reloc_val(data, segs, rel, base_ti + 8))

    # Census counts from the TSVs census.py wrote, qwords + RELATIVE
    # counts recomputed here from the binary.
    callers_rows = read_tsv(HERE / "callers.tsv")
    dispatch_rows = read_tsv(HERE / "dispatch.tsv")
    census = {}
    for t in census_mod.TARGETS:
        calls = [r for r in callers_rows if int(r[1], 16) == t and r[3] == "call"]
        jumps = [r for r in callers_rows if int(r[1], 16) == t and r[3] == "tail jump"]
        leas = [r for r in callers_rows if int(r[1], 16) == t and r[3] == "lea"]
        qw = qword_hits(data, t)
        rel_slots = sorted(o for o, a in rel.items() if a == t)
        entry = {
            "calls": len(calls),
            "jumps": len(jumps),
            "leas": len(leas),
            "qwords": len(qw),
            "relative": len(rel_slots),
        }
        if len(calls) <= 10:
            entry["call_sites"] = [r[0] for r in calls]
        if len(jumps) <= 10:
            entry["jump_sites"] = [r[0] for r in jumps]
        if leas:
            entry["lea_sites"] = [r[0] for r in leas]
        if len(rel_slots) <= 10:
            entry["relative_slots"] = [hex(o) for o in rel_slots]
        census[hex(t)] = entry

    dispatch = {}
    for slot, tgt in sorted(census_mod.DISPATCH_SLOTS.items()):
        sites = [r for r in dispatch_rows if int(r[2], 16) == slot]
        dispatch[hex(slot)] = {
            "target": hex(tgt),
            "count": len(sites),
            "note": ("Indirect calls through vtable displacement %#x "
                     "(call *%#x(%%r..)) across the whole binary. "
                     "Displacement-wide, not type-attributed: any class "
                     "with a slot at that displacement contributes, so "
                     "this is an upper bound on StatisticsImpl dispatches, "
                     "not an exact caller count. Full site list in "
                     "dispatch.tsv." % (slot, slot)),
        }

    records = build_records(data, segs, rel, ti, name, base_ti, base_name,
                            slots, census, dispatch)
    with open(HERE / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")

    with open(HERE / "vtables.tsv", "w") as fh:
        fh.write("vtable\tstored_pointer\ttypeinfo_name\tslot_offset\ttarget\n")
        for off, tgt in slots:
            fh.write("statistics_impl\t0x64d2d88\t%s\t%s\t%s\n" % (name, off, tgt))

    with open(HERE / "relocations.txt", "w") as fh:
        # Raw readelf -r lines for the vtable group (0x64d2ce8..0x64d2f38:
        # the typeinfo records, the 32 primary slots, the three
        # following group vtables and the next typeinfo/name pair)
        # plus the GOT slot 0x64ecf50 that installs the slot-0xc8
        # forwarder a second time. Same range as #3396's file, plus
        # the 0xc8 GOT slot instead of #3396's 0x64ed2f0. Every line
        # is verbatim readelf output; verify.py checks each line
        # against a fresh readelf -r dump.
        import subprocess
        reloc_text = subprocess.run(
            ["readelf", "-r", str(ROOT / BIN)],
            capture_output=True, text=True, check=True).stdout
        want = set(range(0x64D2CE8, 0x64D2F39))
        want.add(0x64ECF50)
        for line in reloc_text.splitlines():
            m = re.match(r"^([0-9a-f]{12})  ", line)
            if m and int(m.group(1), 16) in want \
                    and "R_X86_64_RELATIVE" in line:
                fh.write(line + "\n")
    print("wrote records.json, vtables.tsv, relocations.txt")
    return 0


def build_records(data, segs, rel, ti, name, base_ti, base_name,
                  slots, census, dispatch):
    slot_map = {}
    for off, tgt in slots:
        target, role = SLOTS[int(off, 16)]
        assert target == int(tgt, 16), (off, target, tgt)
        slot_map[off] = {"target": tgt, "role": role}

    methods = {
        "0x6070ea0": {
            "address": "0x6070ea0", "fde": "0x6070ea0..0x607103c",
            "size_bytes": 412, "vtable_slot": "0x00",
            "signature": "(this: StatisticsImpl*) -> void",
            "excerpt": "stats_dtor.txt",
            "steps": [
                "vptr := StatisticsImpl vtable (lea 0x64d2d78 + 0x10, 0x6070eb5..0x6070ec4).",
                "Shard store (0x6070ebc..0x6070f2c): for each shard, walk its 53 histogram records from the end and call each record's dtor through its vtable unless the vtable is the shared 0x5d89570 (the no-op check at 0x6070f00..0x6070f0e), then free the store via 0x60d5db0 (free).",
                "Mutex at this+0x38 destroyed via 0x60d5170 (0x6070f31..0x6070f35).",
                "Delegate shared_ptr released (0x6070f3a..0x6070f80): control block at this+0x30; when its counts are exactly 0x100000001 the fast path at 0x6071002 runs, otherwise the use count at +8 is decremented under the shared lock (0x6070f5e..0x6070f7a, with the 0x64ed290 guard). This is the release half of the ctor's move-in.",
                "vptr := Configurable base 0x64d3420 + 0x10 and the options vector at this+0x8/+0x10 destroyed (0x6070f80..0x6070fc6 and following).",
            ],
        },
        "0x6071040": {
            "address": "0x6071040", "fde": "0x6071040..0x607105b",
            "size_bytes": 27, "vtable_slot": "0x08",
            "signature": "(this: StatisticsImpl*) -> void",
            "excerpt": "deleting-dtor-6071040.objdump.txt",
            "steps": [
                "Call the D1 dtor 0x6070ea0 (0x6071048).",
                "Sized delete: _ZdlPvm(this, 0x70) (0x6071050..0x6071056) — sizeof(StatisticsImpl) is 0x70 (112 bytes).",
                "One direct caller: 0x6077773. Four lea sites compare against it: the _Sp_counted_ptr<StatisticsImpl> deleter 0x6071071, 0x60710c1, and the two factory hosts 0x6071bf0 and 0x6076d04.",
            ],
        },
        "0x609d760": {
            "address": "0x609d760", "fde": "0x609d760..0x609d954",
            "size_bytes": 500, "vtable_slot": "0x10",
            "signature": "Customizable::GetOption",
            "excerpt": "getoption-609d760.objdump.txt",
            "contract": "Shared base method (63 vtables install it; pinned in #3902). If the option name is exactly \"id\" (length 2, bytes 0x6469), return the delegate's own name (its slot-0x78 string) and a zeroed Status; otherwise forward to Configurable's slot 0x10 (0x6099030).",
        },
        "0x609dc40": {
            "address": "0x609dc40", "fde": "0x609dc40..0x609de39",
            "size_bytes": 505, "vtable_slot": "0x18",
            "signature": "Customizable::AreEquivalent",
            "excerpt": "areequivalent-609dc40.objdump.txt",
            "contract": "Shared base method (63 vtables install it; pinned in #3902 and in the delegate-vtable packet). Return 1 when the value's +0x2c byte is <= 1, when out == delegate, or (return 0) when the delegate is null. Otherwise compare the delegate's name with this object's name via slot 0x78; on mismatch rewrite the option name to \"id\", then forward to Configurable's slot 0x18 (0x60996a0) when the value's +0x2c byte is > 2, else return 1.",
        },
        "0x5d32560": {
            "address": "0x5d32560", "fde": "0x5d32560..0x5d3257b",
            "size_bytes": 27, "vtable_slot": "0x20",
            "signature": "(out: std::string*) -> std::string*",
            "excerpt": "slot04-emptystring-5d32560.objdump.txt",
            "contract": "Shared base method (66 vtables install it; pinned in #3902 and in the delegate-vtable packet). Initialize a std::string at rdi: pointer rdi+0x10, length 0, NUL at +0x10. Returns rdi. C++ name open.",
        },
        "0x6095e70": {
            "address": "0x6095e70", "fde": "0x6095e70..0x609661c",
            "size_bytes": 1964, "vtable_slot": "0x28",
            "signature": "base Configurable::PrepareOptions",
            "excerpt": "prepareoptions-base-6095e70.objdump.txt",
            "contract": "Shared base method (50 vtables install it; 8 direct callers are other classes' overrides calling the base, e.g. SystemClockWrapper::PrepareOptions at 0x5fcf5b7). Walk 0x30-byte (name, value) records from the range in rsi. For each record copy the name (SSO-aware) and the 0x20-byte value struct, then walk its +0x18 entry chain; for each entry materialize five sub-values through the +0x40/+0x60/+0x80/+0xa0/+0xc0 copy function pointers (tag 2). Contract per the delegate-vtable packet; the record walk itself is not re-derived here.",
        },
        "0x6096790": {
            "address": "0x6096790", "fde": "0x6096790..0x6096f0c",
            "size_bytes": 1916, "vtable_slot": "0x30",
            "signature": "Configurable::ValidateOptions",
            "excerpt": "validateoptions-6096790.objdump.txt",
            "contract": "Shared base method (64 vtables install it; pinned in #3902). Same record walk and sub-value materialization as slot 0x28, but the worker is 0x60b9f50 (six arguments) and the kind gate has no 0x40 flag-byte check: the worker fires when (HIGH dword of the +0xd0 qword - 4) > 1 unsigned and (the raw +0xc0 function pointer is non-null or (LOW dword of the +0xd0 qword - 0x15) <= 1 unsigned). Contract per the delegate-vtable packet.",
        },
        "0x5d2e090": {
            "address": "0x5d2e090", "fde": "0x5d2e090..0x5d2e0de",
            "size_bytes": 78, "vtable_slot": "0x38",
            "signature": "Customizable::GetOptionsPtr",
            "excerpt": "getoptionsptr-5d2e090.objdump.txt",
            "contract": "Shared base method (62 vtables install it; pinned in #3902 and in the delegate-vtable packet). Call the shared resolver 0x60958c0: it scans the 0x30-byte (name, +0x20 field) record array at *(rdi+0x08)..*(rdi+0x10) for the name in rsi (length then memcmp, SSO-aware) and returns the matching record's +0x20 field, or null. If the resolver returns non-null, return it. Otherwise call this object's slot 0x88 (the wrapped object) and, when non-null, tail-jump to the wrapped object's slot 0x38. One lea site at 0x5eeeb8e.",
        },
        "0x60956f0": {
            "address": "0x60956f0", "fde": "0x60956f0..0x609570c",
            "size_bytes": 28, "vtable_slot": "0x40",
            "signature": "(out: Status*) -> Status*",
            "excerpt": "slot08-emptystatus-60956f0.objdump.txt",
            "contract": "Shared base method (68 vtables install it; pinned in #3902 and in the delegate-vtable packet). Write a zeroed 16-byte Status (u32 0, u16 0, u64 0) into *(rdi) and return rdi. C++ name open. One lea site at 0x609a0d7.",
        },
        "0x609d0e0": {
            "address": "0x609d0e0", "fde": "0x609d0e0..0x609d75e",
            "size_bytes": 1662, "vtable_slot": "0x48",
            "signature": "Configurable::ConfigureOptions",
            "excerpt": "configureoptions-609d0e0.objdump.txt",
            "contract": "Shared base method (66 vtables install it; pinned in #3902). The merge/apply host every slot-0x48 override calls first. It returns a Status in *(rdi); the overrides return early when its first byte is non-zero. Two direct callers: 0x607e447 and 0x60a24a1 (other classes' slot-0x48 overrides). Contract per the delegate-vtable packet.",
        },
        "0x60986b0": {
            "address": "0x60986b0", "fde": "0x60986b0..0x6098a9c",
            "size_bytes": 1004, "vtable_slot": "0x50",
            "signature": "Configurable::ParseOption (SetOption, string value)",
            "excerpt": "parseoption-60986b0.objdump.txt",
            "contract": "Shared base method (67 vtables install it; pinned in #3902). When the value kind byte (+0x04) is 0, forward (name, value) to worker 0x60bedc0. When kind != 0 and the changeable flag at name+0xb1 is set, copy the value struct (shared_ptr refcounted) and call 0x60bedc0. When kind != 0 and the flag is clear, build the error string \"Option not changeable: \" + name and report it through 0x61cf670 with code 4. Contract per the delegate-vtable packet. One direct caller: 0x60d7d49.",
        },
        "0x6095710": {
            "address": "0x6095710", "fde": "0x6095710..0x609579a",
            "size_bytes": 138, "vtable_slot": "0x58",
            "signature": "Configurable::OptionsAreEqual",
            "excerpt": "optionsareequal-6095710.objdump.txt",
            "contract": "Shared base method (65 vtables install it; pinned in #3902). Validate (name, value): call kind validator 0x60bf980; if it accepts, return 1. Otherwise call 0x60bf7c0; if it rejects too, blank the target name string (replace with \"\"). Always returns 1. Contract per the delegate-vtable packet.",
        },
        "0x609de80": {
            "address": "0x609de80", "fde": "0x609de80..0x609e29e",
            "size_bytes": 1054, "vtable_slot": "0x60",
            "signature": "base Customizable::SerializeOptions",
            "excerpt": "serializeoptions-base-609de80.objdump.txt",
            "contract": "Shared base method (50 vtables install it; 3 direct callers: 0x5fcdb3e, 0x5fd5e27, 0x5fe6982 — other classes' SerializeOptions overrides calling the base). Serialize options to a string: call the delegate's slot 0x78 for its name. When the value kind (+0x28) is 1 or the delegate name is empty, compose the out string as <options name> + \"id\" + \"=\" + <delegate name> + <value name>; when the delegate name string is also empty, assign the delegate name directly. Otherwise forward to Configurable's slot 0x60 (0x60985e0, call at 0x609e0a9) and copy its output. Contract per the delegate-vtable packet.",
        },
        "0x609d980": {
            "address": "0x609d980", "fde": "0x609d980..0x609dc18",
            "size_bytes": 664, "vtable_slot": "0x68",
            "signature": "Customizable::GetOptionName",
            "excerpt": "getoptionname-609d980.objdump.txt",
            "contract": "Shared base method (63 vtables install it; pinned in #3902). Dotted-name lookup: call the delegate's slot 0x70 (Name()); if the input name starts with that name followed by '.', strip the prefix (name + '.') and return the remainder as the out string; if Name() is null, throw std::logic_error. Otherwise fall back to Configurable's slot 0x68 (0x6095a60), a std::string copy into the out string. Contract per the delegate-vtable packet.",
        },
        "0x606fa20": {
            "address": "0x606fa20", "fde": "0x606fa20..0x606fa2c",
            "size_bytes": 12, "vtable_slot": "0x70",
            "signature": "(this: StatisticsImpl*) -> const char*",
            "excerpt": "stats_name.txt",
            "contract": "Returns the address of the string \"BasicStatistics\" at 0x432248 (lea 0x432248(%rip), %rax; ret). The same address holds the start of the ticker-name table (\"rocksdb.l1.hit\", \"rocksdb.number.keys.updated\", ... follow it).",
        },
        "0x5d32a30": {
            "address": "0x5d32a30", "fde": "0x5d32a30..0x5d32a51",
            "size_bytes": 33, "vtable_slot": "0x78",
            "signature": "GetId",
            "excerpt": "getid-5d32a30.objdump.txt",
            "contract": "Shared base method (55 vtables install it; pinned in #3902 and in the delegate-vtable packet). Name as std::string: call the delegate's slot 0x70 (Name()) and assign the returned C string into the sret std::string at rdi through 0x5d32940. Returns rdi. For StatisticsImpl the name is \"BasicStatistics\".",
        },
        "0x5d2e770": {
            "address": "0x5d2e770", "fde": "0x5d2e770..0x5d2e832",
            "size_bytes": 194, "vtable_slot": "0x80",
            "signature": "IsInstanceOf",
            "excerpt": "isinstanceof-5d2e770.objdump.txt",
            "contract": "Shared base method (44 vtables install it; pinned in #3902 by contract from #3715 and in the delegate-vtable packet). Return 1 when the input string matches this object's Name() (slot 0x70) or its NickName() (slot 0x90) by length then memcmp; else 0. Verified in this packet's excerpt: Name() via call *0x70(%rax) at 0x5d2e792, strlen compare at 0x5d2e79f..0x5d2e7a7, memcmp at 0x5d2e7ee; NickName() via call *0x90(%rax) at 0x5d2e7b0, strlen compare at 0x5d2e7c5..0x5d2e7cd, memcmp at 0x5d2e826. For StatisticsImpl: Name() is \"BasicStatistics\", NickName() is \"\" — so IsInstanceOf(\"BasicStatistics\") and IsInstanceOf(\"\") both return 1. One tail jump: the MockEnv/CompositeEnvWrapper override at 0x5fd624b tail-jumps here.",
        },
        "0x606fa30": {
            "address": "0x606fa30", "fde": "0x606fa30..0x606fa39",
            "size_bytes": 9, "vtable_slot": "0x88",
            "signature": "(this: StatisticsImpl*) -> Statistics*",
            "excerpt": "delegate_getter.txt",
            "contract": "Returns *(this+0x28) — the delegate pointer, or null. The delegate packet records the same shape for the other wrappers (SystemClockWrapper returns *(obj+0x20), MockEnv *(obj+0x48)); StatisticsImpl returns *(obj+0x28). C++ name open.",
        },
        "0x5d2ca10": {
            "address": "0x5d2ca10", "fde": "0x5d2ca10..0x5d2ca1c",
            "size_bytes": 12, "vtable_slot": "0x90",
            "signature": "(this: StatisticsImpl*) -> const char*",
            "excerpt": "slot18-emptystring-5d2ca10.objdump.txt",
            "contract": "Shared base method (45 vtables install it; pinned in #3902 by contract from #3715 and in the delegate-vtable packet as NickName()). Returns the address 0x4376fd, which holds an empty string (the byte at 0x4376fd is 0x00; the preceding string \"base/src/chain_ext.rs\" ends at 0x4376fc). So StatisticsImpl's NickName() is \"\".",
        },
        "0x6070490": {
            "address": "0x6070490", "fde": "0x6070490..0x60704d2",
            "size_bytes": 66, "vtable_slot": "0x98",
            "signature": "(this: StatisticsImpl*, ticker_id: u32) -> u64",
            "excerpt": "locked_ticker.txt",
            "steps": [
                "Lock the mutex at this+0x38 via 0x60d5230 (call site 0x60704a4), call the ticker getter 0x6070430 (0x60704ae), unlock via 0x60d52f0 (0x60704b9) and return the sum.",
                "Exception path: the landing pad at 0x60704c6 jumps to the fragment at 0x607047e..0x607048e, which unlocks and calls _Unwind_Resume.",
                "No direct call, tail jump or lea anywhere in the binary: reached only through the vtable (RELATIVE 0x64d2e20).",
            ],
        },
        "0x6070610": {
            "address": "0x6070610", "fde": "0x6070610..0x60706c9",
            "size_bytes": 185, "vtable_slot": "0xa0",
            "signature": "(this: StatisticsImpl*, hist_id: u32, out: HistogramData*) -> void",
            "excerpt": "locked_percentiles.txt",
            "steps": [
                "Lock the mutex at this+0x38 (0x607063e), build a fresh 0x3c8-byte HistogramImpl temp via the builder 0x6070500(rsp, this, edx) (0x607064c), fill the caller's struct through the temp's vtable slot 0x78 (call *0x78(%rax) at 0x607065b; thunk 0x606bdd0, percentile struct 0x606bce0 — the 9-field record P50/P95/P99/average/stddev/P100/count/sum/min pinned in #3371), destroy the temp, unlock (0x6070684) and return.",
                "The destroy compares the temp's vtable slot 0x8 against GOT 0x64ed2f0 (sized delete 0x5d8b3b0): equal means _ZdlPvm(temp, 0x3c8), else the deleting dtor is called.",
                "Exception cleanup is the fragment at 0x60705d8..0x607060c (own FDE) with two entries: the head 0x60705d8 (delete temp + unlock + resume, from the landing pad at 0x60706b8) and the interior 0x60705e7 (unlock only, from the landing pad at 0x60706c4).",
                "No direct call, tail jump or lea anywhere in the binary: reached only through the vtable (RELATIVE 0x64d2e28).",
            ],
        },
        "0x6070700": {
            "address": "0x6070700", "fde": "0x6070700..0x60707c1",
            "size_bytes": 193, "vtable_slot": "0xa8",
            "signature": "(out: string*, stats: StatisticsImpl*, hist_id: u32) -> string*",
            "excerpt": "locked_histogram_text.txt",
            "steps": [
                "The stats object arrives in rsi, not rdi: the routine returns a std::string by value, so rdi is the hidden return-value pointer (the out string, returned unchanged) and rsi is this.",
                "Lock rsi+0x38 (0x607072e), build the temp via 0x6070500(rsp, rsi, edx) (0x607073c), render into the out string through the temp's vtable slot 0x30 (call *0x30(%rax) at 0x607074b; entry 0x606bc90, renderer 0x606b6f0 — the Count / Min-Median-Max / Percentiles / dashes / bucket-rows text pinned in #3371), destroy the temp the same way as slot 0xa0, unlock (0x6070774), check the stack canary and return rdi.",
                "Exception cleanup is the fragment at 0x60706ca..0x60706fe (own FDE), the mirror of slot 0xa0's: head 0x60706ca (delete + unlock, from 0x60707b0) and interior 0x60706d9 (unlock only, from 0x60707bc).",
                "No direct call, tail jump or lea anywhere in the binary: reached only through the vtable (RELATIVE 0x64d2e30).",
            ],
        },
        "0x606fba0": {
            "address": "0x606fba0", "fde": "0x606fba0..0x606fc59",
            "size_bytes": 185, "vtable_slot": "0xb0",
            "signature": "(this: StatisticsImpl*, ticker_id: u32, value: u64) -> void",
            "excerpt": "record_tick.txt",
            "steps": [
                "Gate (0x606fba4..0x606fbb4): the enable byte at this+0x20 must be nonzero and ticker_id <= 0xb1 (177); otherwise return silently with no write and no forward.",
                "Shard pick (0x606fbc4): call the CPU picker 0x60d5cd0; a negative return jumps to the fallback at 0x606fc20 (call 0x61c4080 for the thread seed, Park-Miller step, store back, mask).",
                "Mask (0x606fbd2..0x606fbe0): shard = picked & ((1 << u8 at this+0x68) - 1); address = *(this+0x60) + shard*0xce40 + ticker_id*8.",
                "Write (0x606fbf1): `lock add %r12,(%rax)` — the value is added atomically into the picked shard's counter. No mutex is taken on this path.",
                "Forward (0x606fbf5..0x606fc11): rdi = *(this+0x28); if null, return; otherwise tail-jump to the delegate's slot 0xb0 with (delegate, ticker_id, value) — the delegate re-runs its own gate and shard pick.",
            ],
            "correction_to_3396": "The FDE is 0x606fba0..0x606fc59 = 185 bytes; #3396's records.json says size_bytes 441, which does not match its own excerpt (record_tick.txt ends at 0x606fc57). Corrected here to 185.",
        },
        "0x6070dc0": {
            "address": "0x6070dc0", "fde": "0x6070dc0..0x6070e9a",
            "size_bytes": 218, "vtable_slot": "0xb8",
            "signature": "(this: StatisticsImpl*, ticker_id: u32, value: u64) -> void",
            "excerpt": "set_ticker.txt",
            "steps": [
                "Lock the mutex at this+0x38 via 0x60d5230 (0x6070ddd), call the set core 0x6070ac0(this, id, value) (0x6070dea), unlock via 0x60d52f0 (0x6070df2). No enable-byte or id-bound check happens before the set.",
                "Forward (0x6070df7..0x6070e68): delegate = *(this+0x28); if null or ticker_id > 0xb1, return.",
                "Devirtualization check (0x6070e08..0x6070e1c): if the delegate's vtable slot 0xb8 is not the local 0x6070dc0, tail-jump to the delegate's slot 0xb8 with (delegate, id, value) (override branch 0x6070e78..0x6070e61).",
                "Inline level (0x6070e1e..0x6070e3a): otherwise lock the delegate's mutex, set_core(delegate, id, value), unlock.",
                "Second forward (0x6070e3f..0x6070e61): rdi = *(delegate+0x28); if null, return; otherwise tail-jump to that object's slot 0xb8 — a pure virtual call, no second devirtualization check. The chain is unrolled two levels inline, then virtual.",
                "Exception path: landing pads at 0x6070e82 (jmp 0x6070d92) and 0x6070e8e (jmp 0x6070da2); the fragment at 0x6070d92..0x6070db2 unlocks and resumes.",
            ],
        },
        "0x6070c50": {
            "address": "0x6070c50", "fde": "0x6070c50..0x6070d92",
            "size_bytes": 322, "vtable_slot": "0xc0",
            "signature": "(this: StatisticsImpl*, ticker_id: u32) -> u64 (sum)",
            "excerpt": "get_reset_ticker.txt",
            "steps": [
                "Lock the mutex at this+0x38 via 0x60d5230 (0x6070c6a).",
                "Loop (0x6070c88..0x6070cb5): for shard i in 0..(1 << shard_bits)-1, `xchg %rcx,(%rax)` with rcx = 0 — each shard's counter for the id becomes 0 and its old value is added into rbx (u64 wrap).",
                "Unlock via 0x60d52f0 (0x6070cba) and return rbx, the sum over all shards.",
                "Forward (0x6070cbf..0x6070d63): delegate = *(this+0x28); if null or ticker_id > 0xb1, return the sum. The delegate chain is reset via slot 0xb8 with value 0: the same devirtualization check as set-ticker (0x6070cd9..0x6070cee), inline lock + set_core(delegate, id, 0) + unlock (0x6070cf0..0x6070d0c), a second inline level (0x6070d11..0x6070d47), then a virtual CALL to the third delegate's slot 0xb8 with value 0 (0x6070d4c..0x6070d5d). These are calls, not tail jumps, because the sum in rbx must survive to the return.",
                "Exception path: landing pads at 0x6070d7a (jmp 0x6070c2a) and 0x6070d86 (jmp 0x6070c3a); the shared fragment at 0x6070c2a..0x6070c4a has two entries (unlock + resume; unlock only).",
            ],
            "correction_to_3396": "The FDE is 0x6070c50..0x6070d92 = 322 bytes; #3396's records.json says size_bytes 338, which does not match its own excerpt (get_reset_ticker.txt ends at 0x6070d8d). Corrected here to 322.",
        },
        "0x5d48960": {
            "address": "0x5d48960", "fde": "0x5d48960..0x5d48979",
            "size_bytes": 25, "vtable_slot": "0xc8",
            "signature": "(this: StatisticsImpl*, hist_id: u32, value: u64) -> void",
            "excerpt": "slot-c8-forwarder-5d48960.objdump.txt",
            "steps": [
                "Gate (0x5d48964..0x5d4896a): the enable byte at this+0x20 must be > 2 (movzbl 0x20(%rdi),%eax; cmp $0x2,%al; jbe 0x5d48978); level 2 or below returns silently.",
                "Forward (0x5d4896c..0x5d4896f): load this's vtable and tail-jump to this's slot 0xd8 with the same arguments (mov (%rdi),%rax; jmp *0xd8(%rax)).",
                "Installed twice: the vtable slot at 0x64d2e50 and the GOT slot at 0x64ecf50 (both R_X86_64_RELATIVE with addend 0x5d48960).",
                "Caller-side evidence: the host FDE 0x5e080f0..0x5e095ed devirtualizes slot 0xc8 (lea 0x5d48960 at 0x5e08495; compare at 0x5e084a3; override branch at 0x5e0943d) and, when the slot is the local forwarder and the level byte is > 2, calls slot 0xd8 with hist_id 2 (0x5e084ba) and, for a second statistics object, hist_id 3 (0x5e084f1) — a timer recording two histogram ids through this slot.",
                "No direct call anywhere in the binary: reached only through the vtable (RELATIVE 0x64d2e50) and the GOT slot. One lea site: 0x5e08495.",
            ],
            "name_inference": "The slot is the timer-recording method (measureTime): it is the only Statistics write method gated at level > 2 (the detailed-timers level), its caller host records histogram ids 2 and 3 through it, and its body is exactly the level-gated forward to recordHistogram (slot 0xd8). The C++ name is inference, not binary-established; see unknowns.",
        },
        "0x606ffd0": {
            "address": "0x606ffd0", "fde": "0x606ffd0..0x60700c4",
            "size_bytes": 244, "vtable_slot": "0xd0",
            "signature": "(this: StatisticsImpl*, hist_id: u32, value: u64) -> void",
            "excerpt": "record_hist_devirt.txt",
            "steps": [
                "Devirtualization guard (0x606ffde..0x606fff5): load this's vtable slot 0xd8 and compare it against the local 0x606fef0; if it differs, restore the registers and `jmp *%rax` (0x6070078..0x607007f) — a virtual dispatch to the overriding slot 0xd8 with (this, hist_id, value).",
                "Inline body (0x606fffb..0x607006d): otherwise the same body as slot 0xd8 — gate byte > 1, CPU pick (0x6070003) or LCG fallback (0x6070088), record call *0x20, forward to the delegate's slot 0xd8 when hist_id <= 0x33.",
            ],
            "name_inference": "The slot is the second histogram-write method (recordInHistogram): its body is recordHistogram with a devirtualization guard on slot 0xd8, i.e. it is implemented in terms of recordHistogram. The C++ name is inference, not binary-established; see unknowns.",
        },
        "0x606fef0": {
            "address": "0x606fef0", "fde": "0x606fef0..0x606ffce",
            "size_bytes": 222, "vtable_slot": "0xd8",
            "signature": "(this: StatisticsImpl*, hist_id: u32, value: u64) -> void",
            "excerpt": "record_hist.txt",
            "steps": [
                "Gate (0x606fef4..0x606fef8): the enable byte at this+0x20 must be > 1 (cmp $0x1, jbe 0x606ff88); level 1 records ticks only, level 0 records nothing. There is no hist_id bound check before the record call.",
                "Shard pick (0x606ff0c): call the CPU picker 0x60d5cd0; a negative return jumps to the fallback at 0x606ff90 (call 0x61c4080, Park-Miller step, store back, mask) — the same code as record_tick's fallback.",
                "Record call (0x606ff17..0x606ff52): address = *(this+0x60) + shard*0xce40 + 0x598 + hist_id*0x3c8; load the record's vtable (first qword) and `call *0x20(%rax)` with (record, value) — the HistogramImpl record slot 0x606b130.",
                "Forward (0x606ff55..0x606ff77): if hist_id <= 0x33 and *(this+0x28) is non-null, tail-jump to the delegate's slot 0xd8 with (delegate, hist_id, value). The 0x33 bound gates only the forward, not the local record.",
            ],
            "name_inference": "The slot is the histogram record (recordHistogram): it is the target the 0xc8 forwarder and the 0xd0 devirtualized twin both resolve to. The C++ name is inference, not binary-established; see unknowns.",
        },
        "0x6070b30": {
            "address": "0x6070b30", "fde": "0x6070b30..0x6070c2a",
            "size_bytes": 250, "vtable_slot": "0xe0",
            "signature": "(out: Status*, source: StatisticsImpl*) -> void",
            "excerpt": "reset_stats.txt",
            "steps": [
                "Lock the SOURCE's mutex (rsi+0x38) via 0x60d5230 (0x6070b58). The out Status is the first argument, the source the second.",
                "Ticker loop (0x6070b60..0x6070b75): for id in 0..0xb1, set_core(source, id, 0) — every ticker on every shard becomes 0.",
                "Histogram loop (0x6070b77..0x6070be5): for hist_id in 0..0x33, for each shard, call the record's vtable slot 0x10 (locked init/clear, 0x606b0c0) with (record) — `call *0x10(%rax)` at 0x6070bb4.",
                "Write Status OK into out (0x6070be7..0x6070c05): code 0, subcode 0, state null; unlock the source mutex; return. No delegate walk, no enable-byte check.",
                "Exception path: landing pad at 0x6070c1e (mov %rax,%rbx; jmp 0x6070b1c); the fragment at 0x6070b1c..0x6070b2e unlocks the source mutex (pointer saved at 0x18(%rsp)) and resumes unwinding.",
            ],
        },
        "0x6070810": {
            "address": "0x6070810", "fde": "0x6070810..0x6070ab5",
            "size_bytes": 677, "vtable_slot": "0xe8",
            "signature": "std::string ToString(std::string *out, StatisticsImpl *this)",
            "excerpt": "tostring.txt",
            "steps": [
                "Lock the mutex at this+0x38 by 0x60d5230 on entry, unlock by 0x60d52f0 before return.",
                "Reserve 20000 bytes in the out string; append one \"%s COUNT : %lu\\n\" line per ticker (format at 0x44fd60) using the ticker-name table at 0x432248 (40-byte entries: u32 type, string name) and the shard-sum getter 0x6070430.",
                "Append one \"%s P50 : %f P95 : %f P99 : %f P100 : %f COUNT : %lu SUM : %lu\\n\" line per histogram (format at 0x9609a0) using the histogram builder 0x6070500 and the percentile struct 0x606bce0.",
                "Each line is appended only when 0x3fffffffffffffff - len(out) >= len(line), else __throw_length_error.",
                "After the slot-0x78 call the histogram object's vtable slot 1 is compared against GOT 0x64ed2f0 (0x5d8b3b0); equal -> plain operator delete with size 0x3c8, different -> virtual call of slot 1.",
                "shrink_to_fit (reserve() with no size argument) before return.",
            ],
        },
        "0x6076030": {
            "address": "0x6076030", "fde": "0x6076030..0x6076615",
            "size_bytes": 1509, "vtable_slot": "0xf0",
            "signature": "(out: std::map<std::string, uint64_t>*, this: StatisticsImpl*) -> void",
            "excerpt": "slotf0.txt",
            "steps": [
                "Lock the mutex at this+0x38 via 0x60d5230, fill the caller's map with one entry per ticker (name from the ticker-name table at 0x432248, value from the shard-sum getter 0x6070430 at 0x6076133), unlock via 0x60d52f0 and return.",
                "The map insert goes through the std::_Rb_tree machinery (tree_erase.txt covers the erase path); the fill loop and the tree operations are in the excerpt.",
                "No direct call anywhere in the binary: reached only through the vtable (RELATIVE 0x64d2e78).",
            ],
        },
        "0x606fa40": {
            "address": "0x606fa40", "fde": "0x606fa40..0x606fa4b",
            "size_bytes": 11, "vtable_slot": "0xf8",
            "signature": "(this: StatisticsImpl*, hist_id: u32) -> bool",
            "excerpt": "hist_id_check.txt",
            "contract": "Returns hist_id <= 0x33 (52 valid histogram ids, 0..51). This is the bound the record routines use to gate the delegate forward.",
        },
    }

    helpers = {
        "stats_ctor_0x6071a00": {
            "address": "0x6071a00", "fde": "0x6071a00..0x6071b60",
            "size_bytes": 352, "excerpt": "stats_ctor.txt",
            "contract": "Installs the vtable: *(this) = 0x64d2d88 (lea 0x64d2d78 + 0x10). Writes the level byte 3 at +0x20, zeroes the options vector (+0x08..+0x20), moves the two delegate pointers from the 16-byte argument struct into +0x28/+0x30, inits the mutex at +0x38 via 0x60d50c0, builds the shard store via 0x60716d0(this+0x60), and registers the \"StatisticsOptions\" name via options_record_append 0x6099ce0. Two direct callers: 0x6071bda and 0x6077b74.",
        },
        "counted_ptr_deleter_0x6071060": {
            "address": "0x6071060", "fde": "0x6071060..0x60710ab",
            "size_bytes": 75, "excerpt": None,
            "contract": "Census-only neighbour, not excerpted: the _Sp_counted_ptr<StatisticsImpl> deleter. If the object's vtable slot 1 (D0) is the local 0x6071040, call the D1 dtor 0x6070ea0 and _ZdlPvm(this, 0x70); otherwise call the virtual D0. Corroborates sizeof(StatisticsImpl) == 0x70. Installed by the RELATIVE record at 0x64d2f10 (the Sp_counted_ptr<StatisticsImpl> vtable).",
        },
        "set_core_0x6070ac0": {
            "address": "0x6070ac0", "fde": "0x6070ac0..0x6070b1b",
            "size_bytes": 91, "excerpt": "set_core.txt",
            "steps": [
                "First xchg (0x6070ac4..0x6070ad1): `xchg %rdx,(%rax,%rsi,1)` where rax = *(this+0x60) and rsi = ticker_id*8 — shard 0's counter for the id becomes value, the old value is left in rdx. No caller reads it.",
                "Loop (0x6070ad5..0x6070b18): for shard i in 1..(1 << shard_bits)-1, `xchg %rcx,(%rax)` with rcx = 0 — every other shard's counter for the id becomes 0 (the old values are discarded).",
                "Single-shard fast path (0x6070ad8..0x6070ada): when shard_bits is 0 the loop is skipped.",
                "No bound check, no enable-byte check, no lock: callers hold the mutex (set-ticker, get-reset, reset) and pass ids they have already bounded. Five direct callers: 0x6070b67 (reset ticker loop), 0x6070d04 and 0x6070d3f (get-reset delegate inline levels), 0x6070dea and 0x6070e32 (set-ticker self and delegate inline levels).",
            ],
        },
        "cpu_shard_pick_0x60d5cd0": {
            "address": "0x60d5cd0", "fde": "0x60d5cd0..0x60d5cf0",
            "size_bytes": 32, "excerpt": "cpu_shard_pick.txt",
            "steps": [
                "cpuid with eax = 0 (0x60d5cd5..0x60d5cd7); ebx starts at -1.",
                "If leaf 0 reports a max leaf of 0, return -1 (0x60d5cde..0x60d5cec).",
                "Otherwise cpuid with eax = 1 and return EBX >> 24 — the APIC id in EBX[31:24], 0..255 (0x60d5ce2..0x60d5cec).",
                "The record routines treat a negative return as 'CPUID unavailable' and fall back to the thread-local LCG; a non-negative return is masked with (1 << shard_bits) - 1.",
            ],
            "other_callers": ["0x5f0aa40", "0x605e17b", "0x61c1e24"],
            "other_callers_note": "Three other direct callers use the picker outside the write side; their routines are not mapped here.",
        },
        "lcg_seed_0x61c4080": {
            "address": "0x61c4080", "fde": "0x61c4080..0x61c4117",
            "size_bytes": 151, "excerpt": "lcg_seed.txt",
            "contract": "Thread-local LCG seed accessor (pinned in #3396 and in #4156's census): returns a pointer to the calling thread's seed cell; the record fallbacks advance it with a Park-Miller step (imul $0x41a7, mod 2^31-1 reduction) and store it back. 17 direct callers: the three record fallbacks (0x606fc20, 0x606ff90, 0x6070088) plus 14 other per-thread users.",
        },
        "ticker_getter_0x6070430": {
            "address": "0x6070430", "fde": "0x6070430..0x607047d",
            "size_bytes": 77, "excerpt": "ticker_getter.txt",
            "contract": "Sum over 2**(u8 at this+0x68) shards of the u64 at *(this+0x60) + shard*0xce40 + ticker*8 (ticker is zero-extended from u32). Exactly three direct callers: 0x60704ae (locked read), 0x6070895 (ToString), 0x6076133 (slot-0xf0 fill).",
        },
        "histogram_builder_0x6070500": {
            "address": "0x6070500", "fde": "0x6070500..0x60705d8",
            "size_bytes": 216, "excerpt": "histogram_builder.txt",
            "contract": "Build a fresh 0x3c8-byte HistogramImpl for histogram id (rdi=out, rsi=stats, edx=id): allocate via _Znwm, install the HistogramImpl vptr, initialise the inner struct (0x606b080 bucket-count init, 0x606b0c0 locked init, mutex zeroed), publish *out, then merge each shard's record at shard_base + shard*0xce40 + 0x598 + id*0x3c8 via the merge wrapper 0x606bdf0. Exactly three direct callers: 0x607064c (locked percentiles), 0x607073c (locked histogram text), 0x60709d8 (ToString).",
        },
        "hist_record_0x606b130": {
            "address": "0x606b130", "fde": "0x606b130..0x606b1b3",
            "size_bytes": 131, "excerpt": "hist_record.txt",
            "contract": "HistogramImpl record (slot 0x20 target): bucket index via 0x606afa0, bucket count++, min/max by integer compare, count++, sum += value, sum-of-squares += value*value. The value is a u64 throughout (integer compares, adds, multiply). Reached via the thunk 0x606b1c0 (add $0x8,%rdi; jmp 0x606b130), which has exactly three direct callers: 0x606004c, 0x6198ae7, 0x6198e2a.",
        },
        "hist_locked_init_0x606b0c0": {
            "address": "0x606b0c0", "fde": "0x606b0c0..0x606b10a",
            "size_bytes": 74, "excerpt": "hist_locked_init.txt",
            "contract": "HistogramImpl slot 0x10 (locked init / clear): zeroes the record's fields under its mutex. The Reset routine (slot 0xe0) calls it on every shard record to clear all 52 histograms.",
        },
        "mutex_lock_0x60d5230": {
            "address": "0x60d5230", "fde": "0x60d5230..0x60d52c5",
            "size_bytes": 149, "excerpt": "mutex_lock.txt",
            "contract": "pthread_mutex_lock wrapper (re-shipped from #3362/#3378); return codes 0 and 0x6e are accepted, any other prints 'pthread %s: %s' and aborts. It never throws a C++ exception, so the accessors' landing pads cover the builder/delegate calls, not the lock. 157 direct calls + 1 tail jump (0x606ca04).",
        },
        "mutex_unlock_0x60d52f0": {
            "address": "0x60d52f0", "fde": "0x60d52f0..0x60d5385",
            "size_bytes": 149, "excerpt": "mutex_unlock.txt",
            "contract": "pthread_mutex_unlock wrapper (re-shipped from #3362/#3378); same accept/abort discipline as the lock wrapper, never throws. 669 direct calls + 5 tail jumps (0x5d53182, 0x5dfd030, 0x5e8633c, 0x5e86bde, 0x5e86c44).",
        },
    }

    object_layout = {
        "size_bytes": 112,
        "size_evidence": "D0 0x6071040 passes 0x70 to _ZdlPvm; the _Sp_counted_ptr<StatisticsImpl> deleter 0x6071060 does the same.",
        "fields": {
            "+0x00": "vtable pointer (0x64d2d88)",
            "+0x08..+0x20": "options vector (begin/end/capacity of 48-byte elements starting with a std::string)",
            "+0x20": "level byte (std::atomic<StatsLevel>, default 3 = kExceptDetailedTimers)",
            "+0x28": "delegate Statistics* (null when no delegate)",
            "+0x30": "delegate shared_ptr control block",
            "+0x38": "pthread_mutex_t",
            "+0x60": "shard-store base pointer",
            "+0x68": "shard exponent byte (bucket count = 1 << exponent)",
        },
    }

    shard_layout = {
        "shard_stride": 52800,
        "shard_size": "0xce40",
        "ticker_cell": "shard + ticker_id*8 (u64)",
        "histogram_record": "shard + 0x598 + hist_id*0x3c8 (0x3c8 bytes)",
        "ticker_count": 178,
        "histogram_count": 52,
        "tail": "0x598 + 53*0x3c8 == 0xce00, leaving a 0x40 tail per shard whose contents are an open unknown",
    }

    literals = {
        "typeinfo_names": {
            "0x975500": "N7rocksdb14StatisticsImplE",
            "0x9754e0": "N7rocksdb10StatisticsE",
        },
        "strings": {
            "0x432248": "BasicStatistics",
            # 0x4376fd holds an empty string: the byte there is 0x00
            # (the preceding string "base/src/chain_ext.rs" ends at
            # 0x4376fc). It is StatisticsImpl's NickName (slot 0x90).
            "0x4376fd": "",
        },
        "format_strings": {
            "0x44fd60": "%s COUNT : %lu\n",
            "0x9609a0": "%s P50 : %f P95 : %f P99 : %f P100 : %f COUNT : %lu SUM : %lu\n",
        },
    }

    following_vtables = {
        "note": "Vtables that follow the StatisticsImpl primary vtable in the group. Their typeinfo slots sit at primary +0x108/+0x138/+0x170; they are not StatisticsImpl slots and their functions are not mapped here — only their identities (typeinfo name + first function slot) are recorded. Restated from #3392.",
        "tables": {
            "0x64d2e98": {
                "typeinfo": "0x64d2d10",
                "typeinfo_name": "N7rocksdb13ObjectLibrary12FactoryEntryINS_10StatisticsEEE",
                "first_slots": ["0x606fad0", "0x606fda0", "0x606fb40", "0x606fb50"],
                "gap_at": "+0x20",
            },
            "0x64d2ec8": {
                "typeinfo": "0x64d2d48",
                "typeinfo_name": "St15_Sp_counted_ptrIPN7rocksdb14StatisticsImplELN9__gnu_cxx12_Lock_policyE2EE",
                "first_slots": ["0x606fac0", "0x606fb80", "0x60710b0", "0x606fb90", "0x606fb30"],
                "gap_at": "+0x28",
            },
            "0x64d2f00": {
                "typeinfo": "0x64d2d60",
                "typeinfo_name": "St15_Sp_counted_ptrIPN7rocksdb10StatisticsELN9__gnu_cxx12_Lock_policyE2EE",
                "first_slots": ["0x606fab0", "0x606fb60", "0x6071060", "0x606fb70", "0x606fb20"],
                "gap_at": "+0x28",
            },
        },
    }

    records = {
        "task": "RE-001",
        "packet": "RE-001-statisticsimpl-vtable-115",
        "target": "node #115",
        "target_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "base_commit": BASE_COMMIT,
        "bounded_question": "What does each of the 32 slots of the node #115 StatisticsImpl primary vtable (0x64d2d88) implement — the 13 shared Configurable/Customizable base slots, the Statistics-specific reads/writes, the level-3-only 0xc8 forwarder, the deleting dtor, and the delegate chains — and how are the slots reached?",
        "re_shipped_from": {
            "note": "Every re-shipped excerpt was regenerated fresh from the binary by export_excerpts.py and is byte-identical to the source packet's file; verify.py regenerates every excerpt fresh and requires byte-equality, which subsumes the re-ship check.",
            "packets": {
                "RE-001-systemclock-wrapper-vtable-115": 3902,
                "RE-001-stats-write-side-115": 3396,
                "RE-001-locked-ticker-read-115": 3392,
                "RE-001-stats-produce-115": 3362,
                "RE-001-stats-ticker-map-115": 3378,
                "RE-001-statistics-impl-ctor-115": 3572,
            },
            "files": {
                "getoption-609d760.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "areequivalent-609dc40.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "slot04-emptystring-5d32560.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "validateoptions-6096790.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "getoptionsptr-5d2e090.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "slot08-emptystatus-60956f0.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "configureoptions-609d0e0.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "parseoption-60986b0.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "optionsareequal-6095710.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "getoptionname-609d980.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "getid-5d32a30.objdump.txt": "RE-001-systemclock-wrapper-vtable-115",
                "record_tick.txt": "RE-001-stats-write-side-115",
                "cpu_shard_pick.txt": "RE-001-stats-write-side-115",
                "lcg_seed.txt": "RE-001-stats-write-side-115",
                "set_ticker.txt": "RE-001-stats-write-side-115",
                "set_cleanup.txt": "RE-001-stats-write-side-115",
                "set_core.txt": "RE-001-stats-write-side-115",
                "get_reset_ticker.txt": "RE-001-stats-write-side-115",
                "record_hist.txt": "RE-001-stats-write-side-115",
                "record_hist_devirt.txt": "RE-001-stats-write-side-115",
                "reset_stats.txt": "RE-001-stats-write-side-115",
                "reset_cleanup.txt": "RE-001-stats-write-side-115",
                "reset_cleanup2.txt": "RE-001-stats-write-side-115",
                "stats_name.txt": "RE-001-stats-write-side-115",
                "delegate_getter.txt": "RE-001-stats-write-side-115",
                "hist_id_check.txt": "RE-001-stats-write-side-115",
                "stats_ctor.txt": "RE-001-stats-write-side-115 (itself from RE-001-statistics-impl-ctor-115 #3572)",
                "stats_dtor.txt": "RE-001-stats-write-side-115",
                "hist_record.txt": "RE-001-stats-write-side-115",
                "hist_bucket_index.txt": "RE-001-stats-write-side-115",
                "hist_locked_init.txt": "RE-001-stats-write-side-115",
                "hist_shared_init.txt": "RE-001-stats-write-side-115",
                "boundary_gen.txt": "RE-001-stats-write-side-115",
                "locked_ticker.txt": "RE-001-locked-ticker-read-115",
                "landing_pad.txt": "RE-001-locked-ticker-read-115",
                "locked_percentiles.txt": "RE-001-locked-ticker-read-115",
                "locked_histogram_text.txt": "RE-001-locked-ticker-read-115",
                "cleanup_a8.txt": "RE-001-locked-ticker-read-115",
                "cleanup_a0.txt": "RE-001-locked-ticker-read-115",
                "ticker_getter.txt": "RE-001-locked-ticker-read-115 (itself from RE-001-stats-ticker-map-115 #3378)",
                "histogram_builder.txt": "RE-001-locked-ticker-read-115 (itself from RE-001-stats-produce-115 #3362)",
                "mutex_lock.txt": "RE-001-locked-ticker-read-115 (itself from RE-001-stats-produce-115 #3362)",
                "mutex_unlock.txt": "RE-001-locked-ticker-read-115 (itself from RE-001-stats-produce-115 #3362)",
                "tostring.txt": "RE-001-stats-produce-115 (its main.txt, renamed here)",
                "slotf0.txt": "RE-001-stats-ticker-map-115",
            },
        },
        "statistics_impl_vtable": {
            "base": "0x64d2d88",
            "itanium_base": "0x64d2d78",
            "offset_to_top": 0,
            "typeinfo": hex(ti),
            "typeinfo_name": name,
            "typeinfo_name_address": "0x975500",
            "base_typeinfo": hex(base_ti),
            "base_typeinfo_name": base_name,
            "base_typeinfo_name_address": "0x9754e0",
            "slot_count": 32,
            "slots": slot_map,
            "note": "Primary vtable, 32 slots (+0x0..+0xf8), re-derived from the RELATIVE records in relocations.txt. The records at primary +0x108/+0x138/+0x170 are the typeinfo slots of the following group vtables (see following_vtables), not StatisticsImpl slots.",
        },
        "object_layout": object_layout,
        "shard_layout": shard_layout,
        "methods": methods,
        "helpers": helpers,
        "census": census,
        "dispatch": dispatch,
        "shared_slot_vtable_counts": {
            hex(t): census[hex(t)]["relative"] for t in (
                0x609D760, 0x609DC40, 0x5D32560, 0x6095E70, 0x6096790,
                0x5D2E090, 0x60956F0, 0x609D0E0, 0x60986B0, 0x6095710,
                0x609DE80, 0x609D980, 0x5D32A30, 0x5D2E770, 0x5D2CA10)
        },
        "boundaries": {
            "count": 109,
            "first": [1, 2, 3, 4, 6, 10, 15, 22],
            "last": 13000000000000000000,
            "spot": {"b2": 3, "b10": 76, "b50": 850000000,
                     "b100": 540000000000000000},
            "note": "The 109 histogram boundaries from the generator "
                    "0x606bf10 (seeds [1, 2], cur *= 1.5, truncated to 3 "
                    "significant digits above 109); re-derived from the "
                    "model generator in verify.py check 10.",
        },
        "literals": literals,
        "following_vtables": following_vtables,
        "corrections": [
            "record_tick 0x606fba0: the FDE is 0x606fba0..0x606fc59 = 185 bytes; #3396's records.json says size_bytes 441, which does not match its own excerpt (record_tick.txt ends at 0x606fc57). Corrected here to 185.",
            "get_reset_ticker 0x6070c50: the FDE is 0x6070c50..0x6070d92 = 322 bytes; #3396's records.json says size_bytes 338, which does not match its own excerpt (get_reset_ticker.txt ends at 0x6070d8d). Corrected here to 322.",
            "The enable byte at +0x20 has a single writer, the ctor (0x6071a00 movb $0x3 at 0x6071a32) — #4142's whole-binary census (16,889 movb +0x20 stores) proves it; no vtable slot writes +0x20, so #3396's open unknown ('which routine writes the enable byte besides the ctor') is answered: none does; set_stats_level/get_stats_level are non-virtual inlines.",
        ],
        "resolves": [
            "#3396's open unknown 'The remaining StatisticsImpl vtable slots (0x10..0x90 except 0x70/0x88, 0xc8) are not mapped here' — the 13 shared base slots are mapped here (roles from #3902, targets re-verified by this packet's RELATIVE enumeration) and slot 0xc8 is mapped here (the level-3-only forwarder).",
            "#3392's open unknown 'The remaining StatisticsImpl vtable slots (0x10..0x90, 0xb8..0xe0 except 0xe8/0xf0) are not mapped' — all of them are mapped here.",
            "#3572's note 'the 32 slots are pinned by open PRs #3396, #3392, #3378, #3362' — those PRs are merged now, and this packet closes the map into one packet with every slot pinned.",
        ],
        "unknowns": [
            "The public C++ names of slots 0x20, 0x40 and 0x88 (the empty-string, empty-Status and delegate-getter slots) are not established from the stripped binary; they are described by observed behaviour, signatures and vtable slots, not by source-level names.",
            "The 0xc8/0xd0/0xd8 mapping to measureTime/recordInHistogram/recordHistogram is inference from the level gates (0xc8 requires level > 2, the detailed-timers level; 0xd0 is implemented in terms of 0xd8) and from the 0x5e080f0 host, which records histogram ids 2 and 3 through slot 0xc8; it is not binary-established.",
            "The histogram record path treats its third argument as a u64 throughout (integer compares, adds, multiply); no caller that passes a double's bit pattern was examined.",
            "set_core performs no bound check: ids >= 179 index past the ticker area into the histogram records (observed addressing, not exercised).",
            "The 0x40 tail at the end of each 0xce40-byte shard (0xce00..0xce40) is not examined; its contents are open (carried from #3392).",
            "The bucket_count field at record+0x390 is read by the shared init and never written by it; its writer is an open unknown (likely the shard-store builder 0x60716d0 or the bucket-count init 0x606b080).",
            "The +0x28 delegate is moved in from the creator's options struct; which construction paths install a non-null delegate (beyond the factory host, which passes its own options through) is not traced here.",
            "The exact _Hash_bytes output for a given pthread_self is not byte-verified against a live run (the seed is thread-dependent); the model implements the documented libstdc++ MurmurHash64A algorithm and only its determinism and range are tested.",
            "The other three direct callers of the CPU picker (0x5f0aa40, 0x605e17b, 0x61c1e24) and the other 14 direct callers of the LCG seed accessor are other per-CPU / per-thread users; their routines are not mapped here.",
            "Which landing pad covers which call site inside the locked routines is inferred from the register and mutex state, not read from the LSDA; the fragments' shapes and jump targets are pinned.",
            "The 0x5e080f0 host FDE (0x5e080f0..0x5e095ed) is pinned only for its slot-0xc8 devirtualization fragment (0x5e08488..0x5e084f7) and the two slot-0xd8 calls (hist ids 2 and 3); the rest of the 0x14fd-byte FDE is not mapped here.",
            "The ctor's trailing cleanup fragment at 0x6071b60 (outside the ctor FDE) is not excerpted.",
        ],
    }
    return records


if __name__ == "__main__":
    sys.exit(main())
