"""Generate records.json, callers.tsv, relocations.txt and vtables.tsv.

Run from the repository root:
    python3 research/work-items/RE-001-systemclock-wrapper-vtable-115/gen_records.py

Everything derived here comes from the digest-verified binary
(work/hl-node-115.bin) or the repo catalogue (research/byte-windows.json);
the semantic claims are hand-written below from the disassembly and
checked by verify.py. No per-instruction mnemonic list is emitted:
instruction-level detail lives only in the verbatim excerpts.

Vtable geometry used throughout: the "stored pointer" is the value
an object holds in its +0x00 word (the Itanium vtable base + 0x10);
slot N sits at stored + N*8; the typeinfo pointer sits at
stored - 0x08 and the offset-to-top at stored - 0x10. The wrapper
ctor installs 0x64cdd78 (the Itanium base) and objects therefore
hold 0x64cdd88. The file content at the vtable offsets is NOT the
vtable qwords: the entries survive only as R_X86_64_RELATIVE
addends in .rela.dyn, which is what this script reads.
"""

import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, HERE)
import census as census_mod

# --- ELF helpers -------------------------------------------------------

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


def resolve_vtable(data, segs, rel, stored):
    """Return (typeinfo_va, typeinfo_name, [(offset, target-or-None)]).

    `stored` is the stored pointer (what objects hold in +0x00);
    slot N is at stored + N*8 and is None when no RELATIVE record
    covers that VA. All three vtables here have 26 slots.
    """
    ti = reloc_val(data, segs, rel, stored - 8)
    name = cstr_at_va(data, segs, reloc_val(data, segs, rel, ti + 8))
    slots = []
    for n in range(26):
        va = stored + n * 8
        slots.append((hex(n * 8), (hex(rel[va]) if va in rel else None)))
    return ti, name, slots


def resolve_slot_owner(data, segs, rel, slot_va):
    """Find the vtable that owns a RELATIVE slot.

    Walks back from the slot in 8-byte steps (up to 26 slots) looking
    for a candidate stored pointer S where the qword at S-0x10 is a
    small offset-to-top (0 or a small negative, stored raw) and the
    qword at S-0x08 resolves (via reloc) to a typeinfo object whose
    name string is printable ASCII. Returns (stored, typeinfo_name,
    slot_index) or None.
    """
    for k in range(26):
        stored = slot_va - k * 8
        off = va2off(segs, stored - 0x10)
        if off is None:
            continue
        top = struct.unpack_from("<q", data, off)[0]
        if top != 0 and not (-64 <= top < 0):
            continue
        ti = reloc_val(data, segs, rel, stored - 8)
        if ti is None:
            continue
        name_va = reloc_val(data, segs, rel, ti + 8)
        if name_va is None:
            continue
        name = cstr_at_va(data, segs, name_va)
        if not name or len(name) < 3 or len(name) > 200:
            continue
        if not all(32 <= ord(c) < 127 for c in name):
            continue
        return stored, name, k
    return None


def load_fdes():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]{8} .*FDE .*pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)", line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def containing(fdes, va):
    import bisect
    starts = [f[0] for f in fdes]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
        return fdes[i]
    return None


def catalogue_label(by_start, va):
    ws = by_start.get(va)
    if not ws:
        return None
    return ws[0].get("label") or ws[0].get("id")


def short_name(label):
    """'librocksdb-sys 0.11.0+8.1.1: _ZN7rocksdb18SystemClockWrapper14PrepareOptionsE...'
    -> 'SystemClockWrapper::PrepareOptions'. Falls back to the raw
    label (truncated) when it does not parse."""
    if not label:
        return None
    text = label.split(": ", 1)[-1]
    m = re.match(r"^_ZN?K?7rocksdb", text)
    if not m:
        return text[:100]
    rest = text[m.end():]
    parts = []
    try:
        while rest and len(parts) < 2:
            j = 0
            while j < len(rest) and rest[j].isdigit():
                j += 1
            if j == 0:
                break
            n = int(rest[:j])
            rest = rest[j:]
            if len(rest) < n:
                break
            parts.append(rest[:n])
            rest = rest[n:]
    except ValueError:
        return text[:100]
    if len(parts) == 2:
        return parts[0] + "::" + parts[1]
    if len(parts) == 1:
        # A free function (one length-prefixed name, e.g.
        # VerifySstFileChecksum) or a constructor/destructor, whose
        # C1/D0 tag carries no length prefix.
        for tag in ("C1", "C2", "D0", "D1", "D2"):
            if rest.startswith(tag):
                return parts[0] + "::" + tag
        return parts[0]
    return text[:100]


# --- caller roles -------------------------------------------------------

# Explicit roles for the targets with a single site.
EXPLICIT_ROLES = {
    0x5D2E770: {
        0x5FD624B: "CompositeEnvWrapper::IsInstanceOf tail-jumps to the shared Customizable::IsInstanceOf",
    },
    0x5FD0090: {
        0x60293B6: "EmulatedSystemClock::C1 calls the wrapper ctor C1 (the only direct caller in .text)",
    },
}

# Targets whose sites all share one role shape, derived from the
# containing FDE's catalogue label.
LABEL_ROLE_FMT = {
    0x6095E70: "base PrepareOptions call in %s",
    0x6096790: "base ValidateOptions call in %s",
    0x609D0E0: "base ConfigureOptions call in %s",
    0x60986B0: "base ParseOption call in %s",
    0x609DE80: "base SerializeOptions call in %s",
    0x5FE2680: "default-clock accessor call in %s",
}


def role_for(t, site, f, by_start):
    if t in EXPLICIT_ROLES and site in EXPLICIT_ROLES[t]:
        return EXPLICIT_ROLES[t][site]
    fmt = LABEL_ROLE_FMT.get(t)
    if fmt is None:
        raise SystemExit("missing role for site %#x -> %#x" % (t, site))
    lab = catalogue_label(by_start, f[0])
    if lab:
        return fmt % short_name(lab)
    return fmt % ("FDE %#x (no catalogue row)" % f[0])


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    assert __import__("hashlib").sha256(data).hexdigest() == DIGEST
    segs = load_segments(data)
    rel = load_relocs(data)
    fdes = load_fdes()
    cat = json.load(open(os.path.join(ROOT, "research/byte-windows.json")))
    by_start = {}
    for w in cat["windows"]:
        by_start.setdefault(w["start"], []).append(w)

    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, BIN))

    # Vtables.
    vtables = {}
    for key, stored in (("system_clock_wrapper", 0x64CDD88),
                        ("emulated_system_clock", 0x64D1650),
                        ("posix_clock", 0x64CE930)):
        ti, name, entries = resolve_vtable(data, segs, rel, stored)
        vtables[key] = {
            "stored_pointer": hex(stored),
            "itanium_base": hex(stored - 0x10),
            "typeinfo_address": hex(ti),
            "typeinfo_name": name,
            "slots": [{"offset": o, "target": t} for o, t in entries],
        }

    # Vtable-slot owners for every RELATIVE slot pointing at a target.
    # The .got section spans 0x64df458..0x64ee158 (readelf -S); a slot
    # in that range is a GOT entry, not a vtable slot.
    slot_owners = {}
    for t in census_mod.TARGETS:
        owners = []
        for s in slots[t]:
            if 0x64DF458 <= s < 0x64EE158:
                owners.append({"slot": hex(s), "kind": "got_slot"})
                continue
            got = resolve_slot_owner(data, segs, rel, s)
            if got is None:
                owners.append({"slot": hex(s), "kind": "unresolved"})
            else:
                stored, name, k = got
                owners.append({"slot": hex(s), "kind": "vtable_slot",
                               "vtable_stored_pointer": hex(stored),
                               "typeinfo_name": name,
                               "slot_index": k,
                               "slot_offset": hex(k * 8)})
        slot_owners[hex(t)] = owners

    # Callers with roles.
    callers = {}
    for t in census_mod.TARGETS:
        rows = []
        for v in calls[t]:
            f = containing(fdes, v)
            if f is None:
                raise SystemExit("census site without containing FDE: %#x -> %#x" % (t, v))
            role = role_for(t, v, f, by_start)
            rows.append({
                "site": hex(v),
                "kind": "direct_call",
                "containing_fde": [hex(f[0]), hex(f[1])],
                "role": role,
            })
        for v in tails[t]:
            f = containing(fdes, v)
            if f is None:
                raise SystemExit("census tail without containing FDE: %#x -> %#x" % (t, v))
            role = role_for(t, v, f, by_start)
            rows.append({
                "site": hex(v),
                "kind": "tail_jump",
                "containing_fde": [hex(f[0]), hex(f[1])],
                "role": role,
            })
        callers[hex(t)] = rows

    # callers.tsv: target, site, kind, containing FDE, role.
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde\trole\n")
        for t in census_mod.TARGETS:
            for row in callers[hex(t)]:
                fh.write("%s\t%s\t%s\t%s..%s\t%s\n" % (
                    hex(t), row["site"], row["kind"],
                    row["containing_fde"][0], row["containing_fde"][1],
                    row["role"]))

    # vtables.tsv
    with open(os.path.join(HERE, "vtables.tsv"), "w") as fh:
        fh.write("vtable\tstored_pointer\ttypeinfo_name\tslot_offset\ttarget\n")
        for key, vt in vtables.items():
            for s in vt["slots"]:
                fh.write("%s\t%s\t%s\t%s\t%s\n" % (
                    key, vt["stored_pointer"], vt["typeinfo_name"],
                    s["offset"], s["target"]))

    # relocations.txt
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("The SystemClockWrapper vtable (stored pointer 0x64cdd88, Itanium base 0x64cdd78) has 26 slots, stored+0x00..+0xc8; the EmulatedSystemClock vtable (stored 0x64d1650, Itanium base 0x64d1640) has 26 slots; the PosixClock vtable (stored 0x64ce930, Itanium base 0x64ce920) has 26 slots. Typeinfo names and every slot target are in vtables.tsv and records.json.\n")
        fh.write("The wrapper leaves slots 0, 1 and 14 null: no R_X86_64_RELATIVE record covers stored+0x00, +0x08 or +0x70, so a loaded wrapper object has a null D1, a null D0 and a null Name() slot. The wrapper ctor installs the Itanium base 0x64cdd78 (lea at 0x5fd00af), so objects hold the stored pointer 0x64cdd88.\n")
        fh.write("Chain-walk GOT canonicals (R_X86_64_RELATIVE): 0x64ecf80 -> 0x5d4d490 (slot 19 NowMicros), 0x64ed5f8 -> 0x5dd41a0 (slot 23 SleepForMicroseconds), 0x64ed3e8 -> 0x5d4b100 (slot 24 GetCurrentTime). The SerializeOptions identity check compares the wrapped clock's slot-16 result against the GOT slot 0x64eceb8. The shared_ptr refcount selector byte lives at 0x64ed290 (lock addl when 0, plain addl otherwise).\n")
        fh.write("No other relocation in the packet points at a window: the wrapper is 0x30 bytes, its +0x20 target is a shared_ptr<SystemClock> (ptr at +0x20, control block at +0x28), and the emulated clock's extra state is the sleep counter at +0x38, the CPU counter at +0x3c, the emulated offset at +0x40 and the flags at +0x48/+0x49 (no relocation).\n")
    records = build_records(calls, tails, hits, slots, callers, vtables, slot_owners, by_start)
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json, callers.tsv, relocations.txt, vtables.tsv")
    return 0


def build_records(calls, tails, hits, slots, callers, vtables, slot_owners, by_start):
    census = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    windows = [
        ("0x609d760", "rocksdb::Customizable::GetOption", "0x609d760..0x609d954", 500, "getoption-609d760.objdump.txt", None),
        ("0x609dc40", "rocksdb::Customizable::AreEquivalent", "0x609dc40..0x609de39", 505, "areequivalent-609dc40.objdump.txt", None),
        ("0x5d32560", "returns empty std::string (C++ name open)", "0x5d32560..0x5d3257b", 27, "slot04-emptystring-5d32560.objdump.txt", None),
        ("0x5fcf590", "rocksdb::SystemClockWrapper::PrepareOptions", "0x5fcf590..0x5fcf658", 200, "prepareoptions-5fcf590.objdump.txt", None),
        ("0x6096790", "rocksdb::Configurable::ValidateOptions", "0x6096790..0x6096f0c", 1916, "validateoptions-6096790.objdump.txt", None),
        ("0x5d2e090", "rocksdb::Customizable::GetOptionsPtr", "0x5d2e090..0x5d2e0de", 78, "getoptionsptr-5d2e090.objdump.txt", None),
        ("0x60956f0", "returns empty Status (C++ name open)", "0x60956f0..0x609570c", 28, "slot08-emptystatus-60956f0.objdump.txt", None),
        ("0x609d0e0", "rocksdb::Configurable::ConfigureOptions", "0x609d0e0..0x609d75e", 1662, "configureoptions-609d0e0.objdump.txt", None),
        ("0x60986b0", "rocksdb::Configurable::ParseOption", "0x60986b0..0x6098a9c", 1004, "parseoption-60986b0.objdump.txt", None),
        ("0x6095710", "rocksdb::Configurable::OptionsAreEqual", "0x6095710..0x609579a", 138, "optionsareequal-6095710.objdump.txt", None),
        ("0x5fcdae0", "rocksdb::SystemClockWrapper::SerializeOptions", "0x5fcdae0..0x5fcdf63", 1155, "serializeoptions-5fcdae0.objdump.txt", None),
        ("0x609d980", "rocksdb::Customizable::GetOptionName", "0x609d980..0x609dc18", 664, "getoptionname-609d980.objdump.txt", None),
        ("0x5d32a30", "rocksdb::Customizable::GetId", "0x5d32a30..0x5d32a51", 33, "getid-5d32a30.objdump.txt", None),
        ("0x5fcc3f0", "returns *(this+0x20), the wrapped clock (C++ name open)", "0x5fcc3f0..0x5fcc3f9", 9, "slot17-wrapped-5fcc3f0.objdump.txt", None),
        ("0x5d4d490", "rocksdb::SystemClockWrapper::NowMicros", "0x5d4d490..0x5d4d552", 194, "nowmicros-5d4d490.objdump.txt", None),
        ("0x5fcc340", "forwards to wrapped slot 20 (NowNanos)", "0x5fcc340..0x5fcc351", 17, "nownanos-fwd-5fcc340.objdump.txt", None),
        ("0x5fcc360", "forwards to wrapped slot 21 (CPUMicros)", "0x5fcc360..0x5fcc371", 17, "cpumicros-fwd-5fcc360.objdump.txt", None),
        ("0x5fcc380", "forwards to wrapped slot 22 (CPUNanos)", "0x5fcc380..0x5fcc391", 17, "cpunanos-fwd-5fcc380.objdump.txt", None),
        ("0x5dd41a0", "rocksdb::SystemClockWrapper::SleepForMicroseconds", "0x5dd41a0..0x5dd4262", 194, "sleep-5dd41a0.objdump.txt", None),
        ("0x5fcc3a0", "rocksdb::SystemClockWrapper::TimeToString", "0x5fcc3a0..0x5fcc3e7", 71, "timetostring-5fcc3a0.objdump.txt", None),
        ("0x60257a0", "rocksdb::EmulatedSystemClock::Name", "0x60257a0..0x60257ac", 12, "emu-name-60257a0.objdump.txt", None),
        ("0x60259e0", "rocksdb::EmulatedSystemClock::NowMicros", "0x60259e0..0x6025a08", 40, "emu-nowmicros-60259e0.objdump.txt", None),
        ("0x60259a0", "rocksdb::EmulatedSystemClock::NowNanos", "0x60259a0..0x60259d2", 50, "emu-nownanos-60259a0.objdump.txt", None),
        ("0x6025a30", "rocksdb::EmulatedSystemClock::CPUMicros", "0x6025a30..0x6025a46", 22, "emu-cpumicros-6025a30.objdump.txt", None),
        ("0x6025a10", "rocksdb::EmulatedSystemClock::CPUNanos", "0x6025a10..0x6025a26", 22, "emu-cpunanos-6025a10.objdump.txt", None),
        ("0x6025b40", "rocksdb::EmulatedSystemClock::SleepForMicroseconds", "0x6025b40..0x6025b7f", 63, "emu-sleep-6025b40.objdump.txt", None),
        ("0x6025eb0", "rocksdb::EmulatedSystemClock::GetCurrentTime", "0x6025eb0..0x6025feb", 315, "emu-getcurrenttime-6025eb0.objdump.txt", None),
        ("0x5fe0fe0", "PosixClock::Name (returns DefaultClock)", "0x5fe0fe0..0x5fe0fec", 12, "posix-name-5fe0fe0.objdump.txt", None),
        ("0x5d2ca00", "PosixClock slot 17: returns null (C++ name open)", "0x5d2ca00..0x5d2ca07", 7, "posix-slot17-null-5d2ca00.objdump.txt", None),
        ("0x5fe0ff0", "PosixClock slot 18: returns PosixClock (C++ name open)", "0x5fe0ff0..0x5fe0ffc", 12, "posix-slot18-5fe0ff0.objdump.txt", None),
        ("0x5fe1480", "PosixClock::CPUMicros", "0x5fe1480..0x5fe14e4", 100, "posix-cpumicros-5fe1480.objdump.txt", None),
        ("0x5fe1430", "PosixClock::CPUNanos", "0x5fe1430..0x5fe147c", 76, "posix-cpunanos-5fe1430.objdump.txt", None),
        ("0x5fd0090", "rocksdb::SystemClockWrapper::SystemClockWrapper (C1)", "0x5fd0090..0x5fd0178", 232, "ctor-5fd0090.objdump.txt", "re-shipped from open PR #3352 (vtable_install_1.txt), byte-identical to a fresh objdump run"),
    ]
    by_contract = [
        ("0x5d2e770", "rocksdb::Customizable::IsInstanceOf", "0x5d2e770..0x5d2e832", 194, "open PR #3715 (OptionTypeInfo::AsCustomSharedPtr<SystemClock> builder 0x5fd0180)"),
        ("0x5d2ca10", "wrapper slot 18: returns empty string (C++ name open)", "0x5d2ca10..0x5d2ca1c", 12, "open PR #3715"),
        ("0x5d4b100", "GetCurrentTime (canonical chain-walk leaf)", "0x5d4b100..0x5d4b10c", 268, "open PR #3352 (canonical lea sites) and #3322"),
        ("0x6029500", "rocksdb::SystemClockWrapper::~SystemClockWrapper (D0)", "0x6029500..0x602961b", 283, "this cycle's analysis; not a vtable slot (wrapper slots 0/1 are null)"),
    ]
    window_recs = []
    for addr, name, fde, size, excerpt, note in windows:
        lab = catalogue_label(by_start, int(addr, 16))
        rec = {
            "address": addr, "name": name, "fde": fde,
            "size_bytes": size, "catalogue": lab, "excerpt": excerpt,
        }
        if note:
            rec["note"] = note
        window_recs.append(rec)
    for addr, name, fde, size, source in by_contract:
        lab = catalogue_label(by_start, int(addr, 16))
        window_recs.append({
            "address": addr, "name": name, "fde": fde,
            "size_bytes": size, "catalogue": lab, "excerpt": None,
            "by_contract_from": source,
        })
    return {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "resolves": "open PR #3352's open unknown: which of the wrapper vtable's other slot functions each implement",
        "windows": window_recs,
        "layout": {
            "wrapper_size_bytes": 0x30,
            "fields": {
                "+0x00": "vtable 0x64cdd88 (rocksdb::SystemClockWrapper, 26 slots; slots 0, 1, 14 null)",
                "+0x08": "zeroed by the ctor (3-pointer range; exact container identity open: the D0 destroys it as a vector of 0x30-byte elements with leading strings)",
                "+0x10": "zeroed by the ctor (see +0x08)",
                "+0x18": "zeroed by the ctor (see +0x08)",
                "+0x20": "shared_ptr<SystemClock> target (ptr)",
                "+0x28": "shared_ptr<SystemClock> control block",
            },
            "emulated_extra_fields": {
                "+0x38": "sleep counter (lock addl $1 per SleepForMicroseconds call)",
                "+0x3c": "CPU counter (lock addl $1 per CPUMicros/CPUNanos call)",
                "+0x40": "emulated time offset (added to the wrapped time; accumulated by Sleep)",
                "+0x48": "flag: when set, NowMicros/NowNanos/GetCurrentTime return the emulated offset alone",
                "+0x49": "flag: read by SleepForMicroseconds (exact role open)",
            },
        },
        "vtable": {
            "wrapper": {
                "stored_pointer": "0x64cdd88", "itanium_base": "0x64cdd78",
                "typeinfo_address": "0x64cd960",
                "typeinfo_name": "N7rocksdb18SystemClockWrapperE",
                "slot_count": 26,
                "null_slots": [0, 1, 14],
                "slots": [
                    {"offset": "+0x00", "target": None, "role": "D1 (null in the wrapper vtable)"},
                    {"offset": "+0x08", "target": None, "role": "D0 (null in the wrapper vtable)"},
                    {"offset": "+0x10", "target": "0x609d760", "role": "Customizable::GetOption"},
                    {"offset": "+0x18", "target": "0x609dc40", "role": "Customizable::AreEquivalent"},
                    {"offset": "+0x20", "target": "0x5d32560", "role": "returns empty std::string (C++ name open)"},
                    {"offset": "+0x28", "target": "0x5fcf590", "role": "SystemClockWrapper::PrepareOptions"},
                    {"offset": "+0x30", "target": "0x6096790", "role": "Configurable::ValidateOptions"},
                    {"offset": "+0x38", "target": "0x5d2e090", "role": "Customizable::GetOptionsPtr"},
                    {"offset": "+0x40", "target": "0x60956f0", "role": "returns empty Status (C++ name open)"},
                    {"offset": "+0x48", "target": "0x609d0e0", "role": "Configurable::ConfigureOptions"},
                    {"offset": "+0x50", "target": "0x60986b0", "role": "Configurable::ParseOption"},
                    {"offset": "+0x58", "target": "0x6095710", "role": "Configurable::OptionsAreEqual"},
                    {"offset": "+0x60", "target": "0x5fcdae0", "role": "SystemClockWrapper::SerializeOptions"},
                    {"offset": "+0x68", "target": "0x609d980", "role": "Customizable::GetOptionName"},
                    {"offset": "+0x70", "target": None, "role": "Name() (null in the wrapper vtable)"},
                    {"offset": "+0x78", "target": "0x5d32a30", "role": "Customizable::GetId"},
                    {"offset": "+0x80", "target": "0x5d2e770", "role": "Customizable::IsInstanceOf"},
                    {"offset": "+0x88", "target": "0x5fcc3f0", "role": "returns *(this+0x20), the wrapped clock (C++ name open)"},
                    {"offset": "+0x90", "target": "0x5d2ca10", "role": "returns empty string (C++ name open)"},
                    {"offset": "+0x98", "target": "0x5d4d490", "role": "SystemClockWrapper::NowMicros"},
                    {"offset": "+0xa0", "target": "0x5fcc340", "role": "forwards to wrapped slot 20 (NowNanos)"},
                    {"offset": "+0xa8", "target": "0x5fcc360", "role": "forwards to wrapped slot 21 (CPUMicros)"},
                    {"offset": "+0xb0", "target": "0x5fcc380", "role": "forwards to wrapped slot 22 (CPUNanos)"},
                    {"offset": "+0xb8", "target": "0x5dd41a0", "role": "SystemClockWrapper::SleepForMicroseconds"},
                    {"offset": "+0xc0", "target": "0x5d4b100", "role": "GetCurrentTime (canonical chain-walk)"},
                    {"offset": "+0xc8", "target": "0x5fcc3a0", "role": "SystemClockWrapper::TimeToString"},
                ],
            },
            "emulated_system_clock": {
                "stored_pointer": "0x64d1650", "itanium_base": "0x64d1640",
                "typeinfo_address": "0x64d1240",
                "typeinfo_name": "N7rocksdb19EmulatedSystemClockE",
                "slot_count": 26,
                "shared_with_wrapper": "slots 2-13, 15-18, 25 are the same function addresses as the wrapper vtable",
                "overrides": {
                    "0": "0x6029110 (D1, installs the wrapper vtable)",
                    "1": "0x6029620 (D0, installs the wrapper vtable)",
                    "14": "0x60257a0 (Name() -> TimeEmulatedSystemClock)",
                    "19": "0x60259e0 (NowMicros)",
                    "20": "0x60259a0 (NowNanos)",
                    "21": "0x6025a30 (CPUMicros)",
                    "22": "0x6025a10 (CPUNanos)",
                    "23": "0x6025b40 (SleepForMicroseconds)",
                    "24": "0x6025eb0 (GetCurrentTime)",
                },
            },
            "posix_clock": {
                "stored_pointer": "0x64ce930", "itanium_base": "0x64ce920",
                "typeinfo_address": "0x64ce870",
                "typeinfo_name": "*N7rocksdb12_GLOBAL__N_110PosixClockE",
                "slot_count": 26,
                "shared_with_wrapper": "slots 2, 3, 4, 6, 7, 8, 9, 10, 11, 13 are the same function addresses as the wrapper vtable",
                "differs_from_wrapper": {
                    "0": "0x5fe17d0 (D1)", "1": "0x5fe18f0 (D0)",
                    "5": "0x6095e70 (base Configurable::PrepareOptions)",
                    "12": "0x609de80 (base Customizable::SerializeOptions)",
                    "14": "0x5fe0fe0 (Name() -> DefaultClock)",
                    "17": "0x5d2ca00 (returns null)",
                    "18": "0x5fe0ff0 (returns PosixClock)",
                    "19": "0x5fe1540 (NowMicros)",
                    "20": "0x5fe14f0 (NowNanos)",
                    "21": "0x5fe1480 (CPUMicros)",
                    "22": "0x5fe1430 (CPUNanos)",
                    "23": "0x5fe1420 (SleepForMicroseconds)",
                    "24": "0x5fe2230 (GetCurrentTime)",
                    "25": "0x5fe1340 (TimeToString)",
                },
            },
            "shared_slot_counts": {
                "0x609d760": "63 RELATIVE slots (GetOption, shared by 63 Configurable vtables)",
                "0x609dc40": "63 RELATIVE slots (AreEquivalent)",
                "0x5d32560": "66 RELATIVE slots (empty-string slot 4)",
                "0x6096790": "64 RELATIVE slots (ValidateOptions)",
                "0x5d2e090": "62 RELATIVE slots (GetOptionsPtr)",
                "0x60956f0": "68 RELATIVE slots (empty-Status slot 8)",
                "0x609d0e0": "66 RELATIVE slots (ConfigureOptions)",
                "0x60986b0": "67 RELATIVE slots (ParseOption)",
                "0x6095710": "65 RELATIVE slots (OptionsAreEqual)",
                "0x609d980": "63 RELATIVE slots (GetOptionName)",
                "0x5d32a30": "55 RELATIVE slots (GetId)",
                "0x5d2e770": "44 RELATIVE slots (IsInstanceOf)",
                "0x5d2ca10": "45 RELATIVE slots (empty-string slot 18)",
                "0x5d2ca00": "45 RELATIVE slots (null-returning slot 17)",
            },
        },
        "chain_walk": {
            "slots": [19, 23, 24],
            "rule": "an 8-level unrolled walk: each level's slot pointer is compared against the GOT canonical for that slot; the first level whose slot differs from the canonical is called; when all 8 compared levels match, the 9th level's slot is called unconditionally (a 9th-level canonical re-walks from there)",
            "canonicals": {
                "19": {"got": "0x64ecf80", "function": "0x5d4d490"},
                "23": {"got": "0x64ed5f8", "function": "0x5dd41a0"},
                "24": {"got": "0x64ed3e8", "function": "0x5d4b100"},
            },
            "evidence": {
                "19": "NowMicros 0x5d4d490 compares each level's slot-19 pointer against *(0x64ecf80) at 0x5d4d4a2 and tail-jumps via *0x98(%rax) at 0x5d4d53f",
                "23": "SleepForMicroseconds 0x5dd41a0 compares against *(0x64ed5f8) at 0x5dd41b2 and tail-jumps via *0xb8(%rax) at 0x5dd424f",
                "24": "GetCurrentTime 0x5d4b100 is the canonical the chain-walk compares against *(0x64ed3e8), per #3352",
            },
        },
        "forwarding": {
            "slots": [20, 21, 22],
            "rule": "a plain tail-jump to the wrapped clock's same slot: mov 0x20(%rdi),%rdi loads the wrapped clock, then jmp *0xa0/0xa8/0xb0(%rax) calls its slot 20/21/22. No chain-walk, no canonical compare.",
            "slot_25": "TimeToString 0x5fcc3a0 calls the wrapped clock's slot 25 with (Status-out, this) via call *0xc8(%rax) at 0x5fcc3c3",
        },
        "methods": {
            "get_option": {
                "address": "0x609d760", "name": "rocksdb::Customizable::GetOption",
                "arguments": ["rdi = Status out", "rsi = this", "rdx = name (std::string*)", "rcx = config", "r8 = value out"],
                "algorithm": "name length 2 with bytes 'id' (cmpw $0x6469 at 0x609d7b3) calls slot 15 (GetId, call *0x78 at 0x609d7c0) on this, copies the result string into *r8 and writes an empty Status into *rdi; any other name calls the generic path 0x6099030 at 0x609d78d",
            },
            "are_equivalent": {
                "address": "0x609dc40", "name": "rocksdb::Customizable::AreEquivalent",
                "arguments": ["rdi = this", "rsi = other", "rdx = out string*"],
                "algorithm": "config flag <= 1 or this == other returns 1; a null other returns 0; otherwise call slot 15 (GetId, *0x78) on both objects and memcmp the two id strings (call memcmp@plt at 0x609dd8d); equal ids with flag <= 2 return 1; equal ids with flag > 2 tail-jump to the deeper check 0x60996a0 at 0x609dd6e; different ids write 'id' (literal 0x441b15, lea at 0x609dddc) into the out string and return 0",
            },
            "slot_04_empty_string": {
                "address": "0x5d32560", "name": "returns empty std::string (C++ name open)",
                "algorithm": "returns an empty std::string; shared by 66 vtables; no direct calls or tail jumps (virtual dispatch only)",
                "open": "its C++ name (it sits between AreEquivalent and PrepareOptions in the vtable; Configurable::GetOptionString 0x6098510 and Configurable::ToString 0x60971c0 are ruled out: their census VAs are not in this vtable)",
            },
            "prepare_options": {
                "address": "0x5fcf590", "name": "rocksdb::SystemClockWrapper::PrepareOptions",
                "arguments": ["rdi = Status out", "rsi = this", "rdx = config"],
                "algorithm": "if the wrapper target (+0x20) is non-null, call the base Configurable::PrepareOptions 0x6095e70 directly (0x5fcf5b7); if it is null, call the PosixClock accessor 0x5fe2680 (0x5fcf5e9), install the returned shared_ptr (ptr -> +0x20, control block -> +0x28) with the 0x64ed290-selector refcounting (lock addl $0x1,0x8(%rbp) when the selector byte is 0, plain addl otherwise), release the old control block via 0x5d350c0 (0x5fcf62e) when it differs, then call the base PrepareOptions 0x6095e70",
                "note": "the base PrepareOptions is called on both paths; the install path runs first when the target is null",
            },
            "validate_options": {
                "address": "0x6096790", "name": "rocksdb::Configurable::ValidateOptions",
                "algorithm": "the shared Configurable validation: 4x operator delete, 2x 0x63f0e10, 2x 0x63f0dc0, 2x 0x63f0a60, 1x 0x60b9f50; no virtual calls and no indirect jumps (the full internals are the Configurable component's own work)",
                "callers": "4 direct call sites: the ValidateOptions overrides of BlockBasedTableFactory, TtlCompactionFilter, TtlCompactionFilterFactory and TtlMergeOperator, each calling the base to validate",
            },
            "get_options_ptr": {
                "address": "0x5d2e090", "name": "rocksdb::Customizable::GetOptionsPtr",
                "algorithm": "calls 0x60958c0 and the slot-17 function (*0x88) on the options object at 0x5d2e0be; shared by 62 vtables",
            },
            "slot_08_empty_status": {
                "address": "0x60956f0", "name": "returns empty Status (C++ name open)",
                "algorithm": "returns an empty (OK) Status; shared by 68 vtables; no direct calls or tail jumps (virtual dispatch only)",
                "open": "its C++ name (it sits between GetOptionsPtr and ConfigureOptions in the vtable)",
            },
            "configure_options": {
                "address": "0x609d0e0", "name": "rocksdb::Configurable::ConfigureOptions",
                "algorithm": "the shared Configurable configuration: calls GetOptionString 0x6098510, 0x6099e70 and 0x609c8c0, virtual slot 0x10 (x2), slot 0x18 (x2) and slot 0x28 (x1), and 2x _M_release 0x5d35070; the full internals are the Configurable component's own work",
                "callers": "2 direct call sites: ConfigurableCFOptions::ConfigureOptions and DBOptionsConfigurable::ConfigureOptions",
            },
            "parse_option": {
                "address": "0x60986b0", "name": "rocksdb::Configurable::ParseOption",
                "algorithm": "the shared Configurable option parse: calls 0x60bedc0 (x2), 0x61cf670, virtual slot 0x10 and slot 0x18, and 1x _M_release 0x5d35070; the full internals are the Configurable component's own work",
                "callers": "1 direct call site: BlockBasedTableFactory::ParseOption",
            },
            "options_are_equal": {
                "address": "0x6095710", "name": "rocksdb::Configurable::OptionsAreEqual",
                "algorithm": "calls 0x60bf980 and 0x60bf7c0; shared by 65 vtables; the full internals are the Configurable component's own work",
            },
            "serialize_options": {
                "address": "0x5fcdae0", "name": "rocksdb::SystemClockWrapper::SerializeOptions",
                "arguments": ["rdi = Status out", "rsi = this", "rdx = config", "rcx = prefix string"],
                "algorithm": "serializes via the base Customizable::SerializeOptions 0x609de80 (call at 0x5fcdb3e), then, when a wrapped clock is installed (config+0x28 flag and this+0x20 non-null), loads the wrapped clock's vtable, takes the 'DefaultClock' literal (0x431007) and calls the string helper 0x5fcd890, then reads the wrapped clock's slot 16 (IsInstanceOf, *0x70) and compares the result against the GOT slot 0x64eceb8 to decide whether the wrapped clock's serialization is emitted",
                "literals": ["0x431007 (DefaultClock)", "0x4376fd (empty string)", "0x441b15 (id)", "0x445245", "0x4474d2", "0x4496d1"],
                "callees": ["0x609de80 (base SerializeOptions)", "0x60971c0 (Configurable::ToString)", "0x5fcd890 (x4, string helper)", "0x5fcd6f0", "0x61d1390", "0x61d13e0", "virtual slot 0x70 (IsInstanceOf)"],
                "open": "the exact branch outcome of the IsInstanceOf compare against GOT 0x64eceb8",
            },
            "get_option_name": {
                "address": "0x609d980", "name": "rocksdb::Customizable::GetOptionName",
                "algorithm": "calls 0x6095a60 and the slot-14 Name function (*0x70) at 0x609d9b4; the full internals are the Configurable component's own work",
                "literals": ["0x963298", "0x96ab78 (option-type table data, not strings)"],
            },
            "get_id": {
                "address": "0x5d32a30", "name": "rocksdb::Customizable::GetId",
                "algorithm": "calls slot 14 (Name, *0x70) on this at 0x5d32a3e and builds a std::string from the result via 0x5d32940 at 0x5d32a47",
                "open": "a bare wrapper's slot 14 is null, so how a bare wrapper answers GetId/GetOption('id') without dispatching through the null slot is open (the id may come from the wrapped clock's Name when one is installed)",
            },
            "is_instance_of": {
                "address": "0x5d2e770", "name": "rocksdb::Customizable::IsInstanceOf",
                "algorithm": "by contract from #3715: the shared instance check used by the create-by-name dispatch; 44 RELATIVE slots",
                "callers": "1 tail jump: CompositeEnvWrapper::IsInstanceOf tail-jumps to it",
            },
            "slot_17_wrapped": {
                "address": "0x5fcc3f0", "name": "returns *(this+0x20), the wrapped clock (C++ name open)",
                "algorithm": "mov 0x20(%rdi),%rax; ret (9 bytes); shared by the wrapper and emulated vtables",
                "posix_version": "PosixClock's slot 17 is 0x5d2ca00 (7 bytes: endbr64; xor %eax,%eax; ret), which returns null",
                "open": "its C++ name (it sits between IsInstanceOf and the secondary name in the vtable; in #3715's create-host dispatch the candidate is adopted when its slot-0x90 equals the default empty string)",
            },
            "slot_18_empty_string": {
                "address": "0x5d2ca10", "name": "returns empty string (C++ name open)",
                "algorithm": "endbr64; lea 0x4376fd,%rax; ret (12 bytes); shared by 45 vtables",
                "posix_version": "PosixClock's slot 18 is 0x5fe0ff0 (12 bytes: endbr64; lea 0x44768e,%rax; ret), which returns 'PosixClock'",
                "open": "its C++ name (the secondary name: PosixClock returns 'PosixClock', the wrapper returns '')",
            },
            "now_micros": {
                "address": "0x5d4d490", "name": "rocksdb::SystemClockWrapper::NowMicros",
                "algorithm": "the slot-19 chain-walk (see chain_walk): compare each level's slot-19 pointer against *(0x64ecf80) and call the first level that differs, or the 9th level unconditionally",
            },
            "now_nanos_forward": {
                "address": "0x5fcc340", "name": "forwards to wrapped slot 20 (NowNanos)",
                "algorithm": "mov 0x20(%rdi),%rdi; mov (%rdi),%rax; jmp *0xa0(%rax) (17 bytes)",
            },
            "cpu_micros_forward": {
                "address": "0x5fcc360", "name": "forwards to wrapped slot 21 (CPUMicros)",
                "algorithm": "mov 0x20(%rdi),%rdi; mov (%rdi),%rax; jmp *0xa8(%rax) (17 bytes)",
            },
            "cpu_nanos_forward": {
                "address": "0x5fcc380", "name": "forwards to wrapped slot 22 (CPUNanos)",
                "algorithm": "mov 0x20(%rdi),%rdi; mov (%rdi),%rax; jmp *0xb0(%rax) (17 bytes)",
            },
            "sleep_for_microseconds": {
                "address": "0x5dd41a0", "name": "rocksdb::SystemClockWrapper::SleepForMicroseconds",
                "algorithm": "the slot-23 chain-walk (see chain_walk): compare each level's slot-23 pointer against *(0x64ed5f8) and call the first level that differs, or the 9th level unconditionally",
            },
            "get_current_time": {
                "address": "0x5d4b100", "name": "GetCurrentTime (canonical chain-walk)",
                "algorithm": "by contract from #3352/#3322: the slot-24 chain-walk leaf; the canonical the walk compares against *(0x64ed3e8)",
            },
            "time_to_string": {
                "address": "0x5fcc3a0", "name": "rocksdb::SystemClockWrapper::TimeToString",
                "algorithm": "calls the wrapped clock's slot 25 with (Status-out, this) via call *0xc8(%rax) at 0x5fcc3c3",
            },
            "emulated_name": {
                "address": "0x60257a0", "name": "rocksdb::EmulatedSystemClock::Name",
                "algorithm": "endbr64; lea 0x4372ae,%rax; ret (12 bytes): returns 'TimeEmulatedSystemClock'",
            },
            "emulated_now_micros": {
                "address": "0x60259e0", "name": "rocksdb::EmulatedSystemClock::NowMicros",
                "algorithm": "flag +0x48 (movzbl 0x48(%rdi),%edx at 0x60259ea) set returns *(node+0x40) alone; otherwise calls the wrapped slot 19 (*0x98 at 0x60259f9) and adds *(node+0x40) (mov 0x40(%rbx),%rdx at 0x60259ff)",
            },
            "emulated_now_nanos": {
                "address": "0x60259a0", "name": "rocksdb::EmulatedSystemClock::NowNanos",
                "algorithm": "the same shape as NowMicros, but the emulated offset is scaled by 1000",
            },
            "emulated_cpu_micros": {
                "address": "0x6025a30", "name": "rocksdb::EmulatedSystemClock::CPUMicros",
                "algorithm": "lock addl $1,0x3c(%rdi), then forward to the wrapped slot 21 (22 bytes)",
            },
            "emulated_cpu_nanos": {
                "address": "0x6025a10", "name": "rocksdb::EmulatedSystemClock::CPUNanos",
                "algorithm": "lock addl $1,0x3c(%rdi), then forward to the wrapped slot 22 (22 bytes)",
            },
            "emulated_sleep": {
                "address": "0x6025b40", "name": "rocksdb::EmulatedSystemClock::SleepForMicroseconds",
                "algorithm": "lock addl $1,0x38(%rdi) at 0x6025b44, read the flags at +0x48/+0x49 (movzbl 0x48(%rdi),%eax at 0x6025b4f), lock add %rax,0x40(%rdi) at 0x6025b73 (the slept time accumulates into the emulated offset), then tail-jump to the wrapped slot 23 (*0xb8 at 0x6025b64)",
                "open": "the exact role of the +0x48/+0x49 flags in Sleep",
            },
            "emulated_get_current_time": {
                "address": "0x6025eb0", "name": "rocksdb::EmulatedSystemClock::GetCurrentTime",
                "algorithm": "the emulated GetCurrentTime (315 bytes): reads the emulated offset and the flags the same way slot 19 does and otherwise follows the wrapped slot 24",
            },
            "posix_name": {
                "address": "0x5fe0fe0", "name": "PosixClock::Name",
                "algorithm": "endbr64; lea 0x431007,%rax; ret (12 bytes): returns 'DefaultClock'",
            },
            "posix_slot_17_null": {
                "address": "0x5d2ca00", "name": "PosixClock slot 17: returns null (C++ name open)",
                "algorithm": "endbr64; xor %eax,%eax; ret (7 bytes); shared by 45 vtables",
            },
            "posix_slot_18": {
                "address": "0x5fe0ff0", "name": "PosixClock slot 18: returns PosixClock (C++ name open)",
                "algorithm": "endbr64; lea 0x44768e,%rax; ret (12 bytes): returns 'PosixClock'",
            },
            "posix_cpu_micros": {
                "address": "0x5fe1480", "name": "PosixClock::CPUMicros",
                "algorithm": "the PosixClock CPU-time read (100 bytes); the leaf the wrapper chain-walk lands on for slot 21",
            },
            "posix_cpu_nanos": {
                "address": "0x5fe1430", "name": "PosixClock::CPUNanos",
                "algorithm": "the PosixClock CPU-time read (76 bytes); the leaf the wrapper chain-walk lands on for slot 22",
            },
        },
        "constructors": {
            "ctor_c1": {
                "address": "0x5fd0090", "name": "rocksdb::SystemClockWrapper::SystemClockWrapper (C1)",
                "arguments": ["rdi = this (0x30)", "rsi = target shared_ptr", "rdx = config"],
                "algorithm": "installs the vtable (lea 0x64cdd78 at 0x5fd00af, the Itanium base; objects hold the stored pointer 0x64cdd88), zeroes the +0x08..+0x18 range, then calls 0x6099ce0 (0x5fd0124) with (this, an empty-string temp, the target, 0x6504b80)",
                "excerpt_credit": "re-shipped from open PR #3352 (vtable_install_1.txt), byte-identical to a fresh objdump run",
                "callers": "1 direct call site: EmulatedSystemClock::C1 (0x6029390) at 0x60293b6 — the only direct caller in .text",
            },
            "dtor_d0": {
                "address": "0x6029500", "name": "rocksdb::SystemClockWrapper::~SystemClockWrapper (D0)",
                "algorithm": "by contract from this cycle's analysis: deletes with size 0x30 and installs the base vtable 0x64d3420+0x10 mid-teardown; not a vtable slot of the wrapper (slots 0/1 are null), so it is cited here rather than excerpted",
                "emulated_dtors": "EmulatedSystemClock D1 0x6029110 (FDE 0x6029110..0x602922b, 283 bytes) and D0 0x6029620 (FDE 0x6029620..0x602973b, 283 bytes) install the wrapper vtable",
            },
        },
        "referenced_helpers": {
            "0x5fe2680": {
                "name": "PosixClock accessor (the default clock)",
                "fde": "0x5fe2680..0x5fe2756", "size_bytes": 214,
                "catalogue": "librocksdb-sys 0.11.0+8.1.1: _ZN7rocksdb12_GLOBAL__N_111PosixClock8InstanceEv (best-supported reading)",
                "direct_calls": 189,
                "role": "returns the process default PosixClock as a shared_ptr; called by PrepareOptions when the wrapper target is null and by 188 other sites that need the default clock",
            },
            "0x6095e70": {
                "name": "rocksdb::Configurable::PrepareOptions (base)",
                "fde": "0x6095e70..0x609661c", "size_bytes": 1964,
                "direct_calls": 8,
                "role": "the base PrepareOptions every Configurable subclass calls after installing its own target; called by the wrapper's slot 5 and by CompositeEnvWrapper, FileSystemWrapper, MockFileSystem, BlockBasedTableFactory, TtlMergeOperator, TtlCompactionFilter and TtlCompactionFilterFactory PrepareOptions",
            },
            "0x609de80": {
                "name": "rocksdb::Customizable::SerializeOptions (base)",
                "fde": "0x609de80..0x609e29e", "size_bytes": 1054,
                "direct_calls": 3,
                "role": "the base SerializeOptions the wrapper's slot 12 calls first; also called by CompositeEnvWrapper and FileSystemWrapper SerializeOptions",
            },
        },
        "literals": {
            "0x431007": "DefaultClock (PosixClock::Name)",
            "0x44768e": "PosixClock (PosixClock slot 18)",
            "0x4372ae": "TimeEmulatedSystemClock (EmulatedSystemClock::Name)",
            "0x4376fd": "empty string (wrapper slot 18, SerializeOptions)",
            "0x441b15": "id (AreEquivalent mismatch out string, SerializeOptions)",
            "0x6469": "the two bytes 'id' compared by GetOption (cmpw $0x6469 at 0x609d7b3)",
        },
        "open_unknowns": [
            "The C++ names of slots 4, 8, 17 and 18 (the empty-string, empty-Status, wrapped-clock and secondary-name slots). Configurable::GetOptionString 0x6098510 and Configurable::ToString 0x60971c0 are ruled out as slot-4/8 identities: their census VAs are not in this vtable.",
            "The exact container identity of the wrapper's +0x08..+0x18 range (zeroed by the ctor; the D0 destroys it as a vector of 0x30-byte elements with leading strings).",
            "How a bare wrapper answers GetId/GetOption('id') when its slot 14 (Name) is null.",
            "The exact branch outcome of the SerializeOptions IsInstanceOf compare against GOT 0x64eceb8, and the exact role of the emulated +0x48/+0x49 flags in Sleep.",
            "The full internals of the shared Configurable/Customizable base methods (slots 2, 3, 6, 7, 9, 10, 11, 13): pinned here by identity, entry contract and callees; their bodies are the Configurable component's own work.",
            "Why the wrapper vtable leaves slots 0, 1 and 14 null while EmulatedSystemClock and PosixClock fill all 26 slots.",
        ],
        "packet_internal_sites": {
            "0x6099030": [
                {"site": "0x609d78d", "kind": "direct_call", "containing_fde": ["0x609d760", "0x609d954"], "role": "GetOption's generic path for names other than 'id'"},
            ],
            "0x60996a0": [
                {"site": "0x609dd6e", "kind": "tail_jump", "containing_fde": ["0x609dc40", "0x609de39"], "role": "AreEquivalent's deeper check when the ids are equal and the config flag > 2"},
            ],
            "0x5d32940": [
                {"site": "0x5d32a47", "kind": "direct_call", "containing_fde": ["0x5d32a30", "0x5d32a51"], "role": "GetId builds the std::string from the Name() result"},
            ],
            "0x6099ce0": [
                {"site": "0x5fd0124", "kind": "direct_call", "containing_fde": ["0x5fd0090", "0x5fd0178"], "role": "the ctor's shared base/options initialiser"},
            ],
            "0x5d350c0": [
                {"site": "0x5fcf62e", "kind": "direct_call", "containing_fde": ["0x5fcf590", "0x5fcf658"], "role": "PrepareOptions releases the old +0x28 control block when the target is replaced"},
            ],
        },
        "vtables": vtables,
        "vtable_slot_owners": slot_owners,
        "census": census,
        "callers": callers,
    }


if __name__ == "__main__":
    sys.exit(main())

