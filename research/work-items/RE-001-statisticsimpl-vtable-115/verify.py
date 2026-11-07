"""Verify the RE-001-statisticsimpl-vtable-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-statisticsimpl-vtable-115/verify.py

Checks, in order (fails fast with a clear message):
  1. The target digest from provenance/artifacts.json.
  2. MANIFEST.sha256 covers every packet file and every hash matches.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump
     run on the real binary (this subsumes the re-ship check for
     the excerpts copied from #3902, #3396, #3392, #3362, #3378).
  4. Every instruction line in every excerpt matches the raw
     binary bytes at that address.
  5. Fixed spot instructions plus three seeded random gate spots
     (random.seed(20261107)) verify byte-for-byte, including two
     spots from the slot-0xc8 devirtualization host fragment
     (0x5e080f0), which is cited by contract, not excerpted.
  6. Every FDE range in frames.txt is present in a fresh readelf
     frame dump.
  7. Every RELATIVE record in relocations.txt is present in a
     fresh readelf -r dump.
  8. Every literal in records.json (strings, typeinfo names,
     format strings) reads back from the binary.
  9. The census reproduces: re-running census.py leaves
     callers.tsv and dispatch.tsv byte-identical, and the
     per-routine counts, site lists, qword hits and RELATIVE
     counts in records.json match it.
 10. The vtable slot table in vtables.tsv re-derives from
     relocations.txt, the boundary table re-derives from the
     model generator, and the model tables match it.
 11. The model tests pass (tests/test_statisticsimpl_vtable_115.py).

Exit 0 with ALL CHECKS PASSED, else exit 1.
"""

import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = {
    "stats_dtor.txt": (0x6070EA0, 0x607103C),
    "deleting-dtor-6071040.objdump.txt": (0x6071040, 0x607105B),
    "getoption-609d760.objdump.txt": (0x609D760, 0x609D954),
    "areequivalent-609dc40.objdump.txt": (0x609DC40, 0x609DE39),
    "slot04-emptystring-5d32560.objdump.txt": (0x5D32560, 0x5D3257B),
    "prepareoptions-base-6095e70.objdump.txt": (0x6095E70, 0x609661C),
    "validateoptions-6096790.objdump.txt": (0x6096790, 0x6096F0C),
    "getoptionsptr-5d2e090.objdump.txt": (0x5D2E090, 0x5D2E0DE),
    "slot08-emptystatus-60956f0.objdump.txt": (0x60956F0, 0x609570C),
    "configureoptions-609d0e0.objdump.txt": (0x609D0E0, 0x609D75E),
    "parseoption-60986b0.objdump.txt": (0x60986B0, 0x6098A9C),
    "optionsareequal-6095710.objdump.txt": (0x6095710, 0x609579A),
    "serializeoptions-base-609de80.objdump.txt": (0x609DE80, 0x609E29E),
    "getoptionname-609d980.objdump.txt": (0x609D980, 0x609DC18),
    "stats_name.txt": (0x606FA20, 0x606FA2C),
    "getid-5d32a30.objdump.txt": (0x5D32A30, 0x5D32A51),
    "isinstanceof-5d2e770.objdump.txt": (0x5D2E770, 0x5D2E832),
    "delegate_getter.txt": (0x606FA30, 0x606FA39),
    "slot18-emptystring-5d2ca10.objdump.txt": (0x5D2CA10, 0x5D2CA1C),
    "locked_ticker.txt": (0x6070490, 0x60704D2),
    "locked_percentiles.txt": (0x6070610, 0x60706C9),
    "locked_histogram_text.txt": (0x6070700, 0x60707C1),
    "record_tick.txt": (0x606FBA0, 0x606FC59),
    "set_ticker.txt": (0x6070DC0, 0x6070E9A),
    "get_reset_ticker.txt": (0x6070C50, 0x6070D92),
    "slot-c8-forwarder-5d48960.objdump.txt": (0x5D48960, 0x5D48979),
    "record_hist_devirt.txt": (0x606FFD0, 0x60700C4),
    "record_hist.txt": (0x606FEF0, 0x606FFCE),
    "reset_stats.txt": (0x6070B30, 0x6070C2A),
    "tostring.txt": (0x6070810, 0x6070AB5),
    "slotf0.txt": (0x6076030, 0x6076615),
    "hist_id_check.txt": (0x606FA40, 0x606FA4B),
    "stats_ctor.txt": (0x6071A00, 0x6071B60),
    "set_core.txt": (0x6070AC0, 0x6070B1B),
    "cpu_shard_pick.txt": (0x60D5CD0, 0x60D5CF0),
    "lcg_seed.txt": (0x61C4080, 0x61C4117),
    "mutex_lock.txt": (0x60D5230, 0x60D52C5),
    "mutex_unlock.txt": (0x60D52F0, 0x60D5385),
    "ticker_getter.txt": (0x6070430, 0x607047D),
    "histogram_builder.txt": (0x6070500, 0x60705D8),
    "hist_record.txt": (0x606B130, 0x606B1B3),
    "hist_record_thunk.txt": (0x606B1C0, 0x606B1CD),
    "hist_locked_init.txt": (0x606B0C0, 0x606B10A),
    "hist_bucket_index.txt": (0x606AFA0, 0x606B013),
    "hist_shared_init.txt": (0x606B020, 0x606B07C),
    "boundary_gen.txt": (0x606BF10, 0x606C134),
    "landing_pad.txt": (0x607047E, 0x607048E),
    "cleanup_a0.txt": (0x60705D8, 0x607060C),
    "cleanup_a8.txt": (0x60706CA, 0x60706FE),
    "set_cleanup.txt": (0x6070D92, 0x6070DB2),
    "reset_cleanup.txt": (0x6070B1C, 0x6070B2E),
    "reset_cleanup2.txt": (0x6070C2A, 0x6070C4A),
}

# (address, mnemonic text that must appear on that line)
SPOTS = [
    (0x6070EA0, "endbr64"),
    (0x6070EB5, "lea"),
    (0x6070F06, "cmp"),
    (0x6070F35, "call"),
    (0x6071040, "endbr64"),
    (0x6071048, "call"),
    (0x6071050, "mov"),
    (0x609D760, "endbr64"),
    (0x609D797, "sub"),
    (0x609D7AA, "mov"),
    (0x609DC40, "endbr64"),
    (0x5D32560, "endbr64"),
    (0x5D32564, "lea"),
    (0x5D32568, "movq"),
    (0x5D3257A, "ret"),
    (0x6095E70, "endbr64"),
    (0x6096790, "endbr64"),
    (0x5D2E090, "endbr64"),
    (0x60956F0, "endbr64"),
    (0x609D0E0, "endbr64"),
    (0x60986B0, "endbr64"),
    (0x6095710, "endbr64"),
    (0x609DE80, "endbr64"),
    (0x609E0A9, "call"),
    (0x609D980, "endbr64"),
    (0x606FA20, "endbr64"),
    (0x606FA24, "lea"),
    (0x5D32A30, "endbr64"),
    (0x5D2E770, "endbr64"),
    (0x5D2E792, "call"),
    (0x5D2E7EE, "call"),
    (0x606FA30, "endbr64"),
    (0x606FA34, "mov"),
    (0x5D2CA10, "endbr64"),
    (0x5D2CA14, "lea"),
    (0x6070490, "endbr64"),
    (0x60704A4, "call"),
    (0x60704AE, "call"),
    (0x6070610, "endbr64"),
    (0x607063E, "call"),
    (0x607065B, "call"),
    (0x6070700, "endbr64"),
    (0x607072E, "call"),
    (0x607074B, "call"),
    (0x606FBA0, "endbr64"),
    (0x606FBA4, "movzbl"),
    (0x606FBC4, "call"),
    (0x606FBF1, "lock add"),
    (0x606FC0A, "mov"),
    (0x606FC11, "jmp"),
    (0x606FC20, "call"),
    (0x606FC31, "imul"),
    (0x6070DC0, "endbr64"),
    (0x6070DDD, "call"),
    (0x6070DEA, "call"),
    (0x6070DF2, "call"),
    (0x6070E12, "mov"),
    (0x6070E32, "call"),
    (0x6070E61, "jmp"),
    (0x6070C50, "endbr64"),
    (0x6070C6A, "call"),
    (0x6070C96, "xchg"),
    (0x6070CBA, "call"),
    (0x6070D04, "call"),
    (0x6070D5D, "call"),
    (0x5D48960, "endbr64"),
    (0x5D48964, "movzbl"),
    (0x5D4896A, "jbe"),
    (0x5D4896C, "mov"),
    (0x5D4896F, "jmp"),
    (0x606FFD0, "endbr64"),
    (0x606FFEB, "mov"),
    (0x606FFF5, "jne"),
    (0x6070078, "mov"),
    (0x607007F, "jmp"),
    (0x606FEF4, "movzbl"),
    (0x606FEF8, "cmp"),
    (0x606FF0C, "call"),
    (0x606FF52, "call"),
    (0x606FF5A, "cmp"),
    (0x606FF77, "jmp"),
    (0x6070B30, "endbr64"),
    (0x6070B58, "call"),
    (0x6070B67, "call"),
    (0x6070BB4, "call"),
    (0x6070BF3, "movl"),
    (0x6070810, "endbr64"),
    (0x6076030, "endbr64"),
    (0x606FA40, "endbr64"),
    (0x606FA44, "cmp"),
    (0x6071A00, "endbr64"),
    (0x6071A32, "movb"),
    (0x6071A58, "mov"),
    (0x6071A7C, "call"),
    (0x6071AF1, "call"),
    (0x6070AC0, "endbr64"),
    (0x6070AD1, "xchg"),
    (0x6070AFD, "xchg"),
    (0x60D5CD0, "endbr64"),
    (0x60D5CD7, "cpuid"),
    (0x60D5CE9, "shr"),
    (0x61C4080, "endbr64"),
    (0x61C40D5, "mov"),
    (0x61C40E6, "call"),
    (0x61C410A, "mov"),
    (0x60D5230, "endbr64"),
    (0x60D524A, "call"),
    (0x60D52F0, "endbr64"),
    (0x60D530A, "call"),
    (0x6070430, "endbr64"),
    (0x6070500, "endbr64"),
    (0x606B130, "endbr64"),
    (0x606B147, "call"),
    (0x606B151, "mov"),
    (0x606B180, "imul"),
    (0x606B1C0, "endbr64"),
    (0x606B0C0, "endbr64"),
    (0x606AFA0, "endbr64"),
    (0x606AFB8, "cmp"),
    (0x606B020, "endbr64"),
    (0x606B024, "mov"),
    (0x606BF10, "endbr64"),
    (0x606BF43, "call"),
    (0x606BF85, "mulsd"),
    (0x607047E, "mov"),
    (0x60705D8, "mov"),
    (0x60706CA, "mov"),
    (0x6070D92, "mov"),
    (0x6070B1C, "mov"),
    (0x6070C2A, "mov"),
]

# Spots in the slot-0xc8 devirtualization host fragment (0x5e080f0),
# cited by contract in records.json, not excerpted. Checked against
# a fresh objdump run on the host FDE range.
HOST_SPOTS = [
    (0x5E08495, "lea"),
    (0x5E084A3, "cmp"),
    (0x5E084BA, "call"),
    (0x5E084F1, "call"),
]

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )*[0-9a-f]{2})(?:\s*\t| *$)")


def fail(message):
    print("FAIL: " + message)
    sys.exit(1)


def load_segments(data):
    """(vaddr, file offset, file size) for PT_LOAD segments."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz,
         _memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            out.append((p_vaddr, p_offset, p_filesz))
    return out


def va_to_off(segments, va):
    for vaddr, offset, filesz in segments:
        if vaddr <= va < vaddr + filesz:
            return va - vaddr + offset
    fail("address %#x not in a file-backed segment" % va)


def main():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())

    # 1. Target digest.
    artifacts = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    digest = None
    for entry in artifacts["files"]:
        if entry["path"] == "artifacts/node/115/hl-node":
            digest = entry["sha256"]
    if digest != TARGET_SHA256:
        fail("provenance digest mismatch: %r" % digest)
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        fail("binary digest mismatch")
    print("digest OK")

    # 2. Manifest.
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest_hex, name = line.split(None, 1)
        manifest[name.strip()] = digest_hex
    packet_files = sorted(p.name for p in PACKET.iterdir()
                          if p.is_file() and p.name != "MANIFEST.sha256")
    if sorted(manifest) != packet_files:
        fail("manifest file list mismatch: %s vs %s"
             % (sorted(manifest), packet_files))
    for name, digest_hex in manifest.items():
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest_hex:
            fail("manifest hash mismatch for %s" % name)
    print("manifest OK (%d files)" % len(manifest))

    # 3 + 4. Excerpt regeneration and raw bytes.
    all_lines = []  # (address, bytes, text) for the random gate spots
    for name, (start, stop) in sorted(WINDOWS.items()):
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if text != stored:
            fail("excerpt %s differs from a fresh objdump run" % name)
        for line in stored.splitlines():
            match = LINE_RE.match(line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            raw = bytes(int(b, 16) for b in match.group(2).split())
            off = va_to_off(segments, addr)
            if data[off:off + len(raw)] != raw:
                fail("excerpt %s line %#x bytes mismatch" % (name, addr))
            all_lines.append((addr, raw, line))
    print("excerpts OK (%d windows, %d instruction lines byte-checked)"
          % (len(WINDOWS), len(all_lines)))

    # 5. Fixed spots + three seeded random gate spots + host spots.
    by_addr = {addr: line for addr, _raw, line in all_lines}
    for addr, mnemonic in SPOTS:
        if addr not in by_addr or mnemonic not in by_addr[addr]:
            fail("spot %#x (%s) not found" % (addr, mnemonic))
    rng = random.Random(20261107)
    chosen = rng.sample(all_lines, 3)
    for addr, raw, line in chosen:
        off = va_to_off(segments, addr)
        if data[off:off + len(raw)] != raw:
            fail("random gate spot %#x bytes mismatch" % addr)
    host_text = subprocess.run(
        ["objdump", "-d", "--start-address=0x5e080f0",
         "--stop-address=0x5e095ed", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    host_lines = {}
    for line in host_text.splitlines():
        match = LINE_RE.match(line)
        if match:
            host_lines[int(match.group(1), 16)] = line
    for addr, mnemonic in HOST_SPOTS:
        if addr not in host_lines or mnemonic not in host_lines[addr]:
            fail("host spot %#x (%s) not found" % (addr, mnemonic))
    print("spots OK (%d fixed + 3 random: %s + %d host)"
          % (len(SPOTS),
             ", ".join("%#x" % addr for addr, _r, _l in chosen),
             len(HOST_SPOTS)))

    # 6. Frames.
    frames_text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line.strip() and line.strip() not in frames_text:
            fail("frames.txt line missing from fresh readelf: %s" % line)
    print("frames OK")

    # 7. Relocations.
    reloc_text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if line.strip() and line.strip() not in reloc_text:
            fail("relocations.txt line missing from fresh readelf: %s" % line)
    print("relocations OK")

    # 8. Literals.
    literals = records["literals"]

    def read_cstr(addr):
        off = va_to_off(segments, addr)
        end = data.find(b"\x00", off)
        return data[off:end].decode()

    for section in ("strings", "typeinfo_names", "format_strings"):
        for addr_hex, want in literals[section].items():
            got = read_cstr(int(addr_hex, 16))
            if got != want:
                fail("%s at %s: got %r, want %r"
                     % (section, addr_hex, got, want))
    print("literals OK")

    # 9. Census reproduction.
    before_callers = (PACKET / "callers.tsv").read_bytes()
    before_dispatch = (PACKET / "dispatch.tsv").read_bytes()
    subprocess.run([sys.executable, str(PACKET / "census.py")],
                   capture_output=True, text=True, check=True, cwd=ROOT)
    after_callers = (PACKET / "callers.tsv").read_bytes()
    after_dispatch = (PACKET / "dispatch.tsv").read_bytes()
    if before_callers != after_callers:
        fail("census.py did not reproduce callers.tsv")
    if before_dispatch != after_dispatch:
        fail("census.py did not reproduce dispatch.tsv")
    rows = {}
    for line in after_callers.decode().splitlines()[1:]:
        if not line.strip():
            continue
        site, target, _caller, kind = line.split("\t")
        rows.setdefault(target, {"call": [], "tail jump": [], "lea": []})
        rows[target][kind].append(site)
    census = records["census"]
    # RELATIVE map and qword hits, recomputed from the binary.
    rela_off, rela_size = 0x6BE8, 0x163CC8
    rel_map = {}
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel_map.setdefault(add, []).append(ro)
    for target_hex, entry in census.items():
        target = int(target_hex, 16)
        got = rows.get(target_hex, {"call": [], "tail jump": [], "lea": []})
        for kind in ("calls", "jumps", "leas"):
            want = entry.get(kind)
            if want is None:
                continue
            key = {"calls": "call", "jumps": "tail jump",
                   "leas": "lea"}[kind]
            if len(got[key]) != want:
                fail("census %s %s: got %d, want %d"
                     % (target_hex, kind, len(got[key]), want))
        for key, want_key in (("call_sites", "call"),
                              ("jump_sites", "tail jump"),
                              ("lea_sites", "lea")):
            if key in entry:
                want = entry[key]
                if sorted(got[want_key]) != sorted(want):
                    fail("census %s %s mismatch: %r vs %r"
                         % (target_hex, key, got[want_key], want))
        needle = struct.pack("<Q", target)
        qw = 0
        pos = data.find(needle)
        while pos != -1:
            if pos % 8 == 0:
                qw += 1
            pos = data.find(needle, pos + 1)
        if qw != entry["qwords"]:
            fail("census %s qwords: got %d, want %d"
                 % (target_hex, qw, entry["qwords"]))
        rel_slots = rel_map.get(target, [])
        if len(rel_slots) != entry["relative"]:
            fail("census %s relative: got %d, want %d"
                 % (target_hex, len(rel_slots), entry["relative"]))
        if "relative_slots" in entry:
            want = sorted(int(x, 16) for x in entry["relative_slots"])
            if sorted(rel_slots) != want:
                fail("census %s relative slots mismatch" % target_hex)
    drows = {}
    for line in after_dispatch.decode().splitlines()[1:]:
        if not line.strip():
            continue
        _site, _tgt, slot, _caller = line.split("\t")
        drows[slot] = drows.get(slot, 0) + 1
    for slot_hex, entry in records["dispatch"].items():
        got = drows.get(slot_hex, 0)
        if got != entry["count"]:
            fail("dispatch slot %s: got %d, want %d"
                 % (slot_hex, got, entry["count"]))
    print("census OK")

    # 10. Vtable slots re-derived.
    reloc_map = {}
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        match = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if match:
            reloc_map[int(match.group(1), 16)] = int(match.group(2), 16)
    tables = {}
    for line in (PACKET / "vtables.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        _v, _ptr, _ti, slot, target = line.split("\t")
        tables[int(slot, 16)] = int(target, 16)
    if len(tables) != 32:
        fail("vtables.tsv does not hold 32 slots")
    base = int(records["statistics_impl_vtable"]["base"], 16)
    for slot, want in tables.items():
        got = reloc_map.get(base + slot)
        if got != want:
            fail("vtable slot %#x: got %#x, want %#x"
                 % (slot, got if got else -1, want))
    stats = records["statistics_impl_vtable"]
    for slot_hex, entry in stats["slots"].items():
        slot = int(slot_hex, 16)
        want = int(entry["target"], 16)
        got = reloc_map.get(base + slot)
        if got != want:
            fail("StatisticsImpl slot %s: got %#x, want %#x"
                 % (slot_hex, got if got else -1, want))
    for base_hex, entry in records["following_vtables"]["tables"].items():
        fbase = int(base_hex, 16)
        want_ti = int(entry["typeinfo"], 16)
        got_ti = reloc_map.get(fbase - 8)
        if got_ti != want_ti:
            fail("following vtable %s typeinfo: got %#x, want %#x"
                 % (base_hex, got_ti if got_ti else -1, want_ti))
        for i, slot_hex in enumerate(entry["first_slots"]):
            want = int(slot_hex, 16)
            got = reloc_map.get(fbase + i * 8)
            if got != want:
                fail("following vtable %s slot %d: got %#x, want %#x"
                     % (base_hex, i, got if got else -1, want))
    # Model tables match the packet.
    sys.path.insert(0, str(ROOT / "tools"))
    import statisticsimpl_vtable_115 as model
    if model.SLOT_TARGETS != tables:
        fail("model vtable slot map mismatch")
    for slot_hex, entry in records["dispatch"].items():
        if model.DISPATCH_SITES[int(slot_hex, 16)] != entry["count"]:
            fail("model dispatch count mismatch for slot %s" % slot_hex)
    for target_hex, count in records["shared_slot_vtable_counts"].items():
        if model.SHARED_SLOT_VTABLE_COUNTS[int(target_hex, 16)] != count:
            fail("model shared-slot count mismatch for %s" % target_hex)
    bounds = records["boundaries"]
    if len(model.BOUNDARIES) != bounds["count"]:
        fail("boundary count: got %d, want %d"
             % (len(model.BOUNDARIES), bounds["count"]))
    if model.BOUNDARIES[:len(bounds["first"])] != bounds["first"]:
        fail("boundary head mismatch")
    if model.BOUNDARIES[-1] != bounds["last"]:
        fail("boundary ceiling mismatch")
    for key, want in bounds["spot"].items():
        idx = int(key[1:])
        if model.BOUNDARIES[idx] != want:
            fail("boundary %s: got %d, want %d"
                 % (key, model.BOUNDARIES[idx], want))
    print("records re-derived OK")

    # 11. Model tests.
    result = subprocess.run(
        [sys.executable,
         str(ROOT / "tests" / "test_statisticsimpl_vtable_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print("model tests OK: " + result.stdout.strip().splitlines()[0])

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
