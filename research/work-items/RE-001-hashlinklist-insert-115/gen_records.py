"""Generate records.json, callers.tsv, relocations.txt and vtables.tsv.

Run from the repository root:
    python3 research/work-items/RE-001-hashlinklist-insert-115/gen_records.py

Derives everything from the digest-verified work binary:
- runs census.py and parses its canonical output;
- maps every call/tail-jump site to its containing FDE (from a fresh
  objdump --dwarf=frames dump) and verifies the site is a real
  call/jmp to the target in objdump output of that FDE;
- resolves the HashLinkListRep / HashLinkListRepFactory /
  InternalKeySliceTransform vtable and typeinfo slots from .rela.dyn
  R_X86_64_RELATIVE entries;
- reads the literal strings the packet relies on.
Writes the four generated files next to this script.
"""

import hashlib
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

TARGETS = [
    ("host", 0x605F700),
    ("host_cleanup", 0x605F6D6),
    ("ctor", 0x605EB40),
    ("dtor", 0x605EA00),
    ("varint32", 0x61BD4F0),
    ("transform", 0x5E9AF30),
    ("hash64", 0x61C38A0),
    ("hex_encode", 0x61C7E30),
    ("index_builder", 0x605F290),
    ("index_insert", 0x605F340),
    ("log_gate", 0x5FCEF60),
]

# RELATIVE slots whose addends this packet relies on.
RELOC_SLOTS = [
    0x64D2160,  # HashLinkListRep vtable: typeinfo -> 0x64d2050
    0x64D2168, 0x64D2170, 0x64D2178, 0x64D2180, 0x64D2188, 0x64D2190,
    0x64D2198, 0x64D21A0, 0x64D21A8, 0x64D21B0, 0x64D21B8, 0x64D21C0,
    0x64D21C8, 0x64D21D0, 0x64D21D8, 0x64D21E0, 0x64D21E8, 0x64D21F0,
    0x64D21F8, 0x64D2200, 0x64D2208, 0x64D2210, 0x64D2218,  # 23 slots
    0x64D2058,  # HashLinkListRep typeinfo +0x8: name -> 0x974fe0
    0x64D2228,  # HashLinkListRepFactory vtable: typeinfo -> 0x64d2068
    0x64D2230, 0x64D2238, 0x64D2240, 0x64D2248, 0x64D2250, 0x64D2258,
    0x64D2260, 0x64D2268, 0x64D2270, 0x64D2278, 0x64D2280, 0x64D2288,
    0x64D2290, 0x64D2298, 0x64D22A0, 0x64D22A8, 0x64D22B0, 0x64D22B8,
    0x64D22C0, 0x64D22C8, 0x64D22D0, 0x64D22D8, 0x64D22E0,  # 23 slots
    0x64D2070,  # HashLinkListRepFactory typeinfo +0x8: name -> 0x975020
    0x64D3BB8,  # InternalKeySliceTransform vtable: typeinfo -> 0x64d3ae0
    0x64D3BC0, 0x64D3BC8, 0x64D3BD0, 0x64D3BD8, 0x64D3BE0, 0x64D3BE8,
    0x64D3BF0, 0x64D3BF8, 0x64D3C00, 0x64D3C08, 0x64D3C10, 0x64D3C18,
    0x64D3C20, 0x64D3C28, 0x64D3C30, 0x64D3C38, 0x64D3C40, 0x64D3C48,
    0x64D3C50, 0x64D3C58, 0x64D3C60, 0x64D3C68,  # 22 slots
    0x64D3AE8,  # InternalKeySliceTransform typeinfo +0x8: name -> 0x979d80
    0x64ED690,  # GOT slot holding 0x5e9af30 (canonical-transform identity)
]

WINDOWS = {
    "host": ("0x605f700", "0x605fe21", "host-605f700.objdump.txt", "0075a430"),
    "host_cleanup": ("0x605f6d6", "0x605f700", "host-cleanup-605f6d6.objdump.txt", "0075a484"),
    "ctor": ("0x605eb40", "0x605ec19", "ctor-605eb40.objdump.txt", "0075a348"),
    "dtor": ("0x605ea00", "0x605ea23", "dtor-605ea00.objdump.txt", "00367960"),
    "varint32": ("0x61bd4f0", "0x61bd53b", "varint32-61bd4f0.objdump.txt", "0037652c"),
    "transform": ("0x5e9af30", "0x5e9b142", "transform-5e9af30.objdump.txt", "00354dfc"),
    "hash64": ("0x61c38a0", "0x61c3bb9", "wyhash-61c38a0.objdump.txt", "00376e1c"),
    "hex_encode": ("0x61c7e30", "0x61c7fb6", "hex-encode-61c7e30.objdump.txt", "0076c584"),
    "index_builder": ("0x605f290", "0x605f33a", "index-builder-605f290.objdump.txt", "00367b98"),
    "index_insert": ("0x605f340", "0x605f6d5", "index-insert-605f340.objdump.txt", "00367bb4"),
    "log_gate": ("0x5fcef60", "0x5fcf043", "log-gate-5fcef60.objdump.txt", "00362334"),
}


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def run_census():
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py"), BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = {}
    current = None
    for line in out.splitlines():
        m = re.match(r"target (0x[0-9a-f]+)", line)
        if m:
            current = m.group(1)
            blocks[current] = {}
            continue
        m = re.match(r"  direct calls: (.*)", line)
        if m and current:
            blocks[current]["direct_calls"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  tail jumps: (.*)", line)
        if m and current:
            blocks[current]["tail_jumps"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  qword hits \(file offsets\): (.*)", line)
        if m and current:
            blocks[current]["qword_hits_file_offsets"] = [] if m.group(1) == "(none)" else m.group(1).split()
        m = re.match(r"  RELATIVE slots: (.*)", line)
        if m and current:
            blocks[current]["relative_slots"] = [] if m.group(1) == "(none)" else m.group(1).split()
    return blocks


def fde_map():
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for line in frames.splitlines():
        m = re.search(r"FDE .*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def containing_fde(fdes, va):
    for start, end in fdes:
        if start <= va < end:
            return (start, end)
    return None


def verify_sites(fdes, sites):
    """sites: list of (site_va, target_va, kind). Returns rows with FDEs."""
    by_fde = {}
    for site, target, kind in sites:
        fde = containing_fde(fdes, site)
        key = fde if fde else ("window", site)
        by_fde.setdefault(key, []).append((site, target, kind))
    rows = []
    for key, group in sorted(by_fde.items(), key=lambda kv: kv[1][0][0]):
        if key[0] == "window":
            site = key[1]
            start, stop = site - 0x20, site + 0x20
            fde_label = "none"
        else:
            start, stop = key
            fde_label = "0x%x..0x%x" % key
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=" + hex(start), "--stop-address=" + hex(stop), BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        for site, target, kind in group:
            want = "call" if kind == "call" else "jmp"
            pat = re.compile(r"^\s*%x:\t[0-9a-f ]+\t%s\s+%x\b" % (site, want, target), re.M)
            if not pat.search(out):
                fail("site 0x%x not a %s to 0x%x in objdump of %s"
                     % (site, want, target, fde_label))
            rows.append({
                "site": "0x%x" % site,
                "target": "0x%x" % target,
                "kind": kind,
                "fde": fde_label,
            })
    rows.sort(key=lambda r: (int(r["target"], 16), int(r["site"], 16)))
    return rows


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    blocks = run_census()
    fdes = fde_map()
    census = {}
    sites = []
    for name, target in TARGETS:
        got = blocks.get(hex(target))
        if got is None:
            fail("census missing target 0x%x" % target)
        census[hex(target)] = got
        for s in got["direct_calls"]:
            sites.append((int(s, 16), target, "call"))
        for s in got["tail_jumps"]:
            sites.append((int(s, 16), target, "tail"))
    rows = verify_sites(fdes, sites)
    print("verified %d call sites" % len(rows))
    RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
    relocs = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if ro in RELOC_SLOTS and (info & 0xFFFFFFFF) == 8:
            relocs[ro] = add
    for slot in RELOC_SLOTS:
        if slot not in relocs:
            fail("missing RELATIVE entry for slot 0x%x" % slot)
    entries = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        entries[RELA_OFF + k * 24 + 16] = (ro, add)
    hit_notes = {}
    for name, target in TARGETS:
        for h in blocks[hex(target)]["qword_hits_file_offsets"]:
            off = int(h, 16)
            if off in entries:
                ro, add = entries[off]
                hit_notes[h] = ("rela-addend field of entry at 0x%x "
                                "(slot 0x%x, addend 0x%x)" % (off - 16, ro, add))
            else:
                hit_notes[h] = "unclassified qword hit (not a RELATIVE addend field)"
    secs = {}
    out = subprocess.run(["readelf", "-S", "-W", os.path.join(ROOT, BIN)],
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            secs[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16),
                                int(m.group(4), 16))

    def read_vaddr(addr, n):
        for v, o, s in secs.values():
            if v <= addr < v + s:
                return data[o + (addr - v): o + (addr - v) + n]
        raise ValueError("address %#x not in any section" % addr)

    def cstr(va):
        out = bytearray()
        cur = va
        while True:
            b = read_vaddr(cur, 1)[0]
            if b == 0:
                return bytes(out).decode("latin1")
            out.append(b)
            cur += 1

    rep_name = cstr(relocs[0x64D2058])
    factory_name = cstr(relocs[0x64D2070])
    ikst_name = cstr(relocs[0x64D3AE8])
    log_fmt = cstr(0x9638E8)
    if log_fmt != ("HashLinkedList bucket %zu has more than %d entries. "
                   "Key to insert: %s"):
        fail("log format literal mismatch: %r" % log_fmt)
    factory_nick = cstr(0x4394CC)
    if factory_nick != "hash_linkedlist":
        fail("factory nickname literal mismatch: %r" % factory_nick)
    # vtable slot tables
    rep_slots = []
    for off in range(0x00, 0xB8, 0x08):
        slot = 0x64D2168 + off
        rep_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                          "target": "0x%x" % relocs[slot]})
    factory_slots = []
    for off in range(0x00, 0xB8, 0x08):
        slot = 0x64D2230 + off
        factory_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                              "target": "0x%x" % relocs[slot]})
    ikst_slots = []
    for off in range(0x00, 0xB0, 0x08):
        slot = 0x64D3BC0 + off
        ikst_slots.append({"offset": "0x%02x" % off, "slot": "0x%x" % slot,
                           "target": "0x%x" % relocs[slot]})
    records = {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "bounded_question": (
            "How does HashLinkListRep's slot-0x08 method insert one key "
            "record: decoding its key, running the transform chain, "
            "hashing to a bucket, and splicing it into the bucket's "
            "ordered chain, with sub-index conversion and the "
            "bucket-too-full log?"),
        "windows": {
            name: {"start": s, "end": e, "file": f, "fde_offset": fo}
            for name, (s, e, f, fo) in WINDOWS.items()
        },
        "census": census,
        "census_notes": {
            "method": ("per-byte .text scan for e8/e9 with rel32 targets, "
                       "whole-file qword search, .rela.dyn parse; every "
                       "call/tail site re-verified in objdump output of "
                       "its containing FDE (see callers.tsv)"),
            "qword_hit_classification": hit_notes,
            "host_no_direct_calls": (
                "the host 0x605f700 has no direct call or tail-jump site: "
                "it is reached only through the HashLinkListRep vtable "
                "slot 0x08 (RELATIVE at 0x64d2170)"),
            "ctor_no_direct_calls": (
                "the ctor 0x605eb40 has no direct call or tail-jump site: "
                "it is reached only through the HashLinkListRepFactory "
                "vtable slot 0x98 (RELATIVE at 0x64d22c8)"),
            "transform_no_direct_calls": (
                "the canonical transform 0x5e9af30 has no direct call or "
                "tail-jump site: it is reached only through the "
                "InternalKeySliceTransform vtable slot 0x98 (RELATIVE at "
                "0x64d3c58) and the GOT self-reference at 0x64ed690"),
            "varint32_shared": (
                "the varint32 decoder 0x61bd4f0 has 149 direct callers; "
                "it is the general varint32 reader, pinned here because "
                "the host decodes the record's key length through it"),
            "hash64_shared": (
                "the hash 0x61c38a0 has 18 direct callers plus one tail "
                "jump; it is the general 64-bit key hash, pinned here "
                "because the host hashes the transformed key through it"),
            "hex_encode_shared": (
                "the hex encoder 0x61c7e30 has 120 direct callers; it "
                "is the general hex renderer, pinned here because the "
                "host's log path renders the key through it"),
        },
        "host_behavior": {
            "fde": "0x605f700..0x605fe21",
            "vtable": "0x64d2168 (HashLinkListRep, typeinfo 0x64d2050)",
            "vtable_slot": "0x08 (RELATIVE at 0x64d2170)",
            "typeinfo_name": rep_name,
            "signature": "insert(HashLinkListRep *this, record *arg2)",
            "record_layout": {
                "+0x00": "next pointer (written by the host)",
                "+0x08": "varint32 key-length followed by the key bytes",
            },
            "this_fields": {
                "+0x08": "allocator (its vtable slot 0x18 allocates)",
                "+0x10": "bucket count (u64)",
                "+0x18": "bucket-head array (u64*)",
                "+0x20": "sub-index convert threshold (u32, clamped to >= 3 by the ctor)",
                "+0x28": "transform-chain head (InternalKeySliceTransform chain via +0x20)",
                "+0x30": "key object (slot 0x08 record/record compare; slot 0x10 record/slice compare; passed to the index builder)",
                "+0x38": "logger object passed to the log gate",
                "+0x40": "log threshold (u32): <= 0 disables the log; the log fires when the pre-insert chain count equals it",
            },
            "steps": [
                "decode the key length: if the byte at arg2+0x08 has its high bit clear it IS the length and rdx = arg2+0x09; else decode_varint32 0x61bd4f0(arg2+0x08, arg2+0x0d, out) and rdx = the end pointer; on decode failure rdx = 0 and the length stays 0 (the out slot was pre-zeroed)",
                "run the key (ptr, len) through the transform chain at *(this+0x28): the host unrolls 13 hops, checking each node's vtable slot 0x98 against the canonical 0x5e9af30 and calling the first differing slot with the pair (ptr, len - 8*(k+1)); if all 13 match it calls the 13th node's slot with (ptr, len - 104); the canonical callee 0x5e9af30 advances one node and repeats with len - 8 per hop (up to 9 hops per call)",
                "hash the transformed key via 0x61c38a0(ptr, len); bucket = (bucket_count * hash) >> 64 (128-bit multiply-high); bucket head = *(*(this+0x18) + bucket*8)",
                "if the bucket head is null: *(arg2) = 0 and the bucket head becomes arg2 (bare key node)",
                "if the head's next is null: allocate a 0x10-byte count node via the allocator's slot 0x18 (count 1), link it as the bucket head over the old head, and continue with it as the current node",
                "if *(current) == current: the node is a sub-index node: increment its +0x08 count and insert arg2's key into its embedded 0x38-byte index at +0x10 via 0x605f340(index, &(arg2+0x08)); return",
                "otherwise (plain chain head): if *(this+0x40) > 0 and the head's count equals *(this+0x40), run the log path (below); if the count equals *(this+0x20), run the convert path (below); else increment the count and walk the chain from *(head): compare each node's key record against the decoded key via the key object's slot 0x10, splicing arg2 before the first node that compares >= 0 (or at the end when the chain runs out): *(arg2) = that node and the previous node's next (or *(head) when there is no previous node) becomes arg2",
            ],
            "log_path": [
                "re-decode the key length (same fast path / 0x61bd4f0 call as step 1)",
                "hex-encode the decoded key bytes into a stack std::string via 0x61c7e30(out, &slice, flag 1) (UPPERCASE hex)",
                "re-hash the transformed key via 0x61c38a0 and recompute the bucket index by multiply-high",
                "log via 0x5fcef60(logger, 'HashLinkedList bucket %zu has more than %d entries. Key to insert: %s', bucket, count, hex)",
                "destroy the stack string (SSO check, heap free when needed) and continue to the convert check; the landing-pad cleanup 0x605f6d6 disposes the same string on unwind",
            ],
            "convert_path": [
                "allocate a 0x48-byte block via the allocator's slot 0x18; *(block) = block (the self-loop marker); *(block+0x08) = old count + 1",
                "build the 0x38-byte index at block+0x10 via 0x605f290(index, *(this+0x30), count=0xc, arena=*(this+0x08), divisor=4)",
                "insert every existing chain node's key record via 0x605f340(index, &(node+0x08)), then insert arg2's key via 0x605f340(index, &(arg2+0x08))",
                "store the block as the bucket head and return",
            ],
            "return": "no meaningful return value is read by any caller in the binary; the effect is the record's linkage (and *(arg2) in the chain paths)",
            "sibling_slots_same_vtable": {
                "0x90": "0x605feb0 (index rebuild + chain-length histogram + log report; open PR #3575)",
                "0x98": "0x605ec20 (builds a 0x30-byte object, vtable 0x64d20f8; separate work item)",
                "0x48": "0x60602c0",
                "0x60": "0x6060580",
            },
        },
        "ctor_behavior": {
            "fde": "0x605eb40..0x605ec19",
            "factory_vtable": "0x64d2230 (HashLinkListRepFactory, typeinfo 0x64d2068)",
            "factory_vtable_slot": "0x98 (RELATIVE at 0x64d22c8)",
            "typeinfo_name": factory_name,
            "factory_name_literal": "HashLinkListRepFactory (0x43a3e1, slot 0x70 target 0x605ea40)",
            "factory_nickname_literal": "hash_linkedlist (0x4394cc, slot 0x90 target 0x605ea50)",
            "signature": "new_rep(params *cfg, key_obj, allocator, transform_chain_head, arg5)",
            "params_struct": {
                "+0x20": "bucket count (u64)",
                "+0x28": "convert threshold (u32, clamped to >= 3)",
                "+0x30": "qword passed as arg3 to the allocator's slot 0x18 when allocating the bucket array",
                "+0x38": "log threshold (u32) -> this+0x40",
                "+0x3c": "flag byte -> this+0x44",
            },
            "fields": {
                "+0x00": "vtable 0x64d2168",
                "+0x08": "allocator (3rd arg)",
                "+0x10": "bucket count",
                "+0x18": "bucket array (bucket_count*8 bytes via the allocator's slot 0x18, zeroed)",
                "+0x20": "max(params+0x28, 3)",
                "+0x28": "transform-chain head (4th arg)",
                "+0x30": "key object (2nd arg)",
                "+0x38": "arg5 (5th arg)",
                "+0x40": "params+0x38 (u32)",
                "+0x44": "params+0x3c (byte)",
            },
            "return": "the new 0x48-byte object (rax = rbx)",
            "allocation_failure": "bucket counts with bits above bit 60 raise bad_array_new_length via 0x605eb16",
        },
        "dtor_behavior": {
            "fde": "0x605ea00..0x605ea23",
            "vtable_slot": "0x00 (RELATIVE at 0x64d2168)",
            "steps": [
                "load the allocator at this+0x08, call its slot 0x18 with (size = *(rsi)+0x10, 0, 0) and store the returned block+0x08 into *(rdx)",
            ],
            "note": "only the first 0x23 bytes are in the FDE; the body is a 0x10-byte allocator call plus the pointer store, stated as observed",
        },
        "varint32_behavior": {
            "fde": "0x61bd4f0..0x61bd53b",
            "signature": "decode_varint32(ptr, limit, out_u32*) -> end_ptr or 0",
            "steps": [
                "if ptr >= limit: return 0",
                "read bytes while the high bit is set: value |= (b & 0x7f) << shift; shift += 7; if shift > 28 after accumulating, return 0; if ptr reaches limit, return 0",
                "on the first byte without the high bit: value |= (b & 0x7f) << shift; write value to *out; return the pointer past that byte",
            ],
            "callers_in_host": ["0x605f76c (first decode)", "0x605fc81 (log-path re-decode)"],
        },
        "transform_behavior": {
            "fde": "0x5e9af30..0x5e9b142",
            "vtable": "0x64d3bc0 (InternalKeySliceTransform, typeinfo 0x64d3ae0)",
            "vtable_slot": "0x98 (RELATIVE at 0x64d3c58)",
            "typeinfo_name": ikst_name,
            "got_identity": "GOT slot 0x64ed690 holds 0x5e9af30 (RELATIVE)",
            "signature": "transform(node *obj, pair *slice) -> (ptr, len) in (rax, rdx)",
            "pair": "(ptr, len) 16-byte slice; the host builds its pairs on the stack at rsp+0x30..0x108, the callee at rsp+0x00..0x80",
            "steps": [
                "advance obj = *(obj+0x20)",
                "build successive pairs (ptr, len - 8k) for k = 0..8 on the stack",
                "for each of the next 8 nodes, compare its vtable slot 0x98 with the GOT identity (0x5e9af30); on the first mismatch call that slot with the pair for that level and return its (rax, rdx)",
                "if all 8 match, call the 9th node's slot 0x98 unconditionally with the (ptr, len - 72) pair and return its (rax, rdx)",
            ],
            "meaning": "each canonical hop pre-strips 8 from the length; the chain is the InternalKeySliceTransform chain, so each hop accounts for one 8-byte internal-key trailer",
            "host_unrolling": "the host inlines the same walk for 13 hops (pairs at rsp+0x30..0x108, final pair (ptr, len - 104) at rsp+0x100) before calling the 13th node's slot",
        },
        "hash64_behavior": {
            "fde": "0x61c38a0..0x61c3bb9",
            "signature": "hash64(ptr, len) -> u64",
            "structure": "mum-mixing 64-bit hash: seed = len * 0x9e3779b185ebca87; short paths mix the head/tail words with the constants 0xbe4ba423396cfeb8 / 0x1cad21f72c81017c; long paths accumulate one mum-mix per 32-byte lane pair into the seed; every path ends in the finalizer y = x ^ (x >> 37), z = y * 0x165667b19e3779f9, return z ^ (z >> 32)",
            "length_paths": {
                "0": "constant 0x5342c3010fe1dd04",
                "1..3": "v = data[0] | (len << 24) | (data[len/2] << 8) | (data[len-1] << 16); v ^= 0x396cfeb8; return fin(v * 0x9e3779b185ebca87)",
                "4..8": "pre = ((u32(p+len-4) << 32) | u32(p)) ^ 0xbe4ba423396cfeb8; t = pre ^ (pre >> 51); t *= 0x9e3779b1; t += len; u = t ^ (t >> 47); return fin(u * 0xc2b2ae3d27d4eb4f)",
                "9..16": "a = u64(p) ^ 0xbe4ba423396cfeb8; b = u64(p+len-8) ^ 0x1cad21f72c81017c; (lo, hi) = mum(a + len, b); return fin(a + len + b + (lo ^ hi))",
                "17..32": "(lo1, hi1) = mum(u64(p+8) ^ 0x1cad21f72c81017c, u64(p) ^ 0xbe4ba423396cfeb8); (lo2, hi2) = mum(u64(p+len-8) ^ 0x1f67b3b7a4a44072, u64(p+len-16) ^ 0xdb979083e96dd4de); return fin((hi1 ^ lo1) + (hi2 ^ lo2) + seed)",
                "33..64": "one 32-byte lane-pair contribution, then the 17..32 tail",
                "65..96": "two lane-pair contributions, then the 17..32 tail",
                "97..128": "three lane-pair contributions, then the 17..32 tail",
                "129..240": "BOUNDARY: jumps to helper 0x61c3230 (FDE 0x61c3230..0x61c3491), not modeled",
                "241+": "BOUNDARY: jumps to helper 0x61c2890 (FDE 0x61c2890..0x61c2cad), not modeled",
            },
            "lane_pair": "(lo1, hi1) = mum(Ka ^ head_word, Kb ^ head_word2); (lo2, hi2) = mum(Kc ^ tail_word, Kd ^ tail_word2); contribution = (lo1 ^ hi1) + (lo2 ^ hi2); the per-lane constants are in the model source",
        },
        "hex_encode_behavior": {
            "fde": "0x61c7e30..0x61c7fb6",
            "signature": "hex_encode(out_string, slice_ptr, flag) (re-shipped from #3561)",
            "steps": [
                "clear the out string (SSO buffer at out+0x10, length 0)",
                "flag 0: replace the string contents with the slice bytes verbatim (raw copy)",
                "flag != 0: reserve 2*len, then append two hex digits per byte via hexchar 0x61c7da0 (high nibble, then low nibble; 10..15 map to 'A'..'F', UPPERCASE)",
            ],
            "host_use": "the host calls it with flag 1 on the decoded key bytes in the log path",
        },
        "index_builder_behavior": {
            "fde": "0x605f290..0x605f33a",
            "note": "re-shipped byte-identical from open PR #3575; see that packet for the full record",
            "signature": "build(out38, key_obj, u16 count, allocator, u16 divisor)",
            "layout": {
                "+0x00": "count (u16)", "+0x02": "divisor (u16)",
                "+0x04": "0x80000000 / divisor (u32 step)",
                "+0x08": "key_obj", "+0x10": "allocator",
                "+0x18": "array A (count+1 pointers, zeroed)",
                "+0x20": "1", "+0x28": "array B (count pointers, each set to array A)",
                "+0x30": "1",
            },
            "host_use": "the convert path builds the index at block+0x10 with (key_obj = *(this+0x30), count = 0xc, allocator = *(this+0x08), divisor = 4)",
        },
        "index_insert_behavior": {
            "fde": "0x605f340..0x605f6d5",
            "note": "re-shipped byte-identical from open PR #3575; see that packet for the full record",
            "signature": "insert(index38, key_record_ptr)",
            "steps": [
                "comparator dispatch: slot 0x08 of *(index+0x08) on (key, candidate)",
                "scan array A from the end, comparing each occupied slot's key; a negative compare restarts the scan from the matched slot",
                "on reaching array A's head without a match, rehash: advance the per-thread seed (multiply by 0x41a7 mod 0x7fffffff until the step at +0x04) and grow array A when needed",
                "allocate a node through the allocator's slot 0x18, store the key, splice it into the chain ordered by the comparator",
            ],
            "host_use": [
                "self-loop path: insert(cur+0x10, &(arg2+0x08))",
                "convert path: insert(new+0x10, &(node+0x08)) per chain node, then insert(new+0x10, &(arg2+0x08))",
            ],
        },
        "log_gate_behavior": {
            "fde": "0x5fcef60..0x5fcf043",
            "note": "re-shipped byte-identical from open PR #3575; see that packet for the full record",
            "signature": "log_gate(logger, format, varargs...)",
            "steps": [
                "spill the varargs into a stack args array",
                "call the logger's vtable slot 0x40; if the returned level is greater than 1, return without logging",
                "otherwise call the logger's vtable slot 0x28 with (level = 1, format, args pointer)",
            ],
            "host_use": "log(logger = *(this+0x38), 'HashLinkedList bucket %zu has more than %d entries. Key to insert: %s', bucket, count, hex_key)",
        },
        "hashlinklistrep_vtable": {
            "base": "0x64d2168",
            "typeinfo": "0x64d2050",
            "typeinfo_name": rep_name,
            "slots": rep_slots,
        },
        "factory_vtable": {
            "base": "0x64d2230",
            "typeinfo": "0x64d2068",
            "typeinfo_name": factory_name,
            "slots": factory_slots,
        },
        "ikst_vtable": {
            "base": "0x64d3bc0",
            "typeinfo": "0x64d3ae0",
            "typeinfo_name": ikst_name,
            "slots": ikst_slots,
        },
        "literals": {
            "log_format": log_fmt,
            "factory_name": "HashLinkListRepFactory",
            "factory_nickname": factory_nick,
        },
        "assumptions": [
            "the key object's slot-0x08 (record/record) and slot-0x10 (record/slice) comparators are caller-supplied; the model uses bytewise comparison of decoded key bytes as the reference instance",
            "the transform chain's terminal (non-canonical) transform is chain-supplied; the model takes it as a callable and the reference terminal is the identity on the pair it receives",
            "the 0x38-byte sub-index's rehash/growth internals are abstracted in the model as an ordered record list preserving its observable contract (ordered insertion by the comparator)",
            "hash inputs longer than 128 bytes use helpers 0x61c2890 / 0x61c3230 outside the modeled FDE; the model raises for them",
            "std::string storage/SSO is not modeled; only string contents",
            "the host's return value is not read by any caller in the binary and is not modeled",
        ],
        "open_unknowns": [
            "the concrete key object passed as the ctor's 2nd arg (its slot-0x08/0x10 comparator implementations)",
            "the concrete terminal (non-canonical) transform at the end of the *(this+0x28) chain, and which caller builds the chain the factory ctor receives as its 4th arg",
            "who calls the factory's slot 0x98 (the rep ctor has no direct call site; it is reached only through the factory vtable)",
            "the hash helpers 0x61c2890 / 0x61c3230 for inputs longer than 128 bytes",
            "the rep's slot-0x98 method 0x605ec20 (builds a 0x30-byte object, vtable 0x64d20f8) and the other unpinned vtable slots (0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xa0, 0xa8, 0xb0)",
        ],
        "callers": rows,
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=2)
        fh.write("\n")
    print("wrote records.json")
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("site\ttarget\tkind\tfde\n")
        for r in rows:
            fh.write("%s\t%s\t%s\t%s\n" % (r["site"], r["target"], r["kind"], r["fde"]))
    print("wrote callers.tsv (%d rows)" % len(rows))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        for slot in sorted(relocs):
            fh.write("0x%x RELATIVE 0x%x\n" % (slot, relocs[slot]))
    print("wrote relocations.txt (%d rows)" % len(relocs))
    with open(os.path.join(HERE, "vtables.tsv"), "w") as fh:
        fh.write("vtable\toffset\tslot\ttarget\tnote\n")
        for vname, base, slots in (
                ("HashLinkListRep", 0x64D2168, rep_slots),
                ("HashLinkListRepFactory", 0x64D2230, factory_slots),
                ("InternalKeySliceTransform", 0x64D3BC0, ikst_slots)):
            for s in slots:
                fh.write("0x%x\t%s\t%s\t%s\t%s\n" % (
                    base, s["offset"], s["slot"], s["target"], vname))
    print("wrote vtables.tsv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
