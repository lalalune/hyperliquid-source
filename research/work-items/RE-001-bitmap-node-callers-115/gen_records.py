"""Generate the semantic records for RE-001-bitmap-node-callers-115.

Run from the repository root:
    python3 research/work-items/RE-001-bitmap-node-callers-115/gen_records.py

Re-derives every record from the digest-verified work binary:
the caller census (with each site confirmed as a real call in
objdump of its containing FDE), the RELATIVE relocation set for the
MetaBlockIter / DataBlockIter / InternalKeyComparator vtables, the
typeinfo names, and the literal pointers the derivations depend on.
Writes records.json (semantic records only; no per-instruction
mnemonic list -- instruction detail lives in the raw excerpts).
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
    ("bitmap_node_ctor", 0x60F4A00),
    ("reset_helper_a", 0x612A800),
    ("reset_helper_b", 0x612A8A0),
    ("reset_helper_c", 0x612A940),
    ("reset_helper_d", 0x612A9E0),
    ("reset_helper_e", 0x612AA80),
    ("bitmap_node_dtor", 0x60F4900),
    ("consumer_factory", 0x60F4D10),
    ("magnitude_helper", 0x60F4840),
    ("kind_helper", 0x60F48A0),
    ("split_helper", 0x612CEB0),
    ("trailing_u16_helper", 0x612CE30),
    ("tag_helper", 0x612CE90),
    ("consumer_materialize", 0x60F50C0),
    ("slot_release", 0x6106790),
    ("poll_copy", 0x61841A0),
    ("oneshot_prep", 0x6184300),
    ("big_prep", 0x61572D0),
]

METABLOCK_VT = 0x64D43B0
DATABLOCK_VT = 0x64D42A8
COMPARATOR_VT = 0x64C8FE8
RELOC_SLOTS = (
    [METABLOCK_VT + i * 8 for i in range(1, 33)]
    + [DATABLOCK_VT + i * 8 for i in range(1, 33)]
    + [COMPARATOR_VT + i * 8 for i in range(1, 4)]
    + [0x64D3F58 + 8, 0x64D3F40 + 8, 0x64C8F90 + 8]
    + [0x64ECD18, 0x64EDCD8]
)

TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def va_to_off(va):
    if 0x63F3C20 <= va < 0x63F3C20 + 0xFBE80:
        return va - 0x2000
    if 0x64DF458 <= va < 0x64EE158:
        return va - 0x2000
    if 0x64EFA20 <= va < 0x64EFA20 + 0x238F04:
        return va - 0x3000
    if 0x430400 <= va < 0x430400 + 0x76E640:
        return va
    return None


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
    """sites: list of (site_va, target_va). Returns rows with FDEs,
    each confirmed as a real call instruction in objdump output."""
    rows = []
    for site, target in sites:
        fde = containing_fde(fdes, site)
        if fde is None:
            fail("no FDE for site %#x" % site)
        start, end = fde
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start, "--stop-address=%#x" % end,
             BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        pat = re.compile(r"^\s*%x:\t.*\tcall\s+%x\s" % (site, target))
        if not any(pat.match(line) for line in out.splitlines()):
            fail("site %#x is not a call to %#x in FDE %#x" % (site, target, start))
        rows.append({
            "site": hex(site), "target": hex(target),
            "fde_start": hex(start), "fde_end": hex(end),
        })
    return rows


def rela_map():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    rela = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8:
            rela[ro] = add
    return rela, data


def cstr(data, va):
    off = va_to_off(va)
    if off is None:
        return None
    end = data.find(b"\x00", off)
    return data[off:end].decode("utf-8", "replace")


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        fail("binary digest mismatch: %s" % digest)
    census = run_census()
    fdes = fde_map()
    rela, _ = rela_map()

    records = {
        "artifact": {
            "node": 115,
            "sha256": DIGEST,
            "source": "provenance/artifacts.json artifacts/node/115/hl-node",
        },
        "task": "RE-001",
        "bounded_question": (
            "For each of the nine direct callers of the bitmap-node ctor "
            "0x60f4a00, what does the caller pass (arg2 struct, count, "
            "arg4) and what does it do with the node afterwards?"
        ),
        "windows": [
            {"name": "ctor", "address": "0x60f4a00", "fde": ["0x60f4a00", "0x60f4cb5"],
             "file": "ctor-60f4a00.objdump.txt", "note": "re-shipped from #4156, byte-identical"},
            {"name": "dtor", "address": "0x60f4900", "fde": ["0x60f4900", "0x60f4966"],
             "file": "dtor-60f4900.objdump.txt"},
            {"name": "magnitude_helper", "address": "0x60f4840", "fde": ["0x60f4840", "0x60f48a0"],
             "file": "mag-helper-60f4840.objdump.txt"},
            {"name": "kind_helper", "address": "0x60f48a0", "fde": ["0x60f48a0", "0x60f4900"],
             "file": "kind-helper-60f48a0.objdump.txt"},
            {"name": "split_helper", "address": "0x612ceb0", "fde": ["0x612ceb0", "0x612cece"],
             "file": "split-helper-612ceb0.objdump.txt"},
            {"name": "trailing_u16_helper", "address": "0x612ce30", "fde": ["0x612ce30", "0x612ce48"],
             "file": "trail-u16-helper-612ce30.objdump.txt"},
            {"name": "factory", "address": "0x60f4d10", "fde": ["0x60f4d10", "0x60f5069"],
             "file": "factory-60f4d10.objdump.txt"},
            {"name": "materialize", "address": "0x60f50c0", "fde": ["0x60f50c0", "0x60f55a1"],
             "file": "materialize-60f50c0.objdump.txt"},
            {"name": "slot_release", "address": "0x6106790", "fde": ["0x6106790", "0x6106834"],
             "file": "slot-release-6106790.objdump.txt"},
            {"name": "poll_copy", "address": "0x61841a0", "fde": ["0x61841a0", "0x618427d"],
             "file": "poll-copy-61841a0.objdump.txt"},
            {"name": "host_table", "address": "0x60e3ad0", "fde": ["0x60e3ad0", "0x60e3d01"],
             "file": "host-60e3ad0.objdump.txt", "ctor_site": "0x60e3b31"},
            {"name": "host_slot_replace", "address": "0x6117ed0", "fde": ["0x6117ed0", "0x6119dad"],
             "file": "host-6117ed0.objdump.txt", "ctor_site": "0x61197c2"},
            {"name": "host_reset_a", "address": "0x612a800", "fde": ["0x612a800", "0x612a887"],
             "file": "host-612a800.objdump.txt", "ctor_site": "0x612a839"},
            {"name": "host_reset_b", "address": "0x612a8a0", "fde": ["0x612a8a0", "0x612a91f"],
             "file": "host-612a8a0.objdump.txt", "ctor_site": "0x612a8d0"},
            {"name": "host_reset_c", "address": "0x612a940", "fde": ["0x612a940", "0x612a9bf"],
             "file": "host-612a940.objdump.txt", "ctor_site": "0x612a970"},
            {"name": "host_reset_d", "address": "0x612a9e0", "fde": ["0x612a9e0", "0x612aa5f"],
             "file": "host-612a9e0.objdump.txt", "ctor_site": "0x612aa10"},
            {"name": "host_reset_e", "address": "0x612aa80", "fde": ["0x612aa80", "0x612aaff"],
             "file": "host-612aa80.objdump.txt", "ctor_site": "0x612aab0"},
            {"name": "host_oneshot_a", "address": "0x61849e0", "fde": ["0x61849e0", "0x6184b7a"],
             "file": "host-61849e0.objdump.txt", "ctor_site": "0x6184ade"},
            {"name": "host_oneshot_b", "address": "0x6186e30", "fde": ["0x6186e30", "0x618a96f"],
             "file": "host-6186e30.objdump.txt", "ctor_site": "0x6187253"},
        ],
    }

    # Census: verify every direct call site is a real call in its FDE.
    census_records = {}
    for name, target in TARGETS:
        block = census.get(hex(target))
        if block is None:
            fail("census missing target %#x" % target)
        sites = [(int(s, 16), target) for s in block["direct_calls"]]
        rows = verify_sites(fdes, sites)
        tails = block["tail_jumps"]
        census_records[name] = {
            "target": hex(target),
            "direct_calls": rows,
            "tail_jumps": tails,
            "qword_hits_file_offsets": block["qword_hits_file_offsets"],
            "relative_slots": block["relative_slots"],
        }
    records["census"] = census_records

    # Reset-helper caller FDEs (census facts, hosts not reversed here).
    reset_callers = {}
    for name, target in [("reset_helper_a", 0x612A800), ("reset_helper_b", 0x612A8A0),
                         ("reset_helper_c", 0x612A940), ("reset_helper_d", 0x612A9E0),
                         ("reset_helper_e", 0x612AA80)]:
        rows = census_records[name]["direct_calls"]
        fde_set = sorted({(r["fde_start"], r["fde_end"]) for r in rows})
        reset_callers[name] = {
            "sites": [r["site"] for r in rows],
            "host_fdes": [{"start": a, "end": b} for a, b in fde_set],
        }
    records["reset_helper_callers"] = reset_callers

    # Relocations for the three vtables, typeinfo names, globals.
    vtables = {}
    for vt_name, vt_base, slot_count in [
            ("metablock_iter", METABLOCK_VT, 31),
            ("datablock_iter", DATABLOCK_VT, 31),
            ("internal_key_comparator", COMPARATOR_VT, 3)]:
        slots = []
        for i in range(1, slot_count + 1):
            va = vt_base + i * 8
            if va not in rela:
                fail("missing RELATIVE slot %#x" % va)
            slots.append({"offset": hex(i * 8), "target": hex(rela[va])})
        ti = rela.get(vt_base + 0x8)
        name_ptr = rela.get(ti + 8) if ti else None
        vtables[vt_name] = {
            "vtable_base": hex(vt_base),
            "object_vptr": hex(vt_base + 0x10),
            "offset_to_top": 0,
            "typeinfo": hex(ti) if ti else None,
            "typeinfo_name": cstr(data, name_ptr) if name_ptr else None,
            "slots": slots,
        }
    records["vtables"] = vtables
    records["globals"] = {
        "0x64ecd18": {"relative_target": hex(rela[0x64ECD18]),
                      "note": "chain head compared in slot_release"},
        "0x64edcd8": {"relative_target": hex(rela[0x64EDCD8]),
                      "note": "function compared against a vtable slot in host 0x60e3ad0"},
    }

    # Literals.
    oneshot = data[0x4376FD:0x4376FD + 1]
    oneshot_path = cstr(data, 0x4376FE)
    desc = struct.unpack_from("<Q", data, 0x459A38)[0]
    records["literals"] = {
        "oneshot_location_pointer": {
            "address": "0x4376fd", "byte_at_pointer": oneshot[0],
            "string_at_pointer_plus_1": oneshot_path,
            "note": "pointer is stored verbatim; no pinned consumer reads "
                    "the string bytes from +1",
        },
        "factory_path_c_message": {
            "address": "0x434276", "length": 18,
            "string": cstr(data, 0x434276),
        },
        "poll_copy_message": {
            "address": "0x437514", "length": 26,
            "string": cstr(data, 0x437514),
        },
        "inner_node_descriptor": {
            "address": "0x459a38", "qword": hex(desc),
            "low_u32": desc & 0xFFFFFFFF, "high_u32": desc >> 32,
        },
        "consumer_init_constant": {
            "address": "0x455f20",
            "bytes_hex": data[0x455F20:0x455F20 + 16].hex(),
            "note": "16 bytes: qword 0, then qword 0x20; stored at "
                    "consumer +0x58 and +0xa0",
        },
    }

    records["ctor"] = {
        "node_size": 0x48,
        "arg2_struct_size": 0x20,
        "move": {
            "node_+0x00": "arg2+0x00", "node_+0x08": "arg2+0x08",
            "node_+0x10": "arg2+0x10", "node_+0x18": "arg2+0x18",
            "node_+0x20": "arg2+0x00", "node_+0x28": "arg2+0x08",
            "node_+0x30": 0, "node_+0x38": 0, "node_+0x40_u16": 0,
            "arg2_+0x18_after": 0,
            "note": "the 0x4376fd store to node+0x00 is overwritten by "
                    "the 16-byte move of arg2+0x00..0x10",
        },
        "small_arg_gate": "arg2+0x08 <= 3: node+0x28 = 0, return (no bitmap)",
        "trailing_tag": {
            "buffer_ptr": "node+0x20", "buffer_len": "node+0x28",
            "trailing_u32": "*(u32*)(node+0x20 + node+0x28 - 4)",
            "magnitude": "0x60f4840: trailing u32 & 0x7fffffff when "
                         "node+0x28 <= 0x10000, else the raw trailing u32",
            "kind": "0x60f48a0: sign bit of the trailing u32 when "
                    "node+0x28 <= 0x10000, else 0",
            "node_+0x34": "magnitude",
        },
        "kind_0": "node+0x30 = node+0x28 - (4*node+0x34 + 4); "
                  "if node+0x28 - 4 < node+0x30 (unsigned) then node+0x28 = 0",
        "kind_1_small": "node+0x28 <= 5: node+0x28 = 0",
        "kind_1_large": "node+0x28 > 5: 0x612ce30 reads T = *(u16)(buffer + "
                        "len - 2) where len = (u16)(arg2+0x08 - 4); "
                        "node+0x40 (u16) = T; node+0x30 = "
                        "(len - 2 - T) - 4*node+0x34; underflow sets node+0x28 = 0",
        "kind_other": "kind not 0 or 1: node+0x28 = 0, return",
        "bitmap_allocation_gates": "count != 0, arg4 != 0, node+0x28 != 0",
        "inner_node": {
            "size": 0x28,
            "descriptor": "*(0x459a38): low u32 4, high u32 32",
            "inner_+0x20": "seed % count (seed advanced once by the shared "
                          "LCG fold: seed = seed * 0x41a7 folded mod 0x7fffffff)",
            "inner_+0x10_byte": "floor(log2(count >> 1)) + 1 when count >= 2, else 0",
            "inner_+0x18": "arg4",
            "bitmap_words": "((node+0x30 - 1) >> shift) / 32 + 1 u32s, zeroed; "
                           "32 is inner+0x04 (descriptor high u32)",
            "observer_call": "if arg4 != 0: *(arg4 vtable + 0xb0)(arg4, 0x57, node+0x30)",
            "install": "node+0x38 = inner node; previous inner node deleted "
                       "(its bitmap delete[]d, then sized delete 0x28)",
        },
        "seed_advance": "seed = seed * 0x41a7, then "
                        "(seed & 0x7fffffff) + (seed >> 31), minus 0x7fffffff "
                        "once when the 32-bit sum sets the sign flag",
    }

    records["dtor"] = {
        "inner": "if node+0x38 != 0: delete[] inner+0x08 if non-null, "
                 "then sized delete (0x28) of the inner node",
        "arg_pair": "if node+0x18 != 0: if node+0x10 != 0: call "
                   "slot 0xa0 of *(node+0x10); else delete[] node+0x18",
    }

    records["helpers"] = {
        "split_0x612ceb0": "if rsi: *rsi = (u8)(value >> 31); "
                          "if rdx: *rdx = value & 0x7fffffff",
        "trailing_u16_0x612ce30": "T = *(u16)(src + len - 2); "
                                 "*dst (u16) = T; *out (u16) = len - 2 - T",
    }

    records["factory"] = {
        "object_size": 0x120,
        "vtable": "MetaBlockIter (0x64d43b0+0x10)",
        "fixed_fields": {
            "+0xd8": "0x4376fd", "+0xf8": "0x4376fd",
            "+0x88": 1, "+0xd0": 1,
            "+0x58": "0 (const 0x455f20 low qword)",
            "+0x60": "0x20 (const 0x455f20 high qword)",
            "+0xa0": "0 (const 0x455f20 low qword)",
            "+0xa8": "0x20 (const 0x455f20 high qword)",
            "+0x48": "object+0x68", "+0x50": "object+0x68",
            "+0x90": "object+0xb0", "+0x98": "object+0xb0",
            "+0xe0": 0, "+0xe8": 0, "+0xf0": 0, "+0x100": 0,
            "+0x28": "0 on entry (replaced on path A)",
        },
        "path_a": "node+0x28 > 7 and node+0x34 != 0: 0x61be810(node+0x30, "
                  "node+0x34) result is wrapped in a 0x10-byte node with "
                  "the InternalKeyComparator vtable (0x64c8fe8+0x10) and "
                  "linked into object+0x28 (old node deleted); "
                  "object+0x30 = node+0x20; object+0x110 = -1; "
                  "object+0x109 = esi byte; object+0x118 = 0; "
                  "object+0x38 (16 bytes) = {node+0x34, node+0x34, "
                  "node+0x30, node+0x30} as four u32s (low to high)",
        "path_b": "node+0x28 > 7 and node+0x34 == 0: object+0x30 = 0; "
                  "object+0x44 = old object+0x40; the object+0x08 list is "
                  "torn down (each link: call *0x0(link) with "
                  "(link+0x08, link+0x10), sized delete 0x20); "
                  "object+0x08 = 0, object+0x20 = 0",
        "path_c": "node+0x28 <= 7: report call 0x61cf670 with message "
                  "{0x434276, 18} 'bad block contents' and location "
                  "{0x4376fd, 0}; object+0x30 = 0; object+0x44 = old "
                  "object+0x40; object+0xe8/+0xec from the report output; "
                  "object+0xf0 = report output pointer; same list teardown "
                  "as path B; object+0x08 = 0, object+0x20 = 0",
        "returns": "the new 0x120-byte object",
    }

    records["materialize"] = {
        "object_size": 0x178,
        "vtable": "DataBlockIter (0x64d42a8+0x10)",
        "null_arg4": "if rcx == 0: allocate a fresh 0x178-byte object with "
                    "the same init as the factory (vtable DataBlockIter, "
                    "const 0x455f20, 0x4376fd at +0xd8/+0xf8, +0x88 = 1, "
                    "+0xd0 = 1, 0x61bd0c0 on +0x08)",
        "given_arg4": "if rcx != 0: fill that object from the node. "
                     "node+0x28 > 7 and node+0x34 != 0: build a 0x10-byte "
                     "list node (InternalKeyComparator vtable "
                     "0x64c8fe8+0x10, +0x08 = arg2 rsi; old +0x28 node "
                     "deleted with sized delete 0x10 if non-null) into "
                     "+0x28; +0x110 = arg3 (rdx); +0x109 = arg9 low byte; "
                     "+0x30 = node+0x20; +0x118 = 0; +0x120 = node+0x20; "
                     "+0x88 = 0; +0x170 = &(node+0x40) when node+0x40 "
                     "(u16) != 0, else 0; +0x38 (16 bytes) = {node+0x34, "
                     "node+0x34, node+0x30, node+0x30} as four u32s. "
                     "node+0x28 > 7 and node+0x34 == 0: teardown path: "
                     "+0x30 = 0, +0xe8 = 0, +0x44 = old +0x40, +0xec = 0, "
                     "+0xf0 = 0 (old +0xf0 delete[]d), the +0x08 list torn "
                     "down, +0x08 = 0, +0x20 = 0. "
                     "node+0x28 <= 7: report path: 0x61cf670 with message "
                     "{0x434276, 18} 'bad block contents' and location "
                     "{0x4376fd, 0}; +0x30 = 0; +0x44 = old +0x40; "
                     "+0xe8/+0xec from the report output; +0xf0 = report "
                     "output pointer; same list teardown; +0x08 = 0, "
                     "+0x20 = 0",
        "returns": "the object (fresh or given)",
    }

    records["slot_release"] = {
        "slot_layout": "{+0x00 node*, +0x08, +0x10, +0x18 flag byte}",
        "with_second_pointer": "if slot+0x10 != 0: walk the +0x38 chain "
                              "from *(slot+0x08), comparing each link "
                              "against the 0x64ecd18 global (0x5d3f090); "
                              "tail-jump or call the matched link with rdx = 0",
        "flag_path": "else if slot+0x18 byte != 0: dtor 0x60f4900 on "
                    "slot+0x00, then sized delete (0x48)",
    }

    records["poll_copy"] = {
        "probe": "0x6183f20 fills a 0x10-byte result struct on the stack",
        "copy_condition": "copy the result into the out record when the "
                         "result byte != 0, or arg2+0x00 != 0, or "
                         "arg2+0x08 != 0",
        "empty_report": "otherwise: report call 0x61cf670 with message "
                       "{0x437514, 26} 'Cannot find the meta block' and "
                       "location {0x4376fd, 0}, then copy the result",
        "copied_fields": "out+0x00 (u16) = result+0x00; out+0x02 (u32) = "
                        "result+0x02; out+0x08 = result+0x08",
    }

    records["hosts"] = [
        {
            "name": "host_table",
            "address": "0x60e3ad0", "ctor_site": "0x60e3b31",
            "node_storage": "stack, rsp+0x30",
            "arg2": "stack struct at rsp+0x10: {table qword 0, table qword 1, 0, 0}; "
                   "the table is *(vtable of arg2 + 0x708) + arg3<<5, 0x20-byte stride",
            "count": 0, "arg4": 0,
            "after": "post-ctor cleanup reads the moved-from arg2+0x18 (0, "
                    "cleared by the ctor) and arg2+0x10 (0, zeroed by the "
                    "caller), so the virtual-call/delete[] block never runs; "
                    "then materialize 0x60f50c0(node, *(rax+8), -1, 0, 0, 0) "
                    "where rax = *(*(arg2)+0x648); the returned 0x178-byte "
                    "object is stored into *arg1, its vtable slot 0xc8 is "
                    "called, its +0xa0 is zeroed, then the typeinfo-gated "
                    "field copies run (0x64edcd8 check); finally dtor "
                    "0x60f4900 on the stack node",
            "open": "the identity of the +0x708 table; the typeinfo-gated "
                   "field copies after the materialize call",
        },
        {
            "name": "host_slot_replace",
            "address": "0x6117ed0", "ctor_site": "0x61197c2",
            "node_storage": "heap, operator new(0x48)",
            "arg2": "stack struct at rbp-0xbb0 (via -0xc60, last written at "
                   "0x61188d3; the loop body zero-initializes it and "
                   "0x6108b70 at 0x61188da populates it); the populated "
                   "field values are not pinned here",
            "count": "*(u32)(*(arg1+0x08) + 0xdc) (via -0xc98, copied to "
                    "-0xd18 at 0x6118bdc)",
            "arg4": "*(P+0x218) where P = -0xcf8 = the 4th entry argument (rcx)",
            "after": "if the fresh node == *r15 (r15 = *(*(arg1+0x08)+0x128), "
                    "the slot): if the slot+0x18 flag is set, the fresh node "
                    "is destroyed (dtor + sized delete 0x48) as a redundant "
                    "allocation; if the flag is clear, fall through to the "
                    "release path. Otherwise release the old node via "
                    "slot_release 0x6106790(r15) and install the fresh node: "
                    "slot = {node, 0, 0, flag 1}",
            "open": "the arg2 struct's populated field values (set by "
                   "0x6108b70); the wider purpose of the 0x1edd-byte host",
        },
        {
            "name": "host_reset_a",
            "address": "0x612a800", "ctor_site": "0x612a839",
            "node_storage": "heap, operator new(0x48)",
            "arg2": "arg3", "count": "*(u32)(*(arg1) + 0xcc)",
            "arg4": "*(arg1+0x08)",
            "after": "store the fresh node into *arg2 (the unique_ptr slot); "
                    "if the old pointer was non-null, dtor 0x60f4900 + "
                    "sized delete (0x48)",
            "callers": "4 sites in 3 FDEs: 0x6100110, 0x6106c90, 0x6107760 (x2)",
        },
        {
            "name": "host_reset_b",
            "address": "0x612a8a0", "ctor_site": "0x612a8d0",
            "node_storage": "heap, operator new(0x48)",
            "arg2": "arg3", "count": 0, "arg4": "*(arg1+0x08)",
            "after": "same slot replace as reset A",
            "callers": "4 sites in 3 FDEs: 0x6100470, 0x6106e70, 0x6114670 (x2)",
            "note": "byte-identical to reset C/D/E modulo addresses",
        },
        {
            "name": "host_reset_c",
            "address": "0x612a940", "ctor_site": "0x612a970",
            "node_storage": "heap, operator new(0x48)",
            "arg2": "arg3", "count": 0, "arg4": "*(arg1+0x08)",
            "after": "same slot replace as reset A",
            "callers": "4 sites in 3 FDEs: 0x61007d0, 0x6107050, 0x6116290 (x2)",
            "note": "byte-identical to reset B/D/E modulo addresses",
        },
        {
            "name": "host_reset_d",
            "address": "0x612a9e0", "ctor_site": "0x612aa10",
            "node_storage": "heap, operator new(0x48)",
            "arg2": "arg3", "count": 0, "arg4": "*(arg1+0x08)",
            "after": "same slot replace as reset A",
            "callers": "1 site in FDE 0x6107230",
            "note": "byte-identical to reset B/C/E modulo addresses",
        },
        {
            "name": "host_reset_e",
            "address": "0x612aa80", "ctor_site": "0x612aab0",
            "node_storage": "heap, operator new(0x48)",
            "arg2": "arg3", "count": 0, "arg4": "*(arg1+0x08)",
            "after": "same slot replace as reset A",
            "callers": "1 site in FDE 0x6100b80",
            "note": "byte-identical to reset B/C/D modulo addresses",
        },
        {
            "name": "host_oneshot_a",
            "address": "0x61849e0", "ctor_site": "0x6184ade",
            "node_storage": "stack, rbp-0x80",
            "arg2": "stack struct at rbp-0xa0: {0x4376fd, 0, 0, 0}",
            "count": 0, "arg4": 0,
            "before": "oneshot_prep 0x6184300 runs first on the rbp-0xb0 "
                     "struct (the 0x4376fd location struct); its result "
                     "fills the out record at arg1 when the +0xb0 byte is set",
            "after": "factory 0x60f4d10(node, 0) -> MetaBlockIter; "
                    "poll_copy 0x61841a0(out=arg1, factory object, "
                    "arg6, arg2); delete the factory object via its vtable "
                    "slot 0x8; dtor 0x60f4900 on the stack node",
            "resolves": "#4156 open unknown: the 0x4376fd pointer is passed "
                       "verbatim as arg2+0x00 -> node+0x00/node+0x20, and the "
                       "factory stores it into the MetaBlockIter +0xd8/+0xf8 "
                       "and (path A) +0x30; no pinned consumer reads the "
                       "string bytes from 0x4376fd+1",
        },
        {
            "name": "host_oneshot_b",
            "address": "0x6186e30", "ctor_site": "0x6187253",
            "node_storage": "stack, rbp-0x1a50 (via -0x1b70)",
            "arg2": "stack struct at rbp-0x1ab0: {0x4376fd, 0, 0, 0} "
                   "(+0x00 set at 0x6186fc0 from the 0x4376fd lea)",
            "count": 0, "arg4": 0,
            "before": "big_prep 0x61572d0(node, rbp-0x1510 struct) runs first; "
                     "its full behavior is not pinned here",
            "after": "factory 0x60f4d10(node, 0) -> MetaBlockIter (r14); "
                    "operator new(0x2a8) builds a 0x2a8-byte object around "
                    "the factory result; the node is destroyed at 0x61882da "
                    "via dtor 0x60f4900",
            "resolves": "same 0x4376fd pointer flow as host_oneshot_a",
            "open": "the 0x2a8-byte object's layout and use after the "
                   "factory call; the big_prep 0x61572d0 behavior",
        },
    ]

    records["cited_not_pinned"] = {
        "picker_and_seed": "0x60d5cd0 / 0x61c4080 in #3613 and #4156",
        "factory_callees": "0x61be810, 0x61cf670, 0x61bd0c0, 0x612ce50, "
                          "0x612ce90 (tag helper, one caller at 0x6129c9f)",
        "host_callees": "0x61572d0, 0x6184300, 0x6183f20, 0x6108b70, "
                       "0x60fd030, 0x60457d0, 0x6106790 (pinned here as "
                       "slot_release, callers listed in the census)",
        "iterator_slots": "MetaBlockIter/DataBlockIter slot functions "
                         "(0x60e1ff0 etc.) are listed in the vtable maps; "
                         "their individual behaviors are not pinned here",
    }

    records["open_unknowns"] = [
        "host_table: identity of the +0x708 table and the typeinfo-gated "
        "field copies after the materialize call",
        "host_slot_replace: the arg2 struct's populated field values "
        "(set by 0x6108b70) and the wider purpose of the 0x1edd-byte host",
        "host_oneshot_b: the 0x2a8-byte object's layout and use; the "
        "big_prep 0x61572d0 behavior",
        "factory path A: the 0x61be810 result's meaning and the "
        "InternalKeyComparator-vtable node's role in the +0x28 list",
        "factory path C / poll_copy: the 0x61cf670 report call's full "
        "contract (out struct, location pair semantics)",
        "the inner-node descriptor low u32 (4) has no pinned consumer; "
        "only the high u32 (32) is used as the bitmap-word divisor",
        "the dtor's slot-0xa0 call target depends on the class of the "
        "object at node+0x10, not established here; the ctor's slot-0xb0 "
        "observer call target likewise depends on arg4's class",
        "factory other caller 0x6105cff (FDE 0x6105b30..0x6105e38); "
        "magnitude-helper other callers 0x6108281, 0x6115151, 0x6116d71; "
        "tag-helper caller 0x6129c9f (FDE 0x6129c10..0x6129d88); "
        "poll-copy other callers 0x611ec7d, 0x6142d44, 0x6142eb8; "
        "slot-release has 16 callers (see census)",
        "the 0x612ce50 sibling helper (called from the same family) is "
        "not pinned here",
    ]

    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=False)
        fh.write("\n")
    print("wrote records.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
