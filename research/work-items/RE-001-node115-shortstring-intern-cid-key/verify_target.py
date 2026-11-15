#!/usr/bin/env python3
"""Byte comparison of the node #115 ELF against the windows this packet cites.

Bytes only: nothing is disassembled, run or emulated. Each window is a hand-copied byte string at a
virtual address. A "tie" reads an immediate (or a decoded rip-relative / call target) out of the
windows and compares it with a constant in the crate's lib.rs. A pass says the bytes are where
README.md says and that the crate constants equal the immediates in them. It does not say the Rust
behaves like the function.

usage: verify_target.py --binary ELF --outdir NEW_DIR
NEW_DIR must not exist (its parent must) and must not be inside this packet or the crate directory.
The ELF and lib.rs are opened read-only.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
HERE = os.path.dirname(os.path.realpath(__file__))
CRATE = os.path.realpath(os.path.join(HERE, "..", "..", "..", "src", "node115-shortstring-intern"))

# id: (virtual address, bytes as hex)
WINDOWS = {
    "entry_len_gate": (0x1546abe, "4883fe10763e"),
    "entry_short_tail": (0x1546b02, "31d24881c4d80000005b415c415d415e415f5dff25c5a4f904"),
    "entry_empty_map_skip": (0x1546b37, "48833d9195fa04004c896424080f84fb000000"),
    "entry_map_hash": (0x1546b4a, "488d3d8795fa044c89e64889dae8144c0200"),
    "entry_probe_compare": (0x1546bd6, "493b5c2fe075264c01fd488b75d8488b7c24084889da4989dc4c89c341ffd04989d84c89e385c00f842b010000"),
    "entry_hit_value_load": (0x1546d2e, "4c8b65f04c8b6df8"),
    "entry_miss_range_and_call": (0x1546ca4, "48b8000000000a00000048894424404c8d742438488d7424104c89f7e80b620100"),
    "entry_after_generate": (0x1546cd4, "4883fe1048893c240f872305000031d2ff15f6a2f9044989c44989d5"),
    "entry_items_read": (0x1546d75, "4c8b3d5493fa04"),
    "entry_cap_test": (0x1546d9a, "4981ff9f8601000f87f3020000"),
    "entry_key_copy": (0x1546de7, "4889dfff159086f9044885c00f841b0400004989c74889c7488b7424084889daff15fb86f904"),
    "entry_new_key_string": (0x1546e15, "48895c24384c897c244048895c2448"),
    "entry_recheck_hash": (0x1546e24, "488d3dad92fa04488d742438e89b4a0200"),
    "entry_update_existing": (0x1546fc9, "4c8b6424304d8967f04c8b6c24604d896ff8"),
    "entry_items_increment": (0x1547044, "48ff058590fa04"),
    "entry_insert_stores": (0x1547052, "49f7d84b8d0c4048c1e104660f6f442410660f6f4c2420660f7f4c08e0660f7f4408d04c896408f04c896c08f8"),
    "entry_return": (0x15470ae, "4c89e04c89ea"),
    "gen_range_load": (0x155cede, "8b6f088b470c8944240c39c50f8d0f020000"),
    "gen_sip_init": (0x155cf10, "48b875657370656d6f73488944242048b86172656e6567796c488944242848b86d6f646e61726f64488944243048b873657479626465744889442438"),
    "gen_zero_state": (0x155cf4c, "488d4424400f57c00f1140100f110048c7402000000000"),
    "gen_writes": (0x155cf63, "4c89ef488b742418488b542410e87b3a0100c6442408ffba010000004c89ef4c8d7424084c89f6e8613a0100896c2408ba040000004c89ef4c89f6e84d3a0100"),
    "gen_finish_prefix": (0x155cfa3, "488b442430488b7c245048c1e738480b7c2458488b4c24384831f9488b742420"),
    "gen_v0_and_v2_xor": (0x155cff8, "4831fe4881f2ff000000"),
    "gen_final_xor": (0x155d081, "4989d649c1c6204931c64931ce4931d6"),
    # the SipHash `write` body at 0x15709f0: byte count, the eight-byte block loop, the tail commit
    "sip_write_length_add": (0x15709f1, "48015730"),
    "sip_write_block_loop": (0x1570b10, "4a8b1c064931db4c01d049c1c20d4c01d94931c249c1c3104931cb48c1c0204c01d14c01d849c1c2114931ca49c1c31548c1c1204931c34831d84983c0084939d072bd"),
    "sip_write_tail_commit": (0x1570bbd, "488957384c894f40"),
    "gen_mod26": (0x155d091, "4c89f048b9c54eecc44eecc44e48f7e14989d7"),
    "gen_letter": (0x155d0ac, "ffc541c1ef03438d0cbf8d0c894401f94129ce4180c641488b4b0844883401"),
    "gen_loop_back": (0x155d0cb, "49ffc44c896310396c240c0f8534feffff"),
    "cons_item_fields": (0x155cd89, "488b4c243848c1e104488b3c08488b7408084c8bac08b0000000488bac08b8000000"),
    "cons_entry_call": (0x155cdab, "ff158f31f804"),
    "cons_after_key": (0x155cdb1, "4989c74989d4488d7c24284c89ee4889eaff15c03df804807c2428017476"),
    "cons_row_store": (0x155cde3, "4c8963f84c897bf00f284424100f29038b44242089431049ffc64883c330"),
    "cons_unwrap_msg_lea": (0x155ce4f, "488d3d25aaf0fe"),
    # data (.rodata): the 43-byte message the consumer passes to the unwrap-failure call (esi = 0x2b)
    "unwrap_message_data": (0x46787b, b"called `Result::unwrap()` on an `Err` value".hex()),
}

# (window, byte offset of the E8 opcode, expected call target)
CALLS = [
    ("entry_map_hash", 13, 0x156B770), ("entry_miss_range_and_call", 28, 0x155CED0),
    ("entry_recheck_hash", 12, 0x156B8D0),
    ("gen_writes", 13, 0x15709F0), ("gen_writes", 39, 0x15709F0), ("gen_writes", 59, 0x15709F0),
]
# (window, byte offset of FF 15 / FF 25, expected GOT slot, expected R_X86_64_RELATIVE addend or None)
SLOT_CALLS = [
    ("entry_short_tail", 19, 0x64E0FE0, 0x15472B0),        # tail call: the 89-byte fold of the prior packet
    ("entry_after_generate", 16, 0x64E0FE0, 0x15472B0),    # the same fold on the ten generated bytes
    ("cons_entry_call", 0, 0x64DFF40, 0x1546AA0),          # the consumer calls the entry
    ("cons_after_key", 17, 0x64E0B88, 0x150D640),          # then the 20-byte text parser
]
# rip-relative operands at the start of a window that must all name the map's item-count word:
# (window, offset of disp32, instruction length); the first is `cmp qword [rip+d],0` (imm8 after the disp)
ITEMS_REFS = [("entry_empty_map_skip", 3, 8), ("entry_items_read", 3, 7), ("entry_items_increment", 3, 7)]
ITEMS_ADDR = 0x64F00D0
E8_CALLERS = {0x155CED0: 1, 0x156B770: 1, 0x156B8D0: 3}
ENTRY_SLOT_SITES = [0x14AEC3F, 0x155CDAB, 0x15932A3, 0x4526EB1]   # raw `call [slot]` sites of the entry; upper bound
BODY = (0x155CED0, 0x155D10E)


def read_consts():
    src = open(os.path.join(CRATE, "lib.rs")).read()
    c = {}
    for m in re.finditer(r"pub const (\w+): [^=]+ = ([^;]+);", src):
        v = m.group(2).replace("_", "").strip()
        c[m.group(1)] = [int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", v)] if v.startswith("[") else int(v, 0)
    return c, hashlib.sha256(src.encode()).hexdigest()


def imm(win, prefix, width):
    """Little-endian value right after the unique occurrence of prefix."""
    b, p = bytes.fromhex(win), bytes.fromhex(prefix)
    if b.count(p) != 1:
        raise ValueError("prefix %s occurs %d times" % (prefix, b.count(p)))
    i = b.index(p) + len(p)
    return int.from_bytes(b[i:i + width], "little")


def rel_target(va, hx, off, insn_len):
    """Target of a rel32/rip-relative operand whose disp32 starts at off+insn_len-4."""
    b = bytes.fromhex(hx)
    d = int.from_bytes(b[off + insn_len - 4:off + insn_len], "little", signed=True)
    return (va + off + insn_len + d) & 0xFFFFFFFFFFFFFFFF


def rip_target(va, hx, disp_off, insn_len):
    """Target of a rip-relative operand: window address + instruction length + disp32 at disp_off."""
    d = int.from_bytes(bytes.fromhex(hx)[disp_off:disp_off + 4], "little", signed=True)
    return (va + insn_len + d) & 0xFFFFFFFFFFFFFFFF


def call_target(win, off):
    va, hx = win
    b = bytes.fromhex(hx)
    return rel_target(va, hx, off, 5) if b[off] == 0xE8 else None


def slot_of(win, off):
    va, hx = win
    b = bytes.fromhex(hx)
    return rel_target(va, hx, off, 6) if b[off] == 0xFF and b[off + 1] in (0x15, 0x25) else None


def derived(K, win, relo, rol_positions):
    """(name, value read from the bytes, value in the crate)."""
    w = {k: v[1] for k, v in win.items()}
    b = bytes.fromhex(w["gen_sip_init"])           # four times: movabs rax,imm64 (10 bytes); mov [rsp+disp8],rax (5 bytes)
    sip = [int.from_bytes(b[2 + 15 * i:10 + 15 * i], "little") for i in range(4)]
    stores = [b[10 + 15 * i + 4] for i in range(4)]
    m26 = imm(w["gen_mod26"], "48b9", 8)
    shift = imm(w["gen_letter"], "41c1ef", 1)
    xor_va = win["gen_v0_and_v2_xor"][0]
    return [
        ("short_max_len", imm(w["entry_len_gate"], "4883fe", 1), K["SHORT_MAX_LEN"]),
        ("generated_max_is_same_bound_in_entry", imm(w["entry_after_generate"], "4883fe", 1), K["SHORT_MAX_LEN"]),
        ("generated_len_is_high_dword_of_range", imm(w["entry_miss_range_and_call"], "48b8", 8) >> 32, K["GENERATED_LEN"]),
        ("window_fact:range_start_is_low_dword", imm(w["entry_miss_range_and_call"], "48b8", 8) & 0xFFFFFFFF, 0),
        ("terminator", imm(w["gen_writes"], "c6442408", 1), K["TERMINATOR"]),
        ("window_fact:terminator_write_len", imm(w["gen_writes"], "c6442408ffba", 4), 1),
        ("index_write_is_a_dword_store", imm(w["gen_writes"], "896c2408ba", 4), K["INDEX_WIDTH"]),
        ("alphabet_base", imm(w["gen_letter"], "4180c6", 1), K["ALPHABET_BASE"]),
        ("division_constant_is_ceil_2^(64+shift)_over_alphabet", m26, -(-(1 << (64 + shift)) // K["ALPHABET_LEN"])),
        ("window_fact:division_constant_error_below_2^shift_so_exact_for_all_u64",
         int(K["ALPHABET_LEN"] * m26 - (1 << (64 + shift)) < (1 << shift)), 1),
        ("cache_insert_max_len", imm(w["entry_cap_test"], "4981ff", 4), K["CACHE_INSERT_MAX_LEN"]),
        ("window_fact:cache_test_is_unsigned_above_ja", int(bytes.fromhex(w["entry_cap_test"])[7:9] == b"\x0f\x87"), 1),
        ("sip_init_v0_v2_v1_v3_order", sip, K["SIP_INIT"]),
        ("window_fact:sip_init_stored_at_0x20_0x28_0x30_0x38", stores, [0x20, 0x28, 0x30, 0x38]),
        ("sip_rounds_before_v2_xor", sum(p < xor_va for p in rol_positions), K["SIP_C_ROUNDS"]),
        ("sip_rounds_after_v2_xor", sum(p > xor_va for p in rol_positions), K["SIP_D_ROUNDS"]),
        ("window_fact:v2_xor_value", imm(w["gen_v0_and_v2_xor"], "4881f2", 4), 0xFF),
        ("window_fact:length_in_top_byte", imm(w["gen_finish_prefix"], "48c1e7", 1), 56),
        ("sip_write_rounds_per_block", bytes.fromhex(w["sip_write_block_loop"]).count(bytes.fromhex("49c1c20d")), K["SIP_C_ROUNDS"]),
        # the finish at 0x155cfa3 reads rsp+0x50 / rsp+0x58 of a struct based at rsp+0x20; write updates +0x30 / +0x38
        ("window_fact:finish_length_field_is_the_one_write_adds_to",
         imm(w["gen_finish_prefix"], "488b7c24", 1) - stores[0], imm(w["sip_write_length_add"], "480157", 1)),
        ("window_fact:finish_tail_field_is_the_one_write_commits",
         imm(w["gen_finish_prefix"], "480b7c24", 1) - stores[0], imm(w["sip_write_tail_commit"], "488957", 1)),
        ("window_fact:loop_jumps_back_to_sip_init", rel_target(*win["gen_loop_back"], 11, 6), win["gen_sip_init"][0]),
        # movaps [rbx],xmm0 (16 bytes) then a dword store at [rbx+0x10]: 20 bytes of value after the u128
        ("row_value_len", imm(w["cons_row_store"], "8943", 1) + 4, K["ROW_VALUE_LEN"]),
    ]


class Image:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.data = self.f.read()
        d = self.data
        phoff, = struct.unpack_from("<Q", d, 0x20)
        entsz, num = struct.unpack_from("<HH", d, 0x36)
        self.segs, self.exec_segs = [], []
        for i in range(num):
            t, fl, off, va, _pa, fsz, _msz, _al = struct.unpack_from("<IIQQQQQQ", d, phoff + i * entsz)
            if t == 1:
                self.segs.append((va, off, fsz))
                if fl & 1:
                    self.exec_segs.append((va, off, fsz))
        shoff, = struct.unpack_from("<Q", d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3A)
        secs = [struct.unpack_from("<IIQQQQ", d, shoff + i * shentsize) for i in range(shnum)]
        stro = secs[shstrndx][4]
        self.sec = {d[stro + s[0]:d.index(b"\0", stro + s[0])].decode(): s for s in secs}
        rd = self.sec[".rela.dyn"]
        self.relocs = {}
        for i in range(rd[5] // 24):
            off, info, add = struct.unpack_from("<QQq", d, rd[4] + 24 * i)
            self.relocs[off] = (info & 0xFFFFFFFF, add)

    def read(self, va, n):
        for sva, off, fsz in self.segs:
            if sva <= va and va + n <= sva + fsz:
                return self.data[off + va - sva:off + va - sva + n]
        return None

    def scan(self, opcode, length, targets, tail_slot=False):
        """raw scan of executable segments for `opcode rel32` -> {target: [sites]}"""
        found = {t: [] for t in targets}
        for va, off, fsz in self.exec_segs:
            seg = self.data[off:off + fsz]
            i = seg.find(opcode)
            while i != -1:
                if i + length <= len(seg):
                    d = int.from_bytes(seg[i + len(opcode):i + length], "little", signed=True)
                    t = (va + i + length + d) & 0xFFFFFFFFFFFFFFFF
                    if t in found:
                        found[t].append(va + i)
                i = seg.find(opcode, i + 1)
        return found


def check_outdir(path):
    p = os.path.realpath(path)
    if os.path.lexists(path):
        sys.exit("refusing: %s already exists" % path)
    if not os.path.isdir(os.path.dirname(p)):
        sys.exit("refusing: parent directory of --outdir must exist")
    for guard in (HERE, CRATE):
        if p == guard or p.startswith(guard + os.sep):
            sys.exit("refusing: --outdir is inside the packet or the crate")


def flip(hexstr, bit):
    b = bytearray(bytes.fromhex(hexstr))
    b[bit // 8] ^= 1 << (bit % 8)
    return b.hex()


def window_ok(img, va, hx):
    got = img.read(va, len(hx) // 2)
    return got is not None and got.hex() == hx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--outdir", required=True)
    a = ap.parse_args()
    check_outdir(a.outdir)
    h = hashlib.sha256()
    with open(a.binary, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != TARGET_SHA256:
        sys.exit("refusing: binary sha256 %s is not the #115 target" % h.hexdigest())
    img = Image(a.binary)
    K, lib_sha = read_consts()
    for need in ("SHORT_MAX_LEN", "GENERATED_LEN", "TERMINATOR", "INDEX_WIDTH", "ALPHABET_LEN", "ALPHABET_BASE",
                 "CACHE_INSERT_MAX_LEN", "SIP_INIT", "SIP_C_ROUNDS", "SIP_D_ROUNDS"):
        if need not in K:
            sys.exit("lib.rs: constant %s not found" % need)

    allwin = WINDOWS
    res = {"target_sha256": TARGET_SHA256, "lib_rs_sha256": lib_sha, "windows": [], "calls": [], "slots": [], "ties": []}
    bad = 0
    for wid, (va, hx) in allwin.items():
        ok = window_ok(img, va, hx)
        bad += not ok
        res["windows"].append({"id": wid, "va": hex(va), "len": len(hx) // 2, "ok": ok})
    for wid, off, target in CALLS:
        got = call_target(allwin[wid], off)
        bad += got != target
        res["calls"].append({"window": wid, "site": hex(allwin[wid][0] + off), "target": hex(got or 0), "ok": got == target})
    for wid, off, slot, addend in SLOT_CALLS:
        got = slot_of(allwin[wid], off)
        rel = img.relocs.get(slot)
        ok = got == slot and rel is not None and rel == (8, addend)
        bad += not ok
        res["slots"].append({"window": wid, "site": hex(allwin[wid][0] + off), "slot": hex(got or 0),
                             "relative_reloc_addend": hex(rel[1]) if rel and rel[0] == 8 else None, "expected": hex(addend), "ok": ok})
    items = [rip_target(allwin[w][0], allwin[w][1], disp_off, ilen) for w, disp_off, ilen in ITEMS_REFS]
    items_ok = all(x == ITEMS_ADDR for x in items)
    bad += not items_ok
    res["item_count_refs"] = {"targets": [hex(x) for x in items], "all_equal_expected": items_ok, "expected": hex(ITEMS_ADDR)}

    body = img.read(BODY[0], BODY[1] - BODY[0])
    rol_positions = [BODY[0] + m.start() for m in re.finditer(re.escape(bytes.fromhex("48c1c00d")), body)]
    res["rol13_sites_in_generator"] = [hex(p) for p in rol_positions]
    for name, from_bytes, from_crate in derived(K, allwin, img.relocs, rol_positions):
        ok = from_bytes == from_crate
        bad += not ok
        res["ties"].append({"name": name, "bytes_side": from_bytes if not isinstance(from_bytes, int) else from_bytes,
                            "crate_side": from_crate, "ok": ok})

    scan = img.scan(b"\xe8", 5, list(E8_CALLERS))
    res["raw_e8_sites"] = {hex(t): {"found": len(s), "expected": E8_CALLERS[t], "ok": len(s) == E8_CALLERS[t]} for t, s in scan.items()}
    bad += sum(len(s) != E8_CALLERS[t] for t, s in scan.items())
    ff = img.scan(b"\xff\x15", 6, [0x64DFF40])[0x64DFF40]
    res["raw_call_slot_sites_of_entry"] = {"found": [hex(x) for x in ff], "expected": [hex(x) for x in ENTRY_SLOT_SITES],
                                           "ok": ff == ENTRY_SLOT_SITES}
    bad += ff != ENTRY_SLOT_SITES

    # controls: a checker that cannot fail proves nothing
    flips = caught = 0
    for wid, (va, hx) in allwin.items():
        for bit in range(len(hx) * 4):
            flips += 1
            caught += not window_ok(img, va, flip(hx, bit))
    perturb = perturb_caught = 0
    for name in ("SHORT_MAX_LEN", "GENERATED_LEN", "TERMINATOR", "INDEX_WIDTH", "ALPHABET_LEN", "ALPHABET_BASE",
                 "CACHE_INSERT_MAX_LEN", "SIP_C_ROUNDS", "SIP_D_ROUNDS"):
        K2 = dict(K)
        K2[name] += 1
        perturb += 1
        perturb_caught += any(x != y for _n, x, y in derived(K2, allwin, img.relocs, rol_positions))
    K2 = dict(K)
    K2["SIP_INIT"] = [K["SIP_INIT"][0] ^ 1] + K["SIP_INIT"][1:]
    perturb += 1
    perturb_caught += any(x != y for _n, x, y in derived(K2, allwin, img.relocs, rol_positions))
    ctl_calls = sum(call_target((allwin[w][0], flip(allwin[w][1], 8 * (off + 1))), off) != t for w, off, t in CALLS)
    ctl_slots = sum(slot_of((allwin[w][0], flip(allwin[w][1], 8 * (off + 2))), off) != s for w, off, s, _a in SLOT_CALLS)
    scan2 = img.scan(b"\xe8", 5, [t + 1 for t in E8_CALLERS])
    ctl_scan = sum(len(scan2[t + 1]) != n for t, n in E8_CALLERS.items())
    res["controls"] = {"window_bit_flips": flips, "window_bit_flips_detected": caught,
                       "crate_constant_perturbations": perturb, "crate_constant_perturbations_detected": perturb_caught,
                       "call_target_flips": len(CALLS), "call_target_flips_detected": ctl_calls,
                       "slot_flips": len(SLOT_CALLS), "slot_flips_detected": ctl_slots,
                       "e8_scan_off_by_one": len(E8_CALLERS), "e8_scan_off_by_one_detected": ctl_scan}
    res["totals"] = {"windows": len(allwin), "window_bytes": sum(len(v[1]) // 2 for v in allwin.values()),
                     "calls": len(CALLS), "slot_calls": len(SLOT_CALLS), "ties": len(res["ties"]), "failures": bad}
    if (flips != caught or perturb != perturb_caught or ctl_calls != len(CALLS) or ctl_slots != len(SLOT_CALLS)
            or ctl_scan != len(E8_CALLERS)):
        bad += 1
        res["totals"]["control_failure"] = True
    os.mkdir(a.outdir)
    with open(os.path.join(a.outdir, "verification.json"), "w", newline="\n") as f:
        json.dump(res, f, indent=1, sort_keys=True)
        f.write("\n")
    print(json.dumps(res["totals"]), json.dumps(res["controls"]))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
