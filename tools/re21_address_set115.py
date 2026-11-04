#!/usr/bin/env python3
"""Collect selected node 115 address-set insertion and rehash evidence.

This is a static byte reader. It neither runs captured code nor invokes other
programs. All addresses are linked ELF virtual addresses before load bias.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
LEGACY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
MASK = (1 << 64) - 1

# FDEs selected for new analysis. They deliberately exclude the previously
# studied registry builder, extension, wrapper, lookup and projection bodies.
FUNCTIONS = (
    (0x5C05E70, "in-place rehash", "1fe7fd137545104595fcfb21980f27ba76aaa17d46d8c798534735c21b579bc2"),
    (0x5C06100, "element swap", "bb7a294faa0a1d571073de3dc4a6a9e2e8efeb632d1801189ad88cae4f0d954c"),
    (0x5C063B0, "rehash landing cleanup", "a27501e59ce2fa4fc610ed13d3da63c01ea578963bec73d983d86b584a3e49e4"),
    (0x5C06470, "new-table landing cleanup", "3c115dba960268f624c0d553c9aae1a899d3ac2f73b5009d87dbadbc08fab020"),
    (0x5C06630, "20-byte set insertion", "211c94dcd75c9ebadf6e6b5adac0b7fab83ab937b51c454214b81e60b1959dd6"),
    (0x5C06B20, "20-byte table reserve and rehash", "224de8f8e2875b2f9bae24fcb9245515a2400351a572126b5ccd76fe6016f740"),
    (0x5C07440, "in-place key hash callback", "8ae374287642fb4343ad5a719c5a8137593bc94a760b309409599c1b11cdb025"),
    (0x5C394A0, "key hash state update", "25284b67050c3005c1a8984afde7cc6e9a1b1b0779a6920db014d1ea9b830d60"),
)

# Fixed, selected instruction slices. Full FDE-body digests below authenticate
# the selections; these slices are not a general instruction disassembly.
WINDOWS = (
    ("insert_hash_setup", 0x5C0663A, 0x5C0666C),
    ("insert_hash_finish_and_growth_gate", 0x5C0666C, 0x5C0669E),
    ("insert_group_fingerprint", 0x5C0669E, 0x5C066ED),
    ("insert_twenty_byte_equality", 0x5C066ED, 0x5C06727),
    ("insert_free_and_empty_groups", 0x5C06740, 0x5C06780),
    ("insert_reserve_before_probe", 0x5C06790, 0x5C067B5),
    ("insert_control_counts_key", 0x5C067B5, 0x5C0680A),
    ("insert_returns_and_small_table_fallback", 0x5C06808, 0x5C06829),
    ("hash_initial_words", 0x5C394A1, 0x5C394BC),
    ("hash_empty_state_path", 0x5C394DB, 0x5C39507),
    ("hash_first_fold_and_tail", 0x5C39523, 0x5C3954B),
    ("reserve_count_capacity_gate", 0x5C06B42, 0x5C06B75),
    ("reserve_small_bucket_rounding", 0x5C06B75, 0x5C06B9E),
    ("reserve_in_place_callback", 0x5C06B9E, 0x5C06BC6),
    ("reserve_large_bucket_rounding", 0x5C06BC6, 0x5C06C06),
    ("reserve_layout_overflow", 0x5C06C06, 0x5C06C44),
    ("reserve_allocator_and_null", 0x5C06C66, 0x5C06C7D),
    ("reserve_control_initialization", 0x5C06CA7, 0x5C06CC0),
    ("reserve_existing_key_hash", 0x5C06D5B, 0x5C06DAA),
    ("reserve_rehash_probe", 0x5C06DE5, 0x5C06E14),
    ("reserve_rehash_move", 0x5C06E14, 0x5C06E51),
    ("reserve_publish_table", 0x5C06EA4, 0x5C06ED7),
    ("reserve_overflow_and_alloc_failure", 0x5C06F0E, 0x5C06F35),
    ("reserve_landing_cleanup", 0x5C06F35, 0x5C06F4A),
    ("rehash_mark_controls", 0x5C05EE0, 0x5C05EF2),
    ("rehash_callback_and_probe", 0x5C05F60, 0x5C05F9F),
    ("rehash_same_group_test", 0x5C05F9F, 0x5C05FBB),
    ("rehash_store_or_swap", 0x5C05FC8, 0x5C05FF8),
    ("rehash_keep_and_advance", 0x5C06040, 0x5C0607B),
    ("rehash_move_to_empty", 0x5C0607B, 0x5C060A4),
    ("rehash_recompute_growth", 0x5C060A4, 0x5C060CA),
    ("rehash_landing_cleanup", 0x5C060E3, 0x5C060F8),
    ("rehash_cleanup_gate", 0x5C063B0, 0x5C063D1),
    ("rehash_cleanup_pending_slots", 0x5C06403, 0x5C06431),
    ("rehash_cleanup_growth", 0x5C06431, 0x5C06457),
    ("new_table_cleanup", 0x5C06470, 0x5C064C1),
    ("in_place_hash_setup", 0x5C07440, 0x5C07484),
    ("in_place_hash_finish", 0x5C07484, 0x5C074BC),
    ("swap_words", 0x5C06100, 0x5C06161),
    ("swap_tail", 0x5C06161, 0x5C061BF),
)

# Every transfer is decoded from its authenticated opcode and signed operand.
# This is a selected edge ledger, not a complete instruction/CFG inventory.
EDGES = (
    ("insert_hash", 0x5C06667, "e8"),
    ("insert_hash_empty_state", 0x5C06671, "0f84"),
    ("insert_growth_zero", 0x5C06698, "0f84"),
    ("insert_no_fingerprint_match", 0x5C066E0, "74"),
    ("insert_duplicate", 0x5C06721, "0f84"),
    ("insert_more_candidates", 0x5C06732, "75"),
    ("insert_prior_free", 0x5C06744, "74"),
    ("insert_no_free_in_group", 0x5C0674C, "74"),
    ("insert_empty_found", 0x5C06763, "75"),
    ("insert_next_group", 0x5C0677B, "e9"),
    ("insert_fallback_hash_with_growth", 0x5C0678A, "0f85"),
    ("insert_resume_after_reserve", 0x5C067B0, "e9"),
    ("insert_small_table_fallback", 0x5C067BC, "79"),
    ("insert_fallback_rejoin", 0x5C06827, "eb"),
    ("hash_long_state", 0x5C394BA, "72"),
    ("hash_zero_state", 0x5C39505, "74"),
    ("reserve_count_overflow", 0x5C06B46, "0f82"),
    ("reserve_in_place", 0x5C06B73, "76"),
    ("reserve_large_bucket", 0x5C06B83, "73"),
    ("reserve_in_place_call", 0x5C06BBC, "e8"),
    ("reserve_large_count_overflow", 0x5C06BCD, "75"),
    ("reserve_product_overflow", 0x5C06C11, "70"),
    ("reserve_layout_valid", 0x5C06C42, "74"),
    ("reserve_overflow_failure_mode", 0x5C06C46, "0f85"),
    ("reserve_null_allocation", 0x5C06C77, "0f84"),
    ("reserve_no_old_entries", 0x5C06D0F, "0f84"),
    ("reserve_rehash_key", 0x5C06DA5, "e8"),
    ("reserve_rehash_empty_state", 0x5C06DB4, "74"),
    ("reserve_no_free_group", 0x5C06DFC, "74"),
    ("reserve_small_table_fallback", 0x5C06E0D, "79"),
    ("reserve_rehash_more", 0x5C06E56, "0f85"),
    ("reserve_null_failure_mode", 0x5C06E94, "0f85"),
    ("reserve_no_old_allocation", 0x5C06ED1, "0f84"),
    ("reserve_unwind_cleanup", 0x5C06F3D, "e8"),
    ("reserve_unwind_resume", 0x5C06F45, "e8"),
    ("rehash_nonempty_mask", 0x5C05E94, "75"),
    ("rehash_small_controls", 0x5C05F2E, "0f82"),
    ("rehash_no_free_group", 0x5C05F89, "74"),
    ("rehash_small_table_fallback", 0x5C05F99, "0f89"),
    ("rehash_same_group", 0x5C05FB5, "0f82"),
    ("rehash_move_to_empty", 0x5C05FE7, "0f84"),
    ("rehash_swap", 0x5C05FF3, "e8"),
    ("rehash_finished", 0x5C0605D, "74"),
    ("rehash_skip_nonpending", 0x5C06067, "71"),
    ("rehash_unwind_cleanup", 0x5C060EB, "e8"),
    ("rehash_unwind_resume", 0x5C060F3, "e8"),
    ("cleanup_no_drop_callback", 0x5C063C5, "74"),
    ("cleanup_special_mask", 0x5C063CF, "74"),
    ("cleanup_skip_nonpending", 0x5C0640A, "71"),
    ("hash_callback_update", 0x5C0747F, "e8"),
    ("hash_callback_empty_state", 0x5C07489, "74"),
)

CRITICAL_TARGETS = {
    0x5C06667: 0x5C394A0, 0x5C06698: 0x5C06790, 0x5C06721: 0x5C0680A,
    0x5C06B73: 0x5C06B9E, 0x5C06BBC: 0x5C05E70, 0x5C06DA5: 0x5C394A0,
    0x5C05FF3: 0x5C06100, 0x5C060EB: 0x5C063B0, 0x5C06F3D: 0x5C06470,
    0x5C0747F: 0x5C394A0,
}

RIP_REFS = (
    ("insert_secret_slot", 0x5C0664B, "488b0d", 0x64DFA78),
    ("insert_reserve_slot", 0x5C067A7, "ff15", 0x64EC338),
    ("reserve_rehash_callback", 0x5C06BA8, "488d15", 0x5C07440),
    ("reserve_allocator_slot", 0x5C06C6E, "ff15", 0x64DF480),
    ("reserve_memset_slot", 0x5C06CBA, "ff15", 0x64DF750),
    ("reserve_secret_slot", 0x5C06D8A, "488b0d", 0x64DFA78),
    ("reserve_old_buffer_release_slot", 0x5C06F03, "ff15", 0x64DF4A0),
    ("reserve_overflow_failure_slot", 0x5C06F21, "ff15", 0x64DF6B8),
    ("reserve_allocation_failure_slot", 0x5C06F2F, "ff15", 0x64DF490),
    ("rehash_marker_vector", 0x5C05ED3, "660f6f05", 0x454F80),
    ("rehash_memmove_slot", 0x5C05F3F, "ff15", 0x64DF568),
    ("rehash_memcpy_slot", 0x5C0609C, "ff15", 0x64DF508),
    ("rehash_double_failure_slot", 0x5C060F8, "ff15", 0x64DF4C0),
    ("new_table_cleanup_release_slot", 0x5C064BA, "ff25", 0x64DF4A0),
    ("rehash_hash_secret_slot", 0x5C07466, "488b0d", 0x64DFA78),
)

# These tiny slices verify the handoff from previously studied bodies. Those
# bodies are boundaries, not part of the selected FDE/function inventory.
BRIDGE_WINDOWS = (
    ("fourth_record_copies", 0x5C18F57, "488b0502788a0048898424b80200000f1005e3778a000f118424a80200000f1005c4778a000f11842498020000f30f6f05a4778a00f30f7f842488020000"),
    ("four_record_call_arguments", 0x5C18F95, "488dbc2448010000488db424e0010000e836f5ffff"),
    ("copy_and_set_pointer", 0x5C18514, "bae00000004c89f7ff15e66f8c00498d472848898424e0000000"),
    ("four_element_growth_gate", 0x5C1852E, "49837f38030f863c060000"),
    ("four_element_reserve_call", 0x5C18B75, "498d5748be04000000498d7f28b901000000ff15ab378d00e9a7f9ffff"),
    ("element_stride_and_sentinel_test", 0x5C1858A, "486bc0384c8bac04000100004d39e5751b"),
    ("key_loads", 0x5C18600, "488b6808488b58104c8b4818440fb640300fb678310fb750328b4834f30f6f5020"),
    ("key_prefix_forwarding", 0x5C188A4, "660f7f5424100fb66c2410440fb6642411f30f7f542440"),
    ("set_key_and_call", 0x5C1892F, "448844245040887c24516689542452488bbc24e0000000488d742440e8e0dcfeff"),
)

RELOCS = {
    0x64C0748: (8, 0x5C165B0, None),  # prior record callback boundary
    0x64DFA78: (8, 0x64FFE90, None),  # pointer to mutable, non-file-backed state
    0x64EC338: (8, 0x5C06B20, None),
    0x64DF480: (8, 0x6355830, None),
    0x64DF490: (8, 0x141E251, None),
    0x64DF4A0: (8, 0x635DE30, None),
    0x64DF4C0: (8, 0x1680CAB, None),
    0x64DF6B8: (8, 0x1680E80, None),
    0x64DF508: (6, 0, "memcpy"),
    0x64DF568: (6, 0, "memmove"),
    0x64DF750: (6, 0, "memset"),
}


def authenticate(data: bytes) -> None:
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("node 115 SHA-256 mismatch")


class Image:
    def __init__(self, data: bytes):
        self.data = data
        self.sections = sections(data)

    def section(self, name):
        rows = [s for s in self.sections if s["name"] == name]
        if len(rows) != 1 or rows[0]["type"] == 8:
            raise ValueError("missing, duplicate or NOBITS section: " + name)
        return rows[0]

    def locate(self, va, size=1, *, file_backed=True):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError("invalid VA or length")
        found = [s for s in self.sections if s["flags"] & 2 and s["size"]
                 and (not file_backed or s["type"] != 8)
                 and s["address"] <= va and va + size <= s["address"] + s["size"]]
        if len(found) != 1:
            raise ValueError("VA is not in one file-backed allocated section")
        s = found[0]
        return s, s["offset"] + va - s["address"]

    def read(self, va, size):
        _, off = self.locate(va, size)
        return self.data[off:off + size]


def fixed(image, va, expected):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    actual = image.read(va, len(expected))
    if actual != expected:
        raise ValueError(f"instruction/data predicate mismatch at {va:#x}")
    return actual


def branch(image, site, opcode, expected_target=None):
    op = bytes.fromhex(opcode)
    if op[0] in (0xE8, 0xE9) and len(op) == 1:
        width = 4
    elif len(op) == 1 and (op[0] in range(0x70, 0x80) or op == b"\xeb"):
        width = 1
    elif len(op) == 2 and op[0] == 0x0F and 0x80 <= op[1] <= 0x8F:
        width = 4
    else:
        raise ValueError("unsupported selected transfer opcode")
    raw = image.read(site, len(op) + width)
    if raw[:len(op)] != op:
        raise ValueError(f"transfer opcode mismatch at {site:#x}")
    disp = int.from_bytes(raw[len(op):], "little", signed=True)
    target = site + len(raw) + disp
    image.locate(target, 1)
    if expected_target is not None and target != expected_target:
        raise ValueError(f"transfer target mismatch at {site:#x}")
    return raw, target


def rip(image, site, prefix):
    op = bytes.fromhex(prefix)
    raw = image.read(site, len(op) + 4)
    if raw[:len(op)] != op:
        raise ValueError(f"RIP-relative opcode mismatch at {site:#x}")
    target = site + len(raw) + struct.unpack_from("<i", raw, len(op))[0]
    image.locate(target, 1)
    return raw, target


def record_bytes(image, va):
    head = image.read(va, 4)
    length = struct.unpack("<I", head)[0]
    if not 4 <= length < 0x10000:
        raise ValueError("unsupported FDE/CIE record length")
    return image.read(va, length + 4)


def check_body(image, start, end, expected):
    if end <= start:
        raise ValueError("invalid FDE body range")
    body = image.read(start, end - start)
    digest = hashlib.sha256(body).hexdigest()
    if digest != expected:
        raise ValueError(f"selected FDE body mismatch at {start:#x}")
    return body, digest


def collect_functions(image):
    sec, index = unwind_index(image.data)
    del sec
    by_index = {r["start"]: r["fde"] for r in index}
    del index
    cies, all_fdes = eh_frame_records(image.data, image.sections)
    starts = {x[0] for x in FUNCTIONS}
    chosen = [row for row in all_fdes if row["start"] in starts]
    if len(chosen) != len(FUNCTIONS) or len({x["start"] for x in chosen}) != len(FUNCTIONS):
        raise ValueError("selected FDE missing or duplicated")
    records = []
    for start, role, expected in FUNCTIONS:
        row = next(x for x in chosen if x["start"] == start)
        if by_index.get(start) != row["fde"] or row["cie"] not in cies or row["end"] <= start:
            raise ValueError("selected FDE/index mismatch")
        size = row["end"] - start
        section, off = image.locate(start, size)
        if not section["flags"] & 4:
            raise ValueError("selected FDE is not executable")
        body, digest = check_body(image, start, row["end"], expected)
        records.append({
            "role_inferred": role, "start_va": hex(start), "end_va_exclusive": hex(row["end"]),
            "section": section["name"], "file_offset": hex(off), "size": size,
            "sha256": digest, "body_bytes": body.hex(), "fde_va": hex(row["fde"]),
            "fde_bytes": record_bytes(image, row["fde"]).hex(), "cie_va": hex(row["cie"]),
            "cie_bytes": record_bytes(image, row["cie"]).hex(),
            "lsda_va": hex(row["lsda"]) if row["lsda"] is not None else None,
        })
    return records, {x["start"]: x for x in chosen}


def symbol_name(image, index):
    sym = image.section(".dynsym")
    strings = image.section(".dynstr")
    if index < 0 or index * 24 + 24 > sym["size"]:
        raise ValueError("dynamic symbol index out of bounds")
    pos = sym["offset"] + index * 24
    name_off = struct.unpack_from("<I", image.data, pos)[0]
    if name_off >= strings["size"]:
        raise ValueError("dynamic symbol string out of bounds")
    begin = strings["offset"] + name_off
    end = image.data.find(b"\0", begin, strings["offset"] + strings["size"])
    if end < 0:
        raise ValueError("unterminated dynamic symbol")
    return image.data[begin:end].decode("ascii")


def collect_relocs(image, expected_relocs=None):
    expected_relocs = RELOCS if expected_relocs is None else expected_relocs
    sec = image.section(".rela.dyn")
    if sec["size"] % 24:
        raise ValueError("unaligned RELA section")
    selected = {}
    for pos in range(sec["offset"], sec["offset"] + sec["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", image.data, pos)
        if slot not in expected_relocs:
            continue
        if slot in selected:
            raise ValueError("duplicate selected relocation")
        typ, sym = info & 0xFFFFFFFF, info >> 32
        name = symbol_name(image, sym) if typ == 6 else None
        expected_type, expected_addend, expected_name = expected_relocs[slot]
        if (typ, addend, name) != (expected_type, expected_addend, expected_name):
            raise ValueError(f"relocation mismatch at {slot:#x}")
        if typ == 8 and sym != 0:
            raise ValueError("RELATIVE relocation unexpectedly names a symbol")
        image.locate(slot, 8)
        selected[slot] = (slot, typ, sym, addend, name or "", pos,
                          image.data[pos:pos + 24].hex())
    if set(selected) != set(expected_relocs):
        raise ValueError("missing selected relocation")
    return [selected[k] for k in sorted(selected)]


def compare_legacy(legacy_data, target_data):
    """Optional separate #94 identity/record check; does not create files."""
    authenticate(target_data)
    if hashlib.sha256(legacy_data).hexdigest() != LEGACY_SHA256:
        raise ValueError("node 94 SHA-256 mismatch")
    old = Image(legacy_data)
    new = Image(target_data)
    old_record = old.read(0x574F0A8, 48)
    new_record = new.read(0x64C0730, 56)
    old_key, new_key = old_record[24:44], new_record[32:52]
    if old_key != bytes(19) + b"\x09" or new_key != old_key:
        raise ValueError("cross-release address key mismatch")
    old_reloc = collect_relocs(old, {0x574F0B0: (8, 0x4E9D2A0, None)})[0]
    new_reloc = collect_relocs(new, {0x64C0748: (8, 0x5C165B0, None)})[0]
    _, index = unwind_index(legacy_data)
    indexed = {row["start"]: row["fde"] for row in index}
    del index
    _, fdes = eh_frame_records(legacy_data, old.sections)
    want = {0x4E9D2A0: 0x4E9D47B, 0x4E9A8A0: 0x4E9B02C}
    found = [f for f in fdes if f["start"] in want]
    if (len(found) != len(want) or len({f["start"] for f in found}) != len(want)
            or any(f["end"] != want[f["start"]] or indexed.get(f["start"]) != f["fde"] for f in found)):
        raise ValueError("node 94 selected FDE mismatch")
    return {"legacy_sha256": LEGACY_SHA256, "legacy_record_va": "0x574f0a8",
            "legacy_record_size": len(old_record), "legacy_key": old_key.hex(),
            "legacy_callback_slot": hex(old_reloc[0]), "legacy_callback_addend": hex(old_reloc[3]),
            "legacy_fdes": [{"start": hex(f["start"]), "end": hex(f["end"])}
                            for f in sorted(found, key=lambda f: f["start"])],
            "target_sha256": SHA256, "target_record_va": "0x64c0730",
            "target_record_size": len(new_record), "target_key": new_key.hex(),
            "target_callback_slot": hex(new_reloc[0]), "target_callback_addend": hex(new_reloc[3])}


def parse_lsda(image, fde):
    va = fde["lsda"]
    section, pos = image.locate(va, 1)
    if section["name"] != ".gcc_except_table":
        raise ValueError("LSDA outside .gcc_except_table")
    start_pos, limit = pos, section["offset"] + section["size"]
    data = image.data
    if pos + 2 > limit or data[pos] != 0xFF:
        raise ValueError("unsupported LSDA LPStart")
    pos += 1
    ttype = data[pos]
    pos += 1
    type_table = None
    if ttype == 0x9B:
        type_offset, pos = uleb(data, pos, limit)
        type_table = pos + type_offset
        if type_table > limit:
            raise ValueError("LSDA type table outside section")
    elif ttype != 0xFF:
        raise ValueError("unsupported LSDA type encoding")
    if pos >= limit or data[pos] != 1:
        raise ValueError("unsupported LSDA call-site encoding")
    pos += 1
    length, pos = uleb(data, pos, limit)
    table_pos, table_end = pos, pos + length
    if table_end > limit:
        raise ValueError("truncated LSDA call-site table")
    if type_table is not None and table_end > type_table:
        raise ValueError("LSDA call-site table overlaps type table")
    rows = []
    while pos < table_end:
        begin = pos
        offset, pos = uleb(data, pos, table_end)
        size, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        if offset + size > fde["end"] - fde["start"]:
            raise ValueError("LSDA call site exceeds FDE")
        if landing and fde["start"] + landing >= fde["end"]:
            raise ValueError("LSDA landing exceeds FDE")
        rows.append((fde["start"], va, fde["start"] + offset, fde["start"] + offset + size,
                     fde["start"] + landing if landing else None, action,
                     data[begin:pos].hex()))
    header = {"function_va": hex(fde["start"]), "lsda_va": hex(va),
              "file_offset": hex(start_pos), "ttype_encoding": hex(ttype),
              "call_site_encoding": "0x1", "header_bytes": data[start_pos:table_pos].hex(),
              "call_site_bytes": data[table_pos:table_end].hex(), "entries": len(rows)}
    return header, rows


def collect_bridge(image, reloc_rows):
    windows = []
    for name, va, expected in BRIDGE_WINDOWS:
        raw = fixed(image, va, expected)
        _, off = image.locate(va, len(raw))
        windows.append({"name": name, "va": hex(va), "file_offset": hex(off), "bytes": raw.hex()})

    record_va = 0x64C0730
    stride = fixed(image, 0x5C1858A, "486bc038")[-1]
    copy_size = struct.unpack("<I", fixed(image, 0x5C18514, "bae0000000")[1:])[0]
    set_offset = fixed(image, 0x5C18522, "498d4728")[-1]
    key_offset = fixed(image, 0x5C1861C, "f30f6f5020")[-1]
    callback_offset = fixed(image, 0x5C18608, "4c8b4818")[-1]
    growth_cmp = fixed(image, 0x5C1852E, "49837f3803")
    reserve_seed = fixed(image, 0x5C18B75, "498d5748")[-1]
    reserve_additional = struct.unpack("<I", fixed(image, 0x5C18B79, "be04000000")[1:])[0]
    array_argument = fixed(image, 0x5C18F9D, "488db424e0010000")
    array_stack_offset = struct.unpack_from("<I", array_argument, 4)[0]
    record_store = fixed(image, 0x5C18F8C, "f30f7f842488020000")
    record_stack_offset = struct.unpack_from("<I", record_store, 5)[0]
    record = image.read(record_va, stride)
    key = record[key_offset:key_offset + 20]
    sentinel = struct.unpack("<Q", fixed(image, 0x5C18574, "49bc1300000000000080")[2:])[0]
    if key != bytes(19) + b"\x09" or struct.unpack_from("<Q", record)[0] == sentinel:
        raise ValueError("address-09 source record predicate failed")

    # Four already-studied load/store pairs build one fourth record. Decode
    # their RIP displacements and stack displacements, rather than treating an
    # address or record length from a tool's disassembly text as evidence.
    copies = []
    specs = ((0x5C18F57, "488b05", 0x5C18F5E, "48898424", 8),
             (0x5C18F66, "0f1005", 0x5C18F6D, "0f118424", 16),
             (0x5C18F75, "0f1005", 0x5C18F7C, "0f118424", 16),
             (0x5C18F84, "f30f6f05", 0x5C18F8C, "f30f7f8424", 16))
    assembled = bytearray(stride)
    covered = set()
    for load_va, load_op, store_va, store_op, length in specs:
        load, source = rip(image, load_va, load_op)
        prefix = bytes.fromhex(store_op)
        store = image.read(store_va, len(prefix) + 4)
        if not store.startswith(prefix):
            raise ValueError("unexpected bridge store opcode")
        stack_offset = struct.unpack_from("<I", store, len(prefix))[0]
        dest = stack_offset - record_stack_offset
        if not 0 <= dest <= len(assembled) - length:
            raise ValueError("bridge copy outside fourth record")
        covered.update(range(dest, dest + length))
        part = image.read(source, length)
        assembled[dest:dest + length] = part
        copies.append({"load_va": hex(load_va), "load_bytes": load.hex(), "source_va": hex(source),
                       "store_va": hex(store_va), "store_bytes": store.hex(),
                       "stack_offset": hex(stack_offset), "record_offset": dest,
                       "size": length, "source_bytes": part.hex()})
    if bytes(assembled) != record or len(covered) != len(record):
        raise ValueError("bridge copies do not reconstruct the source record")
    callback = next(row[3] for row in reloc_rows if row[0] == record_va + callback_offset)
    call, call_target = branch(image, 0x5C1894B, "e8")
    _, reserve_slot = rip(image, 0x5C18B87, "ff15")
    _, growth_target = branch(image, 0x5C18533, "0f86")
    if (call_target != 0x5C06630 or callback != 0x5C165B0 or reserve_slot != 0x64EC338
            or growth_target != 0x5C18B75 or copy_size != stride * reserve_additional):
        raise ValueError("bridge target mismatch")
    _, off = image.locate(record_va, len(record))
    return {"record_va": hex(record_va), "record_file_offset": hex(off), "record_bytes": record.hex(),
            "key_offset": key_offset, "key_bytes": key.hex(), "record_tag": hex(struct.unpack_from("<Q", record)[0]),
            "skipped_tag": hex(sentinel), "callback_relocation_slot": hex(record_va + callback_offset),
            "callback_addend": hex(callback), "record_stack_offset": hex(record_stack_offset),
            "array_stack_offset": hex(array_stack_offset), "array_index": (record_stack_offset - array_stack_offset) // stride,
            "record_stride": stride, "copy_size": copy_size, "set_offset_in_registry": set_offset,
            "parent_growth_offset_in_set": growth_cmp[-2] - set_offset,
            "parent_growth_threshold": growth_cmp[-1], "parent_reserve_additional": reserve_additional,
            "parent_seed_offset_in_set": reserve_seed - set_offset, "parent_reserve_slot": hex(reserve_slot),
            "insertion_call_va": "0x5c1894b", "insertion_call_bytes": call.hex(),
            "insertion_target": hex(call_target), "record_copies": copies, "boundary_windows": windows}


def fold(a, b):
    product = (a & MASK) * (b & MASK)
    return ((product & MASK) ^ (product >> 64)) & MASK


def hash20(key, seed, secret):
    """Arithmetic model for the observed fresh-state, 20-byte hash path."""
    if len(key) != 20 or not 0 <= seed <= MASK or not 0 <= secret <= MASK:
        raise ValueError("hash20 needs 20 bytes and two unsigned 64-bit values")
    a = int.from_bytes(key[:8], "little")
    b = int.from_bytes(key[8:16], "little")
    c = int.from_bytes(key[16:], "little")
    return fold(fold(a ^ seed, b ^ secret) ^ c, secret)


def capacity(mask):
    if not isinstance(mask, int) or mask < 0 or mask >= MASK or (mask + 1) & mask:
        raise ValueError("mask must describe a representable power-of-two bucket count")
    return mask if mask < 8 else (mask + 1) - ((mask + 1) >> 3)


def reserve_choice(mask, count, additional):
    """Model only the selected reserve decision, not allocator behavior."""
    if any(not isinstance(x, int) or x < 0 or x > MASK for x in (mask, count, additional)):
        raise ValueError("expected unsigned 64-bit inputs")
    cap = capacity(mask)
    if count > cap:
        raise ValueError("invalid count for table capacity")
    if count + additional > MASK:
        return "overflow"
    return "in_place" if count + additional <= cap // 2 else "new_table"


def new_bucket_count(required):
    """Model the selected allocation-size rounding before byte-layout checks."""
    if not isinstance(required, int) or required < 0 or required > MASK:
        raise ValueError("expected an unsigned 64-bit request")
    if required < 4:
        return 4
    if required < 8:
        return 8
    if required < 15:
        return 16
    if required >> 61:
        raise OverflowError("the selected multiplication guard rejects this request")
    quotient = (required * 8) // 7
    return 1 << (quotient - 1).bit_length()


def mark_rehash_control(value):
    if not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError("control must be one byte")
    return 0xFF if value & 0x80 else 0x80


def probe_insert(controls, keys, key, hash_value, growth):
    """Synthetic probe, including mirrored tails; no captured bytes execute.

    Controls are the real buckets only. A valid table has at least one empty
    control. This model intentionally does not implement reservation itself.
    """
    n = len(controls)
    if n < 4 or n & (n - 1) or len(keys) != n or len(key) != 20:
        raise ValueError("invalid synthetic table shape")
    if not 0 <= hash_value <= MASK or growth <= 0 or 0xFF not in controls:
        raise ValueError("probe requires growth and at least one empty control")
    if any(not (0 <= c < 0x80 or c in (0x80, 0xFF))
           or (c < 0x80 and (keys[i] is None or len(keys[i]) != 20))
           for i, c in enumerate(controls)):
        raise ValueError("invalid synthetic control or key")
    mask = n - 1
    tail = list(controls) + ([0xFF] * (16 - n) if n < 16 else [])
    tail += list(controls[:16])
    group = hash_value & mask
    finger = hash_value >> 57
    first_free = None
    step = 0
    for _ in range(n + 1):
        group_bytes = tail[group:group + 16]
        if len(group_bytes) != 16:
            raise ValueError("truncated control mirror")
        for j, c in enumerate(group_bytes):
            idx = (group + j) & mask
            if c == finger and controls[idx] == c and keys[idx] == key:
                return {"duplicate": True, "index": idx, "growth": growth, "old_control": c}
        if first_free is None:
            for j, c in enumerate(group_bytes):
                if c & 0x80:
                    first_free = (group + j) & mask
                    break
        if 0xFF in group_bytes:
            if first_free is None:
                raise ValueError("empty group lacks a free slot")
            # Padding in a small table can alias a full real slot.
            if controls[first_free] < 0x80:
                first_free = next((i for i, c in enumerate(controls) if c & 0x80), None)
            if first_free is None:
                raise ValueError("no real free bucket")
            old = controls[first_free]
            return {"duplicate": False, "index": first_free,
                    "growth": growth - (old & 1), "old_control": old}
        step += 16
        group = (group + step) & mask
    raise ValueError("probe did not terminate")


def write_tsv(path, header, rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter="\t", lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    path.write_text(output.getvalue(), encoding="utf-8")


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def generate(data, out):
    authenticate(data)
    image = Image(data)
    functions, fdes = collect_functions(image)
    relocs = collect_relocs(image)
    bridge = collect_bridge(image, relocs)
    edges = []
    for name, site, opcode in EDGES:
        if not any(f["start"] <= site < f["end"] for f in fdes.values()):
            raise ValueError("selected edge outside selected FDEs")
        raw, dest = branch(image, site, opcode, CRITICAL_TARGETS.get(site))
        _, off = image.locate(site, len(raw))
        edges.append((name, hex(site), hex(off), raw.hex(), hex(dest)))
    references = []
    for name, site, opcode, expected in RIP_REFS:
        raw, dest = rip(image, site, opcode)
        if dest != expected:
            raise ValueError(f"RIP-relative target mismatch at {site:#x}")
        _, off = image.locate(site, len(raw))
        references.append((name, hex(site), hex(off), raw.hex(), hex(dest)))
    slices = []
    for name, start, end in WINDOWS:
        if not any(f["start"] <= start < end <= f["end"] for f in fdes.values()):
            raise ValueError("selected window crosses an FDE boundary")
        section, off = image.locate(start, end - start)
        slices.append((name, hex(start), hex(end), hex(off), section["name"],
                       image.read(start, end - start).hex()))

    # The secret pointer is a relocation to mutable NOBITS, not seed bytes.
    secret_slot = next(row[0] for row in relocs if row[0] == 0x64DFA78)
    secret_va = next(row[3] for row in relocs if row[0] == secret_slot)
    secret_section, _ = image.locate(secret_va, 8, file_backed=False)
    if secret_section["type"] != 8:
        raise ValueError("expected secret state to be NOBITS")
    constants = {"empty_control": image.read(0x5C06086 + 4, 1).hex(),
                 "control_mark_vector": image.read(0x454F80, 16).hex(),
                 "counter_adjust_vector": image.read(0x450790, 16).hex(),
                 "secret_relocation_slot": hex(secret_slot), "secret_state_va": hex(secret_va),
                 "secret_section": secret_section["name"], "secret_file_backed": False,
                 "probe_group_width": image.read(0x5C06773 + 3, 1)[0],
                 "key_stride": struct.unpack("<I", image.read(0x5C06BB4 + 1, 4))[0]}
    if constants["empty_control"] != "ff" or constants["probe_group_width"] != 16 or constants["key_stride"] != 20:
        raise ValueError("selected literal mismatch")

    headers, sites = [], []
    for start in sorted(fdes):
        if fdes[start]["lsda"] is not None:
            header, rows = parse_lsda(image, fdes[start])
            headers.append(header)
            sites.extend(rows)
    summary = {"target_release": "115", "binary_sha256": SHA256,
               "selected_fdes": len(functions), "selected_fde_bytes": sum(x["size"] for x in functions),
               "selected_windows": len(slices), "selected_transfers": len(edges),
               "selected_rip_references": len(references), "selected_relocations": len(relocs), "lsda_tables": len(headers),
               "lsda_call_sites": len(sites), "bridge_windows": len(bridge["boundary_windows"]),
               "limitations": "Selected static evidence only; FDEs are not a complete function census."}

    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "functions.json", functions)
    write_json(out / "handoff.json", bridge)
    write_json(out / "constants.json", constants)
    write_json(out / "exception-headers.json", headers)
    write_json(out / "summary.json", summary)
    write_tsv(out / "windows.tsv", ("name", "start_va", "end_va_exclusive", "file_offset", "section", "bytes"), slices)
    write_tsv(out / "edges.tsv", ("name", "site_va", "file_offset", "bytes", "target_va"), edges)
    write_tsv(out / "rip-references.tsv", ("name", "site_va", "file_offset", "bytes", "target_va"), references)
    write_tsv(out / "relocations.tsv", ("slot_va", "type", "symbol_index", "addend", "symbol", "record_file_offset", "bytes"),
              ((hex(s), t, sym, hex(add) if add >= 0 else str(add), name, hex(pos), raw)
               for s, t, sym, add, name, pos, raw in relocs))
    write_tsv(out / "exception-sites.tsv", ("function_va", "lsda_va", "start_va", "end_va_exclusive", "landing_va", "action_offset", "bytes"),
              ((hex(f), hex(lsda), hex(start), hex(end), hex(landing) if landing is not None else "", action, raw)
               for f, lsda, start, end, landing, action, raw in sites))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--legacy", type=Path, help="optionally authenticate and compare the historical node 94 capture")
    args = parser.parse_args()
    target_data = TARGET.read_bytes()
    if args.legacy is not None:
        print(json.dumps({"optional_cross_release": compare_legacy(args.legacy.read_bytes(), target_data)}, sort_keys=True))
    summary = generate(target_data, args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print(f"re21_address_set115: {error}", file=sys.stderr)
        raise SystemExit(1)
