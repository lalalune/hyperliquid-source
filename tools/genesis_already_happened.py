#!/usr/bin/env python3
"""RE-039: genesis-already-happened host gate at 0x3720150 (node #94).

Standalone static recovery from the pinned node #94 binary:
  * Carve 0x3720150..0x37201f6 (166 bytes exclusive end at first int3;
    10-byte int3 pad then next function push-rbp at 0x3720200 / pay_out);
  * GOT slot 0x5773ef8 with R_X86_64_RELATIVE addend 0x3720150;
    6 inbound ff15; 0 direct e8/e9;
  * Claimed RULE: BTree membership -> Err — when the token id in rdx is
    already present (found-equal after seta/sbb), je takes Err 0xe9 +
    string 0x599262 / 24 "genesis already happened". Also reaches the
    same Err block via test rdx,rdx / je (rdx==0). Claims that
    membership->Err gate + string only.
  * Observed but NOT claimed: Ok 0xea OOB movw store (jae path),
    Ok 0x186 admit/not-present movw store.

Adjacent: merged #449 (genesis finish @ 0x371b950) is a SIBLING that
explicitly left this host-gate GOT slot unread. Output is sorted
deterministic JSON. Stdlib only; no emulation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
BINARY_SHA256 = (
    "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
)

FN = 0x3720150
FN_END = 0x37201F6
CARVED_LEN = FN_END - FN
CARVED_SHA256 = (
    "d4ff8c4365267de03a2a57bddefbb316d1db415a9dfc534af7330650037bc302"
)
NEXT_FN = 0x3720200

GOT_SLOT = 0x5773EF8
R_X86_64_RELATIVE = 8
DIRECT_E8_SITES = ()
FF15_SITES = (
    0x23E7FDF,
    0x23E80F6,
    0x4AD7B7F,
    0x4AD7C96,
    0x4AD84AF,
    0x4AD85C6,
)

ERR_TAG = 0xE9
OK_EA_TAG = 0xEA
OK_186_TAG = 0x186

# OOB path (observed, not claimed).
CMP_OOB_VA = 0x3720153
JAE_OOB_VA = 0x372015A
JAE_OOB_TARGET = 0x37201CD
OK_EA_STORE_VA = 0x37201CD

# rdx==0 early path (lands on same Err block; claimed geometry).
TEST_RDX_VA = 0x372015C
JE_RDX0_VA = 0x372015F
JE_RDX0_TARGET = 0x37201D3

# BTree membership compare + found-equal -> Err (CLAIMED gate).
CMP_KEY_VA = 0x3720195
SETA_VA = 0x372019A
SBB_VA = 0x372019E
TEST_R8_VA = 0x37201B3
JE_FOUND_VA = 0x37201B6
JE_FOUND_TARGET = 0x37201D3

ERR_E9_VA = 0x37201D3
LEA_STR_VA = 0x37201D8
STR_PTR_STORE_VA = 0x37201DF
STR_LEN_STORE_VA = 0x37201E3
STR_LEN_IMM = 0x18
OK_186_STORE_VA = 0x37201F0

ERROR_STRING = (
    "genesis_already_happened",
    0x599262,
    b"genesis already happened",
)

# Same packed string LEA sites outside this carve (not claimed).
NOT_CLAIMED_LEAS = (0x2355DEA, 0x49F631A)

KEY_INSNS = [
    (0x3720150, "4889f8", "mov rax, rdi (Result out-ptr)"),
    (0x3720153, "483b9698010000", "cmp rdx, [rsi+0x198] (OOB bound)"),
    (0x372015a, "7371", "jae 0x37201cd (OOB -> Ok 0xea STORE, not claimed)"),
    (0x372015c, "4885d2", "test rdx, rdx"),
    (0x372015f, "7472", "je 0x37201d3 (rdx==0 -> Err 0xe9 + string)"),
    (0x3720195, "483b54f910", "cmp rdx, [rcx+rdi*8+0x10] (BTree key)"),
    (0x372019a, "410f97c2", "seta r10b"),
    (0x372019e, "4180da00", "sbb r10b, 0 (equal -> r10b==0)"),
    (0x37201b3, "4585c0", "test r8d, r8d (found-equal probe)"),
    (0x37201b6, "741b", "je 0x37201d3 (membership found -> Err)"),
    (0x37201cd, "66c700ea00", "movw [rax], 0xea Ok OOB STORE (not claimed)"),
    (0x37201d3, "66c700e900", "movw [rax], 0xe9 Err STORE (claimed)"),
    (0x37201d8, "488d0d8390e7fc", "lea rcx, [rip+ string 0x599262]"),
    (0x37201df, "48894808", "mov [rax+0x8], rcx (string ptr)"),
    (0x37201e3, "48c7401018000000", "mov qword [rax+0x10], 0x18 (len 24)"),
    (0x37201f0, "66c7008601", "movw [rax], 0x186 Ok admit STORE (not claimed)"),
    (0x23e7fdf, "ff1513bf3803", "ff15 inbound via GOT"),
    (0x23e80f6, "ff15fcbd3803", "ff15 inbound via GOT"),
    (0x4ad7b7f, "ff1573c3c900", "ff15 inbound via GOT"),
    (0x4ad7c96, "ff155cc2c900", "ff15 inbound via GOT"),
    (0x4ad84af, "ff1543bac900", "ff15 inbound via GOT"),
    (0x4ad85c6, "ff152cb9c900", "ff15 inbound via GOT"),
]


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        out.append((p_vaddr, p_offset, p_filesz))
    return out


def read_va(data, segs, va, n):
    for base, off, filesz in segs:
        if base <= va < base + filesz:
            return data[off + va - base : off + va - base + n]
    raise KeyError(hex(va))


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from(
        "<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24
    )
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        name = shstr[name_off : shstr.find(b"\x00", name_off)]
        if name == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return [
                struct.unpack_from("<QQq", data, off + k * 24)
                for k in range(size // 24)
            ]
    return []


def count_direct_calls(data, segs, target):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 5:
            if code[i] in (0xE8, 0xE9):
                va = base + i
                tgt = va + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if tgt == target:
                    sites.append((code[i], va))
                i += 5
                continue
            i += 1
    return sites


def count_ff15_to_got(data, segs, got):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 6:
            if code[i] == 0xFF and code[i + 1] == 0x15:
                va = base + i
                rel = struct.unpack_from("<i", code, i + 2)[0]
                if va + 6 + rel == got:
                    sites.append(va)
                i += 6
                continue
            i += 1
    return sorted(sites)


def string_occurrences(data, needle):
    out = []
    start = 0
    segs = segments(data)
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        va = None
        for base, off, filesz in segs:
            if off <= i < off + filesz:
                va = base + (i - off)
                break
        out.append({"file_offset": hex(i), "va": hex(va) if va is not None else None})
        start = i + 1
    return out


def lea_rip_targets(data, segs, target):
    hits = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 7:
            b0 = code[i]
            if b0 in (0x48, 0x4C) and code[i + 1] == 0x8D and (code[i + 2] & 0xC7) == 0x05:
                va = base + i
                rel = struct.unpack_from("<i", code, i + 3)[0]
                if va + 7 + rel == target:
                    hits.append(va)
                i += 7
                continue
            i += 1
    return sorted(hits)


def analyse(data, check_sha=True):
    if check_sha:
        digest = hashlib.sha256(data).hexdigest()
        if digest != BINARY_SHA256:
            raise SystemExit("binary sha256 mismatch: " + digest)

    segs = segments(data)
    carved = read_va(data, segs, FN, CARVED_LEN)
    carve_sha = hashlib.sha256(carved).hexdigest()

    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    next_fn_va = FN_END + int3_pad
    next_fn_bytes = read_va(data, segs, next_fn_va, 2)

    rela = rela_dyn(data)
    relative_to_entry = [
        {"r_offset": hex(off), "r_info": hex(info), "r_addend": hex(addend)}
        for off, info, addend in rela
        if addend == FN and (info & 0xFFFFFFFF) == R_X86_64_RELATIVE
    ]
    got_rela = None
    for off, info, addend in rela:
        if off == GOT_SLOT and (info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
            got_rela = {
                "r_offset": hex(off),
                "r_info": hex(info),
                "r_addend": hex(addend),
            }
            break

    direct_sites = count_direct_calls(data, segs, FN)
    direct_e8 = sorted(va for kind, va in direct_sites if kind == 0xE8)
    direct_e9 = sorted(va for kind, va in direct_sites if kind == 0xE9)
    ff15 = count_ff15_to_got(data, segs, GOT_SLOT)

    name, sva, expected = ERROR_STRING
    raw = read_va(data, segs, sva, len(expected))
    occ = string_occurrences(data, expected)
    lea_bytes = read_va(data, segs, LEA_STR_VA, 7)
    lea_rel = struct.unpack_from("<i", lea_bytes, 3)[0]
    lea_tgt = LEA_STR_VA + 7 + lea_rel
    all_leas_primary = lea_rip_targets(data, segs, sva)
    not_claimed = [hex(v) for v in all_leas_primary if v != LEA_STR_VA]

    error_string = {
        "name": name,
        "va": hex(sva),
        "len": len(expected),
        "len_expected": STR_LEN_IMM,
        "bytes_hex": raw.hex(),
        "expected_hex": expected.hex(),
        "text": expected.decode("ascii"),
        "match": raw == expected and len(raw) == len(expected),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "occurrence_count": len(occ),
        "occurrences": occ,
        "lea_in_carve": {
            "va": hex(LEA_STR_VA),
            "bytes": lea_bytes.hex(),
            "target": hex(lea_tgt),
            "targets_string": lea_tgt == sva,
        },
        "lea_rip_refs_primary": [hex(v) for v in all_leas_primary],
        "duplicate_copies_not_claimed": [],
        "not_claimed_leas_of_duplicates": [],
        "not_claimed_leas_same_string": not_claimed,
    }

    key_insns = []
    for va, hx, note in KEY_INSNS:
        got = read_va(data, segs, va, len(hx) // 2)
        key_insns.append(
            {
                "va": hex(va),
                "bytes": got.hex(),
                "expected": hx,
                "match": got.hex() == hx,
                "note": note,
            }
        )

    test_rdx = read_va(data, segs, TEST_RDX_VA, 3)
    je_rdx0 = read_va(data, segs, JE_RDX0_VA, 2)
    je_rdx0_tgt = JE_RDX0_VA + 2 + struct.unpack_from("<b", je_rdx0, 1)[0]
    cmp_key = read_va(data, segs, CMP_KEY_VA, 5)
    seta = read_va(data, segs, SETA_VA, 4)
    sbb = read_va(data, segs, SBB_VA, 4)
    test_r8 = read_va(data, segs, TEST_R8_VA, 3)
    je_found = read_va(data, segs, JE_FOUND_VA, 2)
    je_found_tgt = JE_FOUND_VA + 2 + struct.unpack_from("<b", je_found, 1)[0]
    err_bytes = read_va(data, segs, ERR_E9_VA, 5)
    strlen_bytes = read_va(data, segs, STR_LEN_STORE_VA, 8)
    ok_ea = read_va(data, segs, OK_EA_STORE_VA, 5)
    ok_186 = read_va(data, segs, OK_186_STORE_VA, 5)
    cmp_oob = read_va(data, segs, CMP_OOB_VA, 7)
    jae_oob = read_va(data, segs, JAE_OOB_VA, 2)
    jae_oob_tgt = JAE_OOB_VA + 2 + struct.unpack_from("<b", jae_oob, 1)[0]

    rule_match = (
        test_rdx.hex() == "4885d2"
        and je_rdx0.hex() == "7472"
        and je_rdx0_tgt == JE_RDX0_TARGET
        and cmp_key.hex() == "483b54f910"
        and seta.hex() == "410f97c2"
        and sbb.hex() == "4180da00"
        and test_r8.hex() == "4585c0"
        and je_found.hex() == "741b"
        and je_found_tgt == JE_FOUND_TARGET
        and err_bytes.hex() == "66c700e900"
        and lea_tgt == sva
        and strlen_bytes.hex() == "48c7401018000000"
        and JE_FOUND_TARGET == ERR_E9_VA
        and JE_RDX0_TARGET == ERR_E9_VA
    )

    rules = [
        {
            "name": "genesis_already_happened_membership_err",
            "claimed": True,
            "description": (
                "reject when token id in rdx is already present in the "
                "genesis set (BTree membership found-equal), or when "
                "rdx==0: both je to Err 0xe9 + string "
                "genesis already happened"
            ),
            "cmp_key_va": hex(CMP_KEY_VA),
            "cmp_key_bytes": cmp_key.hex(),
            "cmp_key_expected": "483b54f910",
            "seta_va": hex(SETA_VA),
            "seta_bytes": seta.hex(),
            "sbb_va": hex(SBB_VA),
            "sbb_bytes": sbb.hex(),
            "test_r8_va": hex(TEST_R8_VA),
            "test_r8_bytes": test_r8.hex(),
            "je_found_va": hex(JE_FOUND_VA),
            "je_found_bytes": je_found.hex(),
            "je_found_expected": "741b",
            "je_found_target": hex(je_found_tgt),
            "je_found_target_expected": hex(JE_FOUND_TARGET),
            "test_rdx_va": hex(TEST_RDX_VA),
            "test_rdx_bytes": test_rdx.hex(),
            "je_rdx0_va": hex(JE_RDX0_VA),
            "je_rdx0_bytes": je_rdx0.hex(),
            "je_rdx0_target": hex(je_rdx0_tgt),
            "proof": {
                "found_equal_takes_err": (
                    "seta/sbb yields r10b==0 on equal key; after movzbl/"
                    "test r8d, je @ 0x37201b6 -> 0x37201d3 Err 0xe9 + lea "
                    "string + len 0x18"
                ),
                "rdx_eq_0_takes_err": (
                    "test rdx,rdx / je @ 0x372015f -> same Err block "
                    "0x37201d3"
                ),
                "not_found_admits": (
                    "search exhaust / not-present path stores Ok 0x186 "
                    "(observed, not claimed)"
                ),
                "oob_ok_ea": (
                    "cmp [rsi+0x198],rdx / jae stores Ok 0xea "
                    "(observed, not claimed)"
                ),
            },
            "match": rule_match,
            "negative": (
                "tamper je_found (0x37201b6) opcode/rel -> refuse pin fails"
            ),
            "err_string": "genesis_already_happened",
        },
    ]

    negatives = {
        "test_rdx_bytes_match": test_rdx.hex() == "4885d2",
        "je_rdx0_bytes_match": je_rdx0.hex() == "7472",
        "je_rdx0_targets_err": je_rdx0_tgt == ERR_E9_VA,
        "cmp_key_bytes_match": cmp_key.hex() == "483b54f910",
        "seta_sbb_bytes_match": seta.hex() == "410f97c2" and sbb.hex() == "4180da00",
        "test_r8_bytes_match": test_r8.hex() == "4585c0",
        "je_found_bytes_match": je_found.hex() == "741b",
        "je_found_targets_err": je_found_tgt == ERR_E9_VA,
        "err_e9_movw_store": err_bytes.hex() == "66c700e900",
        "string_exact": error_string["match"] and error_string["len"] == 24,
        "string_len_imm_0x18": strlen_bytes.hex() == "48c7401018000000",
        "lea_targets_string": error_string["lea_in_carve"]["targets_string"],
        "occurrence_count_is_1": error_string["occurrence_count"] == 1,
        "got_rela_present": got_rela is not None
        and got_rela["r_addend"] == hex(FN),
        "ff15_inbound_is_6": len(ff15) == 6,
        "no_direct_e8_e9": len(direct_e8) + len(direct_e9) == 0,
        "ok_ea_store_observed": ok_ea.hex() == "66c700ea00",
        "ok_186_store_observed": ok_186.hex() == "66c7008601",
        "oob_jae_targets_ok_ea": jae_oob_tgt == OK_EA_STORE_VA,
        "not_claimed_leas_are_outside_carve": all(
            not (FN <= int(v, 16) < FN_END) for v in not_claimed
        ),
        "not_claimed_lea_list_matches": not_claimed
        == [hex(v) for v in NOT_CLAIMED_LEAS],
    }

    unclaimed_ok_tags = [
        {
            "tag": hex(OK_EA_TAG),
            "va": hex(OK_EA_STORE_VA),
            "bytes": ok_ea.hex(),
            "kind": "movw_store",
            "claimed": False,
            "note": "OOB jae path Ok 0xea STORE; not claimed",
        },
        {
            "tag": hex(OK_186_TAG),
            "va": hex(OK_186_STORE_VA),
            "bytes": ok_186.hex(),
            "kind": "movw_store",
            "claimed": False,
            "note": "admit/not-present Ok 0x186 STORE; not claimed",
        },
    ]

    adjacent_prior_work = {
        "sibling": {
            "pr": 449,
            "component": "RE-006",
            "entry": hex(0x371B950),
            "note": (
                "Merged #449 (genesis finish @ 0x371b950) explicitly left "
                "this host-gate slot unread (GOT 0x5773ef8 cited only as "
                "unread host gate). It does not claim entry 0x3720150, "
                "string 0x599262, or the membership->Err rule."
            ),
        },
        "inventory_only": [],
    }

    result = {
        "abi": {
            "err_tag": hex(ERR_TAG),
            "err_tag_va": hex(ERR_E9_VA),
            "err_tag_bytes": err_bytes.hex(),
            "err_tag_kind": "movw_store",
            "err_note": (
                "Err 0xe9 is a movw STORE at 0x37201d3 reached by the "
                "claimed membership je and by test rdx,rdx / je. Claimed "
                "with the string only."
            ),
            "ok_ea_tag": hex(OK_EA_TAG),
            "ok_ea_kind": "movw_store",
            "ok_ea_claimed": False,
            "ok_186_tag": hex(OK_186_TAG),
            "ok_186_kind": "movw_store",
            "ok_186_claimed": False,
        },
        "adjacent_prior_work": adjacent_prior_work,
        "binary": "artifacts/node/94/hl-node",
        "binary_sha256": BINARY_SHA256,
        "carve": {
            "start": hex(FN),
            "end": hex(FN_END),
            "len": CARVED_LEN,
            "sha256": carve_sha,
            "sha256_expected": CARVED_SHA256,
            "sha256_match": carve_sha == CARVED_SHA256,
        },
        "claim": "genesis_already_happened_membership_err_only",
        "component": "RE-039",
        "direct_call_sites": [hex(v) for v in direct_e8],
        "direct_calls": len(direct_e8) + len(direct_e9),
        "direct_e9_calls": len(direct_e9),
        "error_strings": [error_string],
        "extent": {
            "carve_note": (
                "Exclusive end 0x37201f6 is the first int3 after the "
                "function body; 10-byte int3 pad then next function begins "
                "at push-rbp 0x3720200 (pay_out, sibling #1163). Claims "
                "the membership->Err gate + string only."
            ),
            "fde_end_exclusive": hex(FN_END),
            "fde_start": hex(FN),
            "int3_pad_len": int3_pad,
            "int3_padding_at_fde_end": int3_pad > 0,
            "next_fn_bytes": next_fn_bytes.hex(),
            "next_fn_is_push_rbp": next_fn_bytes[:1] == bytes([0x55]),
            "next_fn_va": hex(next_fn_va),
        },
        "ff15_inbound_via_got": len(ff15),
        "ff15_sites": [hex(v) for v in ff15],
        "got_addend_match": bool(
            got_rela and got_rela["r_addend"] == hex(FN)
        ),
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "got_relative_to_entry": relative_to_entry,
        "key_insns": key_insns,
        "key_insns_all_match": all(k["match"] for k in key_insns),
        "negatives": negatives,
        "oob_path_observed": {
            "cmp_va": hex(CMP_OOB_VA),
            "cmp_bytes": cmp_oob.hex(),
            "jae_va": hex(JAE_OOB_VA),
            "jae_bytes": jae_oob.hex(),
            "jae_target": hex(jae_oob_tgt),
            "claimed": False,
        },
        "rules": rules,
        "slot_ref_counts": {
            "call": len(ff15),
            "jmp": 0,
            "mov": 0,
        },
        "slot_refs": [{"va": hex(v), "kind": "ff15"} for v in ff15],
        "string_len_immediate": {
            "va": hex(STR_LEN_STORE_VA),
            "bytes": strlen_bytes.hex(),
            "value": STR_LEN_IMM,
            "match": strlen_bytes.hex() == "48c7401018000000",
        },
        "unclaimed_ok_tags": unclaimed_ok_tags,
        "unclaimed_observations": [
            {
                "name": "ok_ea_oob_store",
                "note": "Ok 0xea movw STORE on OOB jae; not claimed",
            },
            {
                "name": "ok_186_admit_store",
                "note": "Ok 0x186 movw STORE on admit/not-present; not claimed",
            },
            {
                "name": "not_claimed_leas_same_string",
                "note": (
                    "LEA sites 0x2355dea and 0x49f631a also target the "
                    "same packed string; outside this carve; not claimed"
                ),
            },
            {
                "name": "next_fn_pay_out",
                "note": "Next prologue 0x3720200 is pay_out (sibling #1163)",
            },
        ],
    }
    return result


def expectation_errors(result):
    errs = []
    if not result["carve"]["sha256_match"]:
        errs.append("carve sha256 mismatch")
    if result["carve"]["len"] != CARVED_LEN:
        errs.append("carve len mismatch")
    if not result["key_insns_all_match"]:
        for k in result["key_insns"]:
            if not k["match"]:
                errs.append("key_insn mismatch at " + k["va"])
    for s in result["error_strings"]:
        if not s["match"]:
            errs.append("string " + s["name"] + " mismatch")
        if s["occurrence_count"] != 1:
            errs.append("string occurrence_count != 1")
        if not s["lea_in_carve"]["targets_string"]:
            errs.append("string lea target mismatch")
        if s["len"] != s["len_expected"]:
            errs.append("string len_expected mismatch")
        if s["not_claimed_leas_same_string"] != [hex(v) for v in NOT_CLAIMED_LEAS]:
            errs.append("not_claimed_leas mismatch")
    for r in result["rules"]:
        if r["claimed"] and not r["match"]:
            errs.append("rule " + r["name"] + " mismatch")
    for key, val in sorted(result["negatives"].items()):
        if not val:
            errs.append("negative failed: " + key)
    if result["direct_calls"] != 0:
        errs.append("direct_calls != 0")
    if result["got_slot"] != hex(GOT_SLOT):
        errs.append("got_slot mismatch")
    if not result["got_addend_match"]:
        errs.append("got addend mismatch")
    if result["ff15_inbound_via_got"] != 6:
        errs.append("ff15_inbound_via_got != 6")
    if result["ff15_sites"] != [hex(v) for v in FF15_SITES]:
        errs.append("ff15_sites mismatch")
    return errs


def render(result):
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, help="write JSON packet to this path")
    args = ap.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyse(data)
    text = render(result)
    errs = expectation_errors(result)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    sys.stdout.write(text)
    if errs:
        for e in errs:
            print("EXPECT_FAIL", e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
