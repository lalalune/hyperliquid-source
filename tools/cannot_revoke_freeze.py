#!/usr/bin/env python3
"""RE-040: cannot-revoke-token-freeze gate at 0x27506c0 (node #94).

Standalone static recovery from the pinned node #94 binary:
  * Carve 0x27506c0..0x27507ce (270 bytes, exclusive end at first int3;
    2-byte int3 pad then next function push-rbp at 0x27507d0);
  * 1 direct e8 inbound at 0x23e804f; no R_X86_64_RELATIVE entry for the
    function start, so no GOT slot and no ff15 callers;
  * Claimed RULE: revoke-freeze refusal. Per-token entry is
    [rsi+0x210] + idx*0xe8. When the freeze-privilege word
    dword [entry+0x10] == 1 (jne not taken) AND the frozen-users count
    qword [entry+0x28] != 0 (je not taken), the function stores
    Err 0xdf + string 0x5999c1 / 64 "cannot revoke token freeze
    privilege when there are frozen users". Claims that gate + string only.
  * Observed but NOT claimed: Ok 0x186 STORE after clearing
    qword [entry+0x10] (privilege not set, or no frozen users after the
    collection drain loop via e8 0x33b1e80); OOB jae to a bounds panic
    via ff15 GOT 0x576e470.

Adjacent: merged #650 (spot-meta inventory) lists 0x27506c0 as an
inventory start/owner only; it does not read the rule, the Err tag or the
string. Output is sorted deterministic JSON. Stdlib only; no emulation.
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

FN = 0x27506C0
FN_END = 0x27507CE
CARVED_LEN = FN_END - FN
CARVED_SHA256 = (
    "0fbf9cf933af697d974cfde82054ba4bb70d6fdb8e18d5acc1b4786390d8fe4f"
)
NEXT_FN = 0x27507D0
R_X86_64_RELATIVE = 8
DIRECT_E8_SITES = (0x23E804F,)

ERR_TAG = 0xDF
OK_186_TAG = 0x186

CMP_OOB_VA = 0x27506CB
JAE_OOB_VA = 0x27506D2
JAE_OOB_TARGET = 0x27507B0
PANIC_GOT = 0x576E470

IMUL_STRIDE_VA = 0x27506E2
CMP_PRIV_VA = 0x27506ED
JNE_PRIV_VA = 0x27506F2
JNE_PRIV_TARGET = 0x2750793
CMP_FROZEN_VA = 0x27506F8
JE_FROZEN_VA = 0x27506FE
JE_FROZEN_TARGET = 0x275071D

ERR_DF_VA = 0x2750700
LEA_STR_VA = 0x2750705
STR_PTR_STORE_VA = 0x275070C
STR_LEN_STORE_VA = 0x2750710
STR_LEN_IMM = 0x40
JMP_RET_VA = 0x2750718
JMP_RET_TARGET = 0x27507A1

DRAIN_CALL_VA = 0x2750786
DRAIN_TARGET = 0x33B1E80
CLEAR_PRIV_VA = 0x2750793
OK_186_STORE_VA = 0x275079C

ERROR_STRING = (
    "cannot_revoke_token_freeze",
    0x5999C1,
    b"cannot revoke token freeze privilege when there are frozen users",
)
STRING_SHA256 = (
    "f2ad5057034d6fec797811f9716cad4e3b84a0c2d5694c29535f957db15043a4"
)

# Same string LEA sites outside this carve (not claimed).
NOT_CLAIMED_LEAS = (0x4D74065, 0x4D74175)

KEY_INSNS = [
    (0x27506C0, "4157", "push r15 (prologue)"),
    (0x27506CB, "483b9618020000", "cmp rdx, [rsi+0x218] (OOB bound)"),
    (0x27506D2, "0f83d8000000", "jae 0x27507b0 (OOB -> bounds panic, not claimed)"),
    (0x27506E2, "4869cae8000000", "imul rcx, rdx, 0xe8 (entry stride)"),
    (0x27506ED, "837c081001", "cmp dword [rax+rcx+0x10], 1 (freeze privilege set)"),
    (0x27506F2, "0f859b000000", "jne 0x2750793 (privilege not set -> clear + Ok)"),
    (0x27506F8, "49837c242800", "cmp qword [r12+0x28], 0 (frozen-users count)"),
    (0x27506FE, "741d", "je 0x275071d (no frozen users -> drain + revoke)"),
    (0x2750700, "66c703df00", "movw [rbx], 0xdf Err STORE (claimed)"),
    (0x2750705, "488d05b592e4fd", "lea rax, [rip+ string 0x5999c1]"),
    (0x275070C, "48894308", "mov [rbx+0x8], rax (string ptr)"),
    (0x2750710, "48c7431040000000", "mov qword [rbx+0x10], 0x40 (len 64)"),
    (0x2750718, "e984000000", "jmp 0x27507a1 (return Err)"),
    (0x2750786, "e8f516c600", "call 0x33b1e80 (collection drain, not claimed)"),
    (0x2750793, "49c744241000000000", "mov qword [r12+0x10], 0 (revoke, not claimed)"),
    (0x275079C, "66c7038601", "movw [rbx], 0x186 Ok STORE (not claimed)"),
    (0x27507B7, "ff15b3dc0103", "ff15 bounds panic via GOT 0x576e470 (not claimed)"),
    (0x23E804F, "e86c863600", "e8 inbound direct call"),
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


def rel32_target(data, segs, va, opcode_len, insn_len):
    b = read_va(data, segs, va, insn_len)
    return va + insn_len + struct.unpack_from("<i", b, opcode_len)[0]


def rel8_target(data, segs, va):
    b = read_va(data, segs, va, 2)
    return va + 2 + struct.unpack_from("<b", b, 1)[0]


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

    relative_to_entry = [
        {"r_offset": hex(off), "r_info": hex(info), "r_addend": hex(addend)}
        for off, info, addend in rela_dyn(data)
        if addend == FN and (info & 0xFFFFFFFF) == R_X86_64_RELATIVE
    ]

    direct_sites = count_direct_calls(data, segs, FN)
    direct_e8 = sorted(va for kind, va in direct_sites if kind == 0xE8)
    direct_e9 = sorted(va for kind, va in direct_sites if kind == 0xE9)

    name, sva, expected = ERROR_STRING
    raw = read_va(data, segs, sva, len(expected))
    occ = string_occurrences(data, expected)
    lea_tgt = rel32_target(data, segs, LEA_STR_VA, 3, 7)
    all_leas = lea_rip_targets(data, segs, sva)
    not_claimed = [hex(v) for v in all_leas if v != LEA_STR_VA]

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
            "bytes": read_va(data, segs, LEA_STR_VA, 7).hex(),
            "target": hex(lea_tgt),
            "targets_string": lea_tgt == sva,
        },
        "lea_rip_refs_primary": [hex(v) for v in all_leas],
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

    cmp_priv = read_va(data, segs, CMP_PRIV_VA, 5)
    jne_priv = read_va(data, segs, JNE_PRIV_VA, 6)
    jne_priv_tgt = rel32_target(data, segs, JNE_PRIV_VA, 2, 6)
    cmp_frozen = read_va(data, segs, CMP_FROZEN_VA, 6)
    je_frozen = read_va(data, segs, JE_FROZEN_VA, 2)
    je_frozen_tgt = rel8_target(data, segs, JE_FROZEN_VA)
    err_bytes = read_va(data, segs, ERR_DF_VA, 5)
    strlen_bytes = read_va(data, segs, STR_LEN_STORE_VA, 8)
    jmp_ret_tgt = rel32_target(data, segs, JMP_RET_VA, 1, 5)
    ok_186 = read_va(data, segs, OK_186_STORE_VA, 5)
    clear_priv = read_va(data, segs, CLEAR_PRIV_VA, 9)
    cmp_oob = read_va(data, segs, CMP_OOB_VA, 7)
    jae_oob = read_va(data, segs, JAE_OOB_VA, 6)
    jae_oob_tgt = rel32_target(data, segs, JAE_OOB_VA, 2, 6)
    drain_tgt = rel32_target(data, segs, DRAIN_CALL_VA, 1, 5)

    # Fall-through geometry: jne (6 bytes) falls to cmp_frozen, je (2 bytes)
    # falls to the Err store.
    fallthrough_ok = (
        JNE_PRIV_VA + 6 == CMP_FROZEN_VA and JE_FROZEN_VA + 2 == ERR_DF_VA
    )

    rule_match = (
        cmp_priv.hex() == "837c081001"
        and jne_priv.hex() == "0f859b000000"
        and jne_priv_tgt == JNE_PRIV_TARGET
        and cmp_frozen.hex() == "49837c242800"
        and je_frozen.hex() == "741d"
        and je_frozen_tgt == JE_FROZEN_TARGET
        and fallthrough_ok
        and err_bytes.hex() == "66c703df00"
        and lea_tgt == sva
        and strlen_bytes.hex() == "48c7431040000000"
        and jmp_ret_tgt == JMP_RET_TARGET
    )

    rules = [
        {
            "name": "cannot_revoke_token_freeze_err",
            "claimed": True,
            "description": (
                "refuse to revoke the token freeze privilege while users "
                "are frozen: privilege word == 1 and frozen-users count != 0 "
                "falls through to Err 0xdf + string cannot revoke token "
                "freeze privilege when there are frozen users"
            ),
            "cmp_priv_va": hex(CMP_PRIV_VA),
            "cmp_priv_bytes": cmp_priv.hex(),
            "jne_priv_va": hex(JNE_PRIV_VA),
            "jne_priv_bytes": jne_priv.hex(),
            "jne_priv_target": hex(jne_priv_tgt),
            "cmp_frozen_va": hex(CMP_FROZEN_VA),
            "cmp_frozen_bytes": cmp_frozen.hex(),
            "je_frozen_va": hex(JE_FROZEN_VA),
            "je_frozen_bytes": je_frozen.hex(),
            "je_frozen_target": hex(je_frozen_tgt),
            "fallthrough_to_err": fallthrough_ok,
            "proof": {
                "frozen_users_takes_err": (
                    "dword [entry+0x10]==1 so jne @ 0x27506f2 not taken; "
                    "qword [entry+0x28]!=0 so je @ 0x27506fe not taken; "
                    "falls to 0x2750700 Err 0xdf + lea string + len 0x40, "
                    "jmp to epilogue 0x27507a1"
                ),
                "privilege_not_set": (
                    "jne -> 0x2750793 clears [entry+0x10] and stores Ok "
                    "0x186 (observed, not claimed)"
                ),
                "no_frozen_users": (
                    "je -> 0x275071d drains the collection via e8 0x33b1e80 "
                    "then clears and stores Ok 0x186 (observed, not claimed)"
                ),
                "oob_panic": (
                    "cmp [rsi+0x218],rdx / jae -> bounds panic via ff15 "
                    "(observed, not claimed)"
                ),
            },
            "match": rule_match,
            "negative": (
                "tamper jne_priv / je_frozen / cmp bytes -> rule pin fails"
            ),
            "err_string": "cannot_revoke_token_freeze",
        },
    ]

    negatives = {
        "cmp_priv_bytes_match": cmp_priv.hex() == "837c081001",
        "jne_priv_bytes_match": jne_priv.hex() == "0f859b000000",
        "jne_priv_targets_clear": jne_priv_tgt == CLEAR_PRIV_VA,
        "cmp_frozen_bytes_match": cmp_frozen.hex() == "49837c242800",
        "je_frozen_bytes_match": je_frozen.hex() == "741d",
        "je_frozen_targets_drain": je_frozen_tgt == JE_FROZEN_TARGET,
        "fallthrough_to_err": fallthrough_ok,
        "err_df_movw_store": err_bytes.hex() == "66c703df00",
        "string_exact": error_string["match"] and error_string["len"] == 64,
        "string_sha256_pin": error_string["sha256"] == STRING_SHA256,
        "string_len_imm_0x40": strlen_bytes.hex() == "48c7431040000000",
        "lea_targets_string": lea_tgt == sva,
        "occurrence_count_is_1": error_string["occurrence_count"] == 1,
        "err_jmp_to_epilogue": jmp_ret_tgt == JMP_RET_TARGET,
        "direct_e8_is_1": direct_e8 == list(DIRECT_E8_SITES),
        "no_direct_e9": len(direct_e9) == 0,
        "no_relative_to_entry": relative_to_entry == [],
        "ok_186_store_observed": ok_186.hex() == "66c7038601",
        "clear_priv_store_observed": clear_priv.hex() == "49c744241000000000",
        "oob_jae_targets_panic": jae_oob_tgt == JAE_OOB_TARGET,
        "drain_call_target": drain_tgt == DRAIN_TARGET,
        "not_claimed_leas_are_outside_carve": all(
            not (FN <= int(v, 16) < FN_END) for v in not_claimed
        ),
        "not_claimed_lea_list_matches": not_claimed
        == [hex(v) for v in NOT_CLAIMED_LEAS],
    }

    result = {
        "abi": {
            "err_tag": hex(ERR_TAG),
            "err_tag_va": hex(ERR_DF_VA),
            "err_tag_bytes": err_bytes.hex(),
            "err_tag_kind": "movw_store",
            "err_note": (
                "Err 0xdf is a movw STORE at 0x2750700 reached by fall-"
                "through when the privilege word is 1 and the frozen-users "
                "count is non-zero. Claimed with the string only."
            ),
            "ok_186_tag": hex(OK_186_TAG),
            "ok_186_kind": "movw_store",
            "ok_186_claimed": False,
        },
        "adjacent_prior_work": {
            "sibling": None,
            "inventory_only": [
                {
                    "pr": 650,
                    "component": "spot-meta-inventory-94",
                    "entry": hex(FN),
                    "note": (
                        "Merged #650 lists 0x27506c0 as an inventory "
                        "start/owner only. It does not read the "
                        "privilege/frozen-users gate, Err 0xdf, or string "
                        "0x5999c1."
                    ),
                }
            ],
        },
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
        "claim": "cannot_revoke_token_freeze_err_only",
        "component": "RE-040",
        "direct_call_sites": [hex(v) for v in direct_e8],
        "direct_calls": len(direct_e8) + len(direct_e9),
        "direct_e9_calls": len(direct_e9),
        "error_strings": [error_string],
        "extent": {
            "carve_note": (
                "Exclusive end 0x27507ce is the first int3 after the "
                "landing-pad tail; 2-byte int3 pad then next function "
                "begins at push-rbp 0x27507d0."
            ),
            "fde_end_exclusive": hex(FN_END),
            "fde_start": hex(FN),
            "int3_pad_len": int3_pad,
            "int3_padding_at_fde_end": int3_pad > 0,
            "next_fn_bytes": next_fn_bytes.hex(),
            "next_fn_is_push_rbp": next_fn_bytes[:1] == bytes([0x55]),
            "next_fn_va": hex(next_fn_va),
        },
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
            "panic_got": hex(PANIC_GOT),
            "claimed": False,
        },
        "rules": rules,
        "string_len_immediate": {
            "va": hex(STR_LEN_STORE_VA),
            "bytes": strlen_bytes.hex(),
            "value": STR_LEN_IMM,
            "match": strlen_bytes.hex() == "48c7431040000000",
        },
        "unclaimed_ok_tags": [
            {
                "tag": hex(OK_186_TAG),
                "va": hex(OK_186_STORE_VA),
                "bytes": ok_186.hex(),
                "kind": "movw_store",
                "claimed": False,
                "note": "revoke Ok 0x186 STORE after clearing [entry+0x10]; not claimed",
            },
        ],
        "unclaimed_observations": [
            {
                "name": "collection_drain_loop",
                "note": "e8 0x33b1e80 loop at 0x2750786 drains the frozen-users collection; not claimed",
            },
            {
                "name": "not_claimed_leas_same_string",
                "note": (
                    "LEA sites 0x4d74065 and 0x4d74175 also target the "
                    "same string; outside this carve; not claimed"
                ),
            },
            {
                "name": "oob_bounds_panic",
                "note": "jae 0x27507b0 -> ff15 bounds panic via GOT 0x576e470; not claimed",
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
    if result["direct_call_sites"] != [hex(v) for v in DIRECT_E8_SITES]:
        errs.append("direct_call_sites mismatch")
    if result["got_relative_to_entry"] != []:
        errs.append("unexpected RELATIVE reloc to entry")
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
