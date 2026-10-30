#!/usr/bin/env python3
"""RE-008 consensus error tags: decode the niche-tag table of node #94.

Stdlib only; deterministic; fail-closed on the pinned SHA-256 and on malformed
input. Reuses the ELF / FDE / relocation readers in ``tools/state_roots.py``
via ``importlib`` (as ``tools/state_hashers.py`` does) instead of duplicating
them.

Addresses are linked virtual addresses; an instruction start includes any REX
prefix. The tool computes:

1.  The niche-tag -> name table, decoded independently from the jump tables of
    three niche-dispatch formatter monomorphs: ``0x4753d60`` (table
    ``0x6f9c44``, serde_json-shaped) and ``0x44c4480`` (table ``0x6f2af0``) and
    ``0x244e3f0`` (table ``0x3e23e8``), both core::fmt-shaped. Each dispatch
    head must match pinned bytes (select + tail) with rcx = 2^63 and rax =
    word0 established by constant/provenance tracking. Each arm is walked; the
    first rodata string it hands to a writer is the name. The three copies
    must agree on (name, length) for every tag.
2.  The table bound, from the in-FDE run of each jump table.
3.  A cross-check against a fourth niche-dispatch monomorph (``0x4752890``,
    table ``0x6f9b9c``) whose arms pass an explicit index in ``ecx`` next to
    the variant name.
4.  A census of niche-form constants (``movabs r, 0x80000000000000xx``) in
    seven named consensus FDEs: every 64-bit store and compare each constant
    reaches by register constant propagation, with the store destination; and
    binary-wide counts of the same immediates as the out-of-scope denominator.
5.  Corrections, as data, against the can1357 reference enum and the merged
    RE-008 ``consensus-wire.json`` tag inventory.

The names are the strings the formatters write. They are not claimed to be the
Rust identifiers, and census values carry them only conditionally
(``variant_if_same_enum``): that the census FDEs build the same enum the
formatters dispatch on is an inference, not an observation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("state_roots", ROOT / "tools/state_roots.py")
sr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sr)
EvidenceError = sr.EvidenceError
EXPECTED_SHA256 = sr.EXPECTED_SHA256
TARGET = ROOT / "artifacts/node/94/hl-node"

NICHE = 0x8000000000000000
MASK = (1 << 64) - 1
REG = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
RAX, RCX, RDX, RSP, RSI, RDI, R8, R9 = 0, 1, 2, 4, 6, 7, 8, 9
CALLER_SAVED = frozenset([0, 1, 2, 6, 7, 8, 9, 10, 11])  # rax rcx rdx rsi rdi r8-r11
NEXT_ARG = {RDI: RSI, RSI: RDX, RDX: RCX, RCX: R8, R8: R9}  # SysV (ptr, len) pairing

# Pinned dispatch bytes. SELECT = xor rcx,rax; test rax,rax; mov eax,0x27;
# cmovs rax,rcx. TAIL = movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax.
SELECT = bytes.fromhex("4831c1" "4885c0" "b827000000" "480f48c1")
TAIL = bytes.fromhex("48630481" "4801c8" "ffe0")
LEA_RCX_RIP = bytes.fromhex("488d0d")
DEFAULT_OFF = 7  # offset of the mov eax imm32 inside SELECT
CMOVS_OFF = 11   # offset of cmovs inside SELECT

# (FDE start, pinned jump table, required provenance of word0 in rax).
FORMATTERS = (
    (0x4753D60, 0x6F9C44, "*rdi"),
    (0x44C4480, 0x6F2AF0, "*rdi"),
    (0x244E3F0, 0x3E23E8, "**rdi"),
)
VARIANT_INDEX_MONOMORPH = (0x4752890, 0x6F9B9C, "*rsi")
TABLE_SCAN_CAP = 256

_CAN = ("can1357 node/consensus/signed.rs header comment (IDA rename of seed {seed}) at "
        "commit 999556f6e0a474b8312db96ec3149e1c44e97c23, as adopted by the merged RE-008 "
        "packet (#25) verifiers record; unverified lead")
# The seven consensus FDEs whose niche constants are censused, chosen by
# provenance (not by a closure rule): (FDE start, lead label, its source, why).
CONSENSUS_FDES = (
    (0x47B01B0, "verify_signed_block", _CAN.format(seed="0x47B01B0"),
     "merged #25 verifiers record (verify_signed_block)"),
    (0x4758D70, "verify_qc", _CAN.format(seed="0x4758D70"),
     "merged #25 verifiers record (verify_qc)"),
    (0x47594F0, "verify_tc", _CAN.format(seed="0x47594F0"),
     "merged #25 verifiers record (verify_tc)"),
    (0x454AA10, "verify_signed_timeout", _CAN.format(seed="0x454AA10"),
     "merged #25 verifiers record (verify_signed_timeout)"),
    (0x4B31E70, None, None,
     "callee of 0x47b01b0 through slot 0x5773628 (merged #25 verifiers edge); open PR #49 "
     "labels calls through that slot round_history_lookup (unmerged, not adopted)"),
    (0x44AB560, None, None,
     "merged #25 function with node/src/consensus/state.rs Locations; direct callee of 0x44adfa0"),
    (0x44ADFA0, "state_dispatch", "open PR #49 (unmerged); unverified lead",
     "merged #25 function with node/src/consensus/state.rs Locations"),
)

# can1357 ConsensusRpcError variants, in source order (node/consensus/types.rs
# of the unlicensed reference tree, commit 999556f6). Data only: the diff below
# is computed against the binary-derived table, not the other way round.
CAN1357_COMMIT = "999556f6e0a474b8312db96ec3149e1c44e97c23"
CAN1357_ENUM = (
    "Error", "SignableContent", "VerifySignature", "VerifyQcSignature", "BadBlockRound",
    "BadBlockQcRound", "BadBlockTcRound", "BlockAlreadyRegistered", "QcRoundBeforeHardfork",
    "QcNoQuorum", "TcNoQuorum", "TcNoTimeout", "EmptyValidators", "DuplicateBlockRound",
    "TimeoutRoundMismatch", "AlreadyHaveTimeoutFromNode", "RpcNotFound", "RpcRoundRobin",
    "RpcPeerNoClientBlocks", "ClientBlockQcRound", "ClientBlockQcHash", "ClientBlockTx",
    "ClientBlockTxHashes", "ClientBlockTime", "ClientBlockMissingCommitProof",
    "ClientBlockMissingTxCommitProof", "ChildQcCommitProof", "GrandchildQcCommitProof",
    "Consecutive", "PeerTimedOut", "IncorrectRpcResponseVariant",
)
# The merged RE-008 consensus-wire.json inventories this as one tag literal, and
# records these lea sites for its anchors (tags[].anchors[].lea_sites).
MERGED_RE008_DISPUTED_TOKEN = "ClientBlockMissingTxCommitProof"
MERGED_RE008_LEA_SITES = (0x244ED87, 0x44C4E77, 0x4753850, 0x475527E)
TOKEN_A, TOKEN_B = "ClientBlockMissingTx", "CommitProofChildQc"


# --------------------------------------------------------------------------- #
# x86-64 decoder: instruction length plus the register semantics the walkers  #
# need. Fail-closed: an opcode it cannot size raises EvidenceError.           #
# kinds: movabs/movimm/addimm/subimm/inc/dec/lea/movrr/addrr/subrr/load/      #
#        store/cmp/call/callind/clobber/nowrite/flow.                         #
# clobber det = tuple of further registers written. 64-bit-only kinds:        #
# movrr/addrr/subrr/addimm/subimm/inc/dec (narrower forms are clobbers).      #
# flow det: ("ret",) | ("trap",) | ("jmp", off) | ("jcc", off) | ("jmpind",)  #
# where off is start-relative (caller adds the window base).                  #
# --------------------------------------------------------------------------- #
PREFIXES = (0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65)
SSE_NOWRITE = frozenset((
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
    0x1D, 0x1E, 0x1F, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
    0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
    0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x74, 0x75, 0x76, 0x7E, 0x7F, 0xA3, 0xAB, 0xB3,
    0xBB, 0xC3, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC,
    0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE8, 0xE9, 0xEA, 0xEB,
    0xEC, 0xED, 0xEE, 0xEF, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF8, 0xF9, 0xFA,
    0xFB, 0xFC, 0xFD, 0xFE))


def _modrm(code, i, R, B, X):
    m = code[i]
    mod = m >> 6
    reg = ((m >> 3) & 7) | (8 if R else 0)
    rm = m & 7
    n = 1
    base = None
    index = None
    disp = 0
    rip = False
    if mod != 3 and rm == 4:
        sib = code[i + 1]
        n += 1
        bs = (sib & 7) | (8 if B else 0)
        idx = ((sib >> 3) & 7) | (8 if X else 0)
        if idx != 4:
            index = idx
        if mod == 0 and (sib & 7) == 5:
            disp = struct.unpack_from("<i", code, i + n)[0]
            n += 4
        else:
            base = bs
    elif mod == 0 and rm == 5:
        rip = True
        disp = struct.unpack_from("<i", code, i + 1)[0]
        n += 4
    else:
        base = rm | (8 if B else 0)
    if mod == 1:
        disp = struct.unpack_from("<b", code, i + n)[0]
        n += 1
    elif mod == 2:
        disp = struct.unpack_from("<i", code, i + n)[0]
        n += 4
    rmreg = rm | (8 if B else 0)
    return n, mod, reg, rmreg, base, index, disp, rip


def _r8(r, rex):
    """Full register written by an 8-bit operand (ah/ch/dh/bh without REX)."""
    return r - 4 if (not rex and 4 <= r <= 7) else r


def decode(code, i):
    start = i
    op66 = a67 = f3 = False
    while code[i] in PREFIXES:
        if code[i] == 0x66:
            op66 = True
        elif code[i] == 0x67:
            a67 = True
        elif code[i] == 0xF3:
            f3 = True
        i += 1
    rex = 0
    if 0x40 <= code[i] <= 0x4F:
        rex = code[i]
        i += 1
    W, R, X, B = bool(rex & 8), bool(rex & 4), bool(rex & 2), bool(rex & 1)
    width = 8 if W else (2 if op66 else 4)
    op = code[i]
    i += 1
    if op == 0x0F:
        op2 = code[i]
        i += 1
        if 0x80 <= op2 <= 0x8F:
            rel = struct.unpack_from("<i", code, i)[0]
            i += 4
            return i - start, "flow", None, ("jcc", i - start + rel)
        if op2 == 0x0B:  # ud2
            return i - start, "flow", None, ("trap",)
        # two-byte ops that take a ModRM and write a general register.
        if op2 in (0xB6, 0xB7, 0xBE, 0xBF, 0xAF, 0xBC, 0xBD, 0x50, 0xD7, 0xB0, 0xB1,
                   0xC0, 0xC1) or (0x40 <= op2 <= 0x4F):
            n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
            rm_w = (_r8(rmreg, rex) if op2 in (0xB0, 0xC0) else rmreg)
            if op2 in (0xB0, 0xB1):  # cmpxchg r/m, r: writes rax and r/m
                return i - start + n, "clobber", RAX, ((rm_w,) if mod == 3 else ())
            if op2 in (0xC0, 0xC1):  # xadd r/m, r: writes r and r/m
                return i - start + n, "clobber", (_r8(reg, rex) if op2 == 0xC0 else reg), \
                    ((rm_w,) if mod == 3 else ())
            return i - start + n, "clobber", reg, ()
        if 0x90 <= op2 <= 0x9F:  # setcc r/m8
            n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
            if mod == 3:
                return i - start + n, "clobber", _r8(rmreg, rex), ()
            return i - start + n, "nowrite", None, None
        if op2 == 0x38:  # three-byte 0f 38 (modrm, no imm)
            op3 = code[i]
            i += 1
            n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
            if op3 in (0xF0, 0xF1):  # movbe / crc32: may write reg
                return i - start + n, "clobber", reg, ()
            return i - start + n, "nowrite", None, None
        if op2 == 0x3A:  # three-byte 0f 3a (modrm + imm8)
            op3 = code[i]
            i += 1
            n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
            if op3 in (0x14, 0x15, 0x16, 0x17) and mod == 3:  # pextr*/extractps r/m
                return i - start + n + 1, "clobber", rmreg, ()
            return i - start + n + 1, "nowrite", None, None
        if op2 in (0x71, 0x72, 0x73, 0x70, 0xC2, 0xC4, 0xC5, 0xC6):  # modrm + imm8 (SSE/MMX)
            n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
            i += n + 1
            if op2 == 0xC5:  # pextrw r32
                return i - start, "clobber", reg, ()
            return i - start, "nowrite", None, None
        if op2 in SSE_NOWRITE:  # SSE/MMX/bit ops with a ModRM and no immediate
            n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
            if op2 == 0x7E and not f3 and mod == 3:  # movd/movq r/m, (x)mm
                return i - start + n, "clobber", rmreg, ()
            if op2 in (0x2C, 0x2D):  # cvt(t)s?2si r, xmm/m
                return i - start + n, "clobber", reg, ()
            if op2 in (0xAB, 0xB3, 0xBB) and mod == 3:  # bts/btr/btc r/m, r
                return i - start + n, "clobber", rmreg, ()
            return i - start + n, "nowrite", None, None
        if op2 in (0x05, 0x06, 0x07, 0x08, 0x09, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x77,
                   0xA2, 0xA0, 0xA1, 0xA8, 0xA9):
            if op2 == 0x05:  # syscall
                return i - start, "clobber", RAX, (RCX, 11)
            if op2 in (0x31, 0x32, 0x33):  # rdtsc / rdmsr / rdpmc
                return i - start, "clobber", RAX, (RDX,)
            if op2 == 0xA2:  # cpuid
                return i - start, "clobber", RAX, (RCX, RDX, 3)
            return i - start, "nowrite", None, None
        raise EvidenceError(f"unsupported 0f {op2:02x} at offset {start}")
    if op in (0x88, 0x89, 0x8A, 0x8B):
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        i += n
        w = 1 if op in (0x88, 0x8A) else width
        if op in (0x88, 0x89):
            if mod == 3:
                if w == 8:
                    return i - start, "movrr", rmreg, ("src", reg)
                return i - start, "clobber", (_r8(rmreg, rex) if w == 1 else rmreg), ()
            return i - start, "store", None, ("base", base, "index", index, "disp", disp,
                                              "src", (_r8(reg, rex) if w == 1 else reg),
                                              "rip", rip, "width", w)
        if mod == 3:
            if w == 8:
                return i - start, "movrr", reg, ("src", rmreg)
            return i - start, "clobber", (_r8(reg, rex) if w == 1 else reg), ()
        return i - start, "load", (_r8(reg, rex) if w == 1 else reg), \
            ("base", base, "index", index, "disp", disp, "rip", rip, "width", w)
    if op == 0x8D:
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        return i - start + n, "lea", reg, ("base", base, "index", index, "disp", disp, "rip", rip,
                                           "width", (4 if a67 and width == 8 else width))
    if op == 0x63:  # movsxd r64, r/m32
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        return i - start + n, "clobber", reg, ()
    if op in (0x00, 0x02, 0x08, 0x0A, 0x10, 0x12, 0x18, 0x1A, 0x20, 0x22, 0x28, 0x2A, 0x30, 0x32,
              0x38, 0x3A):  # 8-bit ALU
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        i += n
        if op in (0x38, 0x3A):
            return i - start, "cmp", None, None
        if (op & 2) == 0 and mod != 3:
            return i - start, "nowrite", None, None
        return i - start, "clobber", _r8(reg if (op & 2) else rmreg, rex), ()
    if op in (0x01, 0x03, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33):
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        i += n
        if op & 2:  # r, r/m -> writes reg
            return i - start, "clobber", reg, ()
        if mod == 3:
            if W and op == 0x01:
                return i - start, "addrr", rmreg, ("src", reg)
            if W and op == 0x29:
                return i - start, "subrr", rmreg, ("src", reg)
            return i - start, "clobber", rmreg, ()
        return i - start, "nowrite", None, None
    if op in (0x39, 0x3B):
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        return i - start + n, "cmp", None, ("a", reg, "b", (rmreg if mod == 3 else None),
                                            "width", width)
    if op == 0x3D:
        return i - start + (2 if op66 else 4), "cmp", None, ("a", RAX, "b", "imm", "width", width)
    if op in (0x83, 0x81):
        ext = (code[i] >> 3) & 7
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        if op == 0x83:
            imm = struct.unpack_from("<b", code, i + n)[0]
            i += n + 1
        else:
            imm = struct.unpack_from("<i", code, i + n)[0]
            i += n + (2 if op66 else 4)
        target = rmreg if mod == 3 else None
        if ext == 7:
            return i - start, "cmp", None, ("a", target, "b", "imm", "width", width)
        if ext in (0, 5) and mod == 3 and W:
            return i - start, ("addimm" if ext == 0 else "subimm"), target, imm
        if mod == 3:
            return i - start, "clobber", target, ()
        return i - start, "nowrite", None, None
    if op == 0x80:  # group1 r/m8, imm8
        ext = (code[i] >> 3) & 7
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        i += n + 1
        if ext == 7:
            return i - start, "cmp", None, None
        if mod == 3:
            return i - start, "clobber", _r8(rmreg, rex), ()
        return i - start, "nowrite", None, None
    if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xC6, 0xC7, 0x69, 0x6B):
        ext = (code[i] >> 3) & 7
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        i += n
        byte_op = op in (0xC0, 0xD0, 0xD2, 0xF6, 0xC6)
        rm_w = _r8(rmreg, rex) if byte_op else rmreg
        if op in (0xC0, 0xC1):
            i += 1
        elif op == 0xC6:
            i += 1
        elif op == 0xC7:
            imm = struct.unpack_from("<i", code, i)[0]
            i += (2 if op66 else 4)
            if mod == 3 and ext == 0 and not op66:
                return i - start, "movimm", rmreg, (imm & MASK) if W else (imm & 0xFFFFFFFF)
            return (i - start, "clobber", rmreg, ()) if mod == 3 else (i - start, "nowrite", None, None)
        elif op == 0x69:
            i += (2 if op66 else 4)
            return i - start, "clobber", reg, ()
        elif op == 0x6B:
            i += 1
            return i - start, "clobber", reg, ()
        elif op == 0xF6 and ext in (0, 1):
            i += 1
        elif op == 0xF7 and ext in (0, 1):
            i += (2 if op66 else 4)
        if op in (0xF6, 0xF7):
            if ext in (0, 1):  # test
                return i - start, "nowrite", None, None
            if ext in (2, 3):  # not / neg r/m
                return (i - start, "clobber", rm_w, ()) if mod == 3 else (i - start, "nowrite", None, None)
            return i - start, "clobber", RAX, ((RDX,) if op == 0xF7 else ())  # mul/imul/div/idiv
        if mod == 3:
            return i - start, "clobber", rm_w, ()
        return i - start, "nowrite", None, None
    if 0xB8 <= op <= 0xBF:
        reg = (op - 0xB8) | (8 if B else 0)
        if W:
            imm = struct.unpack_from("<Q", code, i)[0]
            return i - start + 8, "movabs", reg, imm
        imm = struct.unpack_from("<I", code, i)[0]
        if op66:
            return i - start + 4, "clobber", reg, ()
        return i - start + 4, "movimm", reg, imm
    if 0xB0 <= op <= 0xB7:
        return i - start + 1, "clobber", _r8((op - 0xB0) | (8 if B else 0), rex), ()
    if 0x50 <= op <= 0x57:
        return i - start, "nowrite", None, None
    if 0x58 <= op <= 0x5F:
        return i - start, "clobber", (op - 0x58) | (8 if B else 0), ()
    if op == 0xE8:
        rel = struct.unpack_from("<i", code, i)[0]
        i += 4
        return i - start, "call", None, ("rel", i - start + rel)
    if op == 0xE9:
        rel = struct.unpack_from("<i", code, i)[0]
        i += 4
        return i - start, "flow", None, ("jmp", i - start + rel)
    if op == 0xEB:
        rel = struct.unpack_from("<b", code, i)[0]
        i += 1
        return i - start, "flow", None, ("jmp", i - start + rel)
    if 0x70 <= op <= 0x7F:
        rel = struct.unpack_from("<b", code, i)[0]
        i += 1
        return i - start, "flow", None, ("jcc", i - start + rel)
    if op in (0x84, 0x85):
        n = _modrm(code, i, R, B, X)[0]
        return i - start + n, "nowrite", None, None
    if op in (0x86, 0x87):  # xchg r/m, r: writes both
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        f = (lambda r: _r8(r, rex)) if op == 0x86 else (lambda r: r)
        return i - start + n, "clobber", f(reg), ((f(rmreg),) if mod == 3 else ())
    if op == 0xA8:
        return i - start + 1, "nowrite", None, None
    if op == 0xA9:
        return i - start + (2 if op66 else 4), "nowrite", None, None
    if op in (0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34):
        return i - start + 1, "clobber", RAX, ()
    if op == 0x3C:
        return i - start + 1, "cmp", None, None
    if op in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35):
        return i - start + (2 if op66 else 4), "clobber", RAX, ()
    if op == 0x68:
        return i - start + 4, "nowrite", None, None
    if op == 0x6A:
        return i - start + 1, "nowrite", None, None
    if op == 0x98:
        return i - start, "clobber", RAX, ()
    if op == 0x99:
        return i - start, "clobber", RDX, ()
    if op in (0xCC, 0xF4):  # int3 / hlt
        return i - start, "flow", None, ("trap",)
    if op in (0x90, 0x9C, 0x9D, 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD):
        return i - start, "nowrite", None, None
    if op in (0xC3, 0xC2):
        return (i - start + 2 if op == 0xC2 else i - start), "flow", None, ("ret",)
    if op in (0xFE, 0xFF):
        ext = (code[i] >> 3) & 7
        n, mod, reg, rmreg, base, index, disp, rip = _modrm(code, i, R, B, X)
        i += n
        if op == 0xFF and ext == 2:
            how = ("rip", disp) if rip else (("reg", rmreg) if mod == 3 else ("mem",))
            return i - start, "callind", None, how
        if op == 0xFF and ext in (4, 5):
            return i - start, "flow", None, ("jmpind",)
        if op == 0xFF and ext == 6:  # push r/m
            return i - start, "nowrite", None, None
        if mod != 3:
            return i - start, "nowrite", None, None
        if ext in (0, 1) and op == 0xFF and W:
            return i - start, ("inc" if ext == 0 else "dec"), rmreg, None
        return i - start, "clobber", (_r8(rmreg, rex) if op == 0xFE else rmreg), ()
    raise EvidenceError(f"unsupported opcode {op:02x} at offset {start}")


# --------------------------------------------------------------------------- #
class Target:
    """The pinned binary plus the readers borrowed from state_roots."""

    def __init__(self, data):
        self.elf = sr.Elf(data)
        self.starts, self.ends = sr.fde_index(self.elf)
        self.t_va, t_off, t_size = self.elf.sections[".text"]
        self.text = data[t_off:t_off + t_size]
        if len(self.text) != t_size:
            raise EvidenceError(".text is truncated")
        self.ro_va, ro_off, ro_size = self.elf.sections[".rodata"]
        self.ro_hi = self.ro_va + ro_size
        self._relocs = None

    @property
    def relocs(self):
        if self._relocs is None:
            self._relocs = sr.relative_relocs(self.elf)
        return self._relocs

    def fde(self, va):
        c = sr.containing(self.starts, self.ends, va)
        if c is None or c[0] != va:
            raise EvidenceError(f"{va:#x} is not an FDE start")
        return c

    def rostr(self, va, n):
        if not (self.ro_va <= va and va + n <= self.ro_hi):
            return None
        o = self.elf.off(va)
        b = self.elf.data[o:o + n]
        if len(b) == n and all(32 <= c < 127 for c in b):
            return b.decode()
        return None

    def sweep(self, lo, hi):
        """Linear-sweep decode of [lo, hi); the decoder is length-validated
        against GNU objdump at every instruction start of the FDEs used here."""
        out = []
        va = lo
        while va < hi:
            ln, kind, dst, det = decode(self.text, va - self.t_va)
            out.append((va, ln, kind, dst, det))
            va += ln
        if va != hi:
            raise EvidenceError(f"linear decode of [{lo:#x},{hi:#x}) overruns the FDE end")
        return out


def _writes(kind, dst, det):
    regs = set()
    if dst is not None and kind not in ("store", "cmp", "nowrite", "flow", "call", "callind"):
        regs.add(dst)
    if kind == "clobber" and det:
        regs.update(det)
    return regs


# --------------------------------------------------------------------------- #
# Dispatch head: rax = word0 (provenance-tracked), rcx = 2^63 (constant-       #
# tracked), then the pinned SELECT bytes, then lea rcx,[rip+table], then the  #
# pinned TAIL bytes. Everything else fails closed.                            #
# --------------------------------------------------------------------------- #
def read_dispatch(t, fn, table_hint, word0_expected):
    lo, hi = t.fde(fn)
    code = t.text
    val = {RDI: ("sym", "rdi", None), RSI: ("sym", "rsi", None)}
    origin = {}
    va = fn
    steps = 0
    while True:
        if va >= hi or steps >= 64:
            raise EvidenceError(f"dispatch select bytes not found at {fn:#x}")
        o = va - t.t_va
        if code[o:o + len(SELECT)] == SELECT:
            break
        ln, kind, dst, det = decode(code, o)
        if kind in ("flow", "call", "callind"):
            raise EvidenceError(f"dispatch select bytes not found before the first branch at {fn:#x}")
        if kind == "movabs":
            val[dst] = ("const", det, va)
            origin[dst] = va
        elif kind == "load" and det[9] == 8 and det[3] is None and det[5] == 0 and not det[7] \
                and val.get(det[1], ("", None, None))[0] == "sym":
            val[dst] = ("sym", "*" + val[det[1]][1], va)
        elif kind == "lea" and det[9] == 8 and not det[7] and det[3] is None \
                and val.get(det[1], ("", None, None))[0] == "const":
            val[dst] = ("const", (val[det[1]][1] + det[5]) & MASK, va)
            origin[dst] = origin.get(det[1])
        elif kind == "movrr":
            if det[1] in val:
                val[dst] = val[det[1]]
                origin[dst] = origin.get(det[1])
            else:
                val.pop(dst, None)
        else:
            for r in _writes(kind, dst, det):
                val.pop(r, None)
        va += ln
        steps += 1
    select = va
    rcx = val.get(RCX)
    if not rcx or rcx[0] != "const" or rcx[1] != NICHE:
        raise EvidenceError(f"dispatch rcx != 2^63 at the select bytes of {fn:#x}")
    rax = val.get(RAX)
    if not rax or rax[0] != "sym" or rax[1] != word0_expected:
        got = rax[1] if rax else None
        raise EvidenceError(f"dispatch word0 provenance {got} != {word0_expected} at {fn:#x}")
    # after SELECT: only non-branching instructions that leave rax/rcx alone,
    # then lea rcx,[rip+table] and the pinned TAIL bytes.
    va = select + len(SELECT)
    for _ in range(8):
        o = va - t.t_va
        if code[o:o + 3] == LEA_RCX_RIP:
            break
        ln, kind, dst, det = decode(code, o)
        if kind in ("flow", "call", "callind") or _writes(kind, dst, det) & {RAX, RCX}:
            raise EvidenceError(f"dispatch lea rcx,[rip+table] not found at {fn:#x}")
        va += ln
    else:
        raise EvidenceError(f"dispatch lea rcx,[rip+table] not found at {fn:#x}")
    lea = va
    table = lea + 7 + struct.unpack_from("<i", code, lea - t.t_va + 3)[0]
    tail = lea + 7
    if code[tail - t.t_va:tail - t.t_va + len(TAIL)] != TAIL:
        raise EvidenceError(f"dispatch tail bytes (movsxd/add/jmp rax) differ at {fn:#x}")
    if table != table_hint:
        raise EvidenceError(f"dispatch table {table:#x} != pinned {table_hint:#x} at {fn:#x}")
    prod = rcx[2]
    prod_ln = decode(code, prod - t.t_va)[0]
    return {
        "fde": fn, "fde_end": hi, "table": table,
        "word0": rax[1], "word0_load": rax[2],
        "rcx_2pow63": prod, "rcx_2pow63_origin": origin.get(RCX),
        "rcx_2pow63_bytes": code[prod - t.t_va:prod - t.t_va + prod_ln].hex(),
        "select": select, "cmovs": select + CMOVS_OFF, "lea_table": lea, "tail": tail,
        "default_index": struct.unpack_from("<I", SELECT, DEFAULT_OFF)[0],
        "select_bytes": SELECT.hex(), "tail_bytes": TAIL.hex(),
        "core_contiguous": prod + prod_ln == select,
    }


def read_table_run(t, fn, table):
    """Entries of an sdata4 jump table up to the first that leaves the FDE."""
    lo, hi = t.fde(fn)
    run = []
    for k in range(TABLE_SCAN_CAP):
        rel = struct.unpack_from("<i", t.elf.read(table + 4 * k, 4))[0]
        tgt = table + rel
        if not lo <= tgt < hi:
            return run, (k, tgt)
        run.append(tgt)
    raise EvidenceError(f"table {table:#x} has no out-of-FDE entry within {TABLE_SCAN_CAP}")


# --------------------------------------------------------------------------- #
# Arm walker: the ordered rodata strings an arm writes. The first is the      #
# name; later ones (len >= 2) are field keys. Follows unconditional jmps      #
# (incl. the tail-call ``jmp reg`` writer) and takes jcc fall-through. It     #
# fails closed if it leaves the FDE or exhausts its budget.                   #
# --------------------------------------------------------------------------- #
def walk_arm(t, lo, hi, arm, arm_set, budget=800):
    code = t.text
    ip = arm
    seen = set()
    strings = []
    sinks = []
    len_sites = []
    plea = plen = plen_site = None
    steps = 0
    while ip not in seen:
        if not lo <= ip < hi:
            raise EvidenceError(f"arm {arm:#x} walk left the FDE at {ip:#x}")
        if steps >= budget:
            raise EvidenceError(f"arm {arm:#x} walk exceeded {budget} instructions")
        seen.add(ip)
        steps += 1
        ln, kind, dst, det = decode(code, ip - t.t_va)
        if kind == "lea" and dst == RSI and det[7]:  # lea rsi,[rip+disp]
            tgt = ip + ln + det[5]
            if t.ro_va <= tgt < t.ro_hi:
                plea = tgt
        elif kind == "movimm" and dst == RDX:      # mov edx, len
            plen, plen_site = det, ip
        elif kind in ("call", "callind"):
            if plea is not None and plen is not None:
                s = t.rostr(plea, plen)
                if s is not None:
                    strings.append((plea, plen, s))
                    sinks.append(f"call_rel32 {ip + det[1]:#x}" if kind == "call" else "call_indirect")
                    len_sites.append(plen_site)
                plea = plen = None
        if kind == "flow":
            what = det[0]
            if what in ("ret", "trap"):
                break
            if what == "jmpind":
                if plea is not None and plen is not None:
                    s = t.rostr(plea, plen)
                    if s is not None:
                        strings.append((plea, plen, s))
                        sinks.append("jmp_indirect")
                        len_sites.append(plen_site)
                break
            if what == "jmp":
                tgt = ip + det[1]  # det[1] is start-relative (includes the length)
                if tgt in arm_set and tgt != arm:
                    break
                ip = tgt
                continue
            if what == "jcc":
                ip += ln
                continue
        ip += ln
    return strings, sinks, len_sites


def build_tag_table(t):
    copies = []
    for fn, table_hint, w0 in FORMATTERS:
        disp = read_dispatch(t, fn, table_hint, w0)
        run, leave = read_table_run(t, fn, disp["table"])
        copies.append({"fde": fn, "dispatch": disp, "run": run, "leave": leave})
    runs = [len(c["run"]) for c in copies]
    shared = sorted({r for r in runs if runs.count(r) >= 2})
    if len(shared) != 1:
        raise EvidenceError(f"jump-table in-FDE runs {runs} do not fix a bound")
    bound = shared[0]
    for c in copies:
        if len(c["run"]) < bound:
            k, tgt = c["leave"]
            raise EvidenceError(f"table {c['dispatch']['table']:#x} entry {k:#x} target {tgt:#x} "
                                f"leaves FDE before the bound {bound:#x}")
    if not 0 <= copies[0]["dispatch"]["default_index"] < bound:
        raise EvidenceError("dispatch default index outside the table")
    for c in copies:
        lo, hi = t.fde(c["fde"])
        c["entries"] = c["run"][:bound]
        rel = struct.unpack_from("<i", t.elf.read(c["dispatch"]["table"] + 4 * bound, 4))[0]
        past = c["dispatch"]["table"] + rel
        c["entry_past_table"] = {"index": bound, "target": past, "in_fde": bool(lo <= past < hi),
                                 "aliases_tags": [k for k, e in enumerate(c["entries"]) if e == past]}
        arm_set = set(c["entries"])
        walks = [walk_arm(t, lo, hi, arm, arm_set) for arm in c["entries"]]
        c["arms"] = [w[0] for w in walks]
        c["sinks"] = [w[1] for w in walks]
        c["len_sites"] = [w[2][0] if w[2] else None for w in walks]
        users = {}
        for k, site in enumerate(c["len_sites"]):
            users.setdefault(site, []).append(k)
        c["shared_len_sites"] = {site: ks for site, ks in sorted(users.items(), key=lambda kv: kv[1])
                                 if site is not None and len(ks) > 1}
    tags = []
    agree = True
    for k in range(bound):
        names, lens, per_copy = [], [], []
        for c in copies:
            strs = c["arms"][k]
            nm = strs[0] if strs else None
            names.append(nm[2] if nm else None)
            lens.append(nm[1] if nm else None)
            per_copy.append({
                "fde": c["fde"], "arm": c["entries"][k],
                "name_ptr": nm[0] if nm else None,
                "name_len_site": c["len_sites"][k],
                "name_sink": c["sinks"][k][0] if c["sinks"][k] else None,
                "strings": [{"ptr": p, "len": ln, "text": s} for p, ln, s in strs],
            })
        name_ok = (None not in names) and len(set(names)) == 1 and len(set(lens)) == 1
        if not name_ok:
            agree = False
        ptrs = [pc["name_ptr"] for pc in per_copy]
        # field keys = len>=2 strings after the name in the serde_json-shaped
        # copy (0x4753d60); three-way agreement on those is reported, not required.
        per_copy_fields = [[s["text"] for s in pc["strings"][1:] if s["len"] >= 2] for pc in per_copy]
        tags.append({
            "tag": k,
            "variant": names[0] if name_ok else None,
            "name_len": lens[0] if name_ok else None,
            "name_agrees_three_way": name_ok,
            "shared_name_ptr": None not in ptrs and len(set(ptrs)) == 1,
            "names_by_copy": names,
            "field_keys": per_copy_fields[0],
            "field_keys_agree_three_way": len({tuple(x) for x in per_copy_fields}) == 1,
            "field_keys_by_copy": per_copy_fields,
            "copies": per_copy,
        })
    return copies, tags, agree, bound


# --------------------------------------------------------------------------- #
# Fourth niche-dispatch monomorph: arms that pass an explicit index in ecx.   #
# --------------------------------------------------------------------------- #
def explicit_index_call(t, lo, hi, arm, arm_set, budget=800):
    """First call in the arm made with rsi/edx, ecx, r8/r9d all set from
    rip-relative leas / immediates: (container ptr,len), index, (name ptr,len)."""
    code = t.text
    ip = arm
    seen = set()
    regs = {}
    steps = 0
    while steps < budget and lo <= ip < hi and ip not in seen:
        seen.add(ip)
        steps += 1
        ln, kind, dst, det = decode(code, ip - t.t_va)
        if kind == "lea" and det[7] and det[9] == 8:
            regs[dst] = ("ptr", ip + ln + det[5])
        elif kind == "movimm":
            regs[dst] = ("imm", det)
        elif kind in ("call", "callind"):
            r8, r9, rcx = regs.get(R8), regs.get(R9), regs.get(RCX)
            if r8 and r9 and rcx and r8[0] == "ptr" and r9[0] == "imm" and rcx[0] == "imm":
                name = t.rostr(r8[1], r9[1])
                if name is not None:
                    rsi, rdx = regs.get(RSI), regs.get(RDX)
                    cont = (rsi[1], rdx[1]) if (rsi and rdx and rsi[0] == "ptr" and rdx[0] == "imm") else None
                    return {"call": ip, "variant_index": rcx[1], "name_ptr": r8[1], "name_len": r9[1],
                            "name": name,
                            "container_ptr": cont[0] if cont else None,
                            "container_len": cont[1] if cont else None,
                            "container": t.rostr(*cont) if cont else None}
            regs = {}
        else:
            for r in _writes(kind, dst, det):
                regs.pop(r, None)
        if kind == "flow":
            what = det[0]
            if what in ("ret", "trap", "jmpind"):
                break
            if what == "jmp":
                tgt = ip + det[1]
                if tgt in arm_set and tgt != arm:
                    break
                ip = tgt
                continue
            if what == "jcc":
                ip += ln
                continue
        ip += ln
    return None


def variant_index_crosscheck(t, names, bound):
    fn, table_hint, w0 = VARIANT_INDEX_MONOMORPH
    disp = read_dispatch(t, fn, table_hint, w0)
    run, leave = read_table_run(t, fn, disp["table"])
    if len(run) < bound:
        k, tgt = leave
        raise EvidenceError(f"table {disp['table']:#x} entry {k:#x} target {tgt:#x} "
                            f"leaves FDE before the bound {bound:#x}")
    lo, hi = t.fde(fn)
    entries = run[:bound]
    arm_set = set(entries)
    rows = []
    for k, arm in enumerate(entries):
        hit = explicit_index_call(t, lo, hi, arm, arm_set)
        if hit is None:
            continue
        if hit["name"] != names[k]:
            raise EvidenceError(f"fourth monomorph arm {k:#x} writes {hit['name']!r}, table has {names[k]!r}")
        rows.append(dict(hit, tag=k, arm=arm, index_equals_tag=hit["variant_index"] == k))
    return {
        "fde": fn, "fde_end": hi, "jump_table": disp["table"], "dispatch": disp,
        "in_fde_run": len(run), "arms": bound,
        "explicit_index_calls": rows,
    }


# --------------------------------------------------------------------------- #
# Census: niche-form constants in the consensus FDEs, propagated through      #
# registers to every 64-bit store and compare they reach.                     #
# --------------------------------------------------------------------------- #
def census_site(t, lo, hi, movabs_va, reg, V0, budget=8000):
    code = t.text
    ln0 = decode(code, movabs_va - t.t_va)[0]
    stores, cmps, narrow_stores, narrow_cmps = {}, {}, {}, {}
    unresolved = []
    work = [(movabs_va + ln0, ((reg, V0),))]
    seen = set()
    steps = 0
    while work:
        va, st = work.pop()
        if (va, st) in seen:
            continue
        seen.add((va, st))
        steps += 1
        if steps > budget:
            unresolved.append(va)
            continue
        if not (lo <= va < hi):
            continue
        state = dict(st)
        if not state:
            continue
        ln, kind, dst, det = decode(code, va - t.t_va)
        nxt = va + ln

        def put(reg_, v):
            v &= MASK
            if (v & ~0xFF) == NICHE:
                state[reg_] = v
            else:
                state.pop(reg_, None)

        def cont():
            work.append((nxt, tuple(sorted(state.items()))))

        if kind in ("movabs", "movimm"):
            put(dst, det)
            cont()
        elif kind in ("addimm", "subimm"):
            if dst in state:
                put(dst, state[dst] + det if kind == "addimm" else state[dst] - det)
            cont()
        elif kind in ("inc", "dec"):
            if dst in state:
                put(dst, state[dst] + (1 if kind == "inc" else -1))
            cont()
        elif kind == "lea":
            base, index, disp, rip, width = det[1], det[3], det[5], det[7], det[9]
            if rip or index is not None or width != 8 or base not in state:
                state.pop(dst, None)
            else:
                put(dst, state[base] + disp)
            cont()
        elif kind == "movrr":
            src = det[1]
            if src in state:
                state[dst] = state[src]
            else:
                state.pop(dst, None)
            cont()
        elif kind in ("addrr", "subrr"):
            src = det[1]
            if dst in state and src in state:
                put(dst, state[dst] + state[src] if kind == "addrr" else state[dst] - state[src])
            else:
                state.pop(dst, None)
            cont()
        elif kind in ("load", "clobber"):
            state.pop(dst, None)
            if kind == "clobber":
                for r in det:
                    state.pop(r, None)
            cont()
        elif kind == "store":
            src = det[7]
            if src in state:
                rec = (src, det[1], det[3], det[5])  # src, base, index, disp
                (stores if det[11] == 8 else narrow_stores)[(va, state[src])] = rec
            cont()
        elif kind == "cmp":
            if det and det[3] != "imm":
                for rr in (det[1], det[3]):
                    if isinstance(rr, int) and rr in state:
                        (cmps if det[5] == 8 else narrow_cmps)[(va, state[rr])] = rr
            cont()
        elif kind in ("call", "callind"):
            for rr in list(state):
                if rr in CALLER_SAVED:
                    state.pop(rr, None)
            cont()
        elif kind == "flow":
            what = det[0]
            if what in ("ret", "trap", "jmpind"):
                continue
            if what == "jmp":
                work.append((va + det[1], tuple(sorted(state.items()))))  # det[1] includes the length
            elif what == "jcc":
                work.append((va + det[1], tuple(sorted(state.items()))))
                work.append((nxt, tuple(sorted(state.items()))))
        elif kind == "nowrite":
            cont()
        else:
            unresolved.append(va)
    return stores, cmps, narrow_stores, narrow_cmps, unresolved


def _dest(base, index, disp):
    return {"base": REG[base] if base is not None else None,
            "index": REG[index] if index is not None else None,
            "disp": f"{disp:#x}"}


def run_census(t, names, bound):
    census_set = {fn for fn, *_ in CONSENSUS_FDES}
    out, edges = [], []
    for fn, lead, lead_src, selection in CONSENSUS_FDES:
        lo, hi = t.fde(fn)
        sw = t.sweep(lo, hi)
        starts = {va for va, *_ in sw}
        # niche movabs sites, by linear decode; the raw byte pattern is
        # counted too so a hit off an instruction start would show.
        sites = [(va, dst, det) for va, ln, kind, dst, det in sw
                 if kind == "movabs" and (det & ~0xFF) == NICHE]
        body = t.text[lo - t.t_va:hi - t.t_va]
        raw = [lo + m.start() for m in re.finditer(rb"[\x48\x49][\xb8-\xbf]", body)
               if m.start() + 10 <= len(body)
               and (struct.unpack_from("<Q", body, m.start() + 2)[0] & ~0xFF) == NICHE]
        # registers the entry block copies from rdi (before any branch or call).
        entry_rdi, rdi_live = set(), True
        for va, ln, kind, dst, det in sw:
            if kind in ("flow", "call", "callind"):
                break
            w = _writes(kind, dst, det)
            copy = kind == "movrr" and det[1] == RDI and rdi_live
            entry_rdi -= w
            if RDI in w:
                rdi_live = False
            if copy:
                entry_rdi.add(dst)
        # direct / slot calls into the other census FDEs.
        for va, ln, kind, dst, det in sw:
            if kind == "call" and va + det[1] in census_set:
                edges.append({"from": fn, "site": va, "kind": "rel32", "slot": None, "to": va + det[1]})
            elif kind == "callind" and det[0] == "rip":
                slot = va + ln + det[1]
                to = t.relocs.get(slot)
                if to in census_set:
                    edges.append({"from": fn, "site": va, "kind": "slot", "slot": slot, "to": to})
        hist = {}
        for _va, _reg, imm in sites:
            key = f"low_byte_{imm & 0xFF:#04x}"
            hist[key] = hist.get(key, 0) + 1
        all_st, all_cm, all_nst, all_ncm, unresolved, resolved = {}, {}, {}, {}, set(), 0
        for mva, reg, imm in sites:
            st, cm, nst, ncm, un = census_site(t, lo, hi, mva, reg, imm)
            if st or cm or nst or ncm:
                resolved += 1
            all_st.update(st)
            all_cm.update(cm)
            all_nst.update(nst)
            all_ncm.update(ncm)
            unresolved.update(un)

        def dclass(base):
            if base == RSP:
                return "rsp"
            return "entry_rdi_copy" if base in entry_rdi else "other"

        in_range, k0, past, beyond = [], [], [], []
        for (va, v) in sorted(all_st):
            src, base, index, disp = all_st[(va, v)]
            k = v & 0xFF
            rec = {"site": va, "value": v, "tag": k, "src": REG[src],
                   "dest": _dest(base, index, disp), "dest_class": dclass(base)}
            if k == 0:
                rec["variant_if_error"] = names[0]
                k0.append(rec)
            elif k < bound:
                rec["variant_if_same_enum"] = names[k]
                in_range.append(rec)
            elif k == bound:
                past.append(rec)
            else:
                beyond.append(rec)
        comparisons = [{"site": va, "value": v, "reg": REG[all_cm[(va, v)]],
                        "class": f"niche_{v & 0xFF:#04x}"} for (va, v) in sorted(all_cm)]
        out.append({
            "fde": fn, "fde_end": hi, "label": f"fde_{fn:#x}",
            "lead_label": lead, "lead_label_source": lead_src, "selection": selection,
            "instructions": len(sw),
            "entry_rdi_copies": sorted(REG[r] for r in entry_rdi),
            "niche_movabs_sites": [{"site": va, "reg": REG[r], "value": imm} for va, r, imm in sites],
            "niche_movabs_count": len(sites),
            "raw_pattern_hits": len(raw),
            "raw_pattern_hits_at_instruction_starts": sum(1 for x in raw if x in starts),
            "base_immediate_histogram": dict(sorted(hist.items())),
            "movabs_sites_resolved": resolved,
            "unresolved_sites": sorted(unresolved),
            "in_range_tag_stores": in_range,
            "niche_0x00_stores": k0,
            "past_table_niche_stores": past,
            "out_of_range_niche_stores": beyond,
            "narrow_stores": [{"site": va, "value": v} for (va, v) in sorted(all_nst)],
            "narrow_comparisons": [{"site": va, "value": v} for (va, v) in sorted(all_ncm)],
            "niche_comparisons": comparisons,
        })
    return out, edges


def binary_wide_movabs(t, immediates, census_set):
    """Out-of-scope denominator: every REX.W B8+r imm64 byte pattern with these
    immediates anywhere in .text, mapped to its containing FDE. Raw pattern,
    not instruction-start validated outside the census FDEs."""
    out = []
    text = t.text
    for imm in sorted(immediates):
        needle = struct.pack("<Q", imm)
        hits = []
        p = text.find(needle, 2)
        while p != -1:
            if text[p - 2] in (0x48, 0x49) and 0xB8 <= text[p - 1] <= 0xBF:
                hits.append(t.t_va + p - 2)
            p = text.find(needle, p + 1)
        fdes = {}
        outside = 0
        for h in hits:
            c = sr.containing(t.starts, t.ends, h)
            if c is None:
                outside += 1
            else:
                fdes[c[0]] = fdes.get(c[0], 0) + 1
        rest = sorted(f for f in fdes if f not in census_set)
        out.append({
            "immediate": imm, "raw_hits": len(hits), "hits_outside_any_fde": outside,
            "fdes": len(fdes), "census_fdes": sorted(f for f in fdes if f in census_set),
            "fdes_outside_census_count": len(rest),
            "fdes_outside_census": rest if len(rest) <= 100 else None,
        })
    return out


# --------------------------------------------------------------------------- #
def lea_len_pair(t, site):
    """The rip-relative lea at ``site`` and the immediate length that the next
    SysV argument register receives before the next branch or call."""
    ln, kind, dst, det = decode(t.text, site - t.t_va)
    if kind != "lea" or not det[7]:
        raise EvidenceError(f"{site:#x} is not a rip-relative lea")
    target = site + ln + det[5]
    want = NEXT_ARG.get(dst)
    va = site + ln
    for _ in range(6):
        l2, k2, d2, det2 = decode(t.text, va - t.t_va)
        if k2 in ("flow", "call", "callind"):
            break
        if k2 == "movimm" and d2 == want:
            return {"site": site, "reg": REG[dst], "target": target,
                    "len_site": va, "len_reg": REG[want], "len": det2}
        va += l2
    return {"site": site, "reg": REG[dst], "target": target, "len_site": None, "len_reg": None, "len": None}


def corrections(t, tags, xcheck):
    names = [x["variant"] for x in tags]
    binary = set(names)
    can = set(CAN1357_ENUM)
    ro_off = t.elf.off(t.ro_va)
    blob = t.elf.data[ro_off:ro_off + (t.ro_hi - t.ro_va)]

    def find(lit):
        return [t.ro_va + m.start() for m in re.finditer(re.escape(lit.encode()), blob)]

    disputed = MERGED_RE008_DISPUTED_TOKEN
    tx_hits, cq_hits, disp_hits = find(TOKEN_A), find(TOKEN_B), find(disputed)
    cross = [{"occurrence": h, "client_block_missing_tx_at": h, "commit_proof_child_qc_at": h + len(TOKEN_A),
              "spans_two_tokens": (h in tx_hits) and (h + len(TOKEN_A) in cq_hits)} for h in disp_hits]

    def tag_of(name):
        return next((x["tag"] for x in tags if x["variant"] == name), None)

    written = [s["len"] for x in tags for c in x["copies"] for s in c["strings"]]
    written += [r["name_len"] for r in xcheck["explicit_index_calls"]]
    return {
        "can1357_reference_commit": CAN1357_COMMIT,
        "can1357_reference_enum": list(CAN1357_ENUM),
        "binary_variant_count": len(names),
        "can1357_variant_count": len(CAN1357_ENUM),
        "in_binary_not_in_can1357": sorted(binary - can),
        "in_can1357_not_in_binary": sorted(can - binary),
        "merged_re008_disputed_token": {
            "token": disputed,
            "token_len": len(disputed),
            "occurrences": disp_hits,
            "is_single_variant_in_binary": disputed in binary,
            "cross_token_evidence": cross,
            "real_token_a": {"name": TOKEN_A, "tag": tag_of(TOKEN_A), "len": len(TOKEN_A), "occurrences": tx_hits},
            "real_token_b": {"name": TOKEN_B, "tag": tag_of(TOKEN_B), "len": len(TOKEN_B), "occurrences": cq_hits},
            "merged_lea_sites": [lea_len_pair(t, s) for s in MERGED_RE008_LEA_SITES],
            "strings_of_token_len_written_by_any_arm": sum(1 for n in written if n == len(disputed)),
        },
    }


def metrics(tags, copies, bound, xcheck, cen, wide, cor):
    def total(key):
        return sum(len(c[key]) for c in cen)
    in_range = [r for c in cen for r in c["in_range_tag_stores"]]
    by_class = {}
    for c in cen:
        for r in c["niche_comparisons"]:
            by_class[r["class"]] = by_class.get(r["class"], 0) + 1
    dest = {}
    for r in in_range:
        dest[r["dest_class"]] = dest.get(r["dest_class"], 0) + 1
    rows = xcheck["explicit_index_calls"]
    dt = cor["merged_re008_disputed_token"]
    return {
        "tag_table": {
            "copies": len(copies), "tags": bound,
            "rows_agreeing_three_way": sum(1 for x in tags if x["name_agrees_three_way"]),
            "rows_with_per_copy_name_ptrs": sum(1 for x in tags if not x["shared_name_ptr"]),
            "rows_with_one_shared_name_ptr": sum(1 for x in tags if x["shared_name_ptr"]),
            "in_fde_runs": [len(c["run"]) for c in copies],
            "rows_whose_name_len_immediate_is_shared_by_copy": [
                sum(len(ks) for ks in c["shared_len_sites"].values()) for c in copies],
            "copies_whose_past_table_slot_leaves_fde_count": sum(
                1 for c in copies if not c["entry_past_table"]["in_fde"]),
        },
        "variant_index_crosscheck": {
            "arms": xcheck["arms"], "explicit_index_calls": len(rows),
            "index_equals_tag": sum(1 for r in rows if r["index_equals_tag"]),
            "name_equals_table": len(rows),
        },
        "census": {
            "fdes": len(cen),
            "instructions": sum(c["instructions"] for c in cen),
            "niche_movabs_sites": sum(c["niche_movabs_count"] for c in cen),
            "raw_pattern_hits": sum(c["raw_pattern_hits"] for c in cen),
            "raw_pattern_hits_at_instruction_starts": sum(c["raw_pattern_hits_at_instruction_starts"] for c in cen),
            "movabs_sites_resolved": sum(c["movabs_sites_resolved"] for c in cen),
            "unresolved_site_count": total("unresolved_sites"),
            "in_range_tag_store_records": len(in_range),
            "in_range_tag_store_addresses": len({r["site"] for r in in_range}),
            "in_range_distinct_tags": len({r["tag"] for r in in_range}),
            "in_range_records_by_dest_class": dict(sorted(dest.items())),
            "niche_0x00_store_records": total("niche_0x00_stores"),
            "past_table_niche_store_records": total("past_table_niche_stores"),
            "out_of_range_niche_store_records": total("out_of_range_niche_stores"),
            "narrow_store_records": total("narrow_stores"),
            "narrow_comparison_records": total("narrow_comparisons"),
            "comparison_records": total("niche_comparisons"),
            "comparison_records_by_class": dict(sorted(by_class.items())),
        },
        "binary_wide_niche_movabs": [
            {"immediate": w["immediate"], "fdes": w["fdes"], "census_fde_count": len(w["census_fdes"]),
             "fdes_outside_census_count": w["fdes_outside_census_count"]} for w in wide],
        "corrections": {
            "binary_variants": cor["binary_variant_count"], "can1357_variants": cor["can1357_variant_count"],
            "in_binary_not_in_can1357": len(cor["in_binary_not_in_can1357"]),
            "in_can1357_not_in_binary": len(cor["in_can1357_not_in_binary"]),
            "disputed_token_occurrences": len(dt["occurrences"]),
            "occurrences_spanning_two_tokens": sum(1 for e in dt["cross_token_evidence"] if e["spans_two_tokens"]),
            "merged_lea_sites": len(dt["merged_lea_sites"]),
            "merged_lea_sites_with_len_20": sum(1 for e in dt["merged_lea_sites"] if e["len"] == len(TOKEN_A)),
            "strings_of_token_len_written_by_any_arm": dt["strings_of_token_len_written_by_any_arm"],
        },
    }


def _build(data, sha):
    t = Target(data)
    copies, tags, agree, bound = build_tag_table(t)
    if not agree:
        raise EvidenceError("the three niche-dispatch formatter tables disagree on a variant name")
    names = [x["variant"] for x in tags]
    xcheck = variant_index_crosscheck(t, names, bound)
    cen, edges = run_census(t, names, bound)
    census_set = {fn for fn, *_ in CONSENSUS_FDES}
    bases = {s["value"] for c in cen for s in c["niche_movabs_sites"]}
    wide = binary_wide_movabs(t, bases, census_set)
    cor = corrections(t, tags, xcheck)
    d0 = copies[0]["dispatch"]
    core = {(c["dispatch"]["rcx_2pow63_bytes"], c["dispatch"]["select_bytes"], c["dispatch"]["tail_bytes"],
             c["dispatch"]["core_contiguous"]) for c in copies}
    past_niche = NICHE + bound
    vsb_lo, vsb_hi = t.fde(CONSENSUS_FDES[0][0])
    vsb_movabs = [va for va, ln, kind, dst, det in t.sweep(vsb_lo, vsb_hi)
                  if kind == "movabs" and det == past_niche]
    sinks = []
    for c in copies:
        h = {}
        for s in c["sinks"]:
            if s:
                h[s[0]] = h.get(s[0], 0) + 1
        sinks.append(dict(sorted(h.items())))
    result = {
        "binary_sha256": sha,
        "coordinate_system": "linked virtual address; instruction start includes any REX prefix",
        "encoding": ("addresses, niche values, tags and indices are hex strings; counts and "
                     "string lengths are decimal integers"),
        "fde_count": len(t.starts),
        "niche_base": NICHE,
        "tag_count": bound,
        "formatter_monomorphs": [
            {"fde": c["fde"], "fde_end": c["dispatch"]["fde_end"], "jump_table": c["dispatch"]["table"],
             "dispatch": {k: v for k, v in c["dispatch"].items() if k not in ("fde", "fde_end", "table")},
             "in_fde_run": len(c["run"]),
             "entry_past_table": c["entry_past_table"],
             "name_len_sites_shared_by_several_tags": [
                 {"len_site": site, "shared_by_tags": ks} for site, ks in c["shared_len_sites"].items()],
             "name_sink_histogram": h}
            for c, h in zip(copies, sinks)],
        "dispatch_rule": {
            "identical_across_copies": len(core) == 1,
            "rcx_2pow63_bytes": d0["rcx_2pow63_bytes"],
            "select_bytes": d0["select_bytes"],
            "tail_bytes": d0["tail_bytes"],
            "reading_of_enforced_bytes": "k = word0 ^ 0x8000000000000000 if word0 < 0 else 0x27",
            "default_index": d0["default_index"],
            "default_index_row": names[d0["default_index"]],
        },
        "table_bound": {
            "tags": bound,
            "rule": "the in-FDE jump-table run shared by at least two copies; every copy's run reaches it",
            "copies_whose_past_table_slot_leaves_fde": sorted(c["fde"] for c in copies
                                                             if not c["entry_past_table"]["in_fde"]),
            "past_table_niche": past_niche,
            "past_table_niche_movabs_in_fde_0x47b01b0": vsb_movabs,
        },
        "tags": tags,
        "name_table_three_way_agreement": agree,
        "variant_index_crosscheck": xcheck,
        "census": cen,
        "census_call_edges": edges,
        "binary_wide_niche_movabs": wide,
        "corrections": cor,
    }
    result["metrics"] = metrics(tags, copies, bound, xcheck, cen, wide, cor)
    return result


def build(data, expected_sha256=EXPECTED_SHA256):
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"binary sha256 {sha} != {expected_sha256}")
    try:
        return _build(data, sha)
    except EvidenceError:
        raise
    except (struct.error, IndexError, KeyError, TypeError, ValueError) as e:
        raise EvidenceError(f"malformed input: {type(e).__name__}: {e}") from e


HEX_KEYS = {
    # addresses
    "fde", "fde_end", "jump_table", "table", "site", "arm", "name_ptr", "ptr", "target", "occurrence",
    "occurrences", "unresolved_sites", "client_block_missing_tx_at", "commit_proof_child_qc_at",
    "word0_load", "rcx_2pow63", "rcx_2pow63_origin", "select", "cmovs", "lea_table", "tail", "call",
    "container_ptr", "len_site", "name_len_site", "slot", "from", "to", "census_fdes", "fdes_outside_census",
    "copies_whose_past_table_slot_leaves_fde", "past_table_niche_movabs_in_fde_0x47b01b0",
    # niche values
    "value", "niche_base", "immediate", "past_table_niche",
    # tags and indices
    "tag", "index", "default_index", "variant_index", "aliases_tags", "shared_by_tags",
}


def _hex(o, on=False):
    if isinstance(o, dict):
        return {k: _hex(v, k in HEX_KEYS) for k, v in o.items()}
    if isinstance(o, list):
        return [_hex(v, on) for v in o]
    if on and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result):
    return (json.dumps(_hex(result), indent=1, sort_keys=True) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "RE-008 consensus error tags").splitlines()[0])
    ap.add_argument("--binary", type=Path, default=TARGET)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(build(a.binary.read_bytes()))
    except EvidenceError as e:
        print(f"consensus_error_tags: {e}", file=sys.stderr)
        return 2
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
