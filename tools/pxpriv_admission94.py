"""Deterministic generator for RE-004-pxpriv-admission-94.

Maps the PxPriv admission decision in node #94: which integer values the
three PxPriv visitor paths (u64, i64, converting-to-intermediate-u64)
accept, and which diagnostic each rejection produces.

Method (no node execution, no disassembler, no network):
  1. Authenticate the target by SHA-256 and size before decoding anything.
  2. Find the three diagnostic fragments in .rodata by byte pattern
     (0x0e length byte + "invalid value " + c0 marker + suffix).
  3. Scan .text for RIP-relative LEAs to those fragments; each LEA lives in
     one error constructor, resolved through the shared unwind index.
  4. Scan .text for direct calls to those constructors; each call site lives
     in one caller, resolved the same way.
  5. Re-verify every branch row of the guard inventory by decoding the
     branch/call instruction bytes at the recorded source address.
  6. Apply the admission model (a pure function, unit-tested) to boundary
     values and emit the case tables.

Any tampered byte that touches a recorded pattern, LEA, call, branch, or
constructor shape raises EvidenceError instead of emitting output.
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402
import fde_extents  # noqa: E402

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
TARGET_SIZE = 91774280
BINARY = Path("artifacts/node/94/hl-node")
WORK_ITEM = "RE-004-pxpriv-admission-94"

# ---------------------------------------------------------------------------
# Expected observations (asserted against the binary, never trusted blindly)
# ---------------------------------------------------------------------------

# Diagnostic fragment: suffix -> (marker byte, piece VA, piece length).
# Piece VA is the 0x0e length byte; the literal starts one byte later.
EXPECTED_PIECES = {
    "u64": (0x1D, 0x1E66A6, 0x2F),
    "i64": (0x1D, 0x1F7A73, 0x2F),
    "converting": (0x3C, 0x1FF8FB, 0x4E),
}
PIECE_SUFFIX = {
    "u64": b" for PxPriv when visiting u64\x00",
    "i64": b" for PxPriv when visiting i64\x00",
    "converting": b" for PxPriv converting to intermediate u64 when visiting i64\x00",
}
LITERAL = b"invalid value "

# NonZeroU64 fragment: present in .rodata and referenced by exactly three
# LEAs, each in a 141-byte table-referenced function that passes it to the
# shared formatter slot and then dispatches via a vtable call. Those three
# functions are NOT part of the admission guards (no direct call from any of
# the nine admission callers reaches them); the fragment's likely role is an
# "expected type" description, recorded as inference only. Layout: 0x0a
# length byte + "NonZeroU64" + c0 0x0b + " for PxPriv\0".
BARE_VA = 0x1EBE57
BARE_LEN = 0x19  # 0x1ebe57..0x1ebe70
# (LEA VA, containing FDE start, formatter indirect-call VA).
EXPECTED_NONZERO_LEAS = [
    (0x23943F2, 0x23943D0, 0x2394401),
    (0x32853E2, 0x32853C0, 0x32853F1),
    (0x45AC832, 0x45AC810, 0x45AC841),
]

# Constructor: ctor VA -> (diagnostic, form, got_slot, second_call_target).
# form-1a: 70 bytes, returns (eax=1, rdx=payload) via mov rdx,rax; mov eax,1.
# form-1b: 62 bytes, returns rax=payload (caller moves it to r14).
# form-2:  69 bytes, fills the caller-provided out struct via 0x2aea9d0.
EXPECTED_CTORS = {
    0x22E4BD0: ("converting", "form-1a", 0x576E9D0, 0x1EBA7F0),
    0x22E4C20: ("i64", "form-1a", 0x576EA30, 0x1EBA7F0),
    0x22E4C70: ("u64", "form-1b", 0x576EA30, 0x1EBA7F0),
    0x32522F0: ("i64", "form-1a", 0x576EA30, 0x33DDCA0),
    0x3252390: ("converting", "form-1a", 0x576E9D0, 0x33DDCA0),
    0x3252430: ("u64", "form-1b", 0x576EA30, 0x33DDCA0),
    0x3252340: ("i64", "form-2", 0x576EA30, 0x2AEA9D0),
    0x32523E0: ("converting", "form-2", 0x576E9D0, 0x2AEA9D0),
    0x3252470: ("u64", "form-2", 0x576EA30, 0x2AEA9D0),
}
# Shared indirect formatter slot used by all nine constructors.
FORMATTER_SLOT = 0x576E040
# GOT relocations (readelf -r): slot -> (type, addend / resolved value).
EXPECTED_RELOCS = {
    0x576E040: ("R_X86_64_RELATIVE", 0x1344760),
    0x576E9D0: ("R_X86_64_RELATIVE", 0x1570740),
    0x576EA30: ("R_X86_64_RELATIVE", 0x1570900),
}

# Caller family: representative base -> (family, [copy deltas], [ctor set]).
EXPECTED_CALLERS = {
    0x2812C00: ("A", [0x000, 0x720, 0xEF0], (0x22E4BD0, 0x22E4C20, 0x22E4C70)),
    0x35938D0: ("B", [0x000, 0x6D0, 0xF20], (0x32522F0, 0x3252390, 0x3252430)),
    0x2E625E0: ("C", [0x000, 0x33200, 0x7F8E0], (0x3252340, 0x32523E0, 0x3252470)),
}

# Branch rows, relative to the family representative base.
# (rel_src, mnemonic, rel_tgt or None, role, kind, prologue-hex for fallthrough)
# kind: 'branch' (jcc/jmp), 'call' (direct call, absolute target in rel_tgt
# field as an absolute VA), 'fall' (no branch; entry prologue bytes checked).
BRANCH_ROWS = {
    "A": [
        (0xC8, "je", 0x29F, "dispatch-tag-1-to-u64-path", "branch", ""),
        (0xD1, "jne", 0x525, "dispatch-tag-not-1-2-out-of-scope", "branch", ""),
        (0x26F, "je", 0x29F, "dispatch2-tag-1-to-u64-path", "branch", ""),
        (0x274, "jne", 0x525, "dispatch2-tag-not-1-2-out-of-scope", "branch", ""),
        (0x22A, "jne", 0x26C, "subparse-tag-ne-3-to-dispatch2", "branch", ""),
        (0xE4, "js", 0x28D, "i64-negative-to-converting", "branch", ""),
        (0xEE, "jne", 0x2B1, "i64-nonzero-to-ok-trampoline", "branch", ""),
        (0xF4, "fall", None, "i64-zero-fallthrough-to-error", "fall", "4889e7"),
        (0x287, "jns", 0xEA, "i64-nonnegative-to-shared-test", "branch", ""),
        (0x28D, "fall", None, "i64-negative-fallthrough-to-converting", "fall", "488d7c2418"),
        (0x2AB, "je", 0x55A, "u64-zero-to-error", "branch", ""),
        (0x2B5, "je", 0x556, "ok-trampoline-to-ok", "branch", ""),
        (0x2BB, "jmp", 0x59E, "ok-trampoline-dead-jmp", "branch", ""),
        (0xFF, "jmp", 0x54D, "i64-error-to-join", "branch", ""),
        (0x29A, "jmp", 0x54D, "converting-error-to-join", "branch", ""),
        (0x562, "jmp", 0x54A, "u64-error-to-mov-r14", "branch", ""),
        (0x554, "jne", 0x59E, "join-always-to-error-epilogue", "branch", ""),
        (0x558, "jmp", 0x5B4, "ok-to-return", "branch", ""),
        (0x261, "je", 0x556, "parser-loop-exit-to-ok-not-a-value-test", "branch", ""),
        (0xF7, "call", 0x22E4C20, "i64-error-ctor", "call", ""),
        (0x292, "call", 0x22E4BD0, "converting-error-ctor", "call", ""),
        (0x55D, "call", 0x22E4C70, "u64-error-ctor", "call", ""),
    ],
    "B": [
        (0xC8, "je", 0x29F, "dispatch-tag-1-to-u64-path", "branch", ""),
        (0xD1, "jne", 0x525, "dispatch-tag-not-1-2-out-of-scope", "branch", ""),
        (0x26F, "je", 0x29F, "dispatch2-tag-1-to-u64-path", "branch", ""),
        (0x274, "jne", 0x525, "dispatch2-tag-not-1-2-out-of-scope", "branch", ""),
        (0x22A, "jne", 0x26C, "subparse-tag-ne-3-to-dispatch2", "branch", ""),
        (0xE4, "js", 0x28D, "i64-negative-to-converting", "branch", ""),
        (0xEE, "jne", 0x2B1, "i64-nonzero-to-ok-trampoline", "branch", ""),
        (0xF4, "fall", None, "i64-zero-fallthrough-to-error", "fall", "4889e7"),
        (0x287, "jns", 0xEA, "i64-nonnegative-to-shared-test", "branch", ""),
        (0x28D, "fall", None, "i64-negative-fallthrough-to-converting", "fall", "488d7c2418"),
        (0x2AB, "je", 0x55A, "u64-zero-to-error", "branch", ""),
        (0x2B5, "je", 0x556, "ok-trampoline-to-ok", "branch", ""),
        (0x2BB, "jmp", 0x59E, "ok-trampoline-dead-jmp", "branch", ""),
        (0xFF, "jmp", 0x54D, "i64-error-to-join", "branch", ""),
        (0x29A, "jmp", 0x54D, "converting-error-to-join", "branch", ""),
        (0x562, "jmp", 0x54A, "u64-error-to-mov-r14", "branch", ""),
        (0x554, "jne", 0x59E, "join-always-to-error-epilogue", "branch", ""),
        (0x558, "jmp", 0x5B4, "ok-to-return", "branch", ""),
        (0x261, "je", 0x556, "parser-loop-exit-to-ok-not-a-value-test", "branch", ""),
        (0xF7, "call", 0x32522F0, "i64-error-ctor", "call", ""),
        (0x292, "call", 0x3252390, "converting-error-ctor", "call", ""),
        (0x55D, "call", 0x3252430, "u64-error-ctor", "call", ""),
    ],
    "C": [
        (0x6F, "jne", 0x2CC, "u8-nonzero-to-ok", "branch", ""),
        (0x75, "jmp", 0x2DC, "u8-zero-to-u64-error", "branch", ""),
        (0x11B, "jne", 0x2CC, "u8-stream-nonzero-to-ok", "branch", ""),
        (0x121, "jmp", 0x2DC, "u8-stream-zero-to-u64-error", "branch", ""),
        (0x1DC, "jne", 0x2CC, "u16-nonzero-to-ok", "branch", ""),
        (0x1E2, "jmp", 0x2DC, "u16-zero-to-u64-error", "branch", ""),
        (0x2CA, "je", 0x2DC, "u32-u64-zero-to-u64-error", "branch", ""),
        (0x2CC, "fall", None, "u32-u64-nonzero-fallthrough-to-ok", "fall", "48894708"),
        (0x131, "jns", 0x25C, "i8-nonnegative-to-shared-check", "branch", ""),
        (0x137, "fall", None, "i8-negative-fallthrough-to-converting", "fall", "4889fb"),
        (0x19F, "jns", 0x25C, "i16-nonnegative-to-shared-check", "branch", ""),
        (0x1A5, "jmp", 0x137, "i16-negative-to-converting", "branch", ""),
        (0xBC, "jns", 0x25C, "i32-nonnegative-to-shared-check", "branch", ""),
        (0xC2, "jmp", 0x137, "i32-negative-to-converting", "branch", ""),
        (0x256, "js", 0x137, "i64-negative-to-converting", "branch", ""),
        (0x25C, "fall", None, "i64-nonnegative-fallthrough-to-shared-check", "fall", "4889442420"),
        (0x228, "jmp", 0x24E, "i8-stream-to-i64-path", "branch", ""),
        (0x264, "jne", 0x2CC, "shared-nonzero-to-ok", "branch", ""),
        (0x266, "fall", None, "shared-zero-fallthrough-to-i64-error", "fall", "4889fb"),
        (0x142, "call", 0x32523E0, "converting-error-ctor", "call", ""),
        (0x14D, "jne", 0x2FE, "converting-tag-ne-9-to-propagate", "branch", ""),
        (0x153, "fall", None, "converting-tag-9-fallthrough-unreachable-after-form-2", "fall", "488b442408"),
        (0x163, "jne", 0x2CC, "converting-tag9-value-nonzero-to-ok", "branch", ""),
        (0x169, "jmp", 0x266, "converting-tag9-value-zero-to-i64-error", "branch", ""),
        (0x271, "call", 0x3252340, "i64-error-ctor", "call", ""),
        (0x2F2, "jne", 0x2FE, "error-tag-ne-9-to-propagate", "branch", ""),
        (0x2F4, "fall", None, "error-tag-9-fallthrough-unreachable-after-form-2", "fall", "488b442408"),
        (0x2FC, "jmp", 0x2CC, "error-tag-9-to-ok", "branch", ""),
        (0x2E7, "call", 0x3252470, "u64-error-ctor", "call", ""),
    ],
}

# Narrow entries (family C only): (width, signed, source_form, rel_entry,
# rel_anchor, anchor_hex, decision_note).
NARROW_ENTRIES = [
    (8, False, "register", 0x65, 0x65, "0fb6c1", "zero-extend; nonzero->ok, zero->u64-error"),
    (8, False, "stream", 0x105, 0x105, "0fb602", "zero-extend; nonzero->ok, zero->u64-error"),
    (16, False, "buffer-bswap16", 0x1D0, 0x1D0, "410fb7c0", "zero-extend; nonzero->ok, zero->u64-error"),
    (32, False, "buffer-bswap32", 0xE8, 0xE8, "85c00fc8", "zero-extend; nonzero->ok, zero->u64-error"),
    (64, False, "buffer-bswap64", 0x2AC, 0x2BF, "4885c0480fc8", "test+bswap; nonzero->ok, zero->u64-error"),
    (8, True, "register", 0x126, 0x126, "480fbec1", "sign-extend; negative->converting, zero->i64-error, positive->ok"),
    (8, True, "stream", 0x219, 0x219, "480fbe02", "sign-extend, funnels to i64 path; same i64 decision"),
    (16, True, "buffer-bswap16", 0x193, 0x193, "480fbfc2", "sign-extend; same i64 decision"),
    (32, True, "buffer-movsxd", 0xB2, 0xB2, "4863c2", "sign-extend; same i64 decision"),
    (64, True, "buffer-bswap64", 0x23C, 0x24E, "48894424284885c0", "store+test; negative->converting, else shared check"),
]

# FDE cross-check: FDE start -> (objdump .eh_frame offset, objdump cie offset).
# The generator asserts fde_va - eh_frame_va == offset and likewise for cie.
EXPECTED_FDE_OFFSETS = {
    0x22E4BD0: (0x63D7C, 0x0), 0x22E4C20: (0x63D9C, 0x0), 0x22E4C70: (0x63DBC, 0x0),
    0x32522F0: (0x100CD4, 0x0), 0x3252340: (0x100CF4, 0x0), 0x3252390: (0x100D1C, 0x0),
    0x32523E0: (0x100D3C, 0x0), 0x3252430: (0x100D64, 0x0), 0x3252470: (0x100D84, 0x0),
    0x2812C00: (0x41E65C, 0x2DC714), 0x2813320: (0x41E69C, 0x2DC714),
    0x2813AF0: (0x41E6DC, 0x2DC714), 0x35938D0: (0x4A6CA0, 0x2DC714),
    0x3593FA0: (0x4A6CE0, 0x2DC714), 0x35947F0: (0x4A6D20, 0x2DC714),
    0x2E625E0: (0x0D71C8, 0x0), 0x2E957E0: (0x0DF58C, 0x0), 0x2EE1EC0: (0x0EBA38, 0x0),
}


class EvidenceError(Exception):
    pass


def check_digest(data, expected=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise EvidenceError(f"sha256 mismatch: {digest} != {expected}")
    if len(data) != TARGET_SIZE:
        raise EvidenceError(f"size mismatch: {len(data)} != {TARGET_SIZE}")
    return digest


# ---------------------------------------------------------------------------
# Minimal byte decoders (branch/call/LEA only; not a general disassembler)
# ---------------------------------------------------------------------------

JCC = {0x0: "jo", 0x1: "jno", 0x2: "jb", 0x3: "jae", 0x4: "je", 0x5: "jne",
       0x6: "jbe", 0x7: "ja", 0x8: "js", 0x9: "jns", 0xC: "jl", 0xD: "jge",
       0xE: "jle", 0xF: "jg"}


def decode_branch(b, va):
    """Decode one jcc/jmp/call at b[0:]. Returns (mnemonic, length, target)."""
    if not b:
        return None
    op = b[0]
    if 0x70 <= op <= 0x7F and len(b) >= 2:
        code = op & 0xF
        if code not in JCC:
            return None
        disp = struct.unpack_from("<b", b, 1)[0]
        return (JCC[code], 2, va + 2 + disp)
    if op == 0xEB and len(b) >= 2:
        disp = struct.unpack_from("<b", b, 1)[0]
        return ("jmp", 2, va + 2 + disp)
    if op == 0xE9 and len(b) >= 5:
        disp = struct.unpack_from("<i", b, 1)[0]
        return ("jmp", 5, va + 5 + disp)
    if op == 0xE8 and len(b) >= 5:
        disp = struct.unpack_from("<i", b, 1)[0]
        return ("call", 5, va + 5 + disp)
    if op == 0x0F and len(b) >= 6 and 0x80 <= b[1] <= 0x8F:
        code = b[1] & 0xF
        if code not in JCC:
            return None
        disp = struct.unpack_from("<i", b, 2)[0]
        return (JCC[code], 6, va + 6 + disp)
    return None


def resolve_lea_rip(b, va):
    """LEA r64,[rip+disp32]: returns the absolute target, else None."""
    if len(b) >= 7 and 0x48 <= b[0] <= 0x4F and b[1] == 0x8D and (b[2] & 0xC7) == 0x05:
        disp = struct.unpack_from("<i", b, 3)[0]
        return va + 7 + disp
    return None


def resolve_got_load(b, va):
    """MOV rax,[rip+disp32]: returns the GOT slot VA, else None."""
    if len(b) >= 7 and b[0] == 0x48 and b[1] == 0x8B and (b[2] & 0xC7) == 0x05:
        disp = struct.unpack_from("<i", b, 3)[0]
        return va + 7 + disp
    return None


def resolve_indirect_call_slot(b, va):
    """CALL [rip+disp32]: returns the slot VA, else None."""
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x15:
        disp = struct.unpack_from("<i", b, 2)[0]
        return va + 6 + disp
    return None


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = {s["name"]: s for s in elf_index.sections(data)}
        self.text = self.sections[".text"]
        self.rodata = self.sections[".rodata"]
        self.tbody = data[self.text["offset"]:self.text["offset"] + self.text["size"]]
        self.tbase = self.text["address"]
        _, self.fdes, _ = fde_extents.fde_extents(data)
        self.by_start = {f["start"]: f for f in self.fdes}

    def bytes_at(self, va, n):
        for s in self.sections.values():
            if s["address"] <= va < s["address"] + s["size"]:
                off = s["offset"] + (va - s["address"])
                return self.data[off:off + n]
        raise EvidenceError(f"VA {va:#x} is outside every section")

    def fde_of(self, va):
        f = self.by_start.get(va)
        if f is not None:
            return f
        # Fall back to containment (caller VAs are FDE starts, but be safe).
        for g in self.fdes:
            if g["start"] <= va < g["end"]:
                return g
        raise EvidenceError(f"no FDE contains {va:#x}")

    def lea_targets(self):
        """All (lea_va, target) for RIP-relative LEAs in .text."""
        out = []
        pat = re.compile(rb"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
        for m in pat.finditer(self.tbody):
            va = self.tbase + m.start()
            tgt = resolve_lea_rip(self.tbody[m.start():m.start() + 7], va)
            if tgt is not None:
                out.append((va, tgt))
        return out

    def direct_calls(self):
        """All (call_va, target) for E8 direct calls in .text."""
        out = []
        for m in re.finditer(rb"\xe8", self.tbody):
            va = self.tbase + m.start()
            dec = decode_branch(self.tbody[m.start():m.start() + 5], va)
            if dec is not None and dec[0] == "call":
                out.append((va, dec[2]))
        return out


# ---------------------------------------------------------------------------
# Admission model (pure function; the binary observations justify it)
# ---------------------------------------------------------------------------

def admit(visited, value):
    """Returns (outcome, diagnostic) for a visited integer value.

    visited 'u64': admit iff value != 0; 0 is rejected with the u64 diagnostic.
    visited 'i64': step 1 converts to an intermediate u64, which rejects
    negatives with the converting diagnostic; step 2 rejects 0 with the i64
    diagnostic; positives are admitted.
    """
    if visited == "u64":
        if value == 0:
            return ("reject", "u64")
        return ("admit", None)
    if visited == "i64":
        if value < 0:
            return ("reject", "converting")
        if value == 0:
            return ("reject", "i64")
        return ("admit", None)
    raise EvidenceError(f"unknown visited type {visited!r}")


def extend(width, signed, raw):
    """Extend a narrow raw value to the visited 64-bit value."""
    if signed:
        return raw - (1 << width) if raw >= (1 << (width - 1)) else raw
    return raw


# ---------------------------------------------------------------------------
# Discovery and verification
# ---------------------------------------------------------------------------

def find_pieces(img):
    """Locate the three diagnostic fragments plus the bare fragment."""
    rod = img.rodata
    body = img.data[rod["offset"]:rod["offset"] + rod["size"]]
    found = {}
    for m in re.finditer(re.escape(LITERAL), body):
        start = rod["address"] + m.start()
        piece_va = start - 1
        # Only fragments of the 0x0e + "invalid value " + c0 shape qualify;
        # other occurrences of the literal (e.g. inside longer strings) skip.
        if body[m.start() - 1] != 0x0E:
            continue
        after = m.start() + len(LITERAL)
        if body[after] != 0xC0:
            continue
        marker = body[after + 1]
        end = body.index(b"\x00", after + 2)
        suffix = body[after + 2:end + 1]
        # Other types (e.g. NtlPriv) share this fragment shape; only PxPriv
        # fragments are in scope, but every PxPriv one must be accounted for.
        if b"PxPriv" not in suffix:
            continue
        for name, want in PIECE_SUFFIX.items():
            if suffix == want:
                if found.get(name) is not None:
                    raise EvidenceError(f"duplicate {name} fragment at {piece_va:#x}")
                found[name] = piece_va
                break
        else:
            raise EvidenceError(f"unexpected PxPriv diagnostic suffix at {piece_va:#x}: {suffix!r}")
    for name, (marker, va, ln) in EXPECTED_PIECES.items():
        if found.get(name) != va:
            raise EvidenceError(f"{name} fragment: found {found.get(name)}, expected {va:#x}")
        raw = img.bytes_at(va, ln)
        if raw[0] != 0x0E or raw[1:1 + len(LITERAL)] != LITERAL:
            raise EvidenceError(f"{name} fragment header mismatch at {va:#x}")
        if raw[1 + len(LITERAL)] != 0xC0 or raw[2 + len(LITERAL)] != marker:
            raise EvidenceError(f"{name} fragment marker mismatch at {va:#x}")
        if raw[3 + len(LITERAL):] != PIECE_SUFFIX[name]:
            raise EvidenceError(f"{name} fragment suffix mismatch at {va:#x}")
    # Bare fragment: must exist, with exactly the recorded bytes.
    bare = img.bytes_at(BARE_VA, BARE_LEN)
    if bare != b"\x0aNonZeroU64\xc0\x0b for PxPriv\x00":
        raise EvidenceError(f"bare fragment bytes mismatch at {BARE_VA:#x}: {bare!r}")
    # The 0x0a length byte sits at BARE_VA; "NonZeroU64" starts one byte later.
    return found


def verify_ctors(img, leas):
    """Resolve LEAs to constructors and verify each constructor's shape."""
    piece_vas = {va for _, va, _ in EXPECTED_PIECES.values()}
    ctor_leas = {}
    for lea_va, tgt in leas:
        if tgt in piece_vas:
            f = img.fde_of(lea_va)
            ctor_leas.setdefault(f["start"], []).append(lea_va)
    if set(ctor_leas) != set(EXPECTED_CTORS):
        raise EvidenceError(f"ctor set mismatch: {sorted(ctor_leas)} != {sorted(EXPECTED_CTORS)}")
    for ctor, leas_in in ctor_leas.items():
        if len(leas_in) != 1:
            raise EvidenceError(f"ctor {ctor:#x} has {len(leas_in)} piece LEAs, expected 1")
    bare_leas = [(va, tgt) for va, tgt in leas if BARE_VA <= tgt < BARE_VA + BARE_LEN]
    want_bare = {va for va, _, _ in EXPECTED_NONZERO_LEAS}
    if {va for va, _ in bare_leas} != want_bare:
        raise EvidenceError(f"NonZeroU64 fragment LEAs {bare_leas} != {sorted(want_bare)}")
    for lea_va, fde_start, fmt_call in EXPECTED_NONZERO_LEAS:
        f = img.fde_of(lea_va)
        if f["start"] != fde_start or f["end"] - f["start"] != 141:
            raise EvidenceError(f"NonZeroU64 function for LEA {lea_va:#x}: "
                                f"FDE {f['start']:#x}..{f['end']:#x} != 141B at {fde_start:#x}")
        slot = resolve_indirect_call_slot(img.bytes_at(fmt_call, 6), fmt_call)
        if slot != FORMATTER_SLOT:
            raise EvidenceError(f"NonZeroU64 function {fde_start:#x} formatter slot "
                                f"{slot} != {FORMATTER_SLOT:#x}")
    out = {}
    for ctor, (diag, form, got_slot, second) in EXPECTED_CTORS.items():
        f = img.fde_of(ctor)
        size = f["end"] - f["start"]
        want_size = {"form-1a": 70, "form-1b": 62, "form-2": 69}[form]
        if size != want_size:
            raise EvidenceError(f"ctor {ctor:#x} size {size} != {want_size} for {form}")
        raw = img.bytes_at(ctor, size)
        if raw[-1] != 0xC3:
            raise EvidenceError(f"ctor {ctor:#x} does not end with ret")
        if form in ("form-1a", "form-1b"):
            if raw[0] != 0x53 or raw[1:5] != b"\x48\x83\xec\x30":
                raise EvidenceError(f"ctor {ctor:#x} form-1 prologue mismatch")
            got = resolve_got_load(raw[10:17], ctor + 10)
            if got != got_slot:
                raise EvidenceError(f"ctor {ctor:#x} GOT slot {got} != {got_slot:#x}")
            lea = resolve_lea_rip(raw[22:29], ctor + 22)
            if lea != EXPECTED_PIECES[diag][1]:
                raise EvidenceError(f"ctor {ctor:#x} piece LEA {lea} != {EXPECTED_PIECES[diag][1]:#x}")
            slot = resolve_indirect_call_slot(raw[42:48], ctor + 42)
            if slot != FORMATTER_SLOT:
                raise EvidenceError(f"ctor {ctor:#x} formatter slot {slot} != {FORMATTER_SLOT:#x}")
            dec = decode_branch(raw[51:56], ctor + 51)
            if dec is None or dec[0] != "call" or dec[2] != second:
                raise EvidenceError(f"ctor {ctor:#x} second call {dec} != {second:#x}")
            if form == "form-1a":
                if raw[56:64] != b"\x48\x89\xc2\xb8\x01\x00\x00\x00":
                    raise EvidenceError(f"ctor {ctor:#x} form-1a tail mismatch")
            else:
                if raw[56:60] != b"\x48\x83\xc4\x30":
                    raise EvidenceError(f"ctor {ctor:#x} form-1b epilogue mismatch")
        else:
            if raw[0:2] != b"\x41\x56" or raw[2] != 0x53:
                raise EvidenceError(f"ctor {ctor:#x} form-2 prologue mismatch")
            got = resolve_got_load(raw[14:21], ctor + 14)
            if got != got_slot:
                raise EvidenceError(f"ctor {ctor:#x} GOT slot {got} != {got_slot:#x}")
            lea = resolve_lea_rip(raw[26:33], ctor + 26)
            if lea != EXPECTED_PIECES[diag][1]:
                raise EvidenceError(f"ctor {ctor:#x} piece LEA {lea} != {EXPECTED_PIECES[diag][1]:#x}")
            slot = resolve_indirect_call_slot(raw[44:50], ctor + 44)
            if slot != FORMATTER_SLOT:
                raise EvidenceError(f"ctor {ctor:#x} formatter slot {slot} != {FORMATTER_SLOT:#x}")
            dec = decode_branch(raw[56:61], ctor + 56)
            if dec is None or dec[0] != "call" or dec[2] != second:
                raise EvidenceError(f"ctor {ctor:#x} writer call {dec} != {second:#x}")
        fde_off, cie_off = EXPECTED_FDE_OFFSETS[ctor]
        eh = img.sections[".eh_frame"]["address"]
        if f["fde"] - eh != fde_off or f["cie"] - eh != cie_off:
            raise EvidenceError(f"ctor {ctor:#x} FDE/CIE offset mismatch")
        out[ctor] = {
            "diagnostic": diag, "form": form, "size": size,
            "fde": hex(f["fde"]), "fde_section_offset": hex(fde_off),
            "cie": hex(f["cie"]), "cie_section_offset": hex(cie_off),
            "lsda": hex(f["lsda"]) if f["lsda"] else None,
            "got_slot": hex(got_slot), "second_call": hex(second),
            "piece_lea": hex(ctor_leas[ctor][0]),
            "bytes_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest(),
        }
    return out


def verify_call_sites(img, calls):
    """Resolve direct calls to constructors; expect exactly 27 sites."""
    by_ctor = {}
    for call_va, tgt in calls:
        if tgt in EXPECTED_CTORS:
            by_ctor.setdefault(tgt, []).append(call_va)
    if set(by_ctor) != set(EXPECTED_CTORS):
        raise EvidenceError(f"called-ctor set mismatch: {sorted(by_ctor)}")
    sites = []
    for ctor, call_vas in by_ctor.items():
        if len(call_vas) != 3:
            raise EvidenceError(f"ctor {ctor:#x} has {len(call_vas)} call sites, expected 3")
        for call_va in sorted(call_vas):
            f = img.fde_of(call_va)
            sites.append((f["start"], call_va, ctor))
    callers = {}
    for start, _, _ in sites:
        callers.setdefault(start, []).append(1)
    if len(callers) != 9:
        raise EvidenceError(f"caller count {len(callers)} != 9")
    for start, hits in callers.items():
        if len(hits) != 3:
            raise EvidenceError(f"caller {start:#x} has {len(hits)} call sites, expected 3")
    for rep, (fam, deltas, ctors) in EXPECTED_CALLERS.items():
        for d in deltas:
            start = rep + d
            if start not in callers:
                raise EvidenceError(f"expected caller {start:#x} (family {fam}) missing")
            got = sorted(c for (s, _, c) in sites if s == start)
            if sorted(got) != sorted(ctors):
                raise EvidenceError(f"caller {start:#x} ctor set {got} != {sorted(ctors)}")
    for start in callers:
        f = img.fde_of(start)
        fde_off, cie_off = EXPECTED_FDE_OFFSETS[start]
        eh = img.sections[".eh_frame"]["address"]
        if f["fde"] - eh != fde_off or f["cie"] - eh != cie_off:
            raise EvidenceError(f"caller {start:#x} FDE/CIE offset mismatch")
    return sites


def verify_branches(img):
    """Re-verify every guard-inventory row by decoding its source bytes."""
    rows = []
    for rep, (fam, deltas, _) in EXPECTED_CALLERS.items():
        for d in deltas:
            base = rep + d
            for rel_src, mnem, rel_tgt, role, kind, prologue in BRANCH_ROWS[fam]:
                src = base + rel_src
                if kind == "fall":
                    raw = img.bytes_at(src, len(bytes.fromhex(prologue)))
                    if raw.hex() != prologue:
                        raise EvidenceError(f"fallthrough {fam} {src:#x} prologue {raw.hex()} != {prologue}")
                    rows.append((fam, base, src, "fall-through", None, role))
                elif kind == "call":
                    raw = img.bytes_at(src, 5)
                    dec = decode_branch(raw, src)
                    if dec is None or dec[0] != "call" or dec[2] != rel_tgt:
                        raise EvidenceError(f"call {fam} {src:#x} decoded {dec} != call {rel_tgt:#x}")
                    rows.append((fam, base, src, "call", rel_tgt, role))
                else:
                    raw = img.bytes_at(src, 6)
                    dec = decode_branch(raw, src)
                    if dec is None or dec[0] != mnem or dec[2] != base + rel_tgt:
                        raise EvidenceError(f"branch {fam} {src:#x} decoded {dec} != {mnem} {base + rel_tgt:#x}")
                    rows.append((fam, base, src, mnem, base + rel_tgt, role))
    return rows


def verify_narrow(img):
    """Verify family C narrow-entry anchor bytes (representative + copies)."""
    rep = 0x2E625E0
    _, deltas, _ = EXPECTED_CALLERS[rep]
    rows = []
    for d in deltas:
        base = rep + d
        for width, signed, form, rel_entry, rel_anchor, anchor_hex, note in NARROW_ENTRIES:
            raw = img.bytes_at(base + rel_anchor, len(bytes.fromhex(anchor_hex)))
            if raw.hex() != anchor_hex:
                raise EvidenceError(f"narrow {width}{'s' if signed else 'u'} {form} anchor "
                                    f"{base + rel_anchor:#x} {raw.hex()} != {anchor_hex}")
            rows.append((base, width, signed, form, base + rel_entry,
                         base + rel_anchor, anchor_hex, note))
    return rows


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def generate(img):
    pieces = find_pieces(img)
    leas = img.lea_targets()
    ctors = verify_ctors(img, leas)
    calls = img.direct_calls()
    sites = verify_call_sites(img, calls)
    branches = verify_branches(img)
    narrow = verify_narrow(img)

    fam_of = {}
    for rep, (fam, deltas, _) in EXPECTED_CALLERS.items():
        for d in deltas:
            fam_of[rep + d] = fam

    evidence = {
        "work_item": WORK_ITEM,
        "target": {"release": 94, "sha256": TARGET_SHA256, "size": TARGET_SIZE,
                   "path": str(BINARY)},
        "pieces": {},
        "nonzero_fragment_observation": {
            "va": hex(BARE_VA), "length": BARE_LEN,
            "bytes_hex": img.bytes_at(BARE_VA, BARE_LEN).hex(),
            "lea_references": [{"lea_va": hex(v), "function": hex(f), "formatter_call": hex(c)}
                               for v, f, c in EXPECTED_NONZERO_LEAS],
            "status": ("referenced by three table-referenced 141B functions; not part of "
                       "the admission guards; expected-type-description role is inference only"),
        },
        "constructors": {hex(k): v for k, v in sorted(ctors.items())},
        "callers": {},
        "call_sites": [],
        "admission_model": {
            "u64": {"admit": "value != 0", "reject": {"0": "u64"}},
            "i64": {"step_1_convert_to_intermediate_u64": {"reject": {"negative": "converting"}},
                    "step_2_nonzero": {"reject": {"0": "i64"}},
                    "admit": "value > 0"},
            "narrow": "narrow values are extended (zero/sign) then judged by the 64-bit rule",
        },
        "checks": {
            "lea_scan": f"{len([1 for _, t in leas if t in {v for _, v, _ in EXPECTED_PIECES.values()}])} piece LEAs",
            "call_scan": f"{len(sites)} call sites",
            "branch_rows_verified": len(branches),
            "narrow_anchors_verified": len(narrow),
        },
    }
    for name, (marker, va, ln) in EXPECTED_PIECES.items():
        raw = img.bytes_at(va, ln)
        evidence["pieces"][name] = {
            "piece_va": hex(va), "file_offset": hex(va), "length": ln,
            "marker": hex(marker), "suffix": PIECE_SUFFIX[name].decode("latin1"),
            "bytes_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest(),
        }
    for rep, (fam, deltas, _) in EXPECTED_CALLERS.items():
        for d in deltas:
            start = rep + d
            f = img.fde_of(start)
            fde_off, cie_off = EXPECTED_FDE_OFFSETS[start]
            evidence["callers"][hex(start)] = {
                "family": fam, "size": f["end"] - f["start"],
                "fde": hex(f["fde"]), "fde_section_offset": hex(fde_off),
                "cie": hex(f["cie"]), "cie_section_offset": hex(cie_off),
                "lsda": hex(f["lsda"]) if f["lsda"] else None,
            }
    for start, call_va, ctor in sorted(sites):
        diag = EXPECTED_CTORS[ctor][0]
        evidence["call_sites"].append({
            "caller_family": fam_of[start], "caller_start": hex(start),
            "call_va": hex(call_va), "constructor": hex(ctor), "diagnostic": diag,
        })

    call_rows = ["caller_family\tcaller_start\tcall_va\tconstructor\tdiagnostic"]
    for s in evidence["call_sites"]:
        call_rows.append("\t".join([s["caller_family"], s["caller_start"], s["call_va"],
                                    s["constructor"], s["diagnostic"]]))
    branch_rows = ["caller_family\tcaller_start\tsource_va\tmnemonic\ttarget_va\trole"]
    for fam, base, src, mnem, tgt, role in sorted(branches, key=lambda r: (r[0], r[1], r[2])):
        branch_rows.append("\t".join([fam, hex(base), hex(src), mnem,
                                      hex(tgt) if tgt is not None else "-", role]))
    admit_rows = ["visited_type\tinput\trepresentation\toutcome\tdiagnostic"]
    cases = [
        ("u64", 0, "0"), ("u64", 1, "1"), ("u64", (1 << 63) - 1, "2^63-1"),
        ("u64", 1 << 63, "2^63"), ("u64", (1 << 64) - 1, "2^64-1"),
        ("i64", -(1 << 63), "-2^63"), ("i64", -1, "-1"), ("i64", 0, "0"),
        ("i64", 1, "1"), ("i64", (1 << 63) - 1, "2^63-1"),
    ]
    for visited, value, rep_str in cases:
        outcome, diag = admit(visited, value)
        admit_rows.append("\t".join([visited, rep_str, f"{visited} {value}",
                                     outcome, diag if diag else "-"]))
    narrow_rows = ["caller_start\twidth\tsigned\tsource_form\tentry_va\tanchor_va\tanchor_bytes\tdecision"]
    for base, width, signed, form, entry, anchor, anchor_hex, note in sorted(narrow):
        narrow_rows.append("\t".join([hex(base), str(width), "signed" if signed else "unsigned",
                                      form, hex(entry), hex(anchor), anchor_hex, note]))
    ctor_lines = []
    for ctor in sorted(ctors):
        c = ctors[ctor]
        ctor_lines.append(f"{ctor:#x} {c['diagnostic']} {c['form']} {c['size']}B "
                          f"fde={c['fde']} cie={c['cie']} got={c['got_slot']} "
                          f"second={c['second_call']} sha256={c['sha256']}")
        ctor_lines.append(f"  bytes: {c['bytes_hex']}")
    for name in ("u64", "i64", "converting"):
        p = evidence["pieces"][name]
        ctor_lines.append(f"piece {name} {p['piece_va']} {p['length']}B sha256={p['sha256']}")
        ctor_lines.append(f"  bytes: {p['bytes_hex']}")
    ctor_lines.append(f"nonzero-fragment {hex(BARE_VA)} {BARE_LEN}B sha256="
                      f"{hashlib.sha256(img.bytes_at(BARE_VA, BARE_LEN)).hexdigest()}")
    ctor_lines.append(f"  bytes: {img.bytes_at(BARE_VA, BARE_LEN).hex()}")

    return evidence, {
        "evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        "call-sites.tsv": "\n".join(call_rows) + "\n",
        "branches.tsv": "\n".join(branch_rows) + "\n",
        "admission-cases.tsv": "\n".join(admit_rows) + "\n",
        "narrow-width-cases.tsv": "\n".join(narrow_rows) + "\n",
        "constructor-bytes.txt": "\n".join(ctor_lines) + "\n",
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--binary", type=Path, default=ROOT / BINARY)
    args = ap.parse_args(argv)
    data = args.binary.read_bytes()
    check_digest(data)
    img = Image(data)
    _, files = generate(img)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text)
    print(json.dumps({"work_item": WORK_ITEM, "files": sorted(files)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
