#!/usr/bin/env python3
"""RE-014: execute-action enum and dispatcher drift, node #94 (primary) to node #115.

Stdlib only. The ELF, FDE, RELATIVE-relocation and RIP-lea readers come from
``tools/state_roots.py`` and the strict arm walker from
``tools/exchange_dispatch.py`` (RE-010); both are loaded with importlib and
their files are not modified. A second, private instance of
``exchange_dispatch`` runs RE-010's own ``walk`` with ``decode_one`` wrapped
to accept exactly three more encodings (EXT_ENCODINGS); it is used only for
an execute arm that the strict walker rejects, and every such arm is marked.
Every constant below is a pinned *shape* that the tool checks against the
bytes of its own release; any mismatch raises EvidenceError.

Per release the tool derives:

* every copy of the serde ``VARIANTS`` ``&[&str]`` table that holds the seed
  name ``batchModify``: a run of RELATIVE-relocated (ptr, len) slots in
  ``.data.rel.ro`` that starts at a RIP-lea-referenced slot and ends at the
  slot whose string is ``variant index 0 <= i < N``. N must equal the run
  length, and all copies must hold identical names;
* every occurrence in ``.text`` of the release's consecutive 64-bit
  tag-to-index idiom (IDIOM_TEXT: bias subtraction, default index 0x14 loaded
  into a register, then ``cmovae`` or ``cmovb``, consecutive and in that
  order) in any register allocation, and the jump table that the idiom's
  result register indexes, directly or after at most GAP_MAX allowed gap
  instructions (GAP_TEXT); the bias directly followed by the cmov, whose
  default register is not loaded in the matched bytes (DEFAULT_ELSEWHERE_TEXT),
  is listed separately and not surveyed;
* the role of each N-way jump-table site:
  - ``serializer``: every arm K stores the &str VARIANTS[K] at one fixed
    [rsp+off], next to the type, variant and tag strings at off-0x30, off-0x20
    and off-0x10; this binds memory tag K to its serde name without assuming
    declaration order;
  - ``execute``: the idiom is preceded by ``mov ebp,0x3b9aca00; mov R,[r12]``
    with R the idiom's tag register (the RE-010 dispatcher shape);
  - ``sentinel_other_base``: the same sentinel, but the tag is loaded through
    another base register (``[r15]`` in #115);
  - ``other``: anything else (listed, not analysed);
* for each dispatcher instance, each arm's straight-line path to its first
  call (RE-010 walker), entry branches followed one level, and jumps into
  another arm's pre-call path resolved as a shared tail;
* first-party panic ``Location`` records (absolute ``/home/ubuntu/...`` or
  relative ``l1/src/...`` paths of FIRST_PARTY_CRATES) and the functions that
  lea them; direct rel32 callers of owners and dispatcher instances;
* two census controls over all of ``.text``: every jump table in any register
  form with N pairwise-distinct in-FDE entries, tested for the serializer
  shape, and every ``mov ebp,0x3b9aca00`` byte sequence.

It then joins the releases by serde name, checks Location anchors, qualifies
four catalogue paths, cross-checks the RE-010 packet JSON and records handler
sizes (sizes only, never code identity).

Coordinate system: ELF virtual addresses as linked (both images are PIE with
base 0); file offset = VA - p_vaddr + p_offset of the containing PT_LOAD.
Instruction addresses are instruction starts, REX prefix included.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name, tag=""):
    spec = importlib.util.spec_from_file_location(f"re014_{name}{tag}", ROOT / f"tools/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sr = _load("state_roots")
ed = _load("exchange_dispatch")
ed_ext = _load("exchange_dispatch", "_ext")
EvidenceError = sr.EvidenceError

EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
EXPECTED_SHA256_115 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = ROOT / "artifacts/node/94/hl-node"
TARGET_115 = ROOT / "artifacts/node/115/hl-node"
RE010_JSON = ROOT / "research/work-items/RE-010-exchange-handlers/exchange-dispatch.json"
RE010_JSON_SHA256 = "bf82df7744abc508bd73bc8337d5b21af0a17eab9c64b6849137a4f58dfa5cb1"

PROFILE_94 = {
    "release": "94",
    "variants_seed": b"batchModify",
    "variants_count": 88,
    "variants_copies": 3,
    "bias": 0x74,
    "default_index": 0x14,
    # idiom form (any registers, see IDIOM_TEXT); bias_block is the dispatchers' register allocation
    "idiom_form": "lea_cmp",
    "bias_block_text": "lea rcx,[rax-0x74]; cmp rax,0x74; mov eax,0x14; cmovae rax,rcx",
    "bias_block": bytes.fromhex("488d488c" "4883f874" "b814000000" "480f43c1"),
    # (offset, struct format, expected value) inside bias_block
    "bias_block_fields": ((3, "<b", -0x74), (7, "<B", 0x74), (9, "<I", 0x14)),
    "execute_instances": 3,
    "sentinel_other_base_instances": 0,
}
PROFILE_115 = {
    "release": "115",
    "variants_seed": b"batchModify",
    "variants_count": 92,
    "variants_copies": 3,
    "bias": 0x86,
    "default_index": 0x14,
    "idiom_form": "sub",
    "bias_block_text": "sub rax,0x86; mov ecx,0x14; cmovae rcx,rax",
    "bias_block": bytes.fromhex("482d86000000" "b914000000" "480f43c8"),
    "bias_block_fields": ((2, "<I", 0x86), (7, "<I", 0x14)),
    "execute_instances": 3,
    "sentinel_other_base_instances": 3,
}
REG64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
IDIOM_TEXT = {
    "lea_cmp": ("lea X,[R-bias]; cmp R,bias; mov D32,default; then cmovae D,X (index D) or cmovb X,D (index X); "
                "X != R, D != X"),
    "sub": "sub R,bias; mov D32,default; then cmovae D,R (index D) or cmovb R,D (index R); D != R",
}
IDIOM_RULES = ("consecutive and in this order; any registers R (tag), D (default), X (lea destination); the table "
               "index is the cmov destination; 64-bit lea/cmp/sub/cmovae/cmovb (REX.W, register form), "
               "'mov r32,imm32' (B8+r) for the default; the 32-bit byte-truncated gate computation (movzx, 32-bit "
               "cmovae) is a different computation and is not matched; the bias directly followed by the cmov, with "
               "no default load in the matched bytes, is listed separately (idiom_default_elsewhere) and not "
               "surveyed")
DEFAULT_ELSEWHERE_TEXT = {
    "lea_cmp": ("lea X,[R-bias]; cmp R,bias; then directly cmovb X,D (index X) or cmovae D,X (index D); X != R, "
                "D != X, D != R; D is not loaded in these bytes, so its value is not established"),
    "sub": ("sub R,bias; then directly cmovb R,D (index R) or cmovae D,R (index D); D != R; D is not loaded in "
            "these bytes, so its value is not established"),
}
# mov ebp,0x3b9aca00, directly followed by 'mov R,QWORD PTR [base]' (R = the idiom's tag register) and the idiom
SENTINEL = bytes.fromhex("bd00ca9a3b")
SENTINEL_TEXT = "mov ebp,0x3b9aca00"
TAG_BASES = tuple(r for r in range(16) if r & 7 != 5)      # [rbp]/[r13] need a displacement


def _tag_load(dst, base):
    """Bytes of 'mov dst,QWORD PTR [base]' (mod 00, no displacement)."""
    rex = 0x48 | ((dst >> 3) << 2) | (base >> 3)
    reg = (dst & 7) << 3
    return bytes((rex, 0x8B, reg | 0x04, 0x24)) if base & 7 == 4 else bytes((rex, 0x8B, reg | (base & 7)))


EXECUTE_BASE = "r12"
EXECUTE_PROLOGUE_TEXT = "mov ebp,0x3b9aca00; mov R,QWORD PTR [r12] (R = the idiom's tag register)"
TABLE_TEXT = ("lea B,[rip+T]; movsxd J,DWORD PTR [B+I*4]; add J,B; at most 2 'mov QWORD PTR [rsp+d8],r64'; "
              "jmp J; any B and J, I = the idiom's result register, T in .rodata")
MAX_TABLE_STORES = 2
GAP_MAX = 4
GAP_TEXT = ("at most 4 instructions between the idiom and the table lea: 'mov r/m,r' (register form), "
            "'mov r,imm', 'xor r,r' (one register), 'mov r64,QWORD PTR [rsp+disp]', 'lea r64,[base+disp]' "
            "(no index, not RIP-relative) and 'dec I', none writing I except 'dec I', and at most one bounds "
            "check 'cmp I,imm8' directly followed by 'ja'")
TABLE_CANDIDATE_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....[\x48-\x4f]\x63", re.S)
BOUND_RE = re.compile(rb"variant index 0 <= i < ([0-9]+)\Z")
NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*\Z")
# serde TaggedSerializer layout relative to the variant-name &str: type ident, variant ident, tag
TYPE_REL, IDENT_REL, TAG_REL, NAME_REL = -0x30, -0x20, -0x10, 0
ABS_PREFIX = b"/home/ubuntu/hl/code_Mainnet/"
FIRST_PARTY_CRATES = ("base", "db", "evm_rpc", "global_constants", "info_server", "l1", "net_utils", "node")
# Location files used as name anchors: catalogue path -> serde name of the
# action the file is named after (the name association itself is an inference).
ANCHOR_FILES = (
    ("l1/action/c_deposit.rs", "cDeposit"),
    ("l1/action/evm_raw_tx.rs", "evmRawTx"),
    ("l1/action/user_outcome.rs", "userOutcome"),
    ("l1/action/vault_transfer.rs", "vaultTransfer"),
    ("l1/action/vote_global.rs", "VoteGlobalAction"),
    ("l1/action/withdraw3.rs", "withdraw3"),
    ("l1/exchange/impl_outcome_deploy.rs", "outcomeDeploy"),
)
# The four action-related catalogue drift paths (research/catalogue/components.json
# path_totals) and the list each one is in.
CATALOGUE_PATHS = (
    ("l1/action/c_deposit.rs", "absent115"),
    ("l1/action/evm_raw_tx.rs", "absent115"),
    ("l1/action/user_outcome.rs", "added115"),
    ("l1/exchange/impl_outcome_deploy.rs", "added115"),
)
SIZE_BAND = (0.8, 1.25)
# Framing notes carried into the JSON (static text; see the packet README, "Relation to other work").
PR226 = ("open PR #226 (head ad161cb7dde4e9e6246f831e5fba4c90c8600dee, "
         "research/work-items/RE-010-dispatch-cases-76-87/README.md)")
PR226_CASES_NOTE = ("names by index: VARIANTS[K] for #94 execute arm K (inference I2, not a code xref). For #94 these "
                    "12 names, their arms, first calls and first-call FDE extents agree with " + PR226 +
                    ", which decoded the same three #94 VARIANTS copies first; they are not new in this packet")
PR226_LABELS_NOTE = ("the 51/76 wire_type agreement (and the 25 differences) agrees with " + PR226 + "; new here is "
                     "only the serializer string per arm (rust_ident, I1), e.g. 'Hip3Deploy' stored for serde "
                     "'perpDeploy' (case 68)")
ARM_TO_NAME_NOTE = ("names and indices are observations from the VARIANTS tables; attaching an execute arm or "
                    "handler to a name (arm K -> VARIANTS[K]) is inference I2")
CONTRIBUTION_NOTE = ("new in this packet: the #94 -> #115 per-variant drift (name join by serde name, per-variant "
                     "[r12] arms and handlers per I2, the #115-only [r15] family, the qualification of 4 catalogue "
                     "paths), supported by the serializer byte binding and the Location anchors; the #94 VARIANTS "
                     "tables, the names of RE-010 cases 76-87 and the 51/76 wire_type agreement agree with "
                     + PR226 + " and are not new")
# Encodings the private walker accepts on top of RE-010's decode_one (and nothing else).
EXT_ENCODINGS = {"3d": "cmp eax/rax,imm32", "31": "xor r/m,r", "0f4x": "cmovcc r,r/m"}
_ext_used = []


def _decode_ext(code, i, va):
    """RE-010's strict decode_one, plus exactly the encodings in EXT_ENCODINGS; anything else still raises."""
    try:
        return ed.decode_one(code, i, va)
    except ed.EvidenceError as e:
        err = e
    j = i + 1 if 0x40 <= code[i] <= 0x4F else i
    op = code[j]
    if op == 0x3D:
        key, n = "3d", j + 5 - i
    elif op == 0x31:
        key, n = "31", j + 1 + ed._modrm(code, j + 1)[0] - i
    elif op == 0x0F and 0x40 <= code[j + 1] <= 0x4F:
        key, n = "0f4x", j + 2 + ed._modrm(code, j + 2)[0] - i
    else:
        raise err
    _ext_used.append(key)
    return ed.Insn(va, n)


ed_ext.decode_one = _decode_ext
_WALK_ERRORS = (ed.EvidenceError, sr.EvidenceError, IndexError, struct.error)
_WALK_ERRORS_EXT = _WALK_ERRORS + (ed_ext.EvidenceError,)


def _inside(fn, va):
    """FDE ranges are half-open: [start, end)."""
    return fn[0] <= va < fn[1]


class Ctx:
    """Readers for one release, built from state_roots."""

    def __init__(self, data: bytes):
        self.data = data
        self.elf = sr.Elf(data)
        self.starts, self.ends = sr.fde_index(self.elf)
        self.relocs = sr.relative_relocs(self.elf)
        self.leas = sr.lea_targets(self.elf)
        self.transfers = {}
        self._by_addend = None
        self.sec = {}
        for name in (".text", ".rodata", ".data.rel.ro"):
            if name not in self.elf.sections:
                raise EvidenceError(f"missing section {name}")
            va, off, size = self.elf.sections[name]
            self.sec[name] = (va, off, size)

    def in_sec(self, name, va):
        s = self.sec[name]
        return s[0] <= va < s[0] + s[2]

    def sec_bytes(self, name):
        va, off, size = self.sec[name]
        return va, self.data[off:off + size]

    def containing(self, va):
        return sr.containing(self.starts, self.ends, va)

    def is_start(self, va):
        return sr.is_fde_start(self.starts, va)

    def end_of(self, start):
        if not self.is_start(start):
            raise EvidenceError(f"{start:#x} is not an FDE start")
        return self.ends[bisect.bisect_left(self.starts, start)]

    def owner(self, va):
        c = self.containing(va)
        return c[0] if c else None

    def i32(self, va):
        return struct.unpack("<i", self.elf.read(va, 4))[0]

    def reloc_slots_to(self, target):
        if self._by_addend is None:
            inv = {}
            for s, a in self.relocs.items():
                inv.setdefault(a, []).append(s)
            self._by_addend = inv
        return sorted(self._by_addend.get(target, ()))

    def walk(self, va):
        try:
            return ed.walk(self.elf, va, self.relocs, self.starts)
        except _WALK_ERRORS as e:
            raise EvidenceError(f"arm walk from {va:#x}: {e}") from None

    def walk_ext(self, va):
        del _ext_used[:]
        try:
            addrs, jccs, term = ed_ext.walk(self.elf, va, self.relocs, self.starts)
        except _WALK_ERRORS_EXT as e:
            raise EvidenceError(f"extended arm walk from {va:#x}: {e}") from None
        return addrs, jccs, term, sorted(set(_ext_used))


def _str_slot(ctx, slot):
    """Bytes of a RELATIVE-relocated &str (ptr, len) slot in .data.rel.ro, else None."""
    if not ctx.in_sec(".data.rel.ro", slot) or not ctx.in_sec(".data.rel.ro", slot + 15):
        return None
    a = ctx.relocs.get(slot)
    if a is None or not ctx.in_sec(".rodata", a):
        return None
    ln = struct.unpack("<Q", ctx.elf.read(slot + 8, 8))[0]
    if not 0 < ln < 256 or not ctx.in_sec(".rodata", a + ln - 1):
        return None
    return ctx.elf.read(a, ln)


def _bias_at(p, b, i):
    """(end, R, X, src) of the release's bias computation at offset i of b, else None; src holds tag - bias.

    lea_cmp: 'lea X,[R-bias]; cmp R,bias' (X != R, src = X); sub: 'sub R,bias' (X None, src = R).
    """
    bias, form = p["bias"], p["idiom_form"]
    if form == "lea_cmp":
        rex, op, m = b[i], b[i + 1], b[i + 2]
        if rex & 0xFA != 0x48 or op != 0x8D or m >> 6 != 1 or not 0 < bias < 0x80:
            return None
        X, R = ((m >> 3) & 7) | ((rex & 4) << 1), (m & 7) | ((rex & 1) << 3)
        k = i + 3
        if R & 7 == 4:                      # [rsp/r12+disp8] needs SIB 0x24
            if b[k] != 0x24:
                return None
            k += 1
        if b[k] != (-bias) & 0xFF or b[k + 1:k + 5] != bytes((0x48 | (R >> 3), 0x83, 0xF8 | (R & 7), bias)):
            return None
        return (k + 5, R, X, X) if X != R else None
    if form == "sub":
        imm = struct.pack("<I", bias)
        if b[i:i + 2] == b"\x48\x2d" and b[i + 2:i + 6] == imm:
            return i + 6, 0, None, 0
        if b[i] in (0x48, 0x49) and b[i + 1] == 0x81 and b[i + 2] & 0xF8 == 0xE8 and b[i + 3:i + 7] == imm:
            R = (b[i + 2] & 7) | ((b[i] & 1) << 3)
            return i + 7, R, None, R
        return None
    raise EvidenceError(f"profile {p['release']}: unknown idiom form {form!r}")


def _cmov64(b, k):
    """(cc, destination, source) of a 64-bit register-form 'cmovb' or 'cmovae' at offset k of b, else None."""
    rex, op0, op1, m = b[k], b[k + 1], b[k + 2], b[k + 3]
    if rex & 0xFA != 0x48 or op0 != 0x0F or op1 not in (0x42, 0x43) or m >> 6 != 3:
        return None
    return ("cmovb" if op1 == 0x42 else "cmovae"), ((m >> 3) & 7) | ((rex & 4) << 1), (m & 7) | ((rex & 1) << 3)


def _idiom_at(p, b, i):
    """(length, R, I, X, D, cc) of the release's idiom (IDIOM_TEXT[p['idiom_form']]) at offset i of b, else None.

    R is the tag register, I the result (table index) register, X the lea destination (None for 'sub'), D the
    register that 'mov D32,default' loads, cc the cmov: 'cmovae D,src' (I = D) or 'cmovb src,D' (I = src), where
    src (X or R) holds tag - bias.
    """
    try:
        bias_part = _bias_at(p, b, i)
        if bias_part is None:
            return None
        k, R, X, src = bias_part
        hi = 0
        if b[k] == 0x41:
            hi, k = 8, k + 1
        if not 0xB8 <= b[k] <= 0xBF or b[k + 1:k + 5] != struct.pack("<I", p["default_index"]):
            return None
        D = (b[k] - 0xB8) | hi
        k += 5
        c = _cmov64(b, k)
    except IndexError:
        return None
    if c is None or D == src:
        return None
    cc, dst, rm = c
    if cc == "cmovae" and (dst, rm) == (D, src):
        return k + 4 - i, R, D, X, D, cc
    if cc == "cmovb" and (dst, rm) == (src, D):
        return k + 4 - i, R, src, X, D, cc
    return None


def _idiom_default_elsewhere_at(p, b, i):
    """(length, R, I, X, D, cc) of DEFAULT_ELSEWHERE_TEXT[p['idiom_form']] at offset i of b, else None: the bias
    computation directly followed by the cmov, with no 'mov D32,default' in between (D's value is not shown)."""
    try:
        bias_part = _bias_at(p, b, i)
        if bias_part is None:
            return None
        k, R, X, src = bias_part
        c = _cmov64(b, k)
    except IndexError:
        return None
    if c is None:
        return None
    cc, dst, rm = c
    if cc == "cmovb" and dst == src:
        I, D = src, rm
    elif cc == "cmovae" and rm == src:
        I, D = dst, dst
    else:
        return None
    if D in (src, R):
        return None
    return k + 4 - i, R, I, X, D, cc


def _idiom_offsets(p, b, at=_idiom_at):
    """Offsets in b at which the matcher `at` matches, in order (candidates from the bias instruction, then decoded)."""
    bias = p["bias"]
    if p["idiom_form"] == "lea_cmp":
        cand = re.compile(re.escape(bytes(((-bias) & 0xFF,))) + rb"[\x48\x49]\x83[\xf8-\xff]"
                          + re.escape(bytes((bias,))))
        starts = {m.start() - back for m in cand.finditer(b) for back in (3, 4)}
    else:
        cand = re.compile(rb"(?:\x48\x2d|[\x48\x49]\x81[\xe8-\xef])" + re.escape(struct.pack("<I", bias)))
        starts = {m.start() for m in cand.finditer(b)}
    return sorted(i for i in starts if i >= 0 and at(p, b, i))


def _check_profile(p):
    """The numeric bias/default must be the immediates of the bias block, and the bias block must be one
    register allocation of the idiom form; returns the bias block's result register."""
    for off, fmt, want in p["bias_block_fields"]:
        if struct.unpack_from(fmt, p["bias_block"], off)[0] != want:
            raise EvidenceError(f"profile {p['release']}: bias block field at {off} != {want:#x}")
    imms = [w for _o, _f, w in p["bias_block_fields"]]
    if p["bias"] not in [abs(w) for w in imms[:-1]] or imms[-1] != p["default_index"]:
        raise EvidenceError(f"profile {p['release']}: bias/default not encoded in bias block")
    rex, op0, op1, modrm = p["bias_block"][-4:]
    if rex & 0xF8 != 0x48 or (op0, op1) != (0x0F, 0x43) or modrm >> 6 != 3:
        raise EvidenceError(f"profile {p['release']}: bias block does not end in 'cmovae r64,r64'")
    m = _idiom_at(p, p["bias_block"], 0)
    if m is None or m[0] != len(p["bias_block"]):
        raise EvidenceError(f"profile {p['release']}: bias block is not an instance of idiom form {p['idiom_form']}")
    return m[2]


def find_variants(ctx, p):
    seed = p["variants_seed"]
    ro_va, ro = ctx.sec_bytes(".rodata")
    occ = {ro_va + m.start() for m in re.finditer(re.escape(seed), ro)}
    seeds = sorted(s for s, a in ctx.relocs.items()
                   if a in occ and ctx.in_sec(".data.rel.ro", s) and _str_slot(ctx, s) == seed)
    copies = {}
    for s0 in seeds:
        start = s0
        while start not in ctx.leas:
            start -= 16
            if _str_slot(ctx, start) is None:
                raise EvidenceError(f"VARIANTS run at {s0:#x} has no lea-referenced start")
        names, slot = [], start
        while True:
            b = _str_slot(ctx, slot)
            if b is None:
                raise EvidenceError(f"VARIANTS run at {start:#x} ends without a bound slot")
            m = BOUND_RE.match(b)
            if m:
                break
            if slot != start and slot in ctx.leas:
                raise EvidenceError(f"lea-referenced slot {slot:#x} inside VARIANTS run {start:#x}")
            name = b.decode("ascii", "replace")
            if not NAME_RE.match(name):
                raise EvidenceError(f"VARIANTS slot {slot:#x} is not an identifier: {name!r}")
            names.append(name)
            slot += 16
        bound = int(m.group(1))
        if bound != len(names):
            raise EvidenceError(f"VARIANTS {start:#x}: {len(names)} names but bound {bound}")
        start_sites = sorted(ctx.leas[start])
        bound_sites = sorted(ctx.leas.get(slot, ()))
        copies[start] = {
            "start": start,
            "seed_slot": s0,
            "bound_slot": slot,
            "bound_text": b.decode("ascii"),
            "count": len(names),
            "start_lea_sites": start_sites,
            "start_lea_functions": sorted({ctx.owner(x) for x in start_sites if ctx.owner(x) is not None}),
            "bound_lea_sites": bound_sites,
            "bound_lea_functions": sorted({ctx.owner(x) for x in bound_sites if ctx.owner(x) is not None}),
            "names": names,
            "_ptrs": [ctx.relocs[start + 16 * k] for k in range(len(names))],
        }
    rows = [copies[k] for k in sorted(copies)]
    if len(rows) != p["variants_copies"]:
        raise EvidenceError(f"expected {p['variants_copies']} VARIANTS copies, found {len(rows)}")
    names = rows[0]["names"]
    if any(r["names"] != names for r in rows):
        raise EvidenceError("VARIANTS copies differ")
    if len(names) != p["variants_count"] or len(set(names)) != len(names):
        raise EvidenceError(f"VARIANTS count {len(names)} != {p['variants_count']} or duplicate names")
    if not all(r["bound_lea_sites"] for r in rows):
        raise EvidenceError("a VARIANTS bound slot is not lea-referenced")
    return rows


def _stack_strs(ctx, addrs):
    """(ptr, len) &str pairs stored to [rsp+off] on a straight-line path: {off: (ptr, text)}.

    A register holds a pointer from its last 'lea r64,[rip+d]'; any other lea, 'mov r,r/m', or register-form
    'mov r/m,r' into it clears it.
    """
    regs, stores = {}, {}
    for a in addrs:
        b = ctx.elf.read(a, 12)
        rex = b[0] if 0x40 <= b[0] <= 0x4F else 0
        op, m = (b[1], b[2]) if rex else (b[0], b[1])
        if b[0] in (0x48, 0x4C) and b[1] == 0x8D and b[2] & 0xC7 == 0x05:
            regs[((b[2] >> 3) & 7) | ((b[0] & 4) << 1)] = a + 7 + struct.unpack_from("<i", b, 3)[0]
        elif op in (0x8B, 0x8D):
            regs.pop(((m >> 3) & 7) | ((rex & 4) << 1), None)
        elif op == 0x89 and m >> 6 == 3:
            regs.pop((m & 7) | ((rex & 1) << 3), None)
        elif b[0] in (0x48, 0x4C) and b[1] == 0x89 and b[2] & 0xC7 in (0x04, 0x44) and b[3] == 0x24:
            reg = ((b[2] >> 3) & 7) | ((b[0] & 4) << 1)
            stores[0 if b[2] & 0xC7 == 0x04 else b[4]] = ("ptr", regs.get(reg))
        elif b[0] == 0x48 and b[1] == 0xC7 and b[2] == 0x04 and b[3] == 0x24:
            stores[0] = ("imm", struct.unpack_from("<i", b, 4)[0])
        elif b[0] == 0x48 and b[1] == 0xC7 and b[2] == 0x44 and b[3] == 0x24:
            stores[b[4]] = ("imm", struct.unpack_from("<i", b, 5)[0])
    out = {}
    for off in sorted(stores):
        ptr, ln = stores.get(off), stores.get(off + 8)
        if ptr and ln and ptr[0] == "ptr" and ptr[1] is not None and ln[0] == "imm" \
                and 0 < ln[1] < 256 and ctx.in_sec(".rodata", ptr[1]):
            out[off] = (ptr[1], ctx.elf.read(ptr[1], ln[1]).decode("ascii", "replace"))
    return out


def _table_at(ctx, va, index_reg):
    """The jump-table dispatch (TABLE_TEXT) starting at va, else None. index_reg None accepts any index."""
    b = ctx.elf.read(va, 17 + 5 * MAX_TABLE_STORES)
    if len(b) < 17 or b[0] not in (0x48, 0x4C) or b[1] != 0x8D or b[2] & 0xC7 != 0x05:
        return None
    base = ((b[2] >> 3) & 7) | ((b[0] & 4) << 1)
    rex, modrm, sib = b[7], b[9], b[10]
    if rex & 0xF8 != 0x48 or b[8] != 0x63 or modrm & 0xC7 != 0x04 or sib >> 6 != 2:
        return None
    dest = ((modrm >> 3) & 7) | ((rex & 4) << 1)
    index = ((sib >> 3) & 7) | ((rex & 2) << 2)
    if (sib & 7) | ((rex & 1) << 3) != base or base & 7 == 5 or index == 4 \
            or (index_reg is not None and index != index_reg):
        return None
    rex2, op, m2 = b[11], b[12], b[13]
    reg2, rm2 = ((m2 >> 3) & 7) | ((rex2 & 4) << 1), (m2 & 7) | ((rex2 & 1) << 3)
    if rex2 & 0xF8 != 0x48 or m2 >> 6 != 3 or not ((op == 0x01 and (reg2, rm2) == (base, dest))
                                                   or (op == 0x03 and (reg2, rm2) == (dest, base))):
        return None
    jmp = (b"\x41" if dest >= 8 else b"") + bytes((0xFF, 0xE0 | (dest & 7)))
    i, stores = 14, 0
    while b[i:i + len(jmp)] != jmp:
        if stores == MAX_TABLE_STORES or not (b[i] in (0x48, 0x4C) and b[i + 1] == 0x89
                                              and b[i + 2] & 0xC7 == 0x44 and b[i + 3] == 0x24):
            return None
        i, stores = i + 5, stores + 1
    table = va + 7 + struct.unpack_from("<i", b, 3)[0]
    if not ctx.in_sec(".rodata", table):
        return None
    return {"table": table, "table_lea_site": va, "table_jmp_site": va + i,
            "table_regs": f"base {REG64[base]}, dest {REG64[dest]}, index {REG64[index]}",
            "stores_before_jmp": stores}


def _gap_insn(code, index_reg):
    """(kind, length, written register or None) of one allowed gap instruction, else None."""
    rex = code[0] if 0x40 <= code[0] <= 0x4F else 0
    k = 1 if rex else 0
    op, m = code[k], code[k + 1]
    b = (rex & 1) << 3
    on_index = rex & 8 and b == index_reg & 8
    if on_index and op == 0xFF and m == 0xC8 | (index_reg & 7):
        return "dec_index", 3, index_reg
    if on_index and op == 0x83 and m == 0xF8 | (index_reg & 7) and code[k + 2] < 0x80:
        return "cmp_index_imm8", 4, None
    if op in (0x31, 0x33) and m >> 6 == 3 and ((m >> 3) & 7) | ((rex & 4) << 1) == (m & 7) | b:
        return "zero_reg", k + 2, (m & 7) | b                    # xor r,r (one register): writes that register
    if op == 0x89 and m >> 6 == 3:
        return "mov_reg", k + 2, (m & 7) | b
    mod, reg = m >> 6, ((m >> 3) & 7) | ((rex & 4) << 1)
    disp = 1 if mod == 1 else 4
    if rex & 8 and not rex & 3 and op == 0x8B and mod in (1, 2) and m & 7 == 4 and code[k + 2] == 0x24:
        return "load_stack", k + 3 + disp, reg                  # mov r64,QWORD PTR [rsp+disp]
    if rex & 8 and not rex & 2 and op == 0x8D and mod in (1, 2):
        if m & 7 != 4:
            return "lea_reg_disp", k + 2 + disp, reg            # lea r64,[base+disp]
        if code[k + 2] & 0x38 == 0x20:                         # SIB without index
            return "lea_reg_disp", k + 3 + disp, reg
    if 0xB0 <= op <= 0xB7:
        return "mov_imm", k + 2, (op & 3) if not rex and op & 4 else (op & 7) | b
    if 0xB8 <= op <= 0xBF:
        return "mov_imm", k + 1 + (8 if rex & 8 else 4), (op & 7) | b
    return None


def _find_table(ctx, va, index_reg):
    """Follow GAP_TEXT instructions from va to the jump table that the idiom's index selects."""
    gap, decrements, bound = [], 0, None
    pos = va
    while True:
        t = _table_at(ctx, pos, index_reg)
        if t is not None:
            return dict(t, gap_sites=gap, index_decrements=decrements, bounds_check=bound)
        if len(gap) >= GAP_MAX:
            return {"stop": f"no jump table within {GAP_MAX} gap instructions"}
        code = ctx.elf.read(pos, 16)
        g = _gap_insn(code, index_reg)
        if g is None:
            return {"stop": f"instruction at {pos:#x} is not an allowed gap instruction"}
        kind, n, written = g
        if kind == "cmp_index_imm8":
            nxt = ctx.elf.read(pos + n, 6)
            if bound is not None or not (nxt[0] == 0x77 or nxt[:2] == b"\x0f\x87"):
                return {"stop": f"cmp at {pos:#x} is not a single bounds check followed by ja"}
            jn = 2 if nxt[0] == 0x77 else 6
            rel = struct.unpack_from("<b", nxt, 1)[0] if jn == 2 else struct.unpack_from("<i", nxt, 2)[0]
            bound = {"cmp_imm": code[3 if code[0] & 0xF0 == 0x40 else 2], "cmp_site": pos, "ja_site": pos + n,
                     "ja_target": pos + n + jn + rel}
            gap += [pos, pos + n]
            pos += n + jn
            continue
        if kind == "dec_index":
            decrements += 1
        elif written == index_reg:
            return {"stop": f"instruction at {pos:#x} overwrites the index register"}
        gap.append(pos)
        pos += n


def _shape(t):
    if t["bounds_check"] is not None:
        return "after_bounds_check"
    if t["gap_sites"]:
        return "after_gap"
    return "direct_with_stores" if t["stores_before_jmp"] else "direct"


def _sentinel_base(ctx, site, tag_reg):
    """Base register of 'mov ebp,0x3b9aca00; mov tag_reg,[base]' directly before site, else None."""
    for base in TAG_BASES:
        mv = _tag_load(tag_reg, base)
        if ctx.elf.read(site - len(mv) - len(SENTINEL), len(mv) + len(SENTINEL)) == SENTINEL + mv:
            return REG64[base]
    return None


def _register_text(tag_reg, index_reg, tmp, dflt, cc):
    """'tag R, index I[, temp X]' for cmovae (the default is loaded into I); cmovb adds the default register."""
    if cc == "cmovae":
        return f"tag {REG64[tag_reg]}, index {REG64[index_reg]}" + (f", temp {REG64[tmp]}" if tmp is not None else "")
    return f"tag {REG64[tag_reg]}, index {REG64[index_reg]}, default {REG64[dflt]}, {cc}"


def survey_idiom(ctx, p, names):
    """Every idiom occurrence in .text (any register allocation, either cmov) and the jump table its result indexes."""
    n = len(names)
    t_va, text = ctx.sec_bytes(".text")
    sites = []
    for i in _idiom_offsets(p, text):
        va = t_va + i
        ln, tag_reg, index_reg, tmp, dflt, cc = _idiom_at(p, text, i)
        fn = ctx.containing(va)
        if fn is None:
            raise EvidenceError(f"bias block at {va:#x} outside every FDE")
        row = {"site": va, "function": fn[0], "function_end": fn[1], "idiom_length": ln,
               "registers": _register_text(tag_reg, index_reg, tmp, dflt, cc), "cmov": cc,
               "index_register": REG64[index_reg], "tag_register": REG64[tag_reg],
               "temp_register": REG64[tmp] if tmp is not None else None, "default_register": REG64[dflt],
               "dispatcher_register_form": text[i:i + ln] == p["bias_block"],
               "sentinel_base": _sentinel_base(ctx, va, tag_reg)}
        t = _find_table(ctx, va + ln, index_reg)
        if "stop" in t:
            row.update(kind="no_table", stop=t["stop"])
        else:
            cnt = n if t["bounds_check"] is None else t["bounds_check"]["cmp_imm"] + 1
            if not ctx.in_sec(".rodata", t["table"] + 4 * cnt + 3):
                raise EvidenceError(f"jump table {t['table']:#x} of site {va:#x} leaves .rodata")
            entries = [t["table"] + ctx.i32(t["table"] + 4 * k) for k in range(cnt + 1)]
            row.update(t, kind="jump_table", shape=_shape(t), entries_read=cnt,
                       entries_in_function=sum(1 for e in entries[:cnt] if _inside(fn, e)),
                       distinct_entries=len(set(entries[:cnt])), entry_n_target=entries[cnt],
                       entry_n_in_function=_inside(fn, entries[cnt]), _entries=entries[:cnt])
        sites.append(row)
    if not sites:
        raise EvidenceError(f"release {p['release']}: bias block not found")
    return sites


def survey_default_elsewhere(ctx, p):
    """Every DEFAULT_ELSEWHERE_TEXT occurrence in .text: listed with its registers, not surveyed for tables or roles."""
    t_va, text = ctx.sec_bytes(".text")
    rows = []
    for i in _idiom_offsets(p, text, _idiom_default_elsewhere_at):
        va = t_va + i
        ln, tag_reg, index_reg, tmp, dflt, cc = _idiom_default_elsewhere_at(p, text, i)
        fn = ctx.containing(va)
        if fn is None:
            raise EvidenceError(f"bias computation at {va:#x} outside every FDE")
        rows.append({"site": va, "function": fn[0], "function_end": fn[1], "length": ln, "cmov": cc,
                     "registers": f"tag {REG64[tag_reg]}, index {REG64[index_reg]}, default {REG64[dflt]}, {cc}",
                     "tag_register": REG64[tag_reg], "index_register": REG64[index_reg],
                     "temp_register": REG64[tmp] if tmp is not None else None, "default_register": REG64[dflt]})
    counts = {}
    for r in rows:
        counts[r["cmov"]] = counts.get(r["cmov"], 0) + 1
    return {"text": DEFAULT_ELSEWHERE_TEXT[p["idiom_form"]], "count": len(rows), "cmov_counts": counts, "sites": rows}


def serializer_check(ctx, entries, variants):
    """Find the [rsp+off] at which arm K stores the &str VARIANTS[K] for every K (case-sensitive)."""
    names = variants[0]["names"]
    per_arm, errors = [], 0
    for arm in entries:
        try:
            addrs, _j, _t = ctx.walk(arm)
        except EvidenceError:
            errors += 1
            per_arm.append({})
            continue
        per_arm.append(_stack_strs(ctx, addrs))
    hits = {}
    for k, strs in enumerate(per_arm):
        for off, (_ptr, txt) in strs.items():
            if txt == names[k]:
                hits[off] = hits.get(off, 0) + 1
    off = min(hits, key=lambda o: (-hits[o], o)) if hits else None
    out = {"arms_storing_variant_name": hits.get(off, 0), "name_offset": off, "walk_errors": errors}
    if out["arms_storing_variant_name"] != len(names) or off + TYPE_REL < 0:
        return out

    def at(rel):
        return [strs.get(off + rel, (None, None)) for strs in per_arm]

    ptrs = [p for p, _t in at(NAME_REL)]
    out.update({
        "stack_base": off + TYPE_REL,
        "rust_idents": [t for _p, t in at(IDENT_REL)],
        "type_idents": sorted({t or "<missing>" for _p, t in at(TYPE_REL)}),
        "tag_strs": sorted({t or "<missing>" for _p, t in at(TAG_REL)}),
        "name_ptrs_equal_variants_copies": sorted(c["start"] for c in variants if c["_ptrs"] == ptrs),
        "name_ptr_matches_per_copy": [sum(1 for a, b in zip(c["_ptrs"], ptrs) if a == b) for c in variants],
    })
    return out


def assign_roles(ctx, sites, variants):
    """Role of every idiom site; returns (serializers, execute sites, sentinel_other_base sites)."""
    n = len(variants[0]["names"])
    serializers, execute, other_base = [], [], []
    for s in sites:
        if s["kind"] != "jump_table":
            s["role"] = "no_table"
            continue
        s["role"] = "other"
        n_way = (s["bounds_check"] is None and not s["index_decrements"]
                 and s["entries_in_function"] == n and s["distinct_entries"] == n)
        if not n_way:
            if s["sentinel_base"]:
                raise EvidenceError(f"sentinel site {s['site']:#x} has no {n}-way in-FDE jump table")
            continue
        chk = serializer_check(ctx, s["_entries"], variants)
        s["arms_storing_variant_name"] = chk["arms_storing_variant_name"]
        if "stack_base" in chk:
            if s["sentinel_base"]:
                raise EvidenceError(f"site {s['site']:#x} is both serializer and sentinel shaped")
            s["role"] = "serializer"
            serializers.append(dict(chk, function=s["function"], function_end=s["function_end"],
                                    table=s["table"], site=s["site"], shape=s["shape"]))
        elif s["sentinel_base"] == EXECUTE_BASE:
            s["role"] = "execute"
            execute.append(s)
        elif s["sentinel_base"]:
            s["role"] = "sentinel_other_base"
            other_base.append(s)
    return serializers, execute, other_base


def check_serializers(serializers):
    """All serializers must agree on the Rust identifiers and store 'Action' / 'type'; returns the identifiers."""
    if not serializers:
        raise EvidenceError("no arm-wise VARIANTS serializer")
    idents = serializers[0]["rust_idents"]
    if any(x["rust_idents"] != idents for x in serializers) or None in idents \
            or not all(NAME_RE.match(i) for i in idents) or len(set(idents)) != len(idents):
        raise EvidenceError("serializer Rust identifiers missing or inconsistent")
    if any(x["type_idents"] != ["Action"] or x["tag_strs"] != ["type"] for x in serializers):
        raise EvidenceError("serializer type/tag strings are not Action/type")
    return idents


def direct_transfers(ctx, f):
    """Byte-scanned rel32 call/jmp and RIP-slot call/jmp from FDE f to FDE starts (over-approximation)."""
    if f in ctx.transfers:
        return ctx.transfers[f]
    end = ctx.end_of(f)
    code = ctx.elf.read(f, end - f)
    out = set()
    for m in re.finditer(rb"[\xe8\xe9]", code):
        i = m.start()
        if i + 5 <= len(code):
            dst = f + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
            if dst != f and ctx.is_start(dst):
                out.add((f + i, "call" if code[i] == 0xE8 else "jmp", dst, None))
    for m in re.finditer(rb"\xff[\x15\x25]", code):
        i = m.start()
        if i + 6 <= len(code):
            slot = f + i + 6 + struct.unpack_from("<i", code, i + 2)[0]
            dst = ctx.relocs.get(slot)
            if dst is not None and dst != f and ctx.is_start(dst):
                out.add((f + i, "slot_call" if code[i + 1] == 0x15 else "slot_jmp", dst, slot))
    ctx.transfers[f] = sorted(out, key=lambda t: (t[0], t[1], t[2], t[3] or 0))
    return ctx.transfers[f]


def rel32_sources(ctx, targets):
    """Byte-scanned rel32 call/jmp sites anywhere in .text whose target is in targets (over-approximation)."""
    t_va, text = ctx.sec_bytes(".text")
    want = set(targets)
    out = {t: [] for t in want}
    for m in re.finditer(rb"[\xe8\xe9]", text):
        i = m.start()
        if i + 5 > len(text):
            continue
        t = t_va + i + 5 + int.from_bytes(text[i + 1:i + 5], "little", signed=True)
        if t in want:
            out[t].append({"site": t_va + i, "kind": "call" if text[i] == 0xE8 else "jmp",
                           "function": ctx.owner(t_va + i)})
    return out


def _walk_arm(ctx, va):
    """RE-010's strict walk; only if it rejects the path, the extended walk. Returns (addrs, jccs, term, ext)."""
    try:
        a, j, t = ctx.walk(va)
        return a, j, t, None
    except EvidenceError as strict:
        err = strict
    try:
        a, j, t, used = ctx.walk_ext(va)
    except EvidenceError:
        raise err from None
    return a, j, t, {"strict_error": str(err), "encodings": used}


def resolve_arm(ctx, row, arms, tails, lo, instance_starts):
    """Handler of one walked arm: first call, shared arm tail, or the single call of its entry branches."""
    term = row["path_end"]
    res = {"handler": None, "via": "none"}
    if term["kind"] in ("rel32", "rip_slot"):
        res = {"handler": term["target"], "via": "call" if term["kind"] == "rel32" else "slot_call"}
    elif term["target"] in tails and tails[term["target"]] != row["index"]:
        other = arms[tails[term["target"]]]
        if other["path_end"]["kind"] not in ("rel32", "rip_slot"):
            raise EvidenceError(f"shared tail {term['target']:#x} does not end in a call")
        _a, _j, t2, _x = _walk_arm(ctx, term["target"])
        if t2 != other["path_end"]:
            raise EvidenceError(f"shared tail walk from {term['target']:#x} disagrees")
        res = {"handler": other["path_end"]["target"], "via": "shared_arm_tail",
               "shared_with_index": other["index"], "shared_tail_target": term["target"]}
    else:
        calls = sorted({b["path_end"]["target"] for b in row["entry_branches"]
                        if b["path_end"]["kind"] in ("rel32", "rip_slot")})
        if len(calls) == 1:
            res = {"handler": calls[0], "via": "entry_branch"}
        elif calls:
            res = {"handler": None, "via": "ambiguous_entry_branches"}
    h = res["handler"]
    if h is not None:
        res["handler_size"] = ctx.end_of(h) - h if ctx.is_start(h) else None
        if h in instance_starts:
            res["handler_is_dispatcher_instance"] = True
        if h == lo or (ctx.is_start(h) and any(d == lo for _s, _k, d, _sl in direct_transfers(ctx, h))):
            res["reenters_instance"] = True
    return res


def execute_instance(ctx, site, names, instance_starts):
    lo, hi = site["function"], site["function_end"]
    if site["entries_in_function"] != len(names) or site["distinct_entries"] != len(names):
        raise EvidenceError(f"dispatcher {lo:#x}: table entries not {len(names)} distinct in-FDE arms")
    arms, tails = [], {}
    for k, arm in enumerate(site["_entries"]):
        row = {"index": k, "name": names[k], "arm": arm}
        try:
            addrs, jccs, term, ext = _walk_arm(ctx, arm)
        except EvidenceError as e:
            row["unresolved"] = str(e)
            arms.append(row)
            continue
        if ext:
            row["extended_decoder"] = ext
        branches = []
        for j in jccs:
            if not _inside((lo, hi), j["target"]):
                raise EvidenceError(f"jcc at {j['site']:#x} leaves dispatcher {lo:#x}")
            _a, _j, bterm = ctx.walk(j["target"])
            branches.append({"site": j["site"], "target": j["target"], "path_end": dict(bterm)})
        row.update({"path_insns": len(addrs), "path_end": dict(term), "entry_branches": branches})
        for a in addrs:
            tails.setdefault(a, k)
        arms.append(row)
    for row in arms:
        if "unresolved" not in row:
            row["resolution"] = resolve_arm(ctx, row, arms, tails, lo, instance_starts)
    unresolved = [r["index"] for r in arms if "unresolved" in r]
    via = {}
    for r in arms:
        v = r["resolution"]["via"] if "resolution" in r else "unresolved"
        via[v] = via.get(v, 0) + 1
    return {"start": lo, "end": hi, "table": site["table"], "bias_site": site["site"],
            "tag_base": site["sentinel_base"], "tag_register": site["tag_register"],
            "entry_n_target": site["entry_n_target"], "entry_n_in_function": site["entry_n_in_function"],
            "arms": arms, "unresolved_indices": unresolved,
            "extended_decoder_indices": [r["index"] for r in arms if "extended_decoder" in r],
            "via_counts": dict(sorted(via.items()))}


def dispatcher_family(ctx, sites, names, all_starts):
    sites = sorted(sites, key=lambda s: s["function"])
    instances = [execute_instance(ctx, s, names, all_starts) for s in sites]
    if instances and (instances[0]["unresolved_indices"] or instances[0]["extended_decoder_indices"]):
        raise EvidenceError(f"primary instance {instances[0]['start']:#x} has arms the strict walker rejects")
    return instances


def _handler(row):
    return (row or {}).get("resolution", {}).get("handler")


def handler_distinctness(instances, names):
    """Arms resolved in every instance, and how many of them reach pairwise-distinct handlers."""
    resolved, distinct, exceptions = 0, 0, []
    for k in range(len(names)):
        hs = [_handler(x["arms"][k]) for x in instances]
        if not instances or None in hs:
            continue
        resolved += 1
        if len(set(hs)) == len(hs):
            distinct += 1
        else:
            exceptions.append({"index": k, "name": names[k], "handlers": hs})
    return {"arms_resolved_in_all_instances": resolved, "arms_with_pairwise_distinct_handlers": distinct,
            "exceptions": exceptions}


FAMILY_RELATION_RULE = ("direct transfers of the arm-K handler (direct_transfers: byte-scanned rel32 call/jmp and "
                         "RIP-slot call/jmp through a RELATIVE slot); 'same index' = a handler of execute arm K in "
                         "any instance; 'other index' = an execute-family handler that is not also a handler of "
                         "arm K (the cDeposit handler is also the cDeposit2 shared-tail handler, arms 62 and 91)")


def family_relation(ctx, others, executes, names):
    """How each sentinel_other_base instance's handlers relate to the execute family's handlers (by index)."""
    by_index = [{_handler(x["arms"][k]) for x in executes} - {None} for k in range(len(names))]
    every = set().union(*by_index) if by_index else set()
    starts = {x["start"] for x in executes}
    out = []
    for inst in others:
        hs = [_handler(r) for r in inst["arms"]]
        same, same_rel32, cross, into = [], [], [], []
        for k, h in enumerate(hs):
            if h is None or not ctx.is_start(h):
                continue
            tr = direct_transfers(ctx, h)
            dst = {d for _s, _k, d, _sl in tr}
            if dst & by_index[k]:
                same.append(k)
            if {d for _s, kind, d, _sl in tr if kind in ("call", "jmp")} & by_index[k]:
                same_rel32.append(k)
            if (dst & every) - by_index[k]:
                cross.append(k)
            for d in sorted(dst & starts):
                into.append({"index": k, "name": names[k], "handler": h, "dispatcher": d})
        out.append({"start": inst["start"],
                    "handlers_shared_with_execute_family": len(set(hs) & every),
                    "arms_whose_handler_transfers_to_same_index_execute_handler": len(same),
                    "arms_whose_handler_transfers_to_same_index_execute_handler_rel32_only": len(same_rel32),
                    "arms_same_index_only_through_rip_slot": sorted(set(same) - set(same_rel32)),
                    "arms_whose_handler_transfers_to_other_index_execute_handler": cross,
                    "arms_with_handler": sum(1 for h in hs if h is not None),
                    "handlers_transferring_to_execute_instance": into})
    return out


LOCATION_RULE = ("RELATIVE slot in .data.rel.ro whose addend is in .rodata, followed by u64 len, u32 line, u32 col; "
                 "0 < len < 256, path inside .rodata, path ends in '.rs' and has no NUL, line != 0, col != 0")


def _catalogue_path(p):
    """'<crate>/<file>' for a FIRST_PARTY_CRATES path in absolute (ABS_PREFIX) or relative form, else None."""
    rel = p[len(ABS_PREFIX):] if p.startswith(ABS_PREFIX) else p
    m = re.match(rb"([a-z_0-9]+)/src/(.+)\Z", rel)
    if m and m.group(1).decode() in FIRST_PARTY_CRATES:
        return m.group(1).decode() + "/" + m.group(2).decode("ascii", "replace")
    return None


def location_records(ctx, excluded=None):
    """Location records (LOCATION_RULE). Paths that pass every rule except line/col != 0 go to excluded."""
    rows = []
    for slot in sorted(ctx.relocs):
        a = ctx.relocs[slot]
        if not (ctx.in_sec(".data.rel.ro", slot) and ctx.in_sec(".rodata", a)):
            continue
        ln, line, col = struct.unpack("<QII", ctx.elf.read(slot + 8, 16))
        if not 0 < ln < 256 or not ctx.in_sec(".rodata", a + ln - 1):
            continue
        p = ctx.elf.read(a, ln)
        if not p.endswith(b".rs") or b"\0" in p:
            continue
        if line == 0 or col == 0:
            if excluded is not None:
                excluded.append((p, line, col))
            continue
        absolute = p.startswith(ABS_PREFIX)
        cat = _catalogue_path(p)
        sites = sorted(ctx.leas.get(slot, ()))
        form = "absolute" if absolute else "other_absolute" if p.startswith(b"/") else "relative"
        rows.append({"slot": slot, "path": p.decode("ascii", "replace"), "form": form,
                     "catalogue_path": cat, "line": line, "col": col, "lea_sites": sites,
                     "owners": sorted({ctx.owner(x) for x in sites if ctx.owner(x) is not None})})
    return rows


def location_classes(locs):
    """Record counts by form and first path component; first_party_* are the FIRST_PARTY_CRATES records."""
    out = {}
    for r in locs:
        p = r["path"]
        if r["catalogue_path"]:
            k = "first_party_" + r["form"]
        elif r["form"] == "absolute":
            k = "absolute_other_dir:" + p[len(ABS_PREFIX):].split("/", 1)[0]
        elif r["form"] == "other_absolute":
            k = "other_absolute"
        else:
            k = "relative_other_dir:" + p.split("/", 1)[0]
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def _reach(ctx, instances, owners):
    """Arms whose handler is an owner (depth 0) or transfers directly to one (depth 1)."""
    owners = set(owners)
    starts = {i["start"] for i in instances}
    hits = []
    for n_inst, inst in enumerate(instances):
        for row in inst["arms"]:
            h = row.get("resolution", {}).get("handler")
            if h is None or h in starts or not ctx.is_start(h):
                continue
            if h in owners:
                hits.append({"instance": n_inst, "index": row["index"], "name": row["name"], "depth": 0,
                             "handler": h, "site": None, "owner": h})
            for s, k, d, _sl in direct_transfers(ctx, h):
                if d in owners and d not in starts:
                    hits.append({"instance": n_inst, "index": row["index"], "name": row["name"], "depth": 1,
                                 "handler": h, "site": s, "owner": d, "transfer": k})
    hits.sort(key=lambda x: (x["instance"], x["index"], x["depth"], x["site"] or 0, x["owner"]))
    return hits


def anchor_table(ctx, instances, names, locs):
    """For each anchor file: its Location owners and the arms that reach them (depth <= 1)."""
    out = []
    for path, want in ANCHOR_FILES:
        recs = [r for r in locs if r["catalogue_path"] == path]
        owners = sorted({o for r in recs for o in r["owners"]})
        hits = _reach(ctx, instances, owners)
        reached = sorted({h["name"] for h in hits})
        covered = sorted({h["instance"] for h in hits if h["name"] == want})
        out.append({
            "path": path, "expected_name": want,
            "expected_index": names.index(want) if want in names else None,
            "locations": [{k: r[k] for k in ("slot", "path", "form", "line", "col", "lea_sites", "owners")}
                          for r in recs],
            "owners": owners, "reached_by": hits, "reached_names": reached,
            "instances_reached_by_expected": covered,
            "holds_all_instances": bool(recs) and reached == [want] and covered == list(range(len(instances))),
        })
    return out


def _arm_handlers(families):
    """function start -> [(family, instance, index, name)] for every resolved arm handler."""
    out = {}
    for fam, instances in families.items():
        for n_inst, inst in enumerate(instances):
            for r in inst["arms"]:
                h = _handler(r)
                if h is not None:
                    out.setdefault(h, []).append({"family": fam, "instance": n_inst, "index": r["index"],
                                                  "name": r["name"]})
    return out


def _sources(srcs, handlers, dispatchers):
    return [dict(s, arm_handler_of=handlers.get(s["function"], []), dispatcher_of=dispatchers.get(s["function"]))
            for s in srcs]


def _outside_execute_family(src):
    return src["dispatcher_of"] is None and not any(x["family"] == "execute" for x in src["arm_handler_of"])


def analyze(data: bytes, profile: dict, expected_sha256: str) -> dict:
    """Derive one release's evidence. The digest is checked before any parsing; malformed input fails closed."""
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"release {profile['release']}: binary sha256 {sha} != {expected_sha256}")
    index_reg = _check_profile(profile)
    try:
        return _analyze(data, profile, sha, index_reg)
    except (KeyError, IndexError, struct.error, UnicodeDecodeError) as e:
        raise EvidenceError(f"release {profile['release']}: malformed input ({type(e).__name__}: {e})") from None


def table_census(ctx, variants, idiom_serializers):
    """Control: every jump table in .text (any registers) with N pairwise-distinct in-FDE entries."""
    n = len(variants[0]["names"])
    t_va, text = ctx.sec_bytes(".text")
    tables, found = 0, []
    for m in TABLE_CANDIDATE_RE.finditer(text):
        va = t_va + m.start()
        t = _table_at(ctx, va, None)
        fn = ctx.containing(va) if t else None
        if fn is None or not ctx.in_sec(".rodata", t["table"] + 4 * n - 1):
            continue
        ents = [t["table"] + ctx.i32(t["table"] + 4 * k) for k in range(n)]
        if len(set(ents)) != n or not all(_inside(fn, e) for e in ents):
            continue
        tables += 1
        if "stack_base" in serializer_check(ctx, ents, variants):
            found.append(fn[0])
    return {"n_way_tables": tables, "serializer_functions": sorted(found),
            "serializers_equal_idiom_serializers": sorted(found) == sorted(idiom_serializers)}


def sentinel_census(ctx, p):
    """Control: every 'mov ebp,0x3b9aca00' byte sequence in .text, and which ones are directly followed by a tag
    load 'mov R,[base]' (any R, any base) and the idiom (either cmov, any register allocation) with tag register R."""
    t_va, text = ctx.sec_bytes(".text")
    rows = []
    for m in re.finditer(re.escape(SENTINEL), text):
        va = t_va + m.start()
        hit = None
        for dst in range(16):
            for base in TAG_BASES:
                mv = _tag_load(dst, base)
                if text[m.end():m.end() + len(mv)] == mv:
                    r = _idiom_at(p, text, m.end() + len(mv))
                    if r is not None and r[1] == dst:
                        hit = (REG64[base], REG64[dst])
        rows.append({"site": va, "function": ctx.owner(va), "tag_load_then_idiom": hit and hit[0],
                     "tag_register": hit and hit[1]})
    return {"occurrences": len(rows), "before_tag_load_and_idiom": sum(1 for r in rows if r["tag_load_then_idiom"]),
            "sites": rows}


def _analyze(data, profile, sha, index_reg):
    ctx = Ctx(data)
    variants = find_variants(ctx, profile)
    names = variants[0]["names"]
    sites = survey_idiom(ctx, profile, names)
    default_elsewhere = survey_default_elsewhere(ctx, profile)
    serializers, exec_sites, other_sites = assign_roles(ctx, sites, variants)
    idents = check_serializers(serializers)
    if len(exec_sites) != profile["execute_instances"]:
        raise EvidenceError(f"expected {profile['execute_instances']} execute instances, found {len(exec_sites)}")
    if len(other_sites) != profile["sentinel_other_base_instances"]:
        raise EvidenceError(f"expected {profile['sentinel_other_base_instances']} sentinel_other_base instances, "
                            f"found {len(other_sites)}")
    all_starts = {s["function"] for s in exec_sites + other_sites}
    instances = dispatcher_family(ctx, exec_sites, names, all_starts)
    others = dispatcher_family(ctx, other_sites, names, all_starts)
    excluded = []
    locs = location_records(ctx, excluded)
    anchors = anchor_table(ctx, instances, names, locs)
    other_anchors = anchor_table(ctx, others, names, locs) if others else []
    handlers = _arm_handlers({"execute": instances, "sentinel_other_base": others})
    dispatchers = {x["start"]: {"family": fam, "instance": n_inst}
                   for fam, insts in (("execute", instances), ("sentinel_other_base", others))
                   for n_inst, x in enumerate(insts)}
    owner_set = {o for a in anchors for o in a["owners"]}
    srcs = rel32_sources(ctx, owner_set | all_starts)
    for a in anchors:
        a["owner_callers"] = [{"owner": o, "sources": _sources(srcs[o], handlers, dispatchers)} for o in a["owners"]]
    refs = []
    for fam, insts in (("execute", instances), ("sentinel_other_base", others)):
        for n_inst, x in enumerate(insts):
            refs.append({"family": fam, "instance": n_inst, "start": x["start"],
                         "rel32_sources": _sources(srcs[x["start"]], handlers, dispatchers),
                         "reloc_slots": ctx.reloc_slots_to(x["start"]),
                         "lea_sites": sorted(ctx.leas.get(x["start"], ()))})
    basenames, source_paths = {}, {}
    for path, _l in CATALOGUE_PATHS:
        crate, rest = path.split("/", 1)
        basenames[path] = data.count(path.rsplit("/", 1)[1].encode())
        source_paths[path] = data.count(f"{crate}/src/{rest}".encode())
    fp_paths = {}
    for r in locs:
        if r["catalogue_path"]:
            fp_paths.setdefault(r["catalogue_path"], []).append(r)
    form_counts = {}
    for r in locs:
        if r["catalogue_path"]:
            form_counts[r["form"]] = form_counts.get(r["form"], 0) + 1
    census = {"tables": table_census(ctx, variants, [x["function"] for x in serializers]),
              "sentinel": sentinel_census(ctx, profile)}
    shared = [k for k in range(len(names)) if len({c["_ptrs"][k] for c in variants}) == 1]
    pairwise = [[sum(1 for a, b in zip(x["_ptrs"], y["_ptrs"]) if a == b) for y in variants] for x in variants]
    for s in sites:
        s.pop("_entries", None)
    for x in serializers:
        x["rust_idents_equal_first_serializer"] = x.pop("rust_idents") == idents
    for c in variants:
        c.pop("_ptrs", None)
    return {
        "release": profile["release"],
        "binary_sha256": sha,
        "fde_count": len(ctx.starts),
        "profile": {"bias": profile["bias"], "default_index": profile["default_index"],
                    "idiom_form": profile["idiom_form"], "idiom_text": IDIOM_TEXT[profile["idiom_form"]],
                    "idiom_rules": IDIOM_RULES,
                    "bias_block_hex": profile["bias_block"].hex(), "bias_block_text": profile["bias_block_text"],
                    "bias_block_index_register": REG64[index_reg], "table_text": TABLE_TEXT, "gap_text": GAP_TEXT,
                    "sentinel_hex": SENTINEL.hex(), "sentinel_text": SENTINEL_TEXT,
                    "execute_prologue_text": EXECUTE_PROLOGUE_TEXT,
                    "variants_seed": profile["variants_seed"].decode()},
        "variants": {"copies": [{k: v for k, v in c.items() if k != "names"} for c in variants],
                     "copies_identical": True, "count": len(names), "names": names,
                     "default_index_name": names[profile["default_index"]],
                     "slots_with_ptr_shared_by_all_copies": shared,
                     "pairwise_equal_ptr_counts": pairwise},
        "idiom_sites": sites,
        "idiom_site_counts": _counts(sites, len(names)),
        "idiom_register_forms": _register_forms(sites),
        "idiom_default_elsewhere": default_elsewhere,
        "serializers": serializers,
        "rust_idents": idents,
        "execute_instances": instances,
        "sentinel_other_base_instances": others,
        "handler_distinctness": {"execute": handler_distinctness(instances, names),
                                 "sentinel_other_base": handler_distinctness(others, names)},
        "sentinel_other_base_relation": family_relation(ctx, others, instances, names),
        "sentinel_other_base_relation_rule": FAMILY_RELATION_RULE,
        "dispatcher_references": refs,
        "anchors": anchors,
        "sentinel_other_base_anchor_reach": [
            {k: a[k] for k in ("path", "expected_name", "reached_names", "instances_reached_by_expected",
                               "holds_all_instances")} | {"depths": sorted({h["depth"] for h in a["reached_by"]})}
            for a in other_anchors],
        "census": census,
        "first_party_crates": list(FIRST_PARTY_CRATES),
        "first_party_location_count": sum(1 for r in locs if r["catalogue_path"]),
        "first_party_location_forms": dict(sorted(form_counts.items())),
        "location_record_rule": LOCATION_RULE,
        "location_record_count": len(locs),
        "location_record_classes": location_classes(locs),
        "location_records_excluded_line_or_col_zero": {
            "count": len(excluded), "line_zero": sum(1 for _p, ln, _c in excluded if ln == 0),
            "col_zero": sum(1 for _p, _ln, c in excluded if c == 0),
            "first_party_paths": sorted({c for c in (_catalogue_path(x) for x, _l, _c in excluded) if c})},
        "_fp_paths": fp_paths,
        "_ctx": ctx,
        "catalogue_basename_occurrences": basenames,
        "catalogue_source_path_occurrences": source_paths,
    }


def _register_forms(sites):
    """Idiom sites per register allocation, with their shapes and roles."""
    out = {}
    for s in sites:
        r = out.setdefault(s["registers"], {"sites": 0, "dispatcher_register_form": s["dispatcher_register_form"]})
        r["sites"] += 1
        for key in ("shape:" + s.get("shape", "no_table"), "role:" + s["role"]):
            r[key] = r.get(key, 0) + 1
    return dict(sorted(out.items()))


def _counts(sites, n):
    out = {"bias_block_occurrences": len(sites),
           "bias_block_occurrences_dispatcher_register_form": sum(1 for s in sites if s["dispatcher_register_form"])}
    for s in sites:
        for key in ("shape:" + s.get("shape", "no_table"), "role:" + s["role"], "cmov:" + s["cmov"]):
            out[key] = out.get(key, 0) + 1
    unbounded = [s for s in sites if s.get("shape") and s["shape"] != "after_bounds_check"]
    out["n_entry_tables"] = len(unbounded)
    out["n_entry_tables_with_entry_n_in_function"] = sum(1 for s in unbounded if s["entry_n_in_function"])
    out["direct_tables_with_entry_n_in_function"] = sum(1 for s in unbounded if s["shape"] == "direct"
                                                        and s["entry_n_in_function"])
    return dict(sorted(out.items()))


def join(t94, t115):
    n94, n115 = t94["variants"]["names"], t115["variants"]["names"]
    names = sorted(set(n94) | set(n115), key=lambda n: (n94.index(n) if n in n94 else len(n94) + n115.index(n), n))
    rows, counts = [], {"same_index": 0, "shifted": 0, "removed": 0, "added": 0}
    shifts = {}
    for n in names:
        i = n94.index(n) if n in n94 else None
        j = n115.index(n) if n in n115 else None
        cls = ("removed" if j is None else "added" if i is None else "same_index" if i == j else "shifted")
        counts[cls] += 1
        if cls == "shifted":
            shifts[f"{j - i:+d}"] = shifts.get(f"{j - i:+d}", 0) + 1
        row = {"name": n, "class": cls, "index_94": i, "index_115": j,
               "index_delta": None if i is None or j is None else j - i}
        for rel, t, k in (("94", t94, i), ("115", t115, j)):
            if k is None:
                for key in ("rust_ident", "handlers", "handler_sizes", "via", "reenters", "extended_decoder"):
                    row[f"{key}_{rel}"] = None
                continue
            row[f"rust_ident_{rel}"] = t["rust_idents"][k]
            res = [x["arms"][k].get("resolution", {}) for x in t["execute_instances"]]
            row[f"handlers_{rel}"] = [r.get("handler") for r in res]
            row[f"handler_sizes_{rel}"] = [r.get("handler_size") for r in res]
            row[f"via_{rel}"] = [r.get("via", "unresolved") for r in res]
            row[f"reenters_{rel}"] = [bool(r.get("reenters_instance")) for r in res]
            row[f"extended_decoder_{rel}"] = ["extended_decoder" in x["arms"][k] for x in t["execute_instances"]]
        rows.append(row)
    counts.update({"arm_to_name_binding": ARM_TO_NAME_NOTE,
                   "names_94": len(n94), "names_115": len(n115), "common": counts["same_index"] + counts["shifted"],
                   "shift_histogram": dict(sorted(shifts.items())),
                   "rust_ident_changed_common": sum(1 for r in rows if r["index_94"] is not None
                                                    and r["index_115"] is not None
                                                    and r["rust_ident_94"] != r["rust_ident_115"])})
    return rows, counts


def qualify(t94, t115):
    out = []
    anchors = {rel: {a["path"]: a for a in t["anchors"]} for rel, t in (("94", t94), ("115", t115))}
    want = dict(ANCHOR_FILES)
    for path, listed in CATALOGUE_PATHS:
        a94, a115 = anchors["94"][path], anchors["115"][path]
        name = want[path]
        in94, in115 = name in t94["variants"]["names"], name in t115["variants"]["names"]
        p94, p115 = bool(a94["locations"]), bool(a115["locations"])
        q, blocked = None, None
        if p94 and not p115 and in94 and in115:
            q = "absent_path_surviving_variant" if a94["holds_all_instances"] else None
        elif p115 and not p94 and in94 and in115:
            q = "added_path_existing_variant" if a115["holds_all_instances"] else None
        elif p115 and not p94 and in115 and not in94:
            q = "added_path_new_variant" if a115["holds_all_instances"] else None
        if q is None:
            blocked = "anchor does not hold in every execute instance or presence pattern unexpected"
        ctr = {}
        for rel, t in (("94", t94), ("115", t115)):
            rows = []
            if name in t["variants"]["names"]:
                k = t["variants"]["names"].index(name)
                fp = t["_fp_paths"]
                for x in t["execute_instances"]:
                    h = _handler(x["arms"][k])
                    own = sorted({p for p, recs in fp.items() for r in recs if h in r["owners"]}) if h else []
                    rows.append({"handler": h, "handler_size": x["arms"][k].get("resolution", {}).get("handler_size"),
                                 "handler_location_files": own})
            ctr[rel] = rows
        present = a94 if p94 else a115
        out.append({
            "path": path, "catalogue_list": listed, "anchor_name": name,
            "variant_index": {"94": t94["variants"]["names"].index(name) if in94 else None,
                              "115": t115["variants"]["names"].index(name) if in115 else None},
            "location_count": {"94": len(a94["locations"]), "115": len(a115["locations"])},
            "location_forms": {"94": sorted({r["form"] for r in a94["locations"]}),
                               "115": sorted({r["form"] for r in a115["locations"]})},
            "lines": {"94": sorted({r["line"] for r in a94["locations"]}),
                      "115": sorted({r["line"] for r in a115["locations"]})},
            "basename_occurrences": {"94": t94["catalogue_basename_occurrences"][path],
                                     "115": t115["catalogue_basename_occurrences"][path]},
            "source_path_occurrences": {"94": t94["catalogue_source_path_occurrences"][path],
                                        "115": t115["catalogue_source_path_occurrences"][path]},
            "anchor_holds_all_instances": {"94": a94["holds_all_instances"] if p94 else None,
                                           "115": a115["holds_all_instances"] if p115 else None},
            "reach_depths": {"94": sorted({h["depth"] for h in a94["reached_by"]}),
                             "115": sorted({h["depth"] for h in a115["reached_by"]})},
            "owner_callers_outside_execute_family": sorted({s["function"] for c in present["owner_callers"]
                                                            for s in c["sources"] if _outside_execute_family(s)}),
            "variant_handlers": ctr,
            "qualification": q,
            "qualification_blocked": blocked,
        })
    return out


def drift_reach(t94, t115):
    p94, p115 = set(t94["_fp_paths"]), set(t115["_fp_paths"])
    out = {}
    for label, rel, t, paths in (("absent115", "94", t94, sorted(p94 - p115)),
                                 ("added115", "115", t115, sorted(p115 - p94))):
        rows = []
        for path in paths:
            recs = t["_fp_paths"][path]
            owners = sorted({o for r in recs for o in r["owners"]})
            hits = _reach(t["_ctx"], t["execute_instances"], owners)
            rows.append({"path": path, "release": rel, "location_count": len(recs), "owner_count": len(owners),
                         "reached_by": sorted({(h["name"], h["depth"]) for h in hits}),
                         "reached_instances": sorted({h["instance"] for h in hits}),
                         "transfer_kinds": sorted({h.get("transfer", "handler") for h in hits})})
        out[label] = {"paths": rows, "path_count": len(rows),
                      "with_owners": sum(1 for r in rows if r["owner_count"]),
                      "reached": sum(1 for r in rows if r["reached_by"])}
    return out


def re010_crosscheck(t94, re010_bytes, expected_json_sha256=RE010_JSON_SHA256):
    sha = hashlib.sha256(re010_bytes).hexdigest()
    if sha != expected_json_sha256:
        raise EvidenceError(f"RE-010 JSON sha256 {sha} != {expected_json_sha256}")
    d = json.loads(re010_bytes)
    inst = t94["execute_instances"][0]
    if int(d["dispatcher"]["start"], 16) != inst["start"] or int(d["jump_table"], 16) != inst["table"]:
        raise EvidenceError("RE-010 dispatcher/jump table differ from #94 primary instance")
    # The RE-010 packet describes the pinned #94 digest; mutated inputs (tamper controls) are compared to it.
    if d["binary_sha256"] != EXPECTED_SHA256 or d["table_entries"] != len(inst["arms"]):
        raise EvidenceError("RE-010 JSON is for another binary or table length")

    def h(x):
        return {k: (int(v, 16) if k in ("site", "target", "slot") else v) for k, v in x.items()}

    mism = []
    names, idents = t94["variants"]["names"], t94["rust_idents"]
    labels = {"claims": 0, "wire_type_equals_serde_name": 0, "wire_type_equals_rust_ident": 0,
              "rust_variant_equals_ident_plus_Action": 0}
    wire_diff, variant_diff = [], []
    for c in d["cases"]:
        k = c["index"]
        mine = inst["arms"][k]
        theirs_branches = [{"site": int(b["site"], 16), "target": int(b["target"], 16),
                            "path_end": h(b["path_end"])} for b in c["entry_branches"]]
        same = (int(c["arm"], 16) == mine["arm"] and h(c["arm_path_end"]) == mine["path_end"]
                and c["arm_path_insns"] == mine["path_insns"] and theirs_branches == mine["entry_branches"])
        fc = c["first_call"]
        if fc is not None:
            same = same and int(fc["target"], 16) == mine["path_end"]["target"]
        if not same:
            mism.append(k)
        r = c.get("reconstruction")
        if r:
            labels["claims"] += 1
            labels["wire_type_equals_serde_name"] += r["wire_type"] == names[k]
            labels["wire_type_equals_rust_ident"] += r["wire_type"] == idents[k]
            labels["rust_variant_equals_ident_plus_Action"] += r["rust_variant"] == idents[k] + "Action"
            if r["wire_type"] != names[k]:
                wire_diff.append({"index": k, "reconstruction_wire_type": r["wire_type"], "serde_name": names[k],
                                  "rust_ident": idents[k]})
            if r["rust_variant"] != idents[k] + "Action":
                variant_diff.append({"index": k, "reconstruction_rust_variant": r["rust_variant"],
                                     "rust_ident": idents[k]})
    unclaimed = [{"index": c["index"], "serde_name": names[c["index"]], "rust_ident": idents[c["index"]]}
                 for c in d["cases"] if "reconstruction" not in c]
    labels["wire_type_differs"] = len(wire_diff)
    labels["wire_type_differs_but_equals_rust_ident"] = sum(1 for x in wire_diff
                                                            if x["reconstruction_wire_type"] == x["rust_ident"])
    return {"re010_json_sha256": sha, "cases_compared": len(d["cases"]), "mismatched_indices": mism,
            "arm_decoder": "tools/exchange_dispatch.walk, shared with RE-010; only table and instance discovery "
                           "are independent of RE-010",
            "analyzed_binary_is_re010_binary": d["binary_sha256"] == t94["binary_sha256"],
            "label_counts": labels, "label_counts_note": PR226_LABELS_NOTE, "wire_type_differences": wire_diff,
            "rust_variant_differences": variant_diff, "unclaimed_cases": unclaimed,
            "unclaimed_cases_note": PR226_CASES_NOTE}


def _band(rows, i, j):
    """(pairs, usable, within) for #94 execute instance i against #115 execute instance j."""
    pairs = []
    for r in rows:
        if r["class"] not in ("same_index", "shifted"):
            continue
        a, b = r["handler_sizes_94"][i], r["handler_sizes_115"][j]
        excl = None
        if a is None or b is None:
            excl = "no_resolved_handler"
        elif r["reenters_94"][i] or r["reenters_115"][j]:
            excl = "first_call_reenters_dispatcher"
        pairs.append({"name": r["name"], "size_94": a, "size_115": b,
                      "ratio": None if not a or b is None else round(b / a, 4), "excluded": excl})
    usable = [x for x in pairs if x["excluded"] is None]
    return pairs, len(usable), sum(1 for x in usable if SIZE_BAND[0] <= x["ratio"] <= SIZE_BAND[1])


def size_ratios(rows, n94, n115):
    """Handler FDE sizes for common names. Sizes only; never code identity."""
    pairs, usable, within = _band(rows, 0, 0)
    by_pair = {}
    for i in range(n94):
        for j in range(n115):
            _p, u, w = _band(rows, i, j)
            by_pair[f"{i}/{j}"] = {"usable_pairs": u, "within_band": w}
    return {"pairs": pairs, "usable_pairs": usable, "within_band": within, "band": list(SIZE_BAND),
            "pairing": "execute instance 0 / execute instance 0",
            "by_instance_pair": by_pair,
            "within_band_range": [min(x["within_band"] for x in by_pair.values()),
                                  max(x["within_band"] for x in by_pair.values())]}


def instance_spread(t):
    n, diff = 0, 0
    for k in range(len(t["variants"]["names"])):
        sizes = [x["arms"][k].get("resolution", {}).get("handler_size") for x in t["execute_instances"]]
        if None not in sizes:
            n += 1
            diff += len(set(sizes)) > 1
    return {"arms_with_all_instance_sizes": n, "arms_with_differing_instance_sizes": diff}


def build(data: bytes, data115: bytes | None = None, expected_sha256: str = EXPECTED_SHA256,
          expected_sha256_115: str = EXPECTED_SHA256_115, re010_json: bytes | None = None,
          profile94: dict = PROFILE_94, profile115: dict = PROFILE_115) -> dict:
    t94 = analyze(data, profile94, expected_sha256)
    if data115 is None:
        data115 = TARGET_115.read_bytes()
    t115 = analyze(data115, profile115, expected_sha256_115)
    return combine(t94, t115, re010_json)


def combine(t94: dict, t115: dict, re010_json: bytes | None = None) -> dict:
    """Cross-release evidence from two analyze() results, which are read and not modified."""
    rows, counts = join(t94, t115)
    cross = re010_crosscheck(t94, RE010_JSON.read_bytes() if re010_json is None else re010_json)
    quals = qualify(t94, t115)
    drift = drift_reach(t94, t115)
    targets = {}
    for rel, t in (("94", t94), ("115", t115)):
        targets[rel] = {k: v for k, v in t.items() if not k.startswith("_")}
        targets[rel]["instance_size_spread"] = instance_spread(t)
    return {
        "schema": "re014-action-dispatch-drift/v4",
        "coordinate_system": "ELF virtual addresses as linked (PIE, image base 0); file offset = "
                             "VA - p_vaddr + p_offset of the containing PT_LOAD; instruction starts incl. REX",
        "contribution_note": CONTRIBUTION_NOTE,
        "targets": targets,
        "variant_join": rows,
        "variant_join_counts": counts,
        "catalogue_paths": quals,
        "location_drift_reach": drift,
        "re010_crosscheck": cross,
        "handler_size_ratios": size_ratios(rows, len(t94["execute_instances"]), len(t115["execute_instances"])),
    }


ADDR_KEYS = {
    "start", "end", "seed_slot", "bound_slot", "start_lea_sites", "start_lea_functions", "bound_lea_sites",
    "bound_lea_functions", "site", "function", "function_end", "table", "entry_n_target", "arm", "target",
    "slot", "handler", "shared_tail_target", "bias_site", "lea_sites", "owners", "owner",
    "name_ptrs_equal_variants_copies", "handlers_94", "handlers_115", "table_lea_site", "table_jmp_site",
    "gap_sites", "cmp_site", "ja_site", "ja_target", "dispatcher", "reloc_slots", "handlers",
    "serializer_functions", "owner_callers_outside_execute_family",
}


def hexify(o, addr=False):
    if isinstance(o, dict):
        return {k: hexify(v, k in ADDR_KEYS) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [hexify(v, addr) for v in o]
    if addr and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result: dict) -> bytes:
    return (json.dumps(hexify(result), sort_keys=True, indent=1) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "RE-014 action dispatch drift").splitlines()[0])
    ap.add_argument("--binary", type=Path, default=TARGET, help="node #94 hl-node (primary target)")
    ap.add_argument("--binary-115", type=Path, default=TARGET_115, help="node #115 hl-node (comparison target)")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(build(a.binary.read_bytes(), a.binary_115.read_bytes()))
    except (EvidenceError, OSError) as e:
        print(f"action_dispatch_drift: {e}", file=sys.stderr)
        return 2
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
