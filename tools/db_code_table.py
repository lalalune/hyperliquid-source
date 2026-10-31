#!/usr/bin/env python3
"""RE-009: name the 28 db-hub codes, their dhs/ path template and bucket names (node #94).

Stdlib only; deterministic. Reuses the ELF / FDE / relocation / lea / Location
readers in ``tools/state_roots.py`` (imported by path, like
``tools/state_hashers.py``). Addresses are linked virtual addresses of a PIE
(load base 0).

New relative to open PR #245 (which binds the two-letter labels, the two home
masks, the 21..23 construction gate and its global byte):

* the 28 per-code **names**: each wrapper's build branch passes one
  (value, formatter) pair whose value is the code byte; the formatter reads a
  ``u64`` length table and an ``i32`` rel-offset table, and the two tables abut,
  which pins the count;
* the **path template** that branch formats, decoded with the byte rules of the
  capacity pass of the walker the call reaches (GOT ``0x576e040`` ->
  ``0x1344760``), and which codes reach the branch;
* the three **bucket names**, from the two 3-entry formatters that the
  ``db/src/db_home.rs:83`` panic paths pass.

The labels, masks, buckets and gate are decoded again only as cross-checks.

Decoded from the bytes (an all-six-wrapper tamper of any of them changes the
output): tag table base, tags, name formatter, names, the PRIMARY / AUX masks
(from the ``mov eax,imm32; bt eax,r12d; jae`` chain), the three bucket writes,
the EVM-family base (``lea eax,[r14+disp8]``) and threshold (``cmp al,imm8``),
the whole config gate (GOT slot, once-state and global-byte offsets, shift bias,
range and mask, the two code thresholds, the niche ``movabs`` immediate and the
gate's internal branch targets), the template bytes and argument count, the
GOT-called consumers of the built string, the bucket names, the callers' ``esi``
codes, and ``e_type`` / ``DF_1_PIE``.

Pinned (what the tool searches for): the instruction shapes (opcode, ModRM and
the registers they imply) of each idiom above, the ``db_hub.rs:60`` and
``db_home.rs:83`` Location coordinates, the label strings counted, and the
template walker's byte rules (read from ``0x13447a9..0x1344811``, see README).
Structural requirements that fail closed with ``EvidenceError``: two codegen
copies must agree on tags, names and bucket names; all six wrappers must agree
on masks, bucket writes, range tests, config gate and template; within one
wrapper both family compares must agree and the setae/ja code thresholds must
differ by one; the template's argument-slot count must equal the number of
(value, formatter) pairs passed.

The tool does not census aligned instructions in ``.text`` and does not build a
control-flow graph; ``tests/test_db_code_table.py`` does both with GNU objdump.
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

DB_HUB_FILE = "db/src/db_hub.rs"
WRAPPER_LOCATION_LINE = 60
DB_HOME_FILE = "db/src/db_home.rs"
DB_HOME_PANIC_LINE = 83
# label strings the README uses (can1357 leads, or words read from the bytes);
# counted as exact byte occurrences in the whole file.
LABEL_STRINGS = ("DbBundle", "DbHub", "DbCode", "WrappedDbHome", "wrap_home", "home_bucket",
                 "timed_liner", "daily_liner", "db_bundle")

E = re.escape
# ---- pinned instruction shapes (little-endian) -----------------------------
# entry: mov r14d,esi; mov BYTE PTR [rsp+d8],r14b; movzx r12d,r14b; xor ebp,ebp
ENTRY = re.compile(E(b"\x41\x89\xf6\x44\x88\x74\x24") + b"(.)" + E(b"\x45\x0f\xb6\xe6\x31\xed"), re.S)
LEA_RAX = b"\x48\x8d\x05"                       # lea rax,[rip+disp32]
LEA_RSI = b"\x48\x8d\x35"                       # lea rsi,[rip+disp32]
MOV_R13_TAG = b"\x4e\x8b\x2c\xe0"               # mov r13,[rax+r12*8]  (tag index load)
# name formatter: movzx eax,BYTE PTR [rdi]; lea rcx,[rip+LEN]; mov rdx,[rcx+rax*8];
#                 lea rcx,[rip+OFF]; movsxd rax,[rcx+rax*4]
FMT_HEAD = b"\x0f\xb6\x07\x48\x8d\x0d"
FMT_MID = b"\x48\x8b\x14\xc1\x48\x8d\x0d"
FMT_TAIL = b"\x48\x63\x04\x81"
# home masks: mov eax,PRIMARY; bt eax,r12d; jae AUX -> AUX: mov eax,AUX; bt eax,r12d; jae ELSE
PRIMARY_BT = re.compile(b"\xb8(....)" + E(b"\x44\x0f\xa3\xe0") + b"\x73(.)", re.S)
AUX_BT = re.compile(b"\xb8(....)" + E(b"\x44\x0f\xa3\xe0\x0f\x83") + b"(....)", re.S)
MOV_BPL = b"\x40\xb5"                           # mov bpl,imm8  (bucket 1/2)
# EVM family: lea eax,[r14+d8]; cmp al,imm8 ... and the reduced value stored at [rsp+slot]
FAMILY_LEA_CMP = re.compile(E(b"\x41\x8d\x46") + b"(.)\x3c(.)", re.S)
FAMILY_LEA = b"\x41\x8d\x46"                    # lea eax,[r14+d8]
CMP_AL = 0x3C
STORE_EAX_RSP = b"\x89\x44\x24"                 # mov DWORD PTR [rsp+d8],eax
# config gate (one contiguous sequence; immediates and branch targets decoded):
GATE = re.compile(
    E(b"\x4c\x8b\x35") + b"(?P<got>....)"            # mov r14,[rip+GOT]
    + E(b"\x41\x8b\x46") + b"(?P<once>.)"            # mov eax,[r14+once]
    + E(b"\x85\xc0\x0f\x85") + b"(?P<slow>....)"     # test eax,eax; jne slow
    + E(b"\x41\x0f\xb6\x4e") + b"(?P<goff>.)"        # movzx ecx,BYTE PTR [r14+goff]
    + E(b"\x80\xc1") + b"(?P<bias>.)"                # add cl,bias
    + E(b"\x80\xf9") + b"(?P<range>.)"               # cmp cl,range
    + b"\x73(?P<j_out>.)"                            # jae out-of-range compare
    + b"\xb8(?P<mask>....)"                          # mov eax,mask
    + E(b"\xd3\xe8\x80\x7c\x24") + b"(?P<slot1>.)(?P<lt>.)"   # shr eax,cl; cmp BYTE PTR [rsp+slot],lt
    + E(b"\x0f\x93\xc1\x08\xc1\xf6\xc1\x01\x74") + b"(?P<j_build>.)"  # setae cl; or cl,al; test cl,1; je
    + E(b"\x49\xbc") + b"(?P<niche>........)"        # movabs r12,niche
    + b"\xe9(?P<j_merge>....)"                       # jmp merge
    + E(b"\x80\x7c\x24") + b"(?P<slot2>.)(?P<le>.)"  # cmp BYTE PTR [rsp+slot],le
    + b"\x77(?P<j_niche>.)",                         # ja niche ; fall-through = build branch
    re.S)
# args pair: lea rax,[rsp+v]; mov [rsp+a],rax; lea rax,[rip+fmt]; mov [rsp+a+8],rax
_STK = lambda op8, op32: b"(?:" + E(op8) + b"(.)|" + E(op32) + b"(....))"
PAIR = re.compile(_STK(b"\x48\x8d\x44\x24", b"\x48\x8d\x84\x24")
                  + _STK(b"\x48\x89\x44\x24", b"\x48\x89\x84\x24")
                  + E(LEA_RAX) + b"(....)"
                  + _STK(b"\x48\x89\x44\x24", b"\x48\x89\x84\x24"), re.S)
# format call: lea rsi,[rip+tmpl]; lea rdi,[rsp+out]; lea rdx,[rsp+args]; call [rip+GOT]
FORMAT_TAIL = re.compile(E(LEA_RSI) + b"(....)" + _STK(b"\x48\x8d\x7c\x24", b"\x48\x8d\xbc\x24")
                         + _STK(b"\x48\x8d\x54\x24", b"\x48\x8d\x94\x24") + E(b"\xff\x15") + b"(....)", re.S)
# panic call: lea rdi,[rip+tmpl]; lea rdx,[rip+loc]; lea rsi,[rsp+args]; call [rip+GOT]
PANIC_TAIL = re.compile(E(b"\x48\x8d\x3d") + b"(....)" + E(b"\x48\x8d\x15") + b"(....)"
                        + _STK(b"\x48\x8d\x74\x24", b"\x48\x8d\xb4\x24") + E(b"\xff\x15") + b"(....)", re.S)
GOT_CALL = b"\xff\x15"                          # call QWORD PTR [rip+disp32]
MOV_ESI = b"\xbe"                               # mov esi,imm32 (caller code)
# reference scan anchors: e8/e9 rel32, 0f 8x rel32, and ModRM bytes with mod=00 rm=101 (RIP)
REF_ANCHOR = re.compile(b"[\xe8\xe9\x05\x0d\x15\x1d\x25\x2d\x35\x3d]|\x0f[\x80-\x8f]")
REL8_OPS = {0xEB, 0xE0, 0xE1, 0xE2, 0xE3} | set(range(0x70, 0x80))
# 3-arm Display head: mov rax,rsi; movzx ecx,[rdi]; test ecx,ecx; je; cmp ecx,1; jne
DISPLAY_HEAD = b"\x48\x89\xf0\x0f\xb6\x0f\x85\xc9"
MAX_NAME_LEN = 64
MAX_CODES = 32  # a 32-bit `bt` indexes mod 32; codes must stay below this
TEMPLATE_LIMIT = 256
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_PIE = 0x08000000


def _s8(b):
    return b - 0x100 if b >= 0x80 else b


def _shift_expr(bias):
    d = _s8(bias)
    return "global_byte - %d" % -d if d < 0 else "global_byte + %d" % d


def _stk(m, i8, i32):
    """Signed stack displacement from an (disp8 | disp32) alternation pair of groups."""
    if m.group(i8) is not None:
        return _s8(m.group(i8)[0])
    return struct.unpack("<i", m.group(i32))[0]


def _rip(t_va, m, group):
    """Target of a RIP disp32 field that ends its instruction (no trailing immediate)."""
    return t_va + m.end(group) + struct.unpack("<i", m.group(group))[0]


def _elf_type(elf):
    e_type = struct.unpack_from("<H", elf.data, 0x10)[0]
    flags_1 = 0
    if ".dynamic" in elf.sections:
        _a, off, size = elf.sections[".dynamic"]
        for o in range(off, off + size, 16):
            tag, val = struct.unpack_from("<qQ", elf.data, o)
            if tag == DT_FLAGS_1:
                flags_1 = val
    name = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}.get(e_type, f"e_type {e_type}")
    return name + (" (PIE)" if flags_1 & DF_1_PIE else "")


def _all_relocs(elf):
    """Every .rela.dyn / .rela.plt entry as (r_offset, type, symbol index, addend)."""
    out = []
    for sec in (".rela.dyn", ".rela.plt"):
        if sec not in elf.sections:
            continue
        _a, off, size = elf.sections[sec]
        for o in range(off, off + size, 24):
            r_off, info, add = struct.unpack_from("<QQq", elf.data, o)
            out.append((r_off, info & 0xFFFFFFFF, info >> 32, add))
    return out


def _dynsym_name(elf, index):
    _a, s_off, _s = elf.sections[".dynsym"]
    _b, str_off, _t = elf.sections[".dynstr"]
    st_name = struct.unpack_from("<I", elf.data, s_off + 24 * index)[0]
    end = elf.data.index(b"\0", str_off + st_name)
    return elf.data[str_off + st_name:end].decode("ascii", "replace")


def _wrapper_fdes(locs, leas, starts, ends):
    """The wrapper FDEs: functions that lea a db_hub.rs:60 Location."""
    fdes = set()
    slots = []
    for slot, (f, line, _col) in locs.items():
        if f == DB_HUB_FILE and line == WRAPPER_LOCATION_LINE:
            slots.append(slot)
            for site in leas.get(slot, ()):
                c = sr.containing(starts, ends, site)
                if c is None:
                    raise EvidenceError(f"db_hub:60 lea site {site:#x} outside every FDE")
                fdes.add(c)
    if not fdes:
        raise EvidenceError("no db_hub.rs:60 Location found")
    return sorted(fdes), sorted(slots)


def _entry(blob, lo):
    ms = list(ENTRY.finditer(blob))
    if len(ms) != 1:
        raise EvidenceError(f"wrapper {lo:#x}: expected one entry sequence, found {len(ms)}")
    m = ms[0]
    return {"entry_site": lo + m.start(), "code_byte_slot": _s8(m.group(1)[0]),
            "primary_bucket_site": lo + m.end() - 2}


def _tag_table_base(blob, lo):
    """Base of the 2-byte tag pointer table from `lea rax,[rip+T]; mov r13,[rax+r12*8]`."""
    found = []
    for m in re.finditer(E(LEA_RAX), blob):
        i = m.start()
        if blob[i + 7:i + 11] == MOV_R13_TAG:
            found.append(lo + i + 7 + struct.unpack_from("<i", blob, i + 3)[0])
    if len(found) != 1:
        raise EvidenceError(f"wrapper {lo:#x}: expected one tag-table lea, found {len(found)}")
    return found[0]


def _decode_tag_table(elf, relocs, base):
    """Relocated 2-byte ASCII tags that form a stride-2 arithmetic progression.

    Length is pinned where the progression breaks (next slot absent or not at
    first + 2*n). Returns the list of tags.
    """
    first = relocs.get(base)
    if first is None:
        raise EvidenceError(f"tag table {base:#x}: first slot not RELATIVE")
    tags = []
    i = 0
    while i < MAX_CODES + 2:
        add = relocs.get(base + 8 * i)
        if add is None or add != first + 2 * i:
            break
        pair = elf.read(add, 2)
        if not (0x20 <= pair[0] < 0x7F and 0x20 <= pair[1] < 0x7F):
            break
        tags.append(pair.decode("ascii"))
        i += 1
    if not tags:
        raise EvidenceError(f"tag table {base:#x}: no tags")
    # Negative control: the slot one past the table must break the progression.
    nxt = relocs.get(base + 8 * len(tags))
    if nxt is not None and nxt == first + 2 * len(tags):
        raise EvidenceError(f"tag table {base:#x}: progression did not terminate")
    return tags


def _decode_name_tables(elf, fmt):
    """From a formatter head derive (len_table, off_table, names); the tables abut."""
    head = elf.read(fmt, 3 + 3 + 4 + 4 + 3 + 4)  # movzx+lea+mov+lea+movsxd window
    if head[:len(FMT_HEAD)] != FMT_HEAD:
        raise EvidenceError(f"formatter {fmt:#x}: unexpected prologue")
    len_tbl = fmt + 3 + 7 + struct.unpack_from("<i", head, 6)[0]
    if head[10:10 + len(FMT_MID)] != FMT_MID:
        raise EvidenceError(f"formatter {fmt:#x}: unexpected mid")
    off_tbl = fmt + 10 + 4 + 7 + struct.unpack_from("<i", head, 10 + 4 + 3)[0]
    if elf.read(fmt + 10 + 4 + 7, len(FMT_TAIL)) != FMT_TAIL:
        raise EvidenceError(f"formatter {fmt:#x}: unexpected tail")
    span = off_tbl - len_tbl
    if span <= 0 or span % 8 != 0:
        raise EvidenceError(f"formatter {fmt:#x}: bad len/off table span {span:#x}")
    names = []
    for i in range(span // 8):
        ln = struct.unpack_from("<Q", elf.read(len_tbl + 8 * i, 8))[0]
        rel_off = struct.unpack_from("<i", elf.read(off_tbl + 4 * i, 4))[0]
        s = elf.read(off_tbl + rel_off, ln) if 0 < ln <= MAX_NAME_LEN else b""
        if not s or any(not (0x20 <= b < 0x7F) for b in s):
            raise EvidenceError(f"formatter {fmt:#x}: name {i} not printable (len {ln})")
        names.append(s.decode("ascii"))
    return len_tbl, off_tbl, names


def _masks_and_buckets(blob, lo, entry):
    """PRIMARY -> AUX bt chain, and the bucket value each arm assigns.

    PRIMARY: `mov eax,imm32; bt eax,r12d; jae rel8` whose target is the AUX test
    `mov eax,imm32; bt eax,r12d; jae rel32`. The PRIMARY-set arm keeps the entry
    `xor ebp,ebp` (0); the AUX-set arm is the `mov bpl` at the AUX fall-through;
    the else arm is the first `mov bpl` at/after the AUX jae target.
    """
    chains = []
    for m in PRIMARY_BT.finditer(blob):
        aux_at = m.end() + _s8(m.group(2)[0])
        a = AUX_BT.match(blob, aux_at)
        if a:
            chains.append((m, a))
    if len(chains) != 1:
        raise EvidenceError(f"wrapper {lo:#x}: expected one PRIMARY->AUX bt chain, found {len(chains)}")
    m, a = chains[0]
    primary = struct.unpack("<I", m.group(1))[0]
    aux = struct.unpack("<I", a.group(1))[0]
    fall = a.end()
    tgt = fall + struct.unpack("<i", a.group(2))[0]
    if blob[fall:fall + 2] != MOV_BPL:
        raise EvidenceError(f"wrapper {lo:#x}: AUX arm `mov bpl` not at {lo + fall:#x}")
    if not 0 <= tgt < len(blob):
        raise EvidenceError(f"wrapper {lo:#x}: AUX jae target outside the FDE")
    k = blob.find(MOV_BPL, tgt)
    if k < 0:
        raise EvidenceError(f"wrapper {lo:#x}: else arm `mov bpl` not found")
    aux_bucket, other_bucket = blob[fall + 2], blob[k + 2]
    if {0, aux_bucket, other_bucket} != {0, 1, 2}:
        raise EvidenceError(
            f"wrapper {lo:#x}: bucket writes {{0,{aux_bucket},{other_bucket}}} are not {{0,1,2}}")
    return ({"primary": primary, "aux": aux, "primary_site": lo + m.start(), "aux_site": lo + a.start()},
            {"primary_bucket": 0, "aux_bucket": aux_bucket, "other_bucket": other_bucket,
             "primary_bucket_site": entry["primary_bucket_site"], "aux_bucket_site": lo + fall,
             "other_bucket_site": lo + k, "else_arm": lo + tgt})


def _range_tests(blob, lo, slot):
    """EVM-family lea/cmp, and the [rsp+slot] stores of the reduced code."""
    fam = [(m.start(), m.group(1)[0], m.group(2)[0]) for m in FAMILY_LEA_CMP.finditer(blob)]
    if not fam:
        raise EvidenceError(f"wrapper {lo:#x}: EVM-family range test not found")
    if len({d for _i, d, _t in fam}) != 1:
        raise EvidenceError(f"wrapper {lo:#x}: EVM-family lea displacements disagree")
    thresholds = [t for _i, _d, t in fam]
    if len(set(thresholds)) != 1:
        raise EvidenceError(f"wrapper {lo:#x}: EVM-family thresholds disagree {thresholds}")
    disp = fam[0][1]
    # every mov [rsp+slot],eax must store the family lea result (lea directly before,
    # or lea; cmp al,imm8 directly before)
    lea = FAMILY_LEA + bytes([disp])
    stores = [m.start() for m in re.finditer(E(STORE_EAX_RSP + bytes([slot])), blob)]
    if not stores:
        raise EvidenceError(f"wrapper {lo:#x}: no [rsp+{slot:#x}] store of the reduced code")
    for s in stores:
        if not (blob[s - 4:s] == lea or (blob[s - 6:s - 2] == lea and blob[s - 2] == CMP_AL)):
            raise EvidenceError(f"wrapper {lo:#x}: [rsp+{slot:#x}] store at {lo + s:#x} is not the family lea")
    return {"family_base": (-_s8(disp)) & 0xFF, "family_threshold": thresholds[0],
            "family_sites": [lo + i for i, _d, _t in fam], "reduced_code_store_sites": [lo + s for s in stores]}


def _config_gate(blob, lo, relocs):
    ms = list(GATE.finditer(blob))
    if len(ms) != 1:
        raise EvidenceError(f"wrapper {lo:#x}: expected one config-gate sequence, found {len(ms)}")
    m = ms[0]
    rel8 = lambda g: m.end(g) + _s8(m.group(g)[0])
    out_cmp = m.start("slot2") - 3                      # the `cmp BYTE PTR [rsp+slot],le`
    niche_at = m.start("niche") - 2                     # the `movabs r12,imm64`
    build = m.end()
    if rel8("j_out") != out_cmp or rel8("j_build") != build or rel8("j_niche") != niche_at:
        raise EvidenceError(f"wrapper {lo:#x}: config-gate branch targets do not close")
    if m.group("slot1") != m.group("slot2"):
        raise EvidenceError(f"wrapper {lo:#x}: config-gate compares read different slots")
    lt, le = m.group("lt")[0], m.group("le")[0]
    if lt != le + 1:
        raise EvidenceError(f"wrapper {lo:#x}: setae/ja code thresholds disagree ({lt} vs {le})")
    merge = m.end("j_merge") + struct.unpack("<i", m.group("j_merge"))[0]
    slow = m.end("slow") + struct.unpack("<i", m.group("slow"))[0]
    if not (build < merge < len(blob)) or not (0 <= slow < len(blob)):
        raise EvidenceError(f"wrapper {lo:#x}: config-gate merge/slow target outside the FDE")
    got = lo + m.end("got") + struct.unpack("<i", m.group("got"))[0]
    base = relocs.get(got)
    if base is None:
        raise EvidenceError(f"wrapper {lo:#x}: config GOT slot {got:#x} is not RELATIVE")
    goff = m.group("goff")[0]
    return {"gate_site": lo + m.start(), "got_slot": got, "global_base": base,
            "once_state_offset": m.group("once")[0], "global_byte_offset": goff,
            "global_byte_addr": base + goff, "shift_bias": m.group("bias")[0],
            "shift_range": m.group("range")[0], "shift_const": struct.unpack("<I", m.group("mask"))[0],
            "reduced_code_slot": m.group("slot1")[0], "code_lt_threshold": lt, "code_le_threshold": le,
            "niche_when_skipped": struct.unpack("<Q", m.group("niche"))[0], "niche_site": lo + niche_at,
            "build_branch": lo + build, "merge": lo + merge, "slow_path": lo + slow}


def _pairs_before(text, t_va, end):
    """(value, formatter) pairs written back-to-back immediately before `end`.

    Walks backwards over PAIR shapes whose args slots step down by 16 each.
    Returns [(start, value_disp, args_disp, formatter)] in program order.
    """
    pairs = []
    while True:
        hit = None
        for ln in range(22, 32):
            m = PAIR.fullmatch(text, end - ln, end)
            if m:
                hit = m
                break
        if hit is None:
            break
        a0, a1 = _stk(hit, 3, 4), _stk(hit, 6, 7)
        if a1 != a0 + 8 or (pairs and a0 != pairs[0][2] - 16):
            break
        pairs.insert(0, (hit.start(), _stk(hit, 1, 2), a0, _rip(t_va, hit, 5)))
        end = hit.start()
    return pairs


def _walk_template(elf, va):
    """Decode a format template with the byte rules of 0x1344760's capacity pass.

    0x00 end; 0x01..0x7f literal of that length; 0x80 u16 length then literal;
    0x81..0xff argument slot followed by 4*b0 + 2*b1 + 2*b2 + 2*b3 option bytes.
    Returns (pieces, raw) with None marking an argument slot.
    """
    raw = elf.read(va, TEMPLATE_LIMIT)
    pieces = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0:
            return pieces, raw[:i + 1]
        if b < 0x80 or b == 0x80:
            if b == 0x80:
                n, start = struct.unpack_from("<H", raw, i + 1)[0], i + 3
            else:
                n, start = b, i + 1
            lit = raw[start:start + n]
            if len(lit) != n or any(not (0x20 <= c < 0x7F) for c in lit):
                raise EvidenceError(f"template {va:#x}: literal at +{i:#x} is not printable ASCII")
            pieces.append(lit.decode("ascii"))
            i = start + n
        else:
            pieces.append(None)
            i += 1 + 4 * (b & 1) + 2 * ((b >> 1) & 1) + 2 * ((b >> 2) & 1) + 2 * ((b >> 3) & 1)
    raise EvidenceError(f"template {va:#x}: no end byte within {TEMPLATE_LIMIT} bytes")


def _template_record(elf, va, pairs):
    pieces, raw = _walk_template(elf, va)
    slots = sum(1 for p in pieces if p is None)
    if slots != pairs:
        raise EvidenceError(f"template {va:#x}: {slots} argument slots but {pairs} (value, formatter) pairs")
    return {"template_target": va, "template_bytes": " ".join(f"{b:02x}" for b in raw),
            "template_pieces": ["{}" if p is None else p for p in pieces],
            "argument_slots": slots, "rendered_template": "".join("{}" if p is None else p for p in pieces)}


def _fn_locations(locs, leas, starts, ends):
    """FDE start -> sorted first-party 'file:line:col' Locations it leas."""
    out = {}
    for slot, (f, line, col) in locs.items():
        for site in leas.get(slot, ()):
            c = sr.containing(starts, ends, site)
            if c:
                out.setdefault(c[0], set()).add(f"{f}:{line}:{col}")
    return {k: sorted(v) for k, v in out.items()}


def _pairs_from(text, t_va, pos):
    """(value, formatter) pairs written back-to-back from `pos`; returns (pairs, end)."""
    pairs = []
    while True:
        m = PAIR.match(text, pos)
        if m is None:
            return pairs, pos
        a0, a1 = _stk(m, 3, 4), _stk(m, 6, 7)
        if a1 != a0 + 8 or (pairs and a0 != pairs[-1][2] + 16):
            return pairs, pos
        pairs.append((m.start(), _stk(m, 1, 2), a0, _rip(t_va, m, 5)))
        pos = m.end()


def _build_branch(elf, text, t_va, relocs, imports, fn_locs, starts, ends, lo, gate, entry):
    """The dhs/ build branch: args pairs, format call, template, and GOT-called consumers."""
    build = gate["build_branch"]
    pairs, pos = _pairs_from(text, t_va, build - t_va)
    if not pairs:
        raise EvidenceError(f"wrapper {lo:#x}: build branch does not start with an args pair")
    tail = FORMAT_TAIL.match(text, pos)
    if tail is None:
        raise EvidenceError(f"wrapper {lo:#x}: build branch format call not found after the args pairs")
    if _stk(tail, 4, 5) != pairs[0][2]:
        raise EvidenceError(f"wrapper {lo:#x}: format call args pointer is not the pair array")
    if pairs[0][1] != entry["code_byte_slot"]:
        raise EvidenceError(f"wrapper {lo:#x}: formatted value is not the stored code byte")
    template = _template_record(elf, _rip(t_va, tail, 1), len(pairs))
    fmt_got = _rip(t_va, tail, 6)
    call_end = t_va + tail.end()
    consumers = []
    for i in range(call_end - t_va, gate["merge"] - t_va):
        if text[i:i + 2] != GOT_CALL:
            continue
        slot = t_va + i + 6 + struct.unpack_from("<i", text, i + 2)[0]
        rec = {"call_site": t_va + i, "got_slot": slot}
        if slot in relocs:
            c = sr.containing(starts, ends, relocs[slot])
            rec["target_fn"] = relocs[slot]
            rec["location_files"] = fn_locs.get(c[0], []) if c else []
        elif slot in imports:
            rec["import"] = imports[slot]
        else:
            raise EvidenceError(f"wrapper {lo:#x}: GOT slot {slot:#x} at {t_va + i:#x} has no relocation")
        consumers.append(rec)
    return {"args_pairs": len(pairs), "arg_value_slot": f"rsp+{pairs[0][1]:#x}",
            "name_formatter": pairs[0][3], "format_call_site": call_end - 6,
            "format_out_slot": f"rsp+{_stk(tail, 2, 3):#x}", "format_fn_got": fmt_got,
            "format_fn": relocs.get(fmt_got), "template": template, "consumers": consumers}


def _bucket_name_formatters(elf, text, t_va, relocs, locs, leas, starts, ends):
    """The formatter each db_home.rs:83 panic passes, with its decoded name table."""
    slots = sorted(s for s, (f, line, _c) in locs.items() if f == DB_HOME_FILE and line == DB_HOME_PANIC_LINE)
    if not slots:
        raise EvidenceError("no db_home.rs:83 Location found")
    out = []
    for slot in slots:
        sites = leas.get(slot, [])
        if len(sites) != 1:
            raise EvidenceError(f"db_home.rs:83 Location {slot:#x}: {len(sites)} lea sites, expected 1")
        tail = PANIC_TAIL.match(text, sites[0] - 7 - t_va)
        if tail is None or _rip(t_va, tail, 2) != slot:
            raise EvidenceError(f"db_home.rs:83 Location {slot:#x}: not the panic call's Location operand")
        pairs = _pairs_before(text, t_va, tail.start())
        if not pairs or _stk(tail, 3, 4) != pairs[0][2]:
            raise EvidenceError(f"db_home.rs:83 panic at {t_va + tail.start():#x}: args pairs not found")
        fn = sr.containing(starts, ends, sites[0])
        fmts = [p[3] for p in pairs]
        if len(fmts) != 1:
            raise EvidenceError(f"db_home.rs:83 panic at {t_va + tail.start():#x}: {len(fmts)} pairs, expected 1")
        len_tbl, off_tbl, names = _decode_name_tables(elf, fmts[0])
        f, line, col = locs[slot]
        out.append({"function": fn[0], "location_slot": slot, "location": f"{f}:{line}:{col}",
                    "panic_site": t_va + tail.start(), "panic_fn_got": _rip(t_va, tail, 5),
                    "arg_value_slot": f"rsp+{pairs[0][1]:#x}",
                    "template": _template_record(elf, _rip(t_va, tail, 1), len(pairs)),
                    "formatter": fmts[0], "len_table": len_tbl, "off_table": off_tbl, "names": names})
    return out


def _decode_display_arm(elf, va):
    """At `va`, decode `lea rsi,[rip+S]; mov edx,imm32` -> the ASCII string."""
    code = elf.read(va, 12)
    if code[:3] != LEA_RSI:
        raise EvidenceError(f"Display arm {va:#x}: no lea rsi")
    tgt = va + 7 + struct.unpack_from("<i", code, 3)[0]
    if code[7] != 0xBA:  # mov edx,imm32
        raise EvidenceError(f"Display arm {va:#x}: no mov edx,len")
    ln = struct.unpack_from("<I", code, 8)[0]
    if not 0 < ln <= 16:
        raise EvidenceError(f"Display arm {va:#x}: implausible len {ln}")
    s = elf.read(tgt, ln)
    if any(not (0x20 <= b < 0x7F) for b in s):
        raise EvidenceError(f"Display arm {va:#x}: non-ascii")
    return s.decode("ascii")


def _display_candidates(elf, text, t_va, starts):
    """FDE starts with the exact 3-arm `write_str` head that decode to 3 strings.

    Shape: 48 89 f0 0f b6 0f 85 c9 (mov rax,rsi; movzx ecx,[rdi]; test ecx,ecx),
    then je rel8, cmp ecx,1 (83 f9 01), jne rel8, each arm lea rsi + mov edx.
    """
    out = {}
    for m in re.finditer(E(DISPLAY_HEAD), text):
        fn = t_va + m.start()
        if not sr.is_fde_start(starts, fn):
            continue
        b = elf.read(fn, 0x50)
        if b[8] != 0x74 or b[10:13] != b"\x83\xf9\x01" or b[13] != 0x75:
            continue
        arm0 = fn + 10 + _s8(b[9])       # byte == 0
        arm_else = fn + 15 + _s8(b[14])  # byte > 1
        try:
            out[fn] = [_decode_display_arm(elf, arm0), _decode_display_arm(elf, fn + 15),
                       _decode_display_arm(elf, arm_else)]
        except EvidenceError:
            continue
    return out


def _scan_references(elf, text, t_va, all_relocs, targets, point_targets):
    """Every reference form that can name a target address.

    For every target: rel32 `e8` call / `e9` jmp / `0f 8x` jcc whose field
    resolves to it; RIP-relative ModRM (mod=00, rm=101) disp32 fields resolving to
    it with a 0/1/2/4-byte trailing immediate (the disp32 field address is
    recorded); and relocations of any type whose addend is it. For each
    `point_targets` address also: rel8 branches in the 129 bytes before it, and
    absolute qword / dword copies of it anywhere in the file.
    """
    tset = set(targets)
    rec = {t: {"call_rel32": [], "jmp_rel32": [], "jcc_rel32": [], "rip_relative": [],
               "relocations": []} for t in targets}
    for t in point_targets:
        rec[t].update({"rel8_branch": [], "absolute_qword": 0, "absolute_dword": 0})
    near = {}                                # field value -> [(target, trailing immediate size)]
    for t in targets:
        for k in (0, 1, 2, 4):
            near.setdefault(t - k, []).append((t, k))
    unpack = struct.unpack_from
    base = t_va + 4
    for m in REF_ANCHOR.finditer(text, 0, len(text) - 4):
        p = m.end()
        t0 = base + p + unpack("<i", text, p)[0]
        if t0 not in near:
            continue
        b = text[p - 1]
        if 0x80 <= b <= 0x8F:                # 0f 8x jcc rel32 (0x8x is never a 1-byte anchor)
            if t0 in tset:
                rec[t0]["jcc_rel32"].append(t_va + p - 2)
        elif b == 0xE8 or b == 0xE9:
            if t0 in tset:
                rec[t0]["call_rel32" if b == 0xE8 else "jmp_rel32"].append(t_va + p - 1)
        else:                                # ModRM mod=00 rm=101: RIP + disp32 (+ imm k)
            for t, _k in near[t0]:
                rec[t]["rip_relative"].append(t_va + p)
    for t in point_targets:
        for q in range(max(0, t - t_va - 129), t - t_va):
            if text[q] in REL8_OPS and t_va + q + 2 + _s8(text[q + 1]) == t:
                rec[t]["rel8_branch"].append(t_va + q)
        dw = elf.data.count(struct.pack("<I", t))   # every qword copy contains a dword copy
        rec[t]["absolute_dword"] = dw
        rec[t]["absolute_qword"] = elf.data.count(struct.pack("<Q", t)) if dw else 0
    for r_off, _typ, _sym, add in all_relocs:
        if add in tset:
            rec[add]["relocations"].append(r_off)
    for t in targets:
        for k in ("call_rel32", "jmp_rel32", "jcc_rel32", "rip_relative", "rel8_branch", "relocations"):
            if k in rec[t]:
                rec[t][k].sort()
    return rec


def _callers(text, t_va, starts, ends, wrapper, sites):
    """The `mov esi,imm32` code passed at each rel32 call site of `wrapper`."""
    out = []
    for site in sites:
        c = sr.containing(starts, ends, site)
        if c is None:
            raise EvidenceError(f"caller at {site:#x} outside every FDE")
        i = site - t_va
        esi = None
        back = text[max(0, i - 16):i]
        for mm in re.finditer(E(MOV_ESI), back):
            j = mm.start()
            if j + 5 <= len(back):
                esi = struct.unpack_from("<I", back, j + 1)[0]
        if esi is None or esi >= MAX_CODES:
            raise EvidenceError(f"caller at {site:#x}: no esi immediate < {MAX_CODES}")
        out.append({"function": c[0], "call_site": site, "code": esi, "wrapper": wrapper})
    return out


def _require_equal(wrappers, picker, what):
    vals = [picker(w) for w in wrappers]
    if any(v != vals[0] for v in vals):
        raise EvidenceError(f"wrappers disagree on {what}: {vals}")
    return vals[0]


def build(data: bytes, expected_sha256: str = EXPECTED_SHA256) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != expected_sha256:
        raise EvidenceError(f"binary sha256 {sha} != {expected_sha256}")
    elf = sr.Elf(data)
    starts, ends = sr.fde_index(elf)
    relocs = sr.relative_relocs(elf)
    all_relocs = _all_relocs(elf)
    imports = {r_off: _dynsym_name(elf, sym) for r_off, typ, sym, _a in all_relocs if typ in (6, 7) and sym}
    leas = sr.lea_targets(elf)
    locs = sr.first_party_locations(elf, relocs)
    fn_locs = _fn_locations(locs, leas, starts, ends)
    t_va, t_off, t_size = elf.sections[".text"]
    text = data[t_off:t_off + t_size]

    wrapper_fdes, loc_slots = _wrapper_fdes(locs, leas, starts, ends)
    wrappers = []
    tag_copies, name_copies = {}, {}
    for lo, hi in wrapper_fdes:
        blob = text[lo - t_va:hi - t_va]
        entry = _entry(blob, lo)
        gate = _config_gate(blob, lo, relocs)
        masks, buckets = _masks_and_buckets(blob, lo, entry)
        ranges = _range_tests(blob, lo, gate["reduced_code_slot"])
        branch = _build_branch(elf, text, t_va, relocs, imports, fn_locs, starts, ends, lo, gate, entry)
        tag_base = _tag_table_base(blob, lo)
        tags = _decode_tag_table(elf, relocs, tag_base)
        len_tbl, off_tbl, names = _decode_name_tables(elf, branch["name_formatter"])
        tag_copies.setdefault(tag_base, tags)
        name_copies.setdefault(branch["name_formatter"], names)
        wrappers.append({
            "wrapper": lo, "end": hi, "entry": entry, "tag_table": tag_base,
            "name_formatter": branch["name_formatter"], "name_len_table": len_tbl,
            "name_off_table": off_tbl, "masks": masks, "bucket_assignments": buckets,
            "range_tests": ranges, "config_gate": gate, "build_branch": branch,
            "tag_count": len(tags), "name_count": len(names),
        })

    # two codegen copies of the tag / name tables must agree.
    if len({tuple(t) for t in tag_copies.values()}) != 1:
        raise EvidenceError("tag-table copies disagree")
    if len({tuple(n) for n in name_copies.values()}) != 1:
        raise EvidenceError("name-table copies disagree")
    tags = next(iter(tag_copies.values()))
    names = next(iter(name_copies.values()))
    if len(tags) != len(names):
        raise EvidenceError(f"tag count {len(tags)} != name count {len(names)}")
    n = len(tags)
    if n >= MAX_CODES:
        raise EvidenceError(f"code count {n} reaches 32-bit bt wraparound")

    # all six wrappers must agree on every decoded mask / bucket / gate / template field.
    masks = _require_equal(wrappers, lambda w: (w["masks"]["primary"], w["masks"]["aux"]), "mask set")
    assign = _require_equal(wrappers, lambda w: tuple(w["bucket_assignments"][k] for k in
                                                     ("primary_bucket", "aux_bucket", "other_bucket")),
                            "bucket branch writes")
    _require_equal(wrappers, lambda w: (w["range_tests"]["family_base"], w["range_tests"]["family_threshold"]),
                   "range tests")
    gate_keys = ("got_slot", "global_base", "once_state_offset", "global_byte_offset", "shift_bias",
                 "shift_range", "shift_const", "reduced_code_slot", "code_lt_threshold",
                 "code_le_threshold", "niche_when_skipped")
    _require_equal(wrappers, lambda w: tuple(w["config_gate"][k] for k in gate_keys), "config gate")
    _require_equal(wrappers, lambda w: (w["build_branch"]["template"]["template_bytes"],
                                        w["build_branch"]["args_pairs"], w["build_branch"]["arg_value_slot"],
                                        w["build_branch"]["format_fn_got"]), "build-branch template")
    consumers = _require_equal(
        wrappers, lambda w: [{k: v for k, v in c.items() if k != "call_site"}
                             for c in w["build_branch"]["consumers"]], "build-branch consumers")
    primary_mask, aux_mask = masks
    primary_bucket, aux_bucket, other_bucket = assign
    fam_base = wrappers[0]["range_tests"]["family_base"]
    fam_thr = wrappers[0]["range_tests"]["family_threshold"]
    g0 = wrappers[0]["config_gate"]
    code_lt = g0["code_lt_threshold"]

    def bucket(code):
        bit = 1 << code
        if primary_mask & bit:
            return primary_bucket
        if aux_mask & bit:
            return aux_bucket
        return other_bucket

    # bucket names: the formatter of each db_home.rs:83 panic; copies must agree.
    bucket_fmts = _bucket_name_formatters(elf, text, t_va, relocs, locs, leas, starts, ends)
    if len({tuple(b["names"]) for b in bucket_fmts}) != 1:
        raise EvidenceError("bucket-name formatter copies disagree")
    bucket_names = bucket_fmts[0]["names"]
    if len(bucket_names) <= max(assign):
        raise EvidenceError(f"{len(bucket_names)} bucket names for bucket values {sorted(set(assign))}")
    display_cands = _display_candidates(elf, text, t_va, starts)
    matching = [fn for fn, arms in display_cands.items() if arms == bucket_names]
    if len(matching) != 1:
        raise EvidenceError(f"bucket Display: {len(matching)} functions match {bucket_names}")

    # references: wrappers (not address-taken?), formatters, tag blobs.
    blobs = [(base, relocs[base], 2 * len(tags)) for base in sorted(tag_copies)]
    wrapper_starts = [lo for lo, _hi in wrapper_fdes]
    fmt_fns = sorted(name_copies) + sorted(b["formatter"] for b in bucket_fmts)
    blob_bytes = [a for _b, start, ln in blobs for a in range(start, start + ln)]
    refs = _scan_references(elf, text, t_va, all_relocs, wrapper_starts + fmt_fns + blob_bytes,
                            wrapper_starts + fmt_fns)

    callers = []
    for lo in wrapper_starts:
        callers.extend(_callers(text, t_va, starts, ends, lo, refs[lo]["call_rel32"]))
    for c in callers:
        if c["code"] >= n:
            raise EvidenceError(f"caller at {c['call_site']:#x}: code {c['code']} >= {n}")
    code_to_caller = {}
    for c in callers:
        code_to_caller.setdefault(c["code"], []).append(c)

    tag_blobs = []
    for base, start, ln in blobs:
        blob = elf.read(start, ln)
        into = [a for a in range(start, start + ln)]
        tag_blobs.append({
            "tag_table": base, "blob": start, "length": ln,
            "file_occurrences": len(list(re.finditer(E(blob), data))),
            "relative_relocs_into": sum(1 for a in relocs.values() if start <= a < start + ln),
            "code_references_into": sum(len(refs[a][k]) for a in into
                                        for k in ("call_rel32", "jmp_rel32", "jcc_rel32", "rip_relative")),
        })

    rows = []
    for code in range(n):
        reduced = (code - fam_base) & 0xFF
        rows.append({
            "code": code,
            "tag": tags[code],
            "name": names[code],
            "home_bucket": bucket(code),
            "home_bucket_name_inferred": bucket_names[bucket(code)],
            "in_primary_mask": bool(primary_mask & (1 << code)),
            "in_aux_mask": bool(aux_mask & (1 << code)),
            "is_evm_family": reduced < fam_thr,
            "path_built": reduced < code_lt,
            "static_callers": sorted(
                [{"function": x["function"], "call_site": x["call_site"]} for x in code_to_caller.get(code, [])],
                key=lambda r: r["call_site"]),
        })

    # static-config global initializer provenance (the RELATIVE slot at the global base)
    init_fn = relocs.get(g0["global_base"])
    init_c = sr.containing(starts, ends, init_fn) if init_fn is not None else None
    suppressed = [gb for gb in range(256)
                  if ((gb + g0["shift_bias"]) & 0xFF) < g0["shift_range"]
                  and (g0["shift_const"] >> ((gb + g0["shift_bias"]) & 0xFF)) & 1]
    b0 = wrappers[0]["build_branch"]
    caller_fns = sorted({c["function"] for c in callers})

    return {
        "binary_sha256": sha,
        "elf_type": _elf_type(elf),
        "fde_count": len(starts),
        "db_hub_line60_location_slots": loc_slots,
        "wrapper_count": len(wrappers),
        "code_count": n,
        "wrappers": wrappers,
        "tag_table_bases": sorted(tag_copies),
        "tag_blobs": tag_blobs,
        "name_formatters": sorted(name_copies),
        "masks": {"primary": primary_mask, "aux": aux_mask, "config_gate": g0["shift_const"]},
        "home_mask_sites": sorted([w["masks"]["primary_site"] for w in wrappers]
                                  + [w["masks"]["aux_site"] for w in wrappers]),
        "bucket_assignment": {"primary_bucket": primary_bucket, "aux_bucket": aux_bucket,
                              "other_bucket": other_bucket},
        "bucket_names": {str(i): nm for i, nm in enumerate(bucket_names)},
        "bucket_name_formatters": bucket_fmts,
        "bucket_display_fn": matching[0],
        "bucket_display_shape_candidates": sorted(display_cands),
        "evm_family": {"base": fam_base, "threshold": fam_thr},
        "config_gate": {
            "got_slot": g0["got_slot"], "global_base": g0["global_base"],
            "global_byte_offset": g0["global_byte_offset"], "global_byte_addr": g0["global_byte_addr"],
            "once_state_offset": g0["once_state_offset"], "shift_bias": g0["shift_bias"],
            "shift_range": g0["shift_range"], "shift_const": g0["shift_const"],
            "shift_amount_expr": _shift_expr(g0["shift_bias"]),
            "code_lt_threshold": code_lt, "code_le_threshold": g0["code_le_threshold"],
            "gate_sequence_hits_in_text": len(list(GATE.finditer(text))),
            "initializer_fn": init_fn,
            "initializer_location_files": fn_locs.get(init_c[0], []) if init_c else [],
        },
        "path_build": {
            "template_target": b0["template"]["template_target"],
            "template_bytes": b0["template"]["template_bytes"],
            "template_pieces": b0["template"]["template_pieces"],
            "argument_slots": b0["template"]["argument_slots"],
            "rendered_template": b0["template"]["rendered_template"],
            "args_pairs": b0["args_pairs"], "arg_value_slot": b0["arg_value_slot"],
            "format_fn_got": b0["format_fn_got"], "format_fn": b0["format_fn"],
            "built_for_codes": [r["code"] for r in rows if r["path_built"]],
            "code_gate": "(code - %d) as u8 < %d" % (fam_base, code_lt),
            "config_byte_suppressed_values": suppressed,
            "niche_when_skipped": g0["niche_when_skipped"],
            "consumers": consumers,
        },
        "references": {"wrappers": {lo: refs[lo] for lo in wrapper_starts},
                       "formatters": {f: refs[f] for f in fmt_fns}},
        "label_string_counts": {s: data.count(s.encode()) for s in LABEL_STRINGS},
        "static_callers": sorted(
            [{"function": c["function"], "call_site": c["call_site"], "code": c["code"],
              "name": names[c["code"]], "wrapper": c["wrapper"]} for c in callers],
            key=lambda r: r["call_site"]),
        "caller_location_files": {hex(k): fn_locs.get(k, []) for k in caller_fns},
        "table": rows,
    }


ADDR_KEYS = {
    "wrapper", "end", "tag_table", "name_formatter", "name_len_table", "name_off_table",
    "template_target", "primary_site", "aux_site", "primary_bucket_site", "aux_bucket_site",
    "other_bucket_site", "else_arm", "got_slot", "global_base", "global_byte_addr", "target_fn",
    "tag_table_bases", "name_formatters", "home_mask_sites", "bucket_display_fn",
    "bucket_display_shape_candidates", "initializer_fn", "call_site", "function",
    "db_hub_line60_location_slots", "entry_site", "family_sites", "reduced_code_store_sites",
    "gate_site", "niche_site", "build_branch", "merge", "slow_path", "format_fn_got", "format_fn",
    "location_slot", "panic_site", "panic_fn_got", "formatter", "len_table", "off_table", "blob",
    "call_rel32", "jmp_rel32", "jcc_rel32", "rip_relative", "rel8_branch", "relocations",
    "format_call_site",
}
# masks, immediates and small offsets rendered as hex for readability (not addresses).
HEX_KEYS = {"primary", "aux", "config_gate", "shift_const", "niche_when_skipped", "code_byte_slot",
            "reduced_code_slot", "global_byte_offset", "once_state_offset"}


def hexify(o, addr=False):
    """Addresses / masks as hex strings; dicts keyed by address get hex keys."""
    if isinstance(o, dict):
        return {(f"{k:#x}" if isinstance(k, int) else k):
                hexify(v, k in ADDR_KEYS or k in HEX_KEYS) for k, v in o.items()}
    if isinstance(o, list):
        return [hexify(v, addr) for v in o]
    if addr and isinstance(o, int) and not isinstance(o, bool):
        return f"{o:#x}"
    return o


def render(result: dict) -> bytes:
    return (json.dumps(hexify(result), indent=1, sort_keys=True) + "\n").encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", type=Path, default=TARGET)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    try:
        data = a.binary.read_bytes()
    except OSError as e:
        print(f"db_code_table: cannot read {a.binary}: {e}", file=sys.stderr)
        return 2
    try:
        text = render(build(data))
    except EvidenceError as e:
        print(f"db_code_table: {e}", file=sys.stderr)
        return 2
    if a.out:
        a.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
