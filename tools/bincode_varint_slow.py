#!/usr/bin/env python3
"""RE-005 sibling: pin the bincode-fork varint SLOW reader path and the u32 width (node #94).

Static, offline, read-only. Reuses tools/bincode_varint.py ELF/FDE helpers and
refuses to run if the merged RE-005 decode-side JSON (fast path) would change.
Adds:

* the u32 slice decoder at 0x466bc10 (sibling width to the u64 fast path in
  tools/bincode_varint_decode.py) and its slow-branch call through GOT
  0x5775138 into the u32 Reader;
* the slow branch out of the already-pinned u64 slice decoder 0x466bd10
  through GOT 0x57745e0 into the u64 Reader (the fast path itself is not
  re-claimed);
* the two Reader bodies 0x466d850 (u32) and 0x466d980 (u64): FDE extents,
  exact anchors, four-entry tag jump tables, 0xfe/0xff error arms with the
  exact esi/edx codes they pass to the shared error builder at 0x466dac0;
* a closure count of every `call [rip+disp32]` in .text whose GOT slot
  relocates to either Reader;
* decode vectors for inputs of length <= 8 and for the 0xfe/0xff markers,
  derived from the observed little-endian (dl == 0) instruction semantics;
* a u16 length-marker scan over every `cmp <reg>,0xfb` instruction in .text
  (the bincode 0xfb marker compare): for each site, whether a `cmp <reg>,2`
  lies within 0x80 bytes in the same FDE AND a jump-table dispatch follows
  within 0x20 bytes; the one site that matches is characterised.

Addresses are virtual addresses of instruction starts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402
import bincode_varint_decode as dv  # noqa: E402

EvidenceError = bv.EvidenceError
# Negative control: the merged RE-005 decode-sites.json must stay bit-identical.
FAST_PATH_JSON_SHA256 = '6da03736b718d6c7db769a0a1be7e9131a6229cea6b198dd85d535282be5a56f'

# Shared error-builder FDE (writes result tag 0x3 + sil + dl).
ERROR_BUILDER = (0x466dac0, 0x466dace, 0x57745e8)

# (name, fde_start, fde_end, anchors, jump_table_va, expected_targets_by_tag_index,
#  result_store_width, expected_type_code_on_0xfe)
READERS = (
    ('varint_decode_u32_reader', 0x466d850, 0x466d975, (
        (0x466d851, '488b4608', 'mov rax,[rsi+8]: remaining length into rax'),
        (0x466d865, '440fb601', 'movzx r8d,byte [rcx]: read tag'),
        (0x466d870, '4181f8fb000000', 'cmp r8d,0xfb: tag < 251 is the value'),
        (0x466d879, '44894704', 'mov [rdi+4],r8d: store u32 value'),
        (0x466d87d, 'c60712', 'mov byte [rdi],0x12: Ok tag'),
        (0x466d885, 'c60700', 'mov byte [rdi],0: UnexpectedEnd tag'),
        (0x466d888, '48c7470801000000', 'mov qword [rdi+8],1: need 1 more byte'),
        (0x466d895, '4181c005ffffff', 'add r8d,-0xfb: tag index'),
        (0x466d89c, '4183f803', 'cmp r8d,3: indexes 0..3 (0xfb..0xfe)'),
        (0x466d8a6, '4c8d0d1b9608fc', 'lea r9,[jump table]'),
        (0x466d8b7, '4883f803', 'cmp rax,3: 0xfb arm needs 3 total bytes'),
        (0x466d8c4, '4883f805', 'cmp rax,5: 0xfc arm needs 5 total bytes'),
        (0x466d8de, '440fb74101', 'movzx r8d,word [rcx+1]: 0xfb reads u16'),
        (0x466d8ed, '66c1c108', 'rol cx,8: BE swap when dl != 0'),
        (0x466d908, '448b4101', 'mov r8d,dword [rcx+1]: 0xfc reads u32'),
        (0x466d91a, '0fc8', 'bswap eax: BE swap when dl != 0'),
        (0x466d922, '894704', 'mov [rdi+4],eax: store u32 value'),
        (0x466d925, 'c60712', 'mov byte [rdi],0x12: Ok tag'),
        (0x466d92d, '4889fb', 'mov rbx,rdi: 0xfe error prologue'),
        (0x466d930, 'be02000000', 'mov esi,2: expected-type code 2 (u32)'),
        (0x466d935, 'ba04000000', 'mov edx,4: found-type code 4 (u128 / 0xfe)'),
        (0x466d945, '4889fb', 'mov rbx,rdi: 0xfd error prologue'),
        (0x466d948, 'be02000000', 'mov esi,2: expected-type code 2 (u32)'),
        (0x466d94d, 'ba03000000', 'mov edx,3: found-type code 3 (u64 / 0xfd)'),
        (0x466d95d, '4889fb', 'mov rbx,rdi: out-of-range error prologue'),
        (0x466d960, 'be02000000', 'mov esi,2: expected-type code 2 (u32)'),
        (0x466d965, 'ba0c000000', 'mov edx,0xc: found-type code 0xc (0xff)'),
    ), 0x6f6ec8, (0x466d8b7, 0x466d8c4, 0x466d945, 0x466d92d), 4, 2),
    ('varint_decode_u64_reader', 0x466d980, 0x466dabc, (
        (0x466d981, '488b4608', 'mov rax,[rsi+8]: remaining length into rax'),
        (0x466d995, '440fb601', 'movzx r8d,byte [rcx]: read tag'),
        (0x466d9a0, '4981f8fb000000', 'cmp r8,0xfb: tag < 251 is the value'),
        (0x466d9a9, '4c894708', 'mov [rdi+8],r8: store u64 value'),
        (0x466d9ad, 'c60712', 'mov byte [rdi],0x12: Ok tag'),
        (0x466d9b5, 'c60700', 'mov byte [rdi],0: UnexpectedEnd tag'),
        (0x466d9b8, '48c7470801000000', 'mov qword [rdi+8],1: need 1 more byte'),
        (0x466d9c5, '4181c005ffffff', 'add r8d,-0xfb: tag index'),
        (0x466d9cc, '4183f803', 'cmp r8d,3: indexes 0..3 (0xfb..0xfe)'),
        (0x466d9d6, '4c8d0dfb9408fc', 'lea r9,[jump table]'),
        (0x466d9e7, '4883f803', 'cmp rax,3: 0xfb arm needs 3 total bytes'),
        (0x466d9f4, '4883f809', 'cmp rax,9: 0xfd arm needs 9 total bytes'),
        (0x466da01, '4883f805', 'cmp rax,5: 0xfc arm needs 5 total bytes'),
        (0x466da1f, '4c8b4101', 'mov r8,qword [rcx+1]: 0xfd reads u64'),
        (0x466da31, '480fc8', 'bswap rax: BE swap when dl != 0'),
        (0x466da3c, '440fb74101', 'movzx r8d,word [rcx+1]: 0xfb reads u16'),
        (0x466da4b, '66c1c108', 'rol cx,8: BE swap when dl != 0'),
        (0x466da66, '448b4101', 'mov r8d,dword [rcx+1]: 0xfc reads u32'),
        (0x466da78, '0fc8', 'bswap eax: BE swap when dl != 0'),
        (0x466da80, '48894708', 'mov [rdi+8],rax: store u64 value'),
        (0x466da84, 'c60712', 'mov byte [rdi],0x12: Ok tag'),
        (0x466da8c, '4889fb', 'mov rbx,rdi: 0xfe error prologue'),
        (0x466da8f, 'be03000000', 'mov esi,3: expected-type code 3 (u64)'),
        (0x466da94, 'ba04000000', 'mov edx,4: found-type code 4 (u128 / 0xfe)'),
        (0x466daa4, '4889fb', 'mov rbx,rdi: out-of-range error prologue'),
        (0x466daa7, 'be03000000', 'mov esi,3: expected-type code 3 (u64)'),
        (0x466daac, 'ba0c000000', 'mov edx,0xc: found-type code 0xc (0xff)'),
    ), 0x6f6ed8, (0x466d9e7, 0x466da01, 0x466d9f4, 0x466da8c), 8, 3),
)

U32_SLICE = (
    'varint_decode_u32_slice', 0x466bc10, 0x466bd03, (
        (0x466bc3d, '4883f804', 'cmp rax,4: fast path needs > 4 bytes remaining'),
        (0x466bc41, '7664', 'jbe 0x466bca7: take the Reader slow path'),
        (0x466bc47, '0fb611', 'movzx edx,byte [rcx]: read tag byte'),
        (0x466bc4a, '81fafb000000', 'cmp edx,0xfb: tag < 251 is the value (1 byte)'),
        (0x466bc52, '41b801000000', 'mov r8d,1: consumed 1'),
        (0x466bc5a, '81c205ffffff', 'add edx,-0xfb: tag index'),
        (0x466bc60, '83fa03', 'cmp edx,3: indexes 0..3 (0xfb..0xfe)'),
        (0x466bc69, '4c8d0528b208fc', 'lea r8,[jump table]'),
        (0x466bc79, '0fb75101', 'movzx edx,word [rcx+1]: 0xfb arm reads u16'),
        (0x466bc7d, '41b803000000', 'mov r8d,3: consumed 3'),
        (0x466bc85, '8b5101', 'mov edx,dword [rcx+1]: 0xfc arm reads u32'),
        (0x466bc88, '41b805000000', 'mov r8d,5: consumed 5'),
        (0x466bc9c, '895704', 'mov [rdi+4],edx: store u32 value'),
        (0x466bc9f, 'c60712', 'mov byte [rdi],0x12: Ok tag'),
        (0x466bca7, '4883c610', 'add rsi,0x10: pass the inner Reader to the slow path'),
        (0x466bcb0, 'ff1582941001', 'call [rip+disp] GOT 0x5775138 -> u32 Reader'),
        (0x466bcbb, '4889fb', 'mov rbx,rdi: 0xfe error prologue'),
        (0x466bcbe, 'be02000000', 'mov esi,2: expected-type code 2 (u32)'),
        (0x466bcc3, 'ba04000000', 'mov edx,4: found-type code 4 (u128 / 0xfe)'),
        (0x466bcd3, '4889fb', 'mov rbx,rdi: 0xfd error prologue'),
        (0x466bcd6, 'be02000000', 'mov esi,2: expected-type code 2 (u32)'),
        (0x466bcdb, 'ba03000000', 'mov edx,3: found-type code 3 (u64 / 0xfd)'),
        (0x466bceb, '4889fb', 'mov rbx,rdi: out-of-range error prologue'),
        (0x466bcee, 'be02000000', 'mov esi,2: expected-type code 2 (u32)'),
        (0x466bcf3, 'ba0c000000', 'mov edx,0xc: found-type code 0xc (0xff)'),
    ), 0x6f6e98, (0x466bc79, 0x466bc85, 0x466bcd3, 0x466bcbb),
    0x5775138, 0x466d850,
)

U64_SLICE_SLOW = (
    'varint_decode_u64_slice_slow_branch', 0x466bd10, 0x466bdf5, (
        (0x466bd3d, '4883f808', 'cmp rax,8: fast path needs > 8 bytes remaining'),
        (0x466bd41, '766e', 'jbe 0x466bdb1: take the Reader slow path'),
        (0x466bdb1, '4883c610', 'add rsi,0x10: pass the inner Reader to the slow path'),
        (0x466bdba, 'ff1520881001', 'call [rip+disp] GOT 0x57745e0 -> u64 Reader'),
        (0x466bdc5, '4889fb', 'mov rbx,rdi: 0xfe error prologue (fast-path arm)'),
        (0x466bdc8, 'be02000000', 'mov esi,2: expected-type code 2 on the fast-path 0xfe arm'),
        (0x466bdcd, 'ba04000000', 'mov edx,4: found-type code 4 (u128 / 0xfe)'),
        (0x466bddd, '4889fb', 'mov rbx,rdi: out-of-range error prologue'),
        (0x466bde0, 'be02000000', 'mov esi,2: expected-type code 2 on the fast-path 0xff arm'),
        (0x466bde5, 'ba0c000000', 'mov edx,0xc: found-type code 0xc (0xff)'),
    ), 0x57745e0, 0x466d980,
)

READER_CALL_COUNTS = {0x466d850: 2, 0x466d980: 12}

ERROR_BUILDER_ANCHORS = (
    (0x466dac0, '4889f8', 'mov rax,rdi'),
    (0x466dac3, 'c60703', 'mov byte [rdi],0x3: error-result tag'),
    (0x466dac6, '40887701', 'mov [rdi+1],sil: expected-type byte'),
    (0x466daca, '885702', 'mov [rdi+2],dl: found-type byte'),
)


def _check_anchors(data, secs, name, start, end, anchors):
    rows = []
    for va, hexbytes, meaning in anchors:
        want = bytes.fromhex(hexbytes)
        o = bv.va_to_off(secs, va)
        if not start <= va < end or data[o:o + len(want)] != want:
            raise EvidenceError(f'{name}: bytes at {va:#x} are not {hexbytes}')
        rows.append({'va': f'{va:#x}', 'file_offset': f'{o:#x}', 'bytes': hexbytes, 'meaning': meaning})
    return rows


def _check_table(data, secs, name, table, targets):
    o = bv.va_to_off(secs, table)
    got = tuple(table + struct.unpack_from('<i', data, o + 4 * i)[0] for i in range(4))
    if got != targets:
        raise EvidenceError(f'{name}: jump table {table:#x} targets changed')
    return {f'{0xfb + i:#x}': f'{t:#x}' for i, t in enumerate(got)}


def _got_target(relocs, slot, expect):
    got = relocs.get(slot)
    if got != expect:
        raise EvidenceError(f'GOT {slot:#x} relocates to {got and hex(got)}, expected {expect:#x}')


def _call_got_sites(data, secs, relocs):
    text = secs['.text']
    tb = data[text['offset']:text['offset'] + text['size']]
    base = text['addr']
    want = set(READER_CALL_COUNTS)
    sites = {t: [] for t in want}
    for i in range(len(tb) - 6):
        if tb[i:i + 2] != b'\xff\x15':
            continue
        disp = struct.unpack_from('<i', tb, i + 2)[0]
        slot = base + i + 6 + disp
        tgt = relocs.get(slot)
        if tgt in want:
            sites[tgt].append({'site': f'{base + i:#x}', 'got_slot': f'{slot:#x}'})
    for tgt, expect in READER_CALL_COUNTS.items():
        if len(sites[tgt]) != expect:
            raise EvidenceError(f'Reader {tgt:#x} call-site count {len(sites[tgt])} != {expect}')
    return {f'{t:#x}': sites[t] for t in sorted(want)}


# ---- u16 length-marker scan -------------------------------------------------
# Every `cmp <reg>,0xfb` instruction start in .text. The set is pinned here and
# re-proved equal to GNU objdump's complete .text disassembly by the GNU-only
# test (byte patterns alone over-match: they also fire inside other
# instructions). Each entry is (va, instruction bytes).
CMP_FB_SITES = (
    (0x134698d, '4881f9fb000000'), (0x1583bb7, '4881fefb000000'),
    (0x2558975, '4881fbfb000000'), (0x2558aae, '4881fffb000000'),
    (0x2558cca, '4881fafb000000'), (0x2558dba, '4881fafb000000'),
    (0x2558f3c, '4881fbfb000000'), (0x2558fd1, '4981fefb000000'),
    (0x2559068, '4981fffb000000'), (0x255979a, '4881fbfb000000'),
    (0x25598db, '4881f9fb000000'), (0x2561ab5, '4981fffb000000'),
    (0x2561b05, '4881fdfb000000'), (0x27ab0aa, '81f9fb000000'),
    (0x27ab281, '81f9fb000000'), (0x27ab30b, '4881f9fb000000'),
    (0x27ab5b1, '4881f9fb000000'), (0x288f50d, '4881f9fb000000'),
    (0x2973ab6, '4181f8fb000000'), (0x2973ba6, '4981f8fb000000'),
    (0x33355b7, '4881fdfb000000'), (0x3959c68, '4881f9fb000000'),
    (0x395b069, '4981fdfb000000'), (0x4587475, '81f9fb000000'),
    (0x466bc4a, '81fafb000000'), (0x466bd4a, '4881fafb000000'),
    (0x466beaa, '4881fafb000000'), (0x466d870, '4181f8fb000000'),
    (0x466d9a0, '4981f8fb000000'), (0x466daf0, '4981f8fb000000'),
    (0x4aa9aea, '81fbfb000000'), (0x4aa9c93, '3dfb000000'),
    (0x4aa9f8b, '4881f9fb000000'), (0x4aaa231, '4881f9fb000000'),
    (0x4b6fa7d, '4881f9fb000000'),
)
CMP_FB_SITE_COUNT = 35
# Byte-pattern candidates for cmp-imm-0xfb in .text (all encodings incl. 8-bit);
# a superset of instruction starts, recorded so a mutation shows up.
CMP_FB_BYTE_CANDIDATES = 354
CMP_FB_RE = re.compile(rb'[\x40-\x4f]?\x81[\xf8-\xff]\xfb\x00\x00\x00|[\x40-\x4f]?\x3d\xfb\x00\x00\x00'
                       rb'|[\x40-\x4f]?\x80[\xf8-\xff]\xfb|\x3c\xfb')
CMP2_RE = re.compile(rb'[\x48\x49]?\x83[\xf8-\xff]\x02|\x3c\x02|\x80[\xf8-\xff]\x02')
DISPATCH_RE = re.compile(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....(?:.){0,12}?\x41?\xff[\xe0-\xe7]', re.S)
LEN2_WINDOW = 0x80       # [site-0x80, site+0x80) clipped to the FDE
DISPATCH_WINDOW = 0x20   # [site, site+0x20) clipped to the FDE
LEN2_HITS = (0x134698d,)

CHAIN_ID_FN = (0x1346860, 0x1346daf)
CHAIN_ID_ANCHORS = (
    (0x1346906, '488d8fd8dcffff', 'lea rcx,[rdi-0x2328]: rdi-9000'),
    (0x134690d, '4883f902', 'cmp rcx,2: rdi in {9000,9001} (the length-2-adjacent cmp; operand is rdi-9000, not a remaining length)'),
    (0x1346989, '488d4fff', 'lea rcx,[rdi-1]'),
    (0x134698d, '4881f9fb000000', 'cmp rcx,0xfb: rdi-1 <= 251, i.e. rdi in 1..252'),
    (0x134699a, '488d155b2decfe', 'lea rdx,[rip+disp]: jump table 0x2096fc indexed by rdi-1'),
    (0x1346a08, '488d8f4f5bffff', 'lea rcx,[rdi-0xa4b1]: rdi-42161'),
    (0x1346a29, '4881ff697a0000', 'cmp rdi,0x7a69: 31337'),
    (0x1346d38, '4881ff05210000', 'cmp rdi,0x2105: 8453'),
    (0x1346d4c, '4881ffa736aa00', 'cmp rdi,0xaa36a7: 11155111'),
    (0x1346da9, '31c04889fac3', 'xor eax,eax ; mov rdx,rdi ; ret: match / no-match exits return rdi unchanged in rdx'),
)


def _u16_marker_scan(data, secs, fdes):
    text = secs['.text']
    tb = data[text['offset']:text['offset'] + text['size']]
    base = text['addr']
    cands = sum(1 for _ in CMP_FB_RE.finditer(tb))
    if cands != CMP_FB_BYTE_CANDIDATES:
        raise EvidenceError(f'cmp-0xfb byte candidates {cands} != {CMP_FB_BYTE_CANDIDATES}')
    if len(CMP_FB_SITES) != CMP_FB_SITE_COUNT:
        raise EvidenceError('pinned cmp-0xfb site list length changed')
    starts = sorted(fdes)

    def fde_of(va):
        import bisect
        j = bisect.bisect_right(starts, va) - 1
        if j >= 0 and va < fdes[starts[j]]:
            return starts[j], fdes[starts[j]]
        raise EvidenceError(f'{va:#x} outside every FDE')

    rows, hits = [], []
    for va, hexbytes in CMP_FB_SITES:
        want = bytes.fromhex(hexbytes)
        o = bv.va_to_off(secs, va)
        if data[o:o + len(want)] != want or not CMP_FB_RE.match(data, o):
            raise EvidenceError(f'cmp-0xfb site {va:#x}: bytes are not {hexbytes}')
        lo, hi = fde_of(va)
        wl, wh = max(lo, va - LEN2_WINDOW), min(hi, va + LEN2_WINDOW)
        w = data[bv.va_to_off(secs, wl):bv.va_to_off(secs, wl) + (wh - wl)]
        len2 = [wl + m.start() for m in CMP2_RE.finditer(w)]
        dend = min(hi, va + DISPATCH_WINDOW)
        dm = DISPATCH_RE.search(data[o:o + (dend - va)])
        disp = va + dm.start() if dm else None
        hit = bool(len2) and disp is not None
        if hit:
            hits.append(va)
        rows.append({'va': f'{va:#x}', 'bytes': hexbytes, 'fde': f'{lo:#x}..{hi:#x}',
                     'cmp2_sites_in_window': [f'{x:#x}' for x in len2],
                     'dispatch_va': None if disp is None else f'{disp:#x}',
                     'classification': 'length2_adjacent' if hit else 'no_length2_adjacent'})
    if tuple(hits) != LEN2_HITS:
        raise EvidenceError(f'length-2-adjacent hits {[hex(h) for h in hits]} != {[hex(h) for h in LEN2_HITS]}')
    lo, hi = CHAIN_ID_FN
    if fdes.get(lo) != hi:
        raise EvidenceError(f'chain-id FDE is not {lo:#x}..{hi:#x}')
    anchors = _check_anchors(data, secs, 'chain_id_membership', lo, hi, CHAIN_ID_ANCHORS)
    return {
        'rule': ('a cmp <reg>,0xfb instruction is length2_adjacent iff a cmp <reg>,2 starts in '
                 '[site-0x80, site+0x80) and a lea r,[rip+disp] ... jmp r dispatch starts in '
                 '[site, site+0x20), both clipped to the containing FDE'),
        'cmp_0xfb_byte_candidates_in_text': CMP_FB_BYTE_CANDIDATES,
        'cmp_0xfb_instruction_count': len(rows),
        'sites': rows,
        'length2_adjacent_hits': [f'{h:#x}' for h in hits],
        'length2_adjacent_hit_count': len(hits),
        'hit_characterisation': {
            'site': '0x134698d', 'fde_start': f'{lo:#x}', 'fde_end': f'{hi:#x}',
            'anchors': anchors,
            'observed': ('input is the integer in rdi; the function compares rdi (or rdi-k) against '
                         'immediates and a 252-entry jump table, and reads no non-RIP memory operand; '
                         'it never loads a tag byte from a buffer'),
            'interpretation': ('EVM chain-id membership test (immediates include 1..252, 8453, 9000/9001, '
                               '31337, 42161, 11155111); not a u16 decoder. The chain names are an '
                               'inference from the immediates, not an observation'),
        },
        'conclusion': 'no u16 slice decoder: the only length2_adjacent 0xfb site is the chain-id lookup',
    }


def _decode_vectors():
    return [
        {'reader': 'varint_decode_u32_reader', 'input_hex': '', 'len': 0,
         'outcome': 'UnexpectedEnd', 'need': 1},
        {'reader': 'varint_decode_u32_reader', 'input_hex': '00', 'len': 1,
         'outcome': 'Ok', 'value': 0, 'consumed': 1},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'fa', 'len': 1,
         'outcome': 'Ok', 'value': 0xfa, 'consumed': 1},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'fb', 'len': 1,
         'outcome': 'UnexpectedEnd', 'need': 2, 'note': '0xfb arm needs 3 total; 1 present'},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'fb3400', 'len': 3,
         'outcome': 'Ok', 'value': 0x0034, 'consumed': 3, 'note': '0xfb + u16 LE'},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'fc78563412', 'len': 5,
         'outcome': 'Ok', 'value': 0x12345678, 'consumed': 5, 'note': '0xfc + u32 LE'},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'fd', 'len': 1,
         'outcome': 'InvalidIntegerType', 'expected_code': 2, 'found_code': 3,
         'note': '0xfd is u64-width; u32 Reader rejects it'},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'fe', 'len': 1,
         'outcome': 'InvalidIntegerType', 'expected_code': 2, 'found_code': 4,
         'note': '0xfe is u128-width; no 16-byte read'},
        {'reader': 'varint_decode_u32_reader', 'input_hex': 'ff', 'len': 1,
         'outcome': 'InvalidIntegerType', 'expected_code': 2, 'found_code': 0xc,
         'note': '0xff out-of-range marker'},
        {'reader': 'varint_decode_u64_reader', 'input_hex': '', 'len': 0,
         'outcome': 'UnexpectedEnd', 'need': 1},
        {'reader': 'varint_decode_u64_reader', 'input_hex': '7b', 'len': 1,
         'outcome': 'Ok', 'value': 0x7b, 'consumed': 1},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'fb', 'len': 1,
         'outcome': 'UnexpectedEnd', 'need': 2},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'fb3412', 'len': 3,
         'outcome': 'Ok', 'value': 0x1234, 'consumed': 3, 'note': '0xfb + u16 LE'},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'fc78563412', 'len': 5,
         'outcome': 'Ok', 'value': 0x12345678, 'consumed': 5, 'note': '0xfc + u32 LE'},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'fdefcdab9078563412', 'len': 9,
         'outcome': 'Ok', 'value': 0x1234567890abcdef, 'consumed': 9, 'note': '0xfd + u64 LE'},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'fd01020304', 'len': 5,
         'outcome': 'UnexpectedEnd', 'need': 4, 'note': '0xfd needs 9 total; 5 present'},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'fe', 'len': 1,
         'outcome': 'InvalidIntegerType', 'expected_code': 3, 'found_code': 4,
         'note': '0xfe is u128-width; Reader does not read 16 bytes'},
        {'reader': 'varint_decode_u64_reader', 'input_hex': 'ff', 'len': 1,
         'outcome': 'InvalidIntegerType', 'expected_code': 3, 'found_code': 0xc},
        {'reader': 'varint_decode_u64_slice_via_slow', 'input_hex': '00', 'len': 1,
         'outcome': 'Ok', 'value': 0, 'consumed': 1,
         'note': 'len<=8 takes jbe -> GOT 0x57745e0 -> u64 Reader'},
        {'reader': 'varint_decode_u64_slice_via_slow', 'input_hex': 'fe', 'len': 1,
         'outcome': 'InvalidIntegerType', 'expected_code': 3, 'found_code': 4,
         'note': 'slow path uses Reader expected_code 3 (not the fast-path arm esi=2)'},
        {'reader': 'varint_decode_u32_slice_via_slow', 'input_hex': 'fc01000000', 'len': 5,
         'outcome': 'Ok', 'value': 1, 'consumed': 5,
         'note': 'len==5 > 4 so this is still the fast path; included as width control'},
        {'reader': 'varint_decode_u32_slice_via_slow', 'input_hex': 'fb00', 'len': 2,
         'outcome': 'routes_to_reader', 'reader_target': '0x466d850',
         'note': 'len<=4 takes jbe -> GOT 0x5775138 -> u32 Reader; Reader then UnexpectedEnd need 1'},
    ]


def scan(data, expected_sha256=bv.SHA256, check_fast_path=True):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    if check_fast_path:
        fast = bv.render(dv.scan(data, expected_sha256=expected_sha256))
        if hashlib.sha256(fast.encode()).hexdigest() != FAST_PATH_JSON_SHA256:
            raise EvidenceError('merged RE-005 decode-sites.json hash changed (negative control)')
    secs = bv.sections(data)
    fdes = bv.fde_extents(data, secs)
    relocs = bv.relative_relocs(data, secs)

    readers = []
    for name, start, end, anchors, table, targets, width, exp_code in READERS:
        if fdes.get(start) != end:
            raise EvidenceError(f'{name}: FDE extent is not {start:#x}..{end:#x}')
        rows = _check_anchors(data, secs, name, start, end, anchors)
        by_tag = _check_table(data, secs, name, table, targets)
        readers.append({
            'name': name, 'fde_start': f'{start:#x}', 'fde_end': f'{end:#x}',
            'anchors': rows, 'jump_table': f'{table:#x}',
            'jump_targets_by_tag': by_tag,
            'result_store_width_bytes': width,
            'expected_type_code_on_0xfe': exp_code,
        })

    name, start, end, anchors, table, targets, got_slot, got_tgt = U32_SLICE
    if fdes.get(start) != end:
        raise EvidenceError(f'{name}: FDE extent is not {start:#x}..{end:#x}')
    u32_rows = _check_anchors(data, secs, name, start, end, anchors)
    u32_by_tag = _check_table(data, secs, name, table, targets)
    _got_target(relocs, got_slot, got_tgt)

    name, start, end, anchors, got_slot, got_tgt = U64_SLICE_SLOW
    if fdes.get(start) != end:
        raise EvidenceError(f'{name}: FDE extent is not {start:#x}..{end:#x}')
    u64_slow_rows = _check_anchors(data, secs, name, start, end, anchors)
    _got_target(relocs, got_slot, got_tgt)

    eb_start, eb_end, eb_got = ERROR_BUILDER
    if fdes.get(eb_start) != eb_end:
        raise EvidenceError(f'error builder FDE is not {eb_start:#x}..{eb_end:#x}')
    eb_rows = _check_anchors(data, secs, 'error_builder', eb_start, eb_end, ERROR_BUILDER_ANCHORS)
    _got_target(relocs, eb_got, eb_start)

    call_sites = _call_got_sites(data, secs, relocs)
    u16_scan = _u16_marker_scan(data, secs, fdes)

    return {
        'schema': 're005-bincode-varint-slow-widths/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'negative_control_fast_path_json_sha256': FAST_PATH_JSON_SHA256,
        'u32_slice_decoder': {
            'name': U32_SLICE[0], 'fde_start': f'{U32_SLICE[1]:#x}', 'fde_end': f'{U32_SLICE[2]:#x}',
            'anchors': u32_rows, 'jump_table': f'{U32_SLICE[4]:#x}',
            'jump_targets_by_tag': u32_by_tag,
            'slow_path': {'got_slot': f'{U32_SLICE[6]:#x}', 'reader': f'{U32_SLICE[7]:#x}',
                          'gate': 'cmp rax,4 ; jbe', 'gate_va': '0x466bc3d'},
        },
        'u64_slice_slow_branch': {
            'name': U64_SLICE_SLOW[0], 'fde_start': f'{U64_SLICE_SLOW[1]:#x}',
            'fde_end': f'{U64_SLICE_SLOW[2]:#x}',
            'anchors': u64_slow_rows,
            'slow_path': {'got_slot': f'{U64_SLICE_SLOW[4]:#x}', 'reader': f'{U64_SLICE_SLOW[5]:#x}',
                          'gate': 'cmp rax,8 ; jbe', 'gate_va': '0x466bd3d'},
            'note': 'fast-path body is claimed by research/work-items/RE-005-bincode-varint/; '
                    'this packet only pins the slow-branch bytes and the 0xfe/0xff esi/edx codes',
        },
        'readers': readers,
        'error_builder': {
            'fde_start': f'{eb_start:#x}', 'fde_end': f'{eb_end:#x}',
            'got_slot': f'{eb_got:#x}', 'anchors': eb_rows,
        },
        'reader_call_sites': call_sites,
        'reader_call_counts': {f'{k:#x}': v for k, v in sorted(READER_CALL_COUNTS.items())},
        'decode_vectors': _decode_vectors(),
        'u16_marker_scan': u16_scan,
        'wire_rule_observed': {
            'lt_0xfb': 'tag byte is the value, 1 consumed',
            '0xfb': 'u16 LE at +1 (rol/bswap when dl!=0), 3 consumed',
            '0xfc': 'u32 LE at +1 (bswap when dl!=0), 5 consumed',
            '0xfd': 'u64 LE at +1 on the u64 Reader (error on the u32 Reader), 9 consumed',
            '0xfe': 'error arm (no u128 / 16-byte read); found_code=4',
            '0xff': 'error arm; found_code=0xc',
            'Ok_tag': '0x12', 'UnexpectedEnd_tag': '0x0', 'InvalidIntegerType_tag': '0x3',
        },
        'what_this_does_not_claim': [
            'No claim that the binary executes these paths at runtime; evidence is static.',
            'No claim about the 0x466dad0 Reader (esi=5 on its 0xfe arm); different expected-type code.',
            'No u16-width slice decoder: of the 35 cmp <reg>,0xfb instructions in .text exactly one (0x134698d) has a cmp <reg>,2 within 0x80 bytes and a jump-table dispatch within 0x20, and it is a chain-id lookup on an integer, not a decoder (see u16_marker_scan).',
            'u16 appears only as the 0xfb payload width; u128 appears only as the 0xfe error marker.',
            'The merged RE-005 fast-path packet (u64 slice + 21 dispatch sites) is not modified.',
            'Function names are our labels; the binary has no symbols for them.',
            'esi/edx are pinned as raw codes; the IntegerType enum mapping is an inference, not an observation.',
        ],
    }


def render(result):
    return (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, default=bv.TARGET)
    ap.add_argument('--output', type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(scan(a.input.read_bytes()))
    except (EvidenceError, OSError, struct.error, ValueError) as e:
        print(f'bincode_varint_slow: {e}', file=sys.stderr)
        return 1
    if a.output:
        a.output.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
