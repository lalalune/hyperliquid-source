#!/usr/bin/env python3
"""Trace who produces the RE-005 pipeline records above the level-3 callers.

The block-fill packet (research/work-items/RE-005-node115-block-fill-
writers, PR #2543) pinned twelve bodies through two levels above the
dispatcher callers and showed the descriptor blocks are never written
inside them: the bulk selector, the bulk incoming limit, the twin
source pointer, the twin sibling and the twin incoming limit are the
incoming contents of the pipeline records at every traced level, and
the first writer is the producer of those records, above the window.
This packet takes that question.  It pins the level-3 callers the
block-fill packet only censused, the level above them, and -- on the
two chains that leave the direct call graph -- the spawner bodies
that package the records, twenty-two bodies in all.

Answer shape.  A direct-access census of the five descriptor fields,
mapped through every embedding the traced call sites establish, plus
the head sources the pipeline copies from (the bulk a 1 struct's
+0x50 and +0x120, the bulk a 2 struct's +0x1d8), finds no store to --
and no read of -- any mapped offset in any of the twenty-two pinned
bodies.  What each level does write is head fields, and the packet
pins those writes exactly:

- On the a chain, lvl3_a builds the lvl2_a record's head (the pair
  before it at its struct +0x1718 and the record's first 0x22 bytes
  at +0x1728) out of its own struct's fields -- the pair at
  [rbx+0xb10], the return value of an indirect call through GOT slot
  0x64e7430, a self-pointer, and the struct byte at [rbx+0xb21] --
  immediately before its call.  One level up, lvl4_a and lvl3_c run
  the identical shaping on a phase struct: each copies the struct's
  +0xc8..+0xf0 fields over the embedded record at +0x220, sets the
  tag byte at +0x248 to 2 (first site) or 1 (second site) and the
  bytes at +0x290/+0x291 from the struct byte at +0x1e8, then passes
  the shaped record down.  The descriptor offsets sit far above the
  shaped head (+0x1a00 and beyond in the lvl2_c record) and are never
  touched.
- The c chain bottoms out in stack construction.  lvl4_c, whose
  frame is about 0xb328 bytes, passes only pointers into its own
  stack: lvl3_c's two arguments are its stack at +0x80 and +0x2e68,
  lvl4_a's phase struct is its stack buffer at +0x5aa8, filled by an
  indirect call through GOT slot 0x64e1760 out of a query struct the
  helper 0x5cf93f0 filled at +0x130.  lvl4_c's own caller, ctor_c,
  passes its own 0x2c48-byte stack frame as the phase struct (only
  the dispatch byte at struct +0x21a is written, to zero) and is
  itself reachable only through the 39-byte registration stub
  0x2cef8f0, which stores its address in a stack descriptor and
  registers it through GOT slot 0x64e6c30; the stub is the binary's
  only reference to it, and the stub itself is the binary's main
  function -- the ELF entry point loads its address at 0x1419318
  as the main argument of its libc-start call.
- On the d/e chains the level-3 bodies are pure forwarders: each
  holds its entry struct in rbx (an atomic state word at +0x0, a
  pointer at +0x28, a dword at +0x30) and the embedded lvl2 record
  at +0x38 is never written -- the lea that forms the call argument
  is the record's only direct reference in the body.  The bodies
  have no direct callers: each address occurs exactly once in the
  binary's data, as the addend of an R_X86_64_RELATIVE relocation
  in .data.rel.ro (slots in the slot census), and each slot's
  address is embedded by exactly one wrapper spawner into a
  0x3080-byte heap record (tag 0xcc at +0x0, the slot's address at
  +0x10, the spawner's entry rdx at +0x20 and rcx at +0x28), together
  with a 0x2ff8-byte payload that lands at heap +0x38 -- the same
  offset at which the lvl2 record sits inside the lvl3 bodies'
  entry structs.  The wrappers hand the heap records to one of two
  registrars (0x2cd0910 for the d1/e1 pair, 0x2cd06c0 for d2/e2).
- The payload is produced by spawn_d and spawn_e.  Each assembles a
  0x3008-byte record on its own stack -- a self-referential head at
  [rsp+0x3380] (two pointers to its own stack slots) and the record
  proper at [rsp+0x3390] -- through helper calls and copies: an
  indirect call through GOT slot 0x64e7360 with a 0x258 argument, a
  direct call to 0x2d4d540 against the record copy at [rsp+0x6388],
  a 0x148-byte copy into the record head, and whole-record copies of
  the finished struct.  The payload is copied out of the record
  ([rsp+0x3390] -> [rsp+0x9390], 0x2ff8 bytes) and passed to the
  pre_* bodies, which load a refcounted context out of their entry
  rdi and call the wrappers.  spawn_d and spawn_e are themselves
  reached only through .data.rel.ro slots (0x64478f0 and 0x64478d0,
  adjacent entries of one handler table whose other entries are the
  default 0x445db6 and sibling phase functions) with no rip-relative
  reference anywhere -- a table walk, the same boundary shape as the
  b-side caller of the earlier packets.

So the producers are identified at body granularity on every chain
-- lvl4_c's stack construction and its GOT-slot fill on the c chain,
lvl4_a/lvl3_c shaping and lvl3_a head construction on the a/c record
heads, spawn_d/spawn_e's stack assembly on the d/e chains -- and the
descriptor fields' byte-level origin sits one step further inside
them: in the helper calls and whole-record copies whose sources are
themselves stack-built, never in a direct store that names a
descriptor offset.

None of the twenty-two pinned bodies is among PR #2300's six extents
(the reader-state bodies 0x2cd7ac0, 0x2cd7d90, 0x5821250, 0x5821540,
0x58225c0, 0x5822700); the trace does not enter the reader-state
area, and this packet says nothing about the decoder state buffer,
which remains the open question recorded by the block-fill packet.

Every fact is mechanical.  Twenty-two functions are pinned by exact
FDE extent, body SHA-256 and per-instruction byte pins; the eighteen
bodies of at most about 4 KB retain full objdump exports, the rest
are retained as hash plus pins.  The censuses are re-derived from
fresh objdump text and binary scans on every run.  Captured code is
never executed; byte values are recorded exactly as decoded.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105_896_032
TARGET_SHA256 = (
    'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-record-producer'
OUT = ROOT / 'research/work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
COPY_SLOT = 0x64DF508

EXPORTED = {'lvl3_d1', 'lvl3_d2', 'lvl3_e1', 'lvl3_e2', 'ctor_c',
            'registrar_stub_c', 'wrap_d1', 'wrap_d2', 'wrap_e1',
            'wrap_e2', 'pre_d1', 'pre_d2', 'pre_e1', 'pre_e2',
            'call4a_b', 'pre_4ab', 'spawn_d', 'spawn_e'}

CALL_TARGETS = {
    'lvl3_a': {0x2AEC151: 0x2AF0660},
    'lvl3_c': {0x2CDE6F4: 0x2CB6500, 0x2CDF58B: 0x2CB6500},
    'lvl3_d1': {0x2B1DB89: 0x2ACCEE0},
    'lvl3_d2': {0x2B26B09: 0x2ACCEE0},
    'lvl3_e1': {0x2B221F9: 0x2AD0DB0},
    'lvl3_e2': {0x2B24A29: 0x2AD0DB0},
    'lvl4_a': {0x2AE4627: 0x2AEAEF0, 0x2AE548C: 0x2AEAEF0},
    'lvl4_c': {0x2AE1A47: 0x2AE41E0, 0x2AE1EEB: 0x2CDE430,
               0x2AE2306: 0x24535C0},
    'ctor_c': {0x2CD83A2: 0x2AE1690},
    'registrar_stub_c': {},
    'wrap_d1': {0x2CD11E7: 0x2CD0910},
    'wrap_d2': {0x2CD1AE7: 0x2CD06C0},
    'wrap_e1': {0x2CD0FF7: 0x2CD0910},
    'wrap_e2': {0x2CD27E7: 0x2CD06C0},
    'pre_d1': {0x2B3F328: 0x2CD1070},
    'pre_d2': {0x2B403CF: 0x2CD1970},
    'pre_e1': {0x2B3F148: 0x2CD0E80},
    'pre_e2': {0x2B3FC5F: 0x2CD2670},
    'call4a_b': {0x2B40577: 0x2AE41E0},
    'pre_4ab': {0x2453673: 0x2B404B0},
    'spawn_d': {0x2AD6325: 0x2B3F300, 0x2AD633A: 0x2B403A0},
    'spawn_e': {0x2AD6F05: 0x2B3F120, 0x2AD6F1A: 0x2B3FC30},
}

# Caller-set census subjects: function start -> record name.  The
# five level-2 bodies of the block-fill packet and the two spawner
# registrars are subjects even though they are not owners here.
CENSUS_SUBJECTS = {
    0x2AEAEF0: 'lvl3_a', 0x2CDE430: 'lvl3_c',
    0x2B1D9A0: 'lvl3_d1', 0x2B26920: 'lvl3_d2',
    0x2B22010: 'lvl3_e1', 0x2B24840: 'lvl3_e2',
    0x2AE41E0: 'lvl4_a', 0x2AE1690: 'lvl4_c',
    0x2CD8370: 'ctor_c', 0x2CEF8F0: 'registrar_stub_c',
    0x2CD1070: 'wrap_d1', 0x2CD1970: 'wrap_d2',
    0x2CD0E80: 'wrap_e1', 0x2CD2670: 'wrap_e2',
    0x2B3F300: 'pre_d1', 0x2B403A0: 'pre_d2',
    0x2B3F120: 'pre_e1', 0x2B3FC30: 'pre_e2',
    0x2B404B0: 'call4a_b', 0x24535C0: 'pre_4ab',
    0x2AD5980: 'spawn_d', 0x2AD6560: 'spawn_e',
    0x2AF0660: 'lvl2_a', 0x2B41B70: 'lvl2_b', 0x2CB6500: 'lvl2_c',
    0x2ACCEE0: 'lvl2_d', 0x2AD0DB0: 'lvl2_e',
    0x2CD0910: 'registrar_a', 0x2CD06C0: 'registrar_b',
}
EXPECTED_CALLERS = {
    'lvl3_a': [
        {'containing_fde': '0x2ae41e0..0x2ae6d66', 'site': '0x2ae4627'},
        {'containing_fde': '0x2ae41e0..0x2ae6d66', 'site': '0x2ae548c'}],
    'lvl3_c': [
        {'containing_fde': '0x2ae1690..0x2ae27b2', 'site': '0x2ae1eeb'}],
    'lvl3_d1': [], 'lvl3_d2': [], 'lvl3_e1': [], 'lvl3_e2': [],
    'lvl4_a': [
        {'containing_fde': '0x2ae1690..0x2ae27b2', 'site': '0x2ae1a47'},
        {'containing_fde': '0x2b404b0..0x2b40666', 'site': '0x2b40577'}],
    'lvl4_c': [
        {'containing_fde': '0x2cd8370..0x2cd83af', 'site': '0x2cd83a2'}],
    'ctor_c': [], 'registrar_stub_c': [],
    'wrap_d1': [
        {'containing_fde': '0x2b3f300..0x2b3f3e3', 'site': '0x2b3f328'}],
    'wrap_d2': [
        {'containing_fde': '0x2b403a0..0x2b404ad', 'site': '0x2b403cf'}],
    'wrap_e1': [
        {'containing_fde': '0x2b3f120..0x2b3f203', 'site': '0x2b3f148'}],
    'wrap_e2': [
        {'containing_fde': '0x2b3fc30..0x2b3fd3d', 'site': '0x2b3fc5f'}],
    'pre_d1': [
        {'containing_fde': '0x2ad5980..0x2ad655e', 'site': '0x2ad6325'}],
    'pre_d2': [
        {'containing_fde': '0x2ad5980..0x2ad655e', 'site': '0x2ad633a'}],
    'pre_e1': [
        {'containing_fde': '0x2ad6560..0x2ad713e', 'site': '0x2ad6f05'}],
    'pre_e2': [
        {'containing_fde': '0x2ad6560..0x2ad713e', 'site': '0x2ad6f1a'}],
    'call4a_b': [
        {'containing_fde': '0x24535c0..0x245390d', 'site': '0x2453673'}],
    'pre_4ab': [
        {'containing_fde': '0x2ae1690..0x2ae27b2', 'site': '0x2ae2306'}],
    'spawn_d': [], 'spawn_e': [],
    'lvl2_a': [
        {'containing_fde': '0x2aeaef0..0x2af0654', 'site': '0x2aec151'}],
    'lvl2_b': [
        {'containing_fde': '0x2af0660..0x2af45e1', 'site': '0x2af0a5f'},
        {'containing_fde': '0x2cbbbe0..0x2cbfc3f', 'site': '0x2cbc06b'}],
    'lvl2_c': [
        {'containing_fde': '0x2cde430..0x2ce0dd1', 'site': '0x2cde6f4'},
        {'containing_fde': '0x2cde430..0x2ce0dd1', 'site': '0x2cdf58b'}],
    'lvl2_d': [
        {'containing_fde': '0x2b1d9a0..0x2b1df5b', 'site': '0x2b1db89'},
        {'containing_fde': '0x2b26920..0x2b26eaf', 'site': '0x2b26b09'}],
    'lvl2_e': [
        {'containing_fde': '0x2b22010..0x2b225cb', 'site': '0x2b221f9'},
        {'containing_fde': '0x2b24840..0x2b24dcf', 'site': '0x2b24a29'}],
    'registrar_a': [
        {'containing_fde': '0x2cd0cf0..0x2cd0e7b', 'site': '0x2cd0e0d'},
        {'containing_fde': '0x2cd0e80..0x2cd1065', 'site': '0x2cd0ff7'},
        {'containing_fde': '0x2cd1070..0x2cd1255', 'site': '0x2cd11e7'},
        {'containing_fde': '0x2cd13f0..0x2cd15d7', 'site': '0x2cd156d'},
        {'containing_fde': '0x2cd15e0..0x2cd17d2', 'site': '0x2cd1768'},
        {'containing_fde': '0x2cd1e90..0x2cd201b', 'site': '0x2cd1fad'},
        {'containing_fde': '0x2cd2340..0x2cd24cb', 'site': '0x2cd245d'},
        {'containing_fde': '0x2cd24d0..0x2cd2661', 'site': '0x2cd25f7'},
        {'containing_fde': '0x2cd2860..0x2cd29ef', 'site': '0x2cd2985'},
        {'containing_fde': '0x2cd29f0..0x2cd2b7b', 'site': '0x2cd2b0d'},
        {'containing_fde': '0x2cd2d70..0x2cd2efb', 'site': '0x2cd2e8d'},
        {'containing_fde': '0x2cd3240..0x2cd33cb', 'site': '0x2cd335d'},
        {'containing_fde': '0x2cd33d0..0x2cd3579', 'site': '0x2cd350b'},
        {'containing_fde': '0x2cd3580..0x2cd370b', 'site': '0x2cd369d'}],
    'registrar_b': [
        {'containing_fde': '0x2cd0b60..0x2cd0ceb', 'site': '0x2cd0c7d'},
        {'containing_fde': '0x2cd1260..0x2cd13eb', 'site': '0x2cd137d'},
        {'containing_fde': '0x2cd17e0..0x2cd196b', 'site': '0x2cd18fd'},
        {'containing_fde': '0x2cd1970..0x2cd1b55', 'site': '0x2cd1ae7'},
        {'containing_fde': '0x2cd1b60..0x2cd1cf1', 'site': '0x2cd1c87'},
        {'containing_fde': '0x2cd1d00..0x2cd1e8b', 'site': '0x2cd1e1d'},
        {'containing_fde': '0x2cd2020..0x2cd21ab', 'site': '0x2cd213d'},
        {'containing_fde': '0x2cd21b0..0x2cd233f', 'site': '0x2cd22d5'},
        {'containing_fde': '0x2cd2670..0x2cd2855', 'site': '0x2cd27e7'},
        {'containing_fde': '0x2cd2b80..0x2cd2d67', 'site': '0x2cd2cfd'},
        {'containing_fde': '0x2cd2f00..0x2cd308b', 'site': '0x2cd301d'},
        {'containing_fde': '0x2cd3090..0x2cd3239', 'site': '0x2cd31cb'},
        {'containing_fde': '0x2cd3710..0x2cd3902', 'site': '0x2cd3898'},
        {'containing_fde': '0x2cd3910..0x2cd3a9b', 'site': '0x2cd3a2d'}],
}
# Lea references are modrm-checked (rip-relative form only).
EXPECTED_LEA_REFS = {
    'ctor_c': ['0x2cef8f7'],
    'registrar_stub_c': ['0x1419318'],
}

# Slot census subjects: role -> (function start, slot address,
# expected rip-relative references to the slot).
SLOT_SUBJECTS = {
    'lvl3_d1': (0x2B1D9A0, 0x6449600, ['0x2cd113e']),
    'lvl3_d2': (0x2B26920, 0x6449790, ['0x2cd1a3e']),
    'lvl3_e1': (0x2B22010, 0x6449A60, ['0x2cd0f4e']),
    'lvl3_e2': (0x2B24840, 0x64498D0, ['0x2cd273e']),
    'spawn_d': (0x2AD5980, 0x64478F0, []),
    'spawn_e': (0x2AD6560, 0x64478D0, []),
}

# Direct-access census over each owner body's objdump text.  The
# zero patterns are the five descriptor fields and the named head
# sources, mapped through every embedding the traced call sites
# establish, via the record register, the pinned alias registers and
# the stack bases.  A zero entry means the substring never appears;
# an exact entry pins the hit count.
_T_A = (0x1E0, 0x238, 0x270, 0x2E0, 0x2E8, 0x330, 0x368, 0x170, 0x240)
_T_C = (0x1A00, 0x1A58, 0x1A90, 0x1B00, 0x1B08, 0x1968)
_T_DE = (0x12E8, 0x13D8, 0x13E0, 0x13E8, 0x13F0,
         0x2278, 0x2368, 0x2370, 0x2378, 0x2380)


def _pats(reg, base, offs):
    return [f'[{reg}+{base + off:#x}]' for off in offs]


ZERO_PATTERNS = {
    'lvl3_a': _pats('rbx', 0x1728, _T_A) + _pats('r14', 0, _T_A),
    'lvl3_c': (_pats('r13', 0x220, _T_C) + _pats('r14', 0, _T_C) +
               _pats('r12', 0, _T_C)),
    'lvl3_d1': _pats('rbx', 0x38, _T_DE),
    'lvl3_d2': _pats('rbx', 0x38, _T_DE),
    'lvl3_e1': _pats('rbx', 0x38, _T_DE),
    'lvl3_e2': _pats('rbx', 0x38, _T_DE),
    'lvl4_a': _pats('rbx', 0x1948, _T_A) + _pats('r14', 0x1728, _T_A),
    'lvl4_c': (_pats('rsp', 0x5AA8 + 0x1948, _T_A) +
               _pats('r12', 0x1948, _T_A)),
    'ctor_c': [], 'registrar_stub_c': [],
    'wrap_d1': [], 'wrap_d2': [], 'wrap_e1': [], 'wrap_e2': [],
    'pre_d1': [], 'pre_d2': [], 'pre_e1': [], 'pre_e2': [],
    'call4a_b': [], 'pre_4ab': [],
    'spawn_d': _pats('rsp', 0x3390, _T_DE) + _pats('r13', 0, _T_DE),
    'spawn_e': _pats('rsp', 0x3390, _T_DE) + _pats('r13', 0, _T_DE),
}
EXACT_COUNTS = {
    'lvl3_a': {'[rbx+0x1718]': 5, '[rbx+0x1720]': 4, '[rbx+0x1728]': 2,
               '[rbx+0x1738]': 1, '[rbx+0x1740]': 3, '[rbx+0x1748]': 1,
               '[rbx+0x1749]': 2, '[rbx+0xb10]': 4},
    'lvl3_c': {'[r13+0x220]': 21, '[r13+0x230]': 11, '[r13+0x240]': 6,
               '[r13+0x248]': 10, '[r13+0x290]': 2, '[r13+0x291]': 2,
               '[r13+0xc8]': 18, '[r13+0xd8]': 9, '[r13+0xe8]': 6,
               '[r13+0x1e8]': 18, '[r13+0x21a]': 6},
    'lvl3_d1': {'[rbx+0x38]': 1}, 'lvl3_d2': {'[rbx+0x38]': 1},
    'lvl3_e1': {'[rbx+0x38]': 1}, 'lvl3_e2': {'[rbx+0x38]': 1},
    'lvl4_a': {'[rbx+0x220]': 21, '[rbx+0x230]': 11, '[rbx+0x240]': 6,
               '[rbx+0x248]': 10, '[rbx+0x290]': 2, '[rbx+0x291]': 2,
               '[rbx+0xc8]': 18, '[rbx+0xd8]': 9, '[rbx+0xe8]': 6,
               '[rbx+0x1e8]': 18, '[rbx+0x21a]': 5},
    'lvl4_c': {'[rsp+0x5aa8]': 13, '[rsp+0x80]': 4, '[rsp+0x88]': 1,
               '[rsp+0x2e68]': 11, '[rsp+0x18]': 7},
    'ctor_c': {'[rsp+0x222]': 1, '[rsp+0x8]': 1},
    'registrar_stub_c': {'[rsp]': 1},
    'wrap_d1': {'[rsp+0x80]': 3, '[rsp+0x90]': 1, '[rsp+0xa0]': 1,
                '[rsp+0xa8]': 1},
    'wrap_d2': {'[rsp+0x80]': 3, '[rsp+0x90]': 1, '[rsp+0xa0]': 1,
                '[rsp+0xa8]': 1},
    'wrap_e1': {'[rsp+0x80]': 3, '[rsp+0x90]': 1, '[rsp+0xa0]': 1,
                '[rsp+0xa8]': 1},
    'wrap_e2': {'[rsp+0x80]': 3, '[rsp+0x90]': 1, '[rsp+0xa0]': 1,
                '[rsp+0xa8]': 1},
    'spawn_d': {'[rsp+0x9390]': 5, '[rsp+0x3380]': 5,
                '[rsp+0x3390]': 2},
    'spawn_e': {'[rsp+0x9390]': 5, '[rsp+0x3380]': 5,
                '[rsp+0x3390]': 2},
}



# How each traced function is reached and what it does with the
# record it is handed.
CALL_PATHS = {
    'lvl3_a': {
        'entry': '0x2aeaef0',
        'record': 'entry rdi, held in rbx; a phase struct whose '
                  'lvl2_a record is embedded at +0x1728',
        'callers': [
            {'site': '0x2ae4627', 'in': 'lvl4_a',
             'argument': 'rdi = the caller\'s own phase struct '
                         '+ 0x220 (lea r14, [rbx+0x220]), shaped by '
                         'the caller immediately before the call; '
                         'rsi = the caller\'s saved second argument'},
            {'site': '0x2ae548c', 'in': 'lvl4_a',
             'argument': 'the second shaping arm, tag byte 1; same '
                         'argument shape'}],
        'own_writes': 'the lvl2_a record head only: [rbx+0x1718] = '
                      'the return value of the indirect call through '
                      'GOT slot 0x64e7430 at 0x2aec0e2, [rbx+0x1720] '
                      '= rdx, the record pair at +0x1728 copied from '
                      'the struct\'s own [rbx+0xb10], [rbx+0x1738] = '
                      'a self-pointer to +0x1718, [rbx+0x1740] = '
                      'r12, the byte [rbx+0x1748] = the struct byte '
                      'at [rbx+0xb21], [rbx+0x1749] = 0'},
    'lvl3_c': {
        'entry': '0x2cde430',
        'record': 'the phase struct pointer is r13 = [[rdi+8]], '
                  'reached through the guard record in rdi (entry '
                  'rsi is held in rbx as the context argument)',
        'callers': [
            {'site': '0x2ae1eeb', 'in': 'lvl4_c',
             'argument': 'rdi = the caller\'s own stack record at '
                         '[rsp+0x80], rsi = the caller\'s own stack '
                         'at [rsp+0x2e68]; the phase struct pointer '
                         'itself arrives inside the stack record'}],
        'own_writes': 'the identical shaping as lvl4_a, on the '
                      'phase struct in r13: +0xc8..+0xf0 copied over '
                      'the embedded lvl2_c record at +0x220, tag '
                      'byte at +0x248 = 2 at the first call site and '
                      '1 at the second, bytes at +0x290/+0x291 from '
                      'the struct byte at +0x1e8'},
    'lvl3_d1': {
        'entry': '0x2b1d9a0',
        'record': 'entry rdi, held in rbx; an atomic state word at '
                  '+0x0 (lock cmpxchg loops), a pointer at +0x28, a '
                  'dword at +0x30; the lvl2_d record is embedded at '
                  '+0x38 and never written',
        'callers': [
            {'site': 'none', 'in': 'indirect',
             'argument': 'no direct or tail call site anywhere; the '
                         'address occurs once in the binary\'s '
                         'data, as the addend of the R_X86_64_'
                         'RELATIVE relocation at slot 0x6449600, and '
                         'the slot\'s address is embedded by '
                         'wrap_d1 into a heap task record (see the '
                         'slot census)'}],
        'own_writes': 'none into the embedded record: the lea at '
                      '0x2b1db7b that forms the call argument is the '
                      'record\'s only direct reference in the body; '
                      'the second argument is a self-referential '
                      'scope-guard struct built on the body\'s own '
                      'stack at [rsp+0x8..0x30]'},
    'lvl3_d2': {
        'entry': '0x2b26920',
        'record': 'same shape as lvl3_d1; reached through slot '
                  '0x6449790, embedded by wrap_d2',
        'callers': [
            {'site': 'none', 'in': 'indirect',
             'argument': 'no direct or tail call site anywhere; '
                         'see the slot census'}],
        'own_writes': 'none into the embedded record'},
    'lvl3_e1': {
        'entry': '0x2b22010',
        'record': 'same shape as lvl3_d1, calling lvl2_e; reached '
                  'through slot 0x6449a60, embedded by wrap_e1',
        'callers': [
            {'site': 'none', 'in': 'indirect',
             'argument': 'no direct or tail call site anywhere; '
                         'see the slot census'}],
        'own_writes': 'none into the embedded record'},
    'lvl3_e2': {
        'entry': '0x2b24840',
        'record': 'same shape as lvl3_d1, calling lvl2_e; reached '
                  'through slot 0x64498d0, embedded by wrap_e2',
        'callers': [
            {'site': 'none', 'in': 'indirect',
             'argument': 'no direct or tail call site anywhere; '
                         'see the slot census'}],
        'own_writes': 'none into the embedded record'},
    'lvl4_a': {
        'entry': '0x2ae41e0',
        'record': 'entry rdi, held in rbx; a phase struct (dispatch '
                  'byte at +0x21a) whose +0x220 sub-struct is shaped '
                  'and passed to lvl3_a',
        'callers': [
            {'site': '0x2ae1a47', 'in': 'lvl4_c',
             'argument': 'rdi = r12 = the caller\'s stack buffer at '
                         '[rsp+0x5aa8], the phase struct filled by '
                         'an indirect call through GOT slot '
                         '0x64e1760; rsi = r13 = the caller\'s stack '
                         'at [rsp+0xb0]'},
            {'site': '0x2b40577', 'in': 'call4a_b',
             'argument': 'rdi = [[rdx]] of call4a_b\'s entry (loaded '
                         'at 0x2b40573 from [rbp], rbp = [r12], r12 '
                         '= entry rdx); rsi = call4a_b\'s entry rcx'}],
        'own_writes': 'the +0x220 shaping (see lvl3_c own_writes; '
                      'the store shapes and counts are identical), '
                      'plus the phase struct head fields at '
                      '+0x205..+0x21a on its dispatch arms'},
    'lvl4_c': {
        'entry': '0x2ae1690',
        'record': 'entry rdi is a phase struct supplied by ctor_c '
                  '(saved at [rsp+0x18]); everything the body hands '
                  'down points into its own ~0xb328-byte stack frame',
        'callers': [
            {'site': '0x2cd83a2', 'in': 'ctor_c',
             'argument': 'rdi = the caller\'s own stack frame at '
                         '[rsp+0x8]; rsi is inherited unchanged '
                         'from ctor_c\'s caller'}],
        'own_writes': 'stack construction only: the query struct at '
                      '[rsp+0x130] is filled by the helper 0x5cf93f0 '
                      'call at 0x2ae16d1, the phase struct buffer at '
                      '[rsp+0x5aa8] by the indirect call through GOT '
                      'slot 0x64e1760 at 0x2ae16f2; two TLS-derived '
                      'bytes are stored at [rsp+0x80]/[rsp+0x81] on '
                      'the lvl4_a arm and at [rsp+0x60]/[rsp+0x61] '
                      'on the lvl3_c arm; no mapped descriptor '
                      'offset is touched'},
    'ctor_c': {
        'entry': '0x2cd8370',
        'record': 'no incoming record: it builds a 0x2c48-byte '
                  'stack frame and passes it as the phase struct',
        'callers': [
            {'site': 'none', 'in': 'registered',
             'argument': 'no direct or tail call site anywhere and '
                         'no data occurrence of the address; the '
                         'only reference is the lea at 0x2cef8f7 in '
                         'registrar_stub_c'}],
        'own_writes': 'the byte at [rsp+0x222] -- the phase '
                      'struct\'s dispatch byte at +0x21a relative '
                      'to the frame pointer at [rsp+0x8] -- is set '
                      'to zero; nothing else in the frame is '
                      'initialised by the body'},
    'registrar_stub_c': {
        'entry': '0x2cef8f0',
        'record': 'a 39-byte registration stub',
        'callers': [
            {'site': '0x1419318', 'in': 'the ELF entry point',
             'argument': 'the entry point (_start) loads the '
                         'stub\'s address into rdi as the main '
                         'function argument of its libc start call '
                         'through GOT slot 0x64df458 at 0x141931f; '
                         'the stub is the binary\'s main (edi = '
                         'argc, rsi = argv)'}],
        'own_writes': 'stores &ctor_c at [rsp] and calls the '
                      'registrar through GOT slot 0x64e6c30 with '
                      'rsi = the key cell 0x6440b48, rdx = its '
                      'sign-extended first argument and rcx = its '
                      'second argument'},
    'wrap_d1': {
        'entry': '0x2cd1070',
        'record': 'spawner: builds a 0x3080-byte task record on its '
                  'stack and copies it to a fresh allocation',
        'callers': [
            {'site': '0x2b3f328', 'in': 'pre_d1',
             'argument': 'rdi = the context object + 0xa8, rsi = '
                         'the payload buffer supplied by spawn_d, '
                         'rdx = the context object, rcx = pre_d1\'s '
                         'entry rdx'}],
        'own_writes': 'the task record header: 0xcc at [rsp+0x80], '
                      '0 at +0x88, &slot 0x6449600 at +0x90, 0 at '
                      '+0x98, entry rdx at +0xa0, entry rcx at '
                      '+0xa8, dword 0 at +0xb0; the payload copy '
                      '(0x2ff8 bytes from the entry rsi) lands at '
                      'record +0x38 through the second copy; the '
                      'whole 0x3080-byte record is then copied into '
                      'the allocation and handed to registrar_a '
                      '0x2cd0910 with the caller\'s entry rdi'},
    'wrap_d2': {
        'entry': '0x2cd1970',
        'record': 'same spawner shape as wrap_d1, for lvl3_d2',
        'callers': [
            {'site': '0x2b403cf', 'in': 'pre_d2',
             'argument': 'rdi = the context object + 0x170, rsi = '
                         'the payload buffer supplied by spawn_d, '
                         'rdx = the context object, rcx = pre_d2\'s '
                         'entry rdx'}],
        'own_writes': 'the task record header with &slot 0x6449790 '
                      'at +0x90; the record is handed to '
                      'registrar_b 0x2cd06c0'},
    'wrap_e1': {
        'entry': '0x2cd0e80',
        'record': 'same spawner shape as wrap_d1, for lvl3_e1',
        'callers': [
            {'site': '0x2b3f148', 'in': 'pre_e1',
             'argument': 'rdi = the context object + 0xa8, rsi = '
                         'the payload buffer supplied by spawn_e, '
                         'rdx = the context object, rcx = pre_e1\'s '
                         'entry rdx'}],
        'own_writes': 'the task record header with &slot 0x6449a60 '
                      'at +0x90; the record is handed to '
                      'registrar_a 0x2cd0910'},
    'wrap_e2': {
        'entry': '0x2cd2670',
        'record': 'same spawner shape as wrap_d1, for lvl3_e2',
        'callers': [
            {'site': '0x2b3fc5f', 'in': 'pre_e2',
             'argument': 'rdi = the context object + 0x170, rsi = '
                         'the payload buffer supplied by spawn_e, '
                         'rdx = the context object, rcx = pre_e2\'s '
                         'entry rdx'}],
        'own_writes': 'the task record header with &slot 0x64498d0 '
                      'at +0x90; the record is handed to '
                      'registrar_b 0x2cd06c0'},
    'pre_d1': {
        'entry': '0x2b3f300',
        'record': 'loads the refcounted context object r14 = [rdi] '
                  '(lock inc at 0x2b3f32e) and forwards',
        'callers': [
            {'site': '0x2ad6325', 'in': 'spawn_d',
             'argument': 'rdi = r12, a context pointer advanced by '
                         '0x10 from [rsp+0x370] of spawn_d; rsi = '
                         'spawn_d\'s stack payload buffer at '
                         '[rsp+0x9390]'}],
        'own_writes': 'none into any record: it calls wrap_d1 and '
                      'then performs the context object\'s deferred '
                      'release walk over [r14+0x210]/[r14+0x218]'},
    'pre_d2': {
        'entry': '0x2b403a0',
        'record': 'same shape as pre_d1 with the context object in '
                  'r12 and the sub-struct at +0x170',
        'callers': [
            {'site': '0x2ad633a', 'in': 'spawn_d',
             'argument': 'rdi = r12 (same pointer as the pre_d1 '
                         'site); rsi = spawn_d\'s stack payload '
                         'buffer at [rsp+0x9390]'}],
        'own_writes': 'none into any record'},
    'pre_e1': {
        'entry': '0x2b3f120',
        'record': 'same shape as pre_d1',
        'callers': [
            {'site': '0x2ad6f05', 'in': 'spawn_e',
             'argument': 'rdi = r12; rsi = spawn_e\'s stack payload '
                         'buffer at [rsp+0x9390]'}],
        'own_writes': 'none into any record'},
    'pre_e2': {
        'entry': '0x2b3fc30',
        'record': 'same shape as pre_d2',
        'callers': [
            {'site': '0x2ad6f1a', 'in': 'spawn_e',
             'argument': 'rdi = r12 (same pointer as the pre_e1 '
                         'site); rsi = spawn_e\'s stack payload '
                         'buffer at [rsp+0x9390]'}],
        'own_writes': 'none into any record'},
    'call4a_b': {
        'entry': '0x2b404b0',
        'record': 'a guard/swap helper: it exchanges the qword at '
                  'its entry rdi +0x10 for its entry rsi, bumps the '
                  'counter at +0x8 and then dispatches',
        'callers': [
            {'site': '0x2453673', 'in': 'pre_4ab',
             'argument': 'rdi = r15, rsi = r14, rdx = &[rsp+0x50], '
                         'rcx = &[rsp+0x68] of pre_4ab'}],
        'own_writes': 'none into the phase struct: lvl4_a\'s rdi is '
                      'loaded from [[entry rdx]] at 0x2b40573 and '
                      'its rsi is the entry rcx'},
    'pre_4ab': {
        'entry': '0x24535c0',
        'record': 'a swap helper: stores its entry rsi into [rdi], '
                  'saves the displaced values on its stack, clears '
                  'a flag byte at [r15+0x1d0] and calls call4a_b',
        'callers': [
            {'site': '0x2ae2306', 'in': 'lvl4_c',
             'argument': 'censused from the caller census; the body '
                         'is pinned by this packet'}],
        'own_writes': 'none into any pipeline record'},
    'spawn_d': {
        'entry': '0x2ad5980',
        'record': 'assembles the 0x3008-byte record on its own '
                  'stack (record base [rsp+0x3390]) and spawns the '
                  'd1/d2 tasks from it',
        'callers': [
            {'site': 'none', 'in': 'indirect',
             'argument': 'no direct or tail call site anywhere; '
                         'the address occurs once in the binary\'s '
                         'data, as the addend of the R_X86_64_'
                         'RELATIVE relocation at slot 0x64478f0, '
                         'which has no rip-relative reference (see '
                         'the slot census)'}],
        'own_writes': 'the record is assembled by helper calls and '
                      'copies (see the findings); the payload copy '
                      '[rsp+0x3390] -> [rsp+0x9390] (0x2ff8 bytes, '
                      'copy call at 0x2ad6307) is the last write '
                      'before the pre_d1/pre_d2 calls'},
    'spawn_e': {
        'entry': '0x2ad6560',
        'record': 'same assembly as spawn_d, spawning the e1/e2 '
                  'tasks; reached through slot 0x64478d0',
        'callers': [
            {'site': 'none', 'in': 'indirect',
             'argument': 'no direct or tail call site anywhere; '
                         'see the slot census'}],
        'own_writes': 'the record head at [rsp+0x3380] is made '
                      'self-referential ([rsp+0x3380] = &[rsp+0x40], '
                      '[rsp+0x3388] = &[rsp+0xf]) at 0x2ad6d49/'
                      '0x2ad6d56; the record proper at r13 = '
                      '[rsp+0x3390] is filled by the indirect call '
                      'through GOT slot 0x64e7360 at 0x2ad66b2 '
                      '(struct argument, length 0x258), the direct '
                      'call 0x2d4d540 at 0x2ad6cc9 against the '
                      'record copy at [rsp+0x6388], and a 0x148-byte '
                      'copy into the record head at 0x2ad6d76; the '
                      'payload copy [rsp+0x3390] -> [rsp+0x9390] '
                      '(copy call at 0x2ad6ee7) precedes the '
                      'pre_e1/pre_e2 calls'},
}

RECORD_PRODUCER = {
    'descriptor_fields': {
        'fields': 'bulk selector (block +0x178), bulk incoming '
                  'limit (+0x1b0), twin source pointer (+0x8), twin '
                  'sibling (+0x108), twin incoming limit (+0x110), '
                  'as mapped in the input-writers and block-fill '
                  'packets',
        'verdict': 'no direct store to -- and no read of -- any '
                   'mapped offset exists in any of the twenty-two '
                   'pinned bodies, at any embedding, through the '
                   'record registers, the pinned alias registers or '
                   'the stack bases (the access census pattern '
                   'tables are empty everywhere); the fields are '
                   'the incoming contents of the records at every '
                   'level of the enlarged window as well'},
    'head_sources': {
        'fields': 'the bulk a 1 struct\'s +0x50 (the dword its '
                  'twin-call arm forwards into +0x60) and +0x120 '
                  '(its shaping-copy source), and the bulk a 2 '
                  'struct\'s +0x1d8 (its shaping-copy source)',
        'verdict': 'the same census is empty for every mapped '
                   'offset of the three head sources in all '
                   'twenty-two bodies (they are folded into the '
                   'access census pattern sets); within the '
                   'enlarged window none of them is written either '
                   '-- each is an inherited record field whose '
                   'value the producer of the record left there'},
    'a_chain_producer': {
        'record_head': 'lvl3_a is the producer of the lvl2_a '
                       'record\'s head: it stores the pair before '
                       'the record and the record\'s first 0x22 '
                       'bytes from its own struct\'s fields and '
                       'from an indirect call through GOT slot '
                       '0x64e7430 immediately before calling lvl2_a '
                       '(pins in the lvl3_a owner record)',
        'shaping': 'lvl4_a shapes the sub-struct it passes to '
                   'lvl3_a out of its phase struct\'s +0xc8..+0xf0 '
                   'fields, with the tag byte at +0x248 set to 2 or '
                   '1 by arm; those source fields are themselves '
                   'the phase struct\'s incoming contents -- '
                   'lvl4_a\'s callers are lvl4_c (stack buffer) and '
                   'call4a_b (a double dereference of its entry '
                   'rdx)'},
    'c_chain_producer': {
        'stack_construction': 'lvl4_c produces every record it '
                              'hands down on its own stack frame; '
                              'the phase struct it passes to lvl4_a '
                              'is filled by an indirect call through '
                              'GOT slot 0x64e1760 out of the query '
                              'struct the helper 0x5cf93f0 filled',
        'top': 'ctor_c passes its own stack frame as lvl4_c\'s '
               'phase struct and initialises only its dispatch '
               'byte; ctor_c is reachable only through the '
               'registration stub 0x2cef8f0 (sole lea reference '
               '0x2cef8f7), which registers it through GOT slot '
               '0x64e6c30 under the key cell 0x6440b48; the stub '
               'is the binary\'s main function, loaded by the ELF '
               'entry point at 0x1419318'},
    'd_e_chain_producer': {
        'forwarders': 'lvl3_d1/d2/e1/e2 never write the embedded '
                      'lvl2 record (its only direct reference is '
                      'the lea forming the call argument); they are '
                      'invoked through .data.rel.ro cells whose '
                      'addresses the four wrapper spawners embed '
                      'at +0x10 of 0x3080-byte heap task records '
                      'tagged 0xcc',
        'payload_origin': 'the 0x2ff8-byte payload that lands at '
                          'task record +0x38 -- the lvl2 record\'s '
                          'embedding offset inside the lvl3 entry '
                          'structs -- is assembled by spawn_d and '
                          'spawn_e on their own stacks as the '
                          'record at [rsp+0x3390] of a 0x3008-byte '
                          'struct, through the helper calls and '
                          'copies recorded in their call paths, '
                          'then copied to [rsp+0x9390] and handed '
                          'down through pre_d/pre_e and the '
                          'wrappers; the byte-level writers of the '
                          'descriptor fields inside the payload are '
                          'those helper calls, which do not name '
                          'the offsets in any body in the window',
        'spawn_reachability': 'spawn_d and spawn_e are themselves '
                              'reached only through the handler '
                              'table slots 0x64478f0/0x64478d0 '
                              '(no rip-relative reference to '
                              'either slot), so their invocation '
                              'is a table walk'},
    'pr2300_boundary': 'none of the twenty-two pinned bodies is '
                       'among PR #2300\'s six extents (0x2cd7ac0, '
                       '0x2cd7d90, 0x5821250, 0x5821540, 0x58225c0, '
                       '0x5822700); the trace does not enter the '
                       'reader-state area and this packet does not '
                       'duplicate its reconstruction; the decoder '
                       'state buffer question is untouched',
}

BOUNDARIES = {
    'descriptor_and_head_first_writer':
        'inside the producers, one step below body granularity: '
        'on the a/c chains the deep fields are incoming contents of '
        'stack-built phase structs whose fills are an indirect call '
        'through GOT slot 0x64e1760 (lvl4_c) and a double '
        'dereference (call4a_b); on the d/e chains they are bytes '
        'of the payload records spawn_d/spawn_e assemble through '
        'helper calls (GOT slot 0x64e7360, the direct call '
        '0x2d4d540) and whole-record copies',
    'invocation_boundaries':
        'ctor_c is reached only through its registration stub, '
        'which is the binary\'s main function (entry-point lea '
        'at 0x1419318); '
        'lvl3_d1/d2/e1/e2 are reached only through .data.rel.ro '
        'cells embedded in heap task records handed to the two '
        'registrars, and the executor that later invokes the cells '
        'is not statically attributable; spawn_d/spawn_e are '
        'reached only through a handler-table walk',
    'next_questions':
        'which helper inside spawn_d/spawn_e writes which payload '
        'field (the 0x64e7360-slot call with its 0x258 argument and '
        'the direct call 0x2d4d540 are the candidates); which code '
        'walks the handler table at 0x64478a0..0x6447910; what the '
        'GOT-slot 0x64e1760 callee fills into lvl4_c\'s phase '
        'struct, and what produces the phase structs that reach '
        'lvl4_a through call4a_b\'s [[rdx]]',
}

LIMITS = (
    'Static trace only: no captured instruction was executed and no '
    'concrete input values were observed.  The direct-access census '
    'covers the record registers, the pinned alias registers and '
    'the stack bases of the twenty-two pinned bodies, at the '
    'embeddings the traced call sites establish; whole-record '
    'copies move bytes without naming fields -- the copies observed '
    'are enumerated in the call paths (the spawn bodies\' struct '
    'copies, the wrappers\' payload and record copies, the shaping '
    'copies of lvl4_a/lvl3_c) -- so for copied fields the census is '
    'a statement about direct accesses and the copies actually '
    'observed.  The step from the wrappers\' heap task records to '
    'the lvl3_d/e invocations is established by the relocation '
    'slots, the wrappers\' slot-address stores and the exact offset '
    'alignment (payload byte 0 lands at task record +0x38, the '
    'lvl2 record\'s embedding offset in the lvl3 entry structs); '
    'the executor that performs the invocation is not identified.  '
    'The phase-struct layout shared by lvl4_a, lvl3_c and ctor_c\'s '
    'frame (dispatch byte +0x21a, shaping at +0x220) is established '
    'by identical offsets and store shapes, not by type '
    'information.  Jump-table arm reachability is recorded where '
    'the earlier packets recorded it and is not re-decided here.  '
    'The two registrars and the helper bodies 0x5cf93f0, 0x2d4d540 '
    'are censused as call targets only; their bodies are not '
    'pinned by this packet.  Raw values are recorded mechanically; '
    'no field types are guessed.')

OWNERS = {
    'lvl3_a': ('0x2aeaef0', '0x2af0654',
        'd1b4e3ecb40fb4027b69240f48eacf2de2cf5f7e8c3ae5c0e6910a784fdcce29'),
    'lvl3_c': ('0x2cde430', '0x2ce0dd1',
        '99c49a3e20f63cf199f2a160ba9560e439acb2b49a66968623aa9607acfa417b'),
    'lvl3_d1': ('0x2b1d9a0', '0x2b1df5b',
        'bf6e24bee368a0399750ffb036edb98365585df4de593a47276d13bbcb9f163e'),
    'lvl3_d2': ('0x2b26920', '0x2b26eaf',
        'b3496c033685869a4f65bcd60c0cf10011210ef0ae08775661965ed97442354a'),
    'lvl3_e1': ('0x2b22010', '0x2b225cb',
        '5f4c2d4a72325da89d4bfa7cf7f269cfdfd8036c1b0027a537f8b0d76e260f2c'),
    'lvl3_e2': ('0x2b24840', '0x2b24dcf',
        'b4239dafaeb594af453a7ebb205d0dbe33c09e0af0b506a35f70e7c7b7ed2091'),
    'lvl4_a': ('0x2ae41e0', '0x2ae6d66',
        '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b'),
    'lvl4_c': ('0x2ae1690', '0x2ae27b2',
        '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9'),
    'ctor_c': ('0x2cd8370', '0x2cd83af',
        'ed23bc89640a43b1a5f373d5cb18929d79ce5b47923e58ba0565f592ba2b60d6'),
    'registrar_stub_c': ('0x2cef8f0', '0x2cef917',
        'c0621248d6ec3fd7ae1ee2df6b09bdd79541219362b313e5567717eb8f59a5c9'),
    'wrap_d1': ('0x2cd1070', '0x2cd1255',
        '819291051154010f8524e049c2c477bc03a9c0754880d28a682eaab733f6d9a7'),
    'wrap_d2': ('0x2cd1970', '0x2cd1b55',
        '938cc4c6d33f40867bd4eb4102d18b1b528c55d6ce093e43367954816dfc1ace'),
    'wrap_e1': ('0x2cd0e80', '0x2cd1065',
        '1d6fc7d0c78577eb5b08dc5ad990ba9d70b92b74ce75234d92493bb8280e383f'),
    'wrap_e2': ('0x2cd2670', '0x2cd2855',
        '07cc8225a55fa15a4cd70b51a31c863a4e9d9b2abd2aa60c78037dbd8aba0140'),
    'pre_d1': ('0x2b3f300', '0x2b3f3e3',
        'd42df649beeb7a76032c68ba8573f8e1d5a3f3d421d7b4c800e508bcaba091d3'),
    'pre_d2': ('0x2b403a0', '0x2b404ad',
        '7ca3d56a61898ec3b2484ea9e5c10f079b82f615f1005bedaa22f01a2e0e7274'),
    'pre_e1': ('0x2b3f120', '0x2b3f203',
        '43abf1337e1a134674b93eaaa6a6d29c5fd023f3622adf5cb9ada25e2d0dfd64'),
    'pre_e2': ('0x2b3fc30', '0x2b3fd3d',
        '83307137c6f55fe673c3c70349210175188bf99d4bad3c4862667061154f8401'),
    'call4a_b': ('0x2b404b0', '0x2b40666',
        '05ef87dc8cdf209d34d246b129dfe209764fe409efda8ee0ad73ceebb54fedac'),
    'pre_4ab': ('0x24535c0', '0x245390d',
        'a088c449b6f4f8d7f75517ed445b3fb65b0eaeaccf04b2763a12cb5ca5778edb'),
    'spawn_d': ('0x2ad5980', '0x2ad655e',
        '42d1acf80b7d6f20612d69b1df61149a8e669996649b6044f97a4859fac764a4'),
    'spawn_e': ('0x2ad6560', '0x2ad713e',
        'c8863fdfc321585b0cd46a5bdb0bcd1bd4c1a820ba53f9e56b6082037df03a79'),
}

FRAMES = {'lvl3_a': {'fde': {'va': '0x117c598', 'bytes_hex': '6400000098ef130050e996016457000004d72b0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0ee08d0183078c068d058e048f0386020307530e38410e30420e28420e20420e18420e10410e08410ee08d01000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl3_c': {'fde': {'va': '0x11986ac', 'bytes_hex': '50000000acb015007c5db401a12900000493f70dff410e10420e18420e20420e28420e30410e38470ee00983078c068d058e048f03860203f11a0e38410e30420e28420e20420e18420e10410e08410ee0090000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl3_d1': {'fde': {'va': '0x117f5b8', 'bytes_hex': '6c000000b81f1400e0e39901bb05000004ab360eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0eb8a0014f0eb8c0014c0ef0c00183078c068d058e048f03860203f7030e38410e30420e28420e20420e18420e10410e08410ef0c00100'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl3_d2': {'fde': {'va': '0x117fce0', 'bytes_hex': '6c000000e0261400386c9a018f05000004433b0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0eb8a0014f0eb8c0014c0ef0c00183078c068d058e048f03860203cb030e38410e30420e28420e20420e18420e10410e08410ef0c00100'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl3_e1': {'fde': {'va': '0x117f854', 'bytes_hex': '6c00000054221400b4279a01bb0500000477390eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0eb8a0014f0eb8c0014c0ef0c00183078c068d058e048f03860203f7030e38410e30420e28420e20420e18420e10410e08410ef0c00100'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl3_e2': {'fde': {'va': '0x117fac4', 'bytes_hex': '6c000000c4241400744d9a018f050000045f3a0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0eb8a0014f0eb8c0014c0ef0c00183078c068d058e048f03860203cb030e38410e30420e28420e20420e18420e10410e08410ef0c00100'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl4_a': {'fde': {'va': '0x117c49c', 'bytes_hex': '500000009cee13003c7d9601862b00000417260eff410e10420e18420e20420e28420e30410e38470ee01f83078c068d058e048f03860203791c0e38410e30420e28420e20420e18420e10410e08410ee01f0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'lvl4_c': {'fde': {'va': '0x117c394', 'bytes_hex': '5c00000094ed1300f45296012211000004ab230eff410e10420e18420e20420e28420e30410e384a0d0b0eb8e0025b0d070ee0e60283078c068d058e048f038602034e0d0e38410e30420e28420e20420e18420e10410e08410ee0e602000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'ctor_c': {'fde': {'va': '0xd8be0c', 'bytes_hex': '1c000000384f0e005cc5f4013f00000000470e88204f0e88404f0ed058590e08'}, 'cie': {'va': '0xca6ed8', 'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}}, 'registrar_stub_c': {'fde': {'va': '0xd8e218', 'bytes_hex': '1400000044730e00d016f6012700000000410e10650e0800'}, 'cie': {'va': '0xca6ed8', 'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}}, 'wrap_d1': {'fde': {'va': '0x11978e4', 'bytes_hex': '30000000e4a215008497b301e50100000433f90dff410e108602430d06026c83068c058e048f03031e010c0708410c0610000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'wrap_d2': {'fde': {'va': '0x11979d0', 'bytes_hex': '30000000d0a31500989fb301e50100000437f90dff410e108602430d06026c83068c058e048f03031e010c0708410c0610000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'wrap_e1': {'fde': {'va': '0x11978b0', 'bytes_hex': '30000000b0a21500c895b301e50100000437f90dff410e108602430d06026c83068c058e048f03031e010c0708410c0610000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'wrap_e2': {'fde': {'va': '0x1197b48', 'bytes_hex': '3000000048a5150020abb301e5010000043ff90dff410e108602430d06026c83068c058e048f03031e010c0708410c0610000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'pre_d1': {'fde': {'va': '0x1182f7c', 'bytes_hex': '3c0000007c5914007cc39b01e30000000467350eff420e10420e18420e20410e28440e5083058c048e038f0202950e28410e20420e18420e10420e08410e5000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'pre_d2': {'fde': {'va': '0x11833e4', 'bytes_hex': '44000000e45d1400b4cf9b010d010000044b330eff420e10420e18420e20420e28410e30440e4083068c058d048e038f0202800e30410e28420e20420e18420e10420e08410e4000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'pre_e1': {'fde': {'va': '0x1182efc', 'bytes_hex': '3c000000fc5814001cc29b01e30000000497350eff420e10420e18420e20410e28440e5083058c048e038f0202950e28410e20420e18420e10420e08410e5000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'pre_e2': {'fde': {'va': '0x11831ec', 'bytes_hex': '44000000ec5b14003cca9b010d0100000447340eff420e10420e18420e20420e28410e30440e4083068c058d048e038f0202800e30410e28420e20420e18420e10420e08410e4000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'call4a_b': {'fde': {'va': '0x118342c', 'bytes_hex': '4c0000002c5e14007cd09b01b60100000427330eff410e10420e18420e20420e28420e30410e38410e4083078c068d058e048f038602032b010e38410e30420e28420e20420e18420e10410e08410e40'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'pre_4ab': {'fde': {'va': '0x110e384', 'bytes_hex': '50000000840d0d00345234014d0300000477db10ff410e10420e18420e20420e28420e30410e38470ec00183078c068d058e048f03860203ce020e38410e30420e28420e20420e18420e10410e08410ec0010000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'spawn_d': {'fde': {'va': '0x117c13c', 'bytes_hex': '5c0000003ceb13003c989501de0b000004831a0eff410e10420e18420e20420e28420e30410e384a0d0b0eb880035b0d070ec0870383078c068d058e048f0386020393080e38410e30420e28420e20420e18420e10410e08410ec08703000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}, 'spawn_e': {'fde': {'va': '0x117c19c', 'bytes_hex': '5c0000009ceb1300bca39501de0b0000040b1b0eff410e10420e18420e20420e28420e30410e384a0d0b0eb880035b0d070ec0870383078c068d058e048f0386020393080e38410e30420e28420e20420e18420e10410e08410ec08703000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}}



PINS = {
    'call4a_b': [
        (11, '4989f7',
         'the save of the entry rsi in r15'),
        (195, '488b7d00',
         "the load rdi = [rbp], the double dereference that produces lvl4_a's phase struct"),
        (199, 'e8643cfaff',
         'the call to lvl4_a'),
    ],
    'ctor_c': [
        (37, 'c684242202000000',
         'the zeroing of the phase struct dispatch byte at [rsp+0x222]'),
        (45, '488d7c2408',
         'the lea forming rdi = the own stack frame [rsp+0x8]'),
        (50, 'e8e992e0ff',
         'the call to lvl4_c'),
    ],
    'lvl3_a': [
        (4291, 'f30f6f83100b0000',
         'the load of the struct pair at [rbx+0xb10] that becomes the record pair'),
        (4594, 'ff1548b39f03',
         'the indirect call through GOT slot 0x64e7430 whose return value becomes the record head word'),
        (4607, '48898318170000',
         'the store of that return value at [rbx+0x1718], before the record'),
        (4646, 'f30f7f8328170000',
         'the store of the pair into the record head at [rbx+0x1728]'),
        (4682, '4c8db328170000',
         'the lea forming r14 = the record base [rbx+0x1728]'),
        (4705, 'e80a450000',
         'the call to lvl2_a'),
    ],
    'lvl3_c': [
        (101, '4d8b2e',
         'the load r13 = [r14], the phase struct pointer'),
        (634, '410f118520020000',
         'the first shaping store into the embedded record at [r13+0x220]'),
        (672, '41c6854802000002',
         'the tag byte store [r13+0x248] = 2 at the first shaping site'),
        (708, 'e8077efdff',
         'the first call to lvl2_c'),
        (4443, 'e8706ffdff',
         'the second call to lvl2_c'),
    ],
    'lvl3_d1': [
        (104, '4889fb',
         'the entry struct held in rbx'),
        (130, 'f0480fb10b',
         'the atomic state-word lock cmpxchg at [rbx]'),
        (475, '488d7b38',
         "the lea forming the lvl2_d record pointer [rbx+0x38] -- the record's only direct reference in the body"),
        (489, 'e852f3faff',
         'the call to lvl2_d'),
    ],
    'lvl3_d2': [
        (104, '4889fb',
         'the entry struct held in rbx'),
        (475, '488d7b38',
         'the lea forming the lvl2_d record pointer [rbx+0x38]'),
        (489, 'e8d263faff',
         'the call to lvl2_d'),
    ],
    'lvl3_e1': [
        (104, '4889fb',
         'the entry struct held in rbx'),
        (475, '488d7b38',
         'the lea forming the lvl2_e record pointer [rbx+0x38]'),
        (489, 'e8b2ebfaff',
         'the call to lvl2_e'),
    ],
    'lvl3_e2': [
        (104, '4889fb',
         'the entry struct held in rbx'),
        (475, '488d7b38',
         'the lea forming the lvl2_e record pointer [rbx+0x38]'),
        (489, 'e882c3faff',
         'the call to lvl2_e'),
    ],
    'lvl4_a': [
        (17, '4889fb',
         'the phase struct held in rbx'),
        (1025, '0f118320020000',
         'the first shaping store into the sub-record at [rbx+0x220]'),
        (1060, 'c6834802000002',
         'the tag byte store [rbx+0x248] = 2 at the first shaping site'),
        (1095, 'e8c4680000',
         'the first call to lvl3_a'),
        (4780, 'e85f5a0000',
         'the second call to lvl3_a'),
    ],
    'lvl4_c': [
        (47, '48897c2418',
         'the save of the entry phase struct pointer at [rsp+0x18]'),
        (65, 'e81a7d2103',
         'the helper call that fills the query struct at [rsp+0x130]'),
        (98, 'ff156800a003',
         'the indirect call through GOT slot 0x64e1760 that fills the phase struct buffer'),
        (807, '4c8da424a85a0000',
         'the lea forming r12 = the stack phase struct buffer [rsp+0x5aa8]'),
        (951, 'e894270000',
         'the call to lvl4_a'),
        (2139, 'e840c51f00',
         'the call to lvl3_c'),
        (3190, 'e8b51297ff',
         'the call to pre_4ab'),
    ],
    'pre_4ab': [
        (29, '488937',
         'the store of the entry rsi into [rdi]'),
        (179, 'e838ce6e00',
         'the call to call4a_b'),
    ],
    'pre_d1': [
        (11, '4c8b37',
         'the load of the refcounted context object r14 = [rdi]'),
        (27, '498dbea8000000',
         'the lea forming rdi = context + 0xa8 for the wrapper call'),
        (40, 'e8431d1900',
         'the call to wrap_d1'),
    ],
    'pre_d2': [
        (13, '4c8b27',
         'the load of the refcounted context object r12 = [rdi]'),
        (33, '498dbc2470010000',
         'the lea forming rdi = context + 0x170 for the wrapper call'),
        (47, 'e89c151900',
         'the call to wrap_d2'),
    ],
    'pre_e1': [
        (11, '4c8b37',
         'the load of the refcounted context object r14 = [rdi]'),
        (27, '498dbea8000000',
         'the lea forming rdi = context + 0xa8 for the wrapper call'),
        (40, 'e8331d1900',
         'the call to wrap_e1'),
    ],
    'pre_e2': [
        (13, '4c8b27',
         'the load of the refcounted context object r12 = [rdi]'),
        (33, '498dbc2470010000',
         'the lea forming rdi = context + 0x170 for the wrapper call'),
        (47, 'e80c2a1900',
         'the call to wrap_e2'),
    ],
    'registrar_stub_c': [
        (7, '488d05728afeff',
         'the lea loading the address of ctor_c'),
        (14, '48890424',
         'the store of the ctor_c address into the stack descriptor at [rsp]'),
        (31, 'ff151b737f03',
         'the registrar call through GOT slot 0x64e6c30'),
    ],
    'spawn_d': [
        (2439, 'ff15fb91a003',
         'the payload copy call (copy slot) at 0x2ad6307'),
        (2469, 'e8d68f0600',
         'the call to pre_d1'),
        (2490, 'e861a00600',
         'the call to pre_d2'),
    ],
    'spawn_e': [
        (52, '4889fb',
         'the entry context held in rbx'),
        (338, 'ff15a80ca103',
         'the indirect call through GOT slot 0x64e7360 that fills the record'),
        (1897, 'e872682700',
         'the direct call 0x2d4d540 against the record copy'),
        (2046, '4c8dac2490330000',
         'the lea forming r13 = the record base [rsp+0x3390]'),
        (2070, 'ff158c87a003',
         'the 0x148-byte copy call into the record head'),
        (2439, 'ff151b86a003',
         'the payload copy call (copy slot) at 0x2ad6ee7'),
        (2469, 'e816820600',
         'the call to pre_e1'),
        (2490, 'e8118d0600',
         'the call to pre_e2'),
    ],
    'wrap_d1': [
        (182, '48c7842480000000cc000000',
         'the 0xcc tag store at the task record head [rsp+0x80]'),
        (206, '488d05bb847703',
         'the lea loading the address of the lvl3_d1 slot 0x6449600'),
        (375, 'e824f7ffff',
         'the call to registrar_a 0x2cd0910'),
    ],
    'wrap_d2': [
        (182, '48c7842480000000cc000000',
         'the 0xcc tag store at the task record head [rsp+0x80]'),
        (206, '488d054b7d7703',
         'the lea loading the address of the lvl3_d2 slot 0x6449790'),
        (375, 'e8d4ebffff',
         'the call to registrar_b 0x2cd06c0'),
    ],
    'wrap_e1': [
        (182, '48c7842480000000cc000000',
         'the 0xcc tag store at the task record head [rsp+0x80]'),
        (206, '488d050b8b7703',
         'the lea loading the address of the lvl3_e1 slot 0x6449a60'),
        (375, 'e814f9ffff',
         'the call to registrar_a 0x2cd0910'),
    ],
    'wrap_e2': [
        (182, '48c7842480000000cc000000',
         'the 0xcc tag store at the task record head [rsp+0x80]'),
        (206, '488d058b717703',
         'the lea loading the address of the lvl3_e2 slot 0x64498d0'),
        (375, 'e8d4deffff',
         'the call to registrar_b 0x2cd06c0'),
    ],
}

def read(va, data, size=None):
    for section in sections(data):
        if section['type'] == 8:
            continue
        if (section['address'] <= va and
                va < section['address'] + section['size']):
            offset = section['offset'] + va - section['address']
            end = (section['offset'] + section['size'] if size is None
                   else offset + size)
            return offset, bytes(data[offset:end])
    raise ValueError(hex(va))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def owners(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'unexpected node artifact')
    _, fdes, _ = fde_extents(data)
    extents = {(f['start'], f['end']): f for f in fdes}
    records = {}
    for role, (start, end, digest) in OWNERS.items():
        start, end = int(start, 16), int(end, 16)
        check((start, end) in extents, f'missing FDE {role}')
        offset, body = read(start, data, end - start)
        check(sha(body) == digest, f'body hash mismatch {role}')
        for kind in ('fde', 'cie'):
            fva = extents[(start, end)][kind]
            size = struct.unpack('<I', read(fva, data, 4)[1])[0] + 4
            want = FRAMES[role][kind]
            check(int(want['va'], 16) == fva and
                  read(fva, data, size)[1].hex() == want['bytes_hex'],
                  f'frame mismatch {role} {kind}')
        records[role] = {
            'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}
    return records


def check_pins(data):
    records = {}
    for role, rows in PINS.items():
        _, body = read(int(OWNERS[role][0], 16), data,
                       int(OWNERS[role][1], 16) - int(OWNERS[role][0], 16))
        for rel, expected, _ in rows:
            got = body[rel:rel + len(bytes.fromhex(expected))]
            check(got.hex() == expected,
                  f'byte pin mismatch {role} at +{rel:#x}')
        if role in EXPORTED:
            records[role] = {hex(int(OWNERS[role][0], 16) + rel): expected
                             for rel, expected, _ in rows}
    return records


def check_call(data, va, target):
    disp = struct.unpack('<i', read(va + 1, data, 4)[1])[0]
    check(read(va, data, 1)[1] == b'\xe8' and va + 5 + disp == target,
          f'call target mismatch at {va:#x}')


def check_call_targets(data):
    for role, mapping in CALL_TARGETS.items():
        for va, target in mapping.items():
            check_call(data, va, target)


def frame_lines(data):
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
    wanted = []
    for start, end, _ in OWNERS.values():
        needle = (f'pc={int(start, 16):016x}..{int(end, 16):016x}')
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def objdump_text(data, role):
    start, end = int(OWNERS[role][0], 16), int(OWNERS[role][1], 16)
    offset, body = read(start, data, end - start)
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(body)
        name = tmp.name
    try:
        return subprocess.run(
            ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64',
             '-M', 'intel', '--adjust-vma', str(start), name],
            check=True, capture_output=True, text=True).stdout
    finally:
        Path(name).unlink()


def access_census(data):
    records = {}
    for role in OWNERS:
        text = objdump_text(data, role)
        zero, exact = {}, {}
        for pattern in ZERO_PATTERNS[role]:
            count = text.count(pattern)
            check(count == 0,
                  f'census pattern {pattern} hit in {role}: {count}')
            zero[pattern] = 0
        for pattern, want in EXACT_COUNTS.get(role, {}).items():
            count = text.count(pattern)
            check(count == want,
                  f'census count {pattern} in {role}: {count} != {want}')
            exact[pattern] = count
        records[role] = {'zero_patterns': zero, 'exact_counts': exact}
    return records


def exports(data, role):
    start, end = OWNERS[role][0], OWNERS[role][1]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', start, '--stop-address', end, str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def caller_census(data):
    _, fdes, _ = fde_extents(data)
    ordered = sorted((f['start'], f['end']) for f in fdes)
    starts = [s for s, _ in ordered]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and ordered[i][0] <= va < ordered[i][1]:
            return f'{ordered[i][0]:#x}..{ordered[i][1]:#x}'
        return None

    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    check(text_sec is not None, 'missing.text section')
    base, off, size = (text_sec['address'], text_sec['offset'],
                       text_sec['size'])
    body = bytes(data[off:off + size])
    calls = {name: [] for name in CENSUS_SUBJECTS.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        target = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if target in CENSUS_SUBJECTS:
            calls[CENSUS_SUBJECTS[target]].append(
                {'site': hex(va), 'containing_fde': containing(va)})
        i = body.find(b'\xe8', i + 1)
    tails = {name: [] for name in CENSUS_SUBJECTS.values()}
    i = body.find(b'\xe9')
    while i != -1:
        va = base + i
        target = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if target in CENSUS_SUBJECTS:
            tails[CENSUS_SUBJECTS[target]].append(hex(va))
        i = body.find(b'\xe9', i + 1)
    # Rip-relative lea references, modrm-checked: REX + 8D + modrm
    # with mod 0 and r/m 5.
    lea_refs = {name: [] for name in CENSUS_SUBJECTS.values()}
    for rex in (b'\x48', b'\x4c', b'\x49', b'\x4d'):
        j = body.find(rex)
        while j != -1:
            if j + 7 <= size and body[j + 1] == 0x8D \
                    and (body[j + 2] & 0xC7) == 0x05:
                target = (base + j + 7 +
                          struct.unpack_from('<i', body, j + 3)[0])
                if target in CENSUS_SUBJECTS:
                    lea_refs[CENSUS_SUBJECTS[target]].append(
                        hex(base + j))
            j = body.find(rex, j + 1)
    lea_refs = {k: sorted(set(v)) for k, v in lea_refs.items()}
    for name, sites in calls.items():
        check(sites == EXPECTED_CALLERS[name],
              f'caller census mismatch for {name}: {sites}')
        check(tails[name] == [], f'tail call to {name}')
        check(lea_refs[name] == EXPECTED_LEA_REFS.get(name, []),
              f'lea references to {name}: {lea_refs[name]}')
    return {'direct_call_sites': calls, 'tail_call_sites': tails,
            'lea_references': lea_refs}


RIP_OPS = (0x8D, 0x8B, 0x89, 0x88, 0x39, 0x3B)


def rip_references(data, target):
    """Rip-relative references to an exact address anywhere in .text."""
    text_sec = next((s for s in sections(data) if s['name'] == '.text'), None)
    check(text_sec is not None, 'missing.text section')
    base = text_sec['address']
    body = bytes(data[text_sec['offset']:
                      text_sec['offset'] + text_sec['size']])
    hits = []
    for rex in (0x48, 0x4C, 0x49, 0x4D, 0xFF):
        i = body.find(bytes([rex]))
        while i != -1:
            if i + 7 <= len(body):
                if rex != 0xFF and body[i + 1] in RIP_OPS \
                        and (body[i + 2] & 0xC7) == 0x05:
                    disp = struct.unpack_from('<i', body, i + 3)[0]
                    if base + i + 7 + disp == target:
                        hits.append(base + i)
                elif rex == 0xFF and body[i + 1] in (0x15, 0x25):
                    disp = struct.unpack_from('<i', body, i + 2)[0]
                    if base + i + 6 + disp == target:
                        hits.append(base + i)
                elif rex == 0x48 and body[i + 1] == 0xC7 \
                        and body[i + 2] == 0x05:
                    disp = struct.unpack_from('<i', body, i + 3)[0]
                    if base + i + 11 + disp == target:
                        hits.append(base + i)
            i = body.find(bytes([rex]), i + 1)
    return sorted(hits)


def slot_census(data):
    """The six indirect-invocation boundaries, from the relocations."""
    rela = next((s for s in sections(data) if s['name'] == '.rela.dyn'), None)
    check(rela is not None, 'missing.rela.dyn section')
    check(rela['size'] % 24 == 0, 'truncated.rela.dyn section')
    entries = {}
    for i in range(rela['size'] // 24):
        off, typ, add = struct.unpack_from('<QQq', data,
                                           rela['offset'] + 24 * i)
        entries[off] = (typ, add)
    records = {}
    for role, (start, slot, want_refs) in SLOT_SUBJECTS.items():
        needle = struct.pack('<q', start)
        occurrences = []
        pos = data.find(needle)
        while pos != -1:
            occurrences.append(pos)
            pos = data.find(needle, pos + 1)
        check(len(occurrences) == 1,
              f'{role} address occurrence count changed')
        check(entries.get(slot) == (8, start),
              f'{role} relocation slot changed')
        neighbours = {}
        for other in sorted(entries):
            if other != slot and abs(other - slot) <= 0x30:
                neighbours[hex(other)] = hex(entries[other][1])
        refs = [hex(va) for va in rip_references(data, slot)]
        check(refs == want_refs,
              f'{role} slot rip references changed: {refs}')
        records[role] = {
            'function': hex(start),
            'file_wide_qword_occurrences': len(occurrences),
            'relocation': {'slot': hex(slot), 'type': 8,
                           'section': '.data.rel.ro',
                           'addend': hex(start)},
            'neighbour_addends': neighbours,
            'rip_relative_references_to_slot': refs,
        }
    return records


def analyze(data=None):
    data = TARGET.read_bytes() if data is None else data
    owner_records = owners(data)
    pin_records = check_pins(data)
    check_call_targets(data)
    census = caller_census(data)
    slots = slot_census(data)
    access = access_census(data)
    return {
        'artifact': {
            'path': 'artifacts/node/115/hl-node', 'size': TARGET_SIZE,
            'sha256': TARGET_SHA256},
        'packet': WORK_ITEM,
        'captured_code_executed': False,
        'copy_slot': hex(COPY_SLOT),
        'owners': owner_records,
        'pins': pin_records,
        'call_census': census,
        'slot_census': slots,
        'access_census': access,
        'call_paths': CALL_PATHS,
        'record_producer': RECORD_PRODUCER,
        'boundaries': BOUNDARIES,
        'limits': LIMITS,
    }


def generate():
    data = TARGET.read_bytes()
    OUT.mkdir(parents=True, exist_ok=True)
    payload = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(payload, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in sorted(EXPORTED):
        (OUT / f'{role}.objdump.txt').write_text(exports(data, role))
    print(f'wrote packet payloads to {OUT}')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    if args.generate:
        generate()
    else:
        print(json.dumps(analyze(), indent=1, sort_keys=True))
