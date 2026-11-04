#!/usr/bin/env python3
"""Trace who fills the RE-005 descriptor blocks, arena and decoder +0x28.

The input-writers packet (research/work-items/RE-005-node115-input-writers,
PR #2531) pinned the four top dispatchers' direct callers and showed the
derivation inputs are never written inside them: the bulk selector bytes,
the twin sibling slots and the incoming limits arrive as the incoming
contents of descriptor blocks inside the callers' context structs (a
side) and of a shared arena (b side), and the twin-a stage result's
+0x28 is forwarded from the nested decoder `0x2ce1730`.  This packet
takes the two questions that packet left open:

1. Who fills the caller context structs' descriptor blocks (block
   offsets: bulk selector +0x178, bulk incoming limit +0x1b0, twin
   source pointer +0x8, twin sibling +0x108, twin incoming limit
   +0x110) and the b-side arena fields the dispatchers read?

2. What writes the nested decoder `0x2ce1730` result's +0x28 field,
   which the twin-a stage `0x2e466b0` forwards at its sole +0x28 store
   (0x2e46968, loaded at 0x2e467a8)?

Answer shape.  On the a side the traced callers are themselves phase
functions embedded in larger pipeline records, and the trace continues
through two more levels of phase functions (twelve bodies pinned in
all).  Every level receives its record by pointer -- entry rsi, in one
case dereferenced once from entry rsi -- and passes an embedded
sub-record to the next level, initialising only the sub-record's head
fields at the call.  A direct-access census of the mapped target
offsets -- through the record register and the pinned alias registers,
at every embedding, in all twelve bodies -- finds no store to, and no
read of, the bulk selector, the bulk incoming limit, the twin sibling
or the twin incoming limit anywhere, and no access at all to the twin
source-pointer slot outside the twin callers themselves.  The single
exception sits inside caller bulk a 1: its record-shaping arm stores
the record's own [struct +0x60] qword into the twin sibling offset
(0x2ad8459) and copies 0xa0 bytes from [struct +0x120] over the twin
limit offset (copy call at 0x2ad84cb).  That arm is a different
jump-table arm from the twin call, no direct-edge path connects them,
and both sources are themselves record fields with no writer in the
window, so the exception moves inherited record bytes between fields
of the same record; it does not originate any input.  On the b side
the shared caller has no direct call site anywhere in the binary and
no tail call: its address occurs exactly once in the binary's data,
as the addend of the R_X86_64_RELATIVE relocation at slot 0x64b91c0
(.data.rel.ro), among neighbouring phase-function pointers, and no
instruction references that slot rip-relatively.  It is reached only
through a table walk, so the arena's first writer sits above an
indirect boundary as well as above the traced window.

For question 2 the chain bottoms out.  The decoder reads up to five
u64 values through the helper `0x2cd7ac0`; each read's value is
captured only when the read record's tag byte is 0x12 (read 1 -> r15,
read 2 -> r12, read 3 -> r13, read 4 -> rbp).  Its result's +0x28 is
stored exactly once, at 0x2ce191e in the success store block, from
rbp: the fourth read's value.  Every failure arm leaves +0x28
unwritten and sets the result tag 2 (or the error record's tag byte),
which is exactly the distinction the stage relies on when it forwards
+0x28 only for a tag other than 2.

Every fact is mechanical.  Twelve functions are pinned by exact FDE
extent, body SHA-256 and per-instruction byte pins; two small bodies
retain full objdump exports, the rest are retained as hash plus pins.
The censuses are re-derived from fresh objdump text and binary scans
on every run.  Captured code is never executed; byte values are
recorded exactly as decoded.
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
WORK_ITEM = 'RE-005-node115-block-fill-writers'
OUT = ROOT / 'research/work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'
COPY_SLOT = 0x64DF508
B_SIDE_SLOT = 0x64B91C0
B_SIDE_CALLER = 0x5A82670

EXPORTED = {'phase_after_twin_a_1', 'decoder_nested'}

CALL_TARGETS = {
    'caller_bulk_a_1': {0x2AD7FF7: 0x2B67E50, 0x2ADACC4: 0x2AE0100},
    'caller_bulk_a_2': {0x2CC52BF: 0x2B67E50, 0x2CC6356: 0x2CB1EB0,
                        0x2CC831B: 0x2CB1EB0},
    'outer_bulk_a_1': {0x2AF4D07: 0x2AD7140, 0x2AF4797: 0x2ADCE40},
    'outer_bulk_a_2': {0x2CBC4B4: 0x2CC1120},
    'phase_after_bulk_a_1': {0x2ADEE64: 0x2AE0100},
    'phase_after_twin_a_1': {0x2AE097F: 0x2AE0100},
    'lvl2_a': {0x2AF072F: 0x2AF45F0},
    'lvl2_b': {0x2B41C63: 0x2ADCE40, 0x2B42429: 0x2AF45F0},
    'lvl2_c': {0x2CB7771: 0x2CBBBE0},
    'lvl2_d': {0x2ACD8C1: 0x2AE0920, 0x2AD028B: 0x2AE0920},
    'lvl2_e': {0x2AD17DB: 0x2AE0920, 0x2AD42B3: 0x2AE0920},
    'decoder_nested': {0x2CE1749: 0x2CD7AC0, 0x2CE1768: 0x2CD7AC0,
                       0x2CE1788: 0x2CD7AC0, 0x2CE17A8: 0x2CD7AC0,
                       0x2CE1843: 0x2CD7AC0},
}

# Caller-set census subjects: function start -> record name.  The
# input-writers packet's five traced functions and the nested decoder
# are subjects even though two of them are not owners of this packet.
CENSUS_SUBJECTS = {
    0x2AD7140: 'caller_bulk_a_1', 0x2CC1120: 'caller_bulk_a_2',
    0x2AE0100: 'caller_twin_a_1', 0x2CB1EB0: 'caller_twin_a_2',
    0x5A82670: 'caller_b_side', 0x2CE1730: 'decoder_nested',
    0x2AF45F0: 'outer_bulk_a_1', 0x2CBBBE0: 'outer_bulk_a_2',
    0x2ADCE40: 'phase_after_bulk_a_1', 0x2AE0920: 'phase_after_twin_a_1',
    0x2AF0660: 'lvl2_a', 0x2B41B70: 'lvl2_b', 0x2CB6500: 'lvl2_c',
    0x2ACCEE0: 'lvl2_d', 0x2AD0DB0: 'lvl2_e',
}
EXPECTED_CALLERS = {
    'caller_bulk_a_1': [
        {'containing_fde': '0x2af45f0..0x2af652a', 'site': '0x2af4d07'}],
    'caller_bulk_a_2': [
        {'containing_fde': '0x2cbbbe0..0x2cbfc3f', 'site': '0x2cbc4b4'}],
    'caller_twin_a_1': [
        {'containing_fde': '0x2ad7140..0x2adce3a', 'site': '0x2adacc4'},
        {'containing_fde': '0x2adce40..0x2ae00f8', 'site': '0x2adee64'},
        {'containing_fde': '0x2ae0920..0x2ae135b', 'site': '0x2ae097f'}],
    'caller_twin_a_2': [
        {'containing_fde': '0x2cc1120..0x2cc971b', 'site': '0x2cc6356'},
        {'containing_fde': '0x2cc1120..0x2cc971b', 'site': '0x2cc831b'}],
    'caller_b_side': [],
    'decoder_nested': [
        {'containing_fde': '0x2e466b0..0x2e469a9', 'site': '0x2e46771'}],
    'outer_bulk_a_1': [
        {'containing_fde': '0x2af0660..0x2af45e1', 'site': '0x2af072f'},
        {'containing_fde': '0x2b41b70..0x2b43283', 'site': '0x2b42429'}],
    'outer_bulk_a_2': [
        {'containing_fde': '0x2cb6500..0x2cbbbdf', 'site': '0x2cb7771'}],
    'phase_after_bulk_a_1': [
        {'containing_fde': '0x2af45f0..0x2af652a', 'site': '0x2af4797'},
        {'containing_fde': '0x2b41b70..0x2b43283', 'site': '0x2b41c63'}],
    'phase_after_twin_a_1': [
        {'containing_fde': '0x2accee0..0x2ad0db0', 'site': '0x2acd8c1'},
        {'containing_fde': '0x2accee0..0x2ad0db0', 'site': '0x2ad028b'},
        {'containing_fde': '0x2ad0db0..0x2ad4db7', 'site': '0x2ad17db'},
        {'containing_fde': '0x2ad0db0..0x2ad4db7', 'site': '0x2ad42b3'}],
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
}

# Direct-access census over each owner body's objdump text.  Patterns
# are the target fields mapped through every embedding of the traced
# structs inside that body, via the record register and the pinned
# alias registers.  A zero entry means the substring never appears; an
# exact entry pins the hit count.
ZERO_PATTERNS = {
    'caller_bulk_a_1': ['[rbx+0xc0]'],
    'caller_bulk_a_2': ['[r15+0x270]', '[r15+0x370]', '[r15+0x378]',
                        '[rsi+0x270]', '[rsi+0x370]', '[rsi+0x378]',
                        '[rcx+0x178]', '[rcx+0x278]', '[rcx+0x280]'],
    'outer_bulk_a_1': ['[rbx+0x308]', '[rbx+0x340]', '[rbx+0x1b8]',
                       '[rbx+0x2b8]', '[rbx+0x2c0]', '[rbx+0x2b0]',
                       '[rbx+0x3b0]', '[rbx+0x3b8]', '[r14+0x210]',
                       '[r14+0x248]', '[r14+0x220]', '[r14+0x320]',
                       '[r14+0x328]'],
    'outer_bulk_a_2': ['[rbx+0x330]', '[rbx+0x368]', '[rbx+0x2d8]',
                       '[rbx+0x3d8]', '[rbx+0x3e0]', '[r15+0x2c8]',
                       '[r15+0x300]'],
    'phase_after_bulk_a_1': ['[rbx+0x220]', '[rbx+0x320]', '[rbx+0x328]',
                             '[rcx+0x220]', '[rcx+0x320]', '[rcx+0x328]',
                             '[r14+0x50]', '[r14+0x150]', '[r14+0x158]'],
    'phase_after_twin_a_1': ['[rbx+0x60]', '[rbx+0x160]', '[rbx+0x168]',
                             '[r14+0x50]', '[r14+0x150]', '[r14+0x158]'],
    'lvl2_a': ['[rbx+0x330]', '[rbx+0x368]', '[rbx+0x1e0]', '[rbx+0x2e0]',
               '[rbx+0x2e8]', '[r14+0x210]', '[r14+0x248]', '[r14+0x1b8]',
               '[r14+0x2b8]', '[r14+0x2c0]'],
    'lvl2_b': ['[rbx+0x358]', '[rbx+0x390]', '[rbx+0x208]', '[rbx+0x308]',
               '[rbx+0x310]', '[rbx+0x278]', '[rbx+0x378]', '[rbx+0x380]',
               '[r13+0x308]', '[r13+0x340]', '[r13+0x1b8]', '[r13+0x2b8]',
               '[r13+0x2c0]', '[r15+0x220]', '[r15+0x320]', '[r15+0x328]'],
    'lvl2_c': ['[rbx+0x1a58]', '[rbx+0x1a90]', '[rbx+0x1a00]',
               '[rbx+0x1b00]', '[rbx+0x1b08]', '[r14+0x330]',
               '[r14+0x368]', '[r14+0x2d8]', '[r14+0x3d8]', '[r14+0x3e0]'],
    'lvl2_d': ['[rbx+0x2278]', '[rbx+0x2368]', '[rbx+0x2370]',
               '[rbx+0x12e8]', '[rbx+0x13d8]', '[rbx+0x13e0]',
               '[r14+0x60]', '[r14+0x160]', '[r14+0x168]', '[r13+0x60]',
               '[r13+0x160]', '[r13+0x168]'],
    'lvl2_e': ['[rbx+0x2278]', '[rbx+0x2368]', '[rbx+0x2370]',
               '[rbx+0x12e8]', '[rbx+0x13d8]', '[rbx+0x13e0]',
               '[r14+0x60]', '[r14+0x160]', '[r14+0x168]', '[r13+0x60]',
               '[r13+0x160]', '[r13+0x168]'],
    'decoder_nested': [],
}
EXACT_COUNTS = {
    'caller_bulk_a_1': {'[rbx+0x1c0]': 2, '[rbx+0x1c8]': 2,
                        '[rbx+0x120]': 1},
    'caller_bulk_a_2': {'[r15+0x280]': 2, '[r15+0x1d8]': 3},
    'decoder_nested': {'[rbx+0x28]': 1},
}

# How each traced function is reached: every caller passes a pointer
# into its own record; only the embedded sub-record's head fields are
# initialised at the call, never the descriptor-block targets.
CALL_PATHS = {
    'caller_bulk_a_1': {
        'entry': '0x2ad7140',
        'callers': [
            {'site': '0x2af4d07', 'in': 'outer_bulk_a_1',
             'argument': 'rsi = record + 0xf8 (lea r14, [rbx+0xf8] at '
                         '0x2af4cf0); the caller stores the sub-record '
                         'head fields at record +0xf0, +0x130, +0x140 '
                         'and +0x150 immediately before the call'}]},
    'caller_bulk_a_2': {
        'entry': '0x2cc1120',
        'callers': [
            {'site': '0x2cbc4b4', 'in': 'outer_bulk_a_2',
             'argument': 'rsi = record + 0x68 (lea r15, [rbx+0x68] at '
                         '0x2cbc4a2)'}]},
    'caller_twin_a_1': {
        'entry': '0x2ae0100',
        'callers': [
            {'site': '0x2adacc4', 'in': 'caller_bulk_a_1',
             'argument': 'rsi = struct + 0x70 (lea r15, [rbx+0x70] at '
                         '0x2adaca3); the caller stores the head '
                         'qwords at struct +0x70 (immediate 1) and '
                         'struct +0x88 immediately before the call'},
            {'site': '0x2adee64', 'in': 'phase_after_bulk_a_1',
             'argument': 'rsi = element + 0x1d0 (lea r14, [rcx+0x1d0] '
                         'at 0x2adee4d); the phase walks an array of '
                         '0xf60-byte elements (add rbx, 0xf60 at '
                         '0x2adee26) and stores the element head '
                         'fields at +0x1d0 and +0x1e8 before the call'},
            {'site': '0x2ae097f', 'in': 'phase_after_twin_a_1',
             'argument': 'rsi = record + 0x10 (lea r14, [rbx+0x10] at '
                         '0x2ae096d); the caller stores the head '
                         'qwords at record +0x10 (immediate 1) and '
                         'record +0x28 (a self-pointer to record '
                         '+0x9) immediately before the call'}]},
    'caller_twin_a_2': {
        'entry': '0x2cb1eb0',
        'callers': [
            {'site': '0x2cc6356', 'in': 'caller_bulk_a_2',
             'argument': 'rsi = record + 0x128, the record held in '
                         'rcx (loaded from [rsp]); the caller stores '
                         'the head qwords at record +0x128 '
                         '(immediate 1) and record +0x140 before the '
                         'call'},
            {'site': '0x2cc831b', 'in': 'caller_bulk_a_2',
             'argument': 'rsi = struct + 0x220 (lea r15, [rsi+0x220] '
                         'at 0x2cc8304); the caller stores the head '
                         'qword at struct +0x220 (immediate 2) and '
                         'struct +0x238 before the call'}]},
    'outer_bulk_a_1': {
        'entry': '0x2af45f0',
        'record': 'entry rsi, held in rbx',
        'callers': [
            {'site': '0x2af072f', 'in': 'lvl2_a',
             'argument': 'rsi = record + 0x28 (lea r14, [rbx+0x28] at '
                         '0x2af071d)'},
            {'site': '0x2b42429', 'in': 'lvl2_b',
             'argument': 'rsi = record + 0x50 (lea r13, [rbx+0x50] at '
                         '0x2b4241a)'}]},
    'outer_bulk_a_2': {
        'entry': '0x2cbbbe0',
        'record': 'entry rsi, held in rbx',
        'callers': [
            {'site': '0x2cb7771', 'in': 'lvl2_c',
             'argument': 'rsi = record + 0x1728 (lea r14, '
                         '[rbx+0x1728] at 0x2cb775a)'}]},
    'phase_after_bulk_a_1': {
        'entry': '0x2adce40',
        'record': 'entry rsi, held in rbx; walks 0xf60-byte elements',
        'callers': [
            {'site': '0x2af4797', 'in': 'outer_bulk_a_1',
             'argument': 'rsi = record + 0x90 (lea r14, [rbx+0x90] at '
                         '0x2af4782)'},
            {'site': '0x2b41c63', 'in': 'lvl2_b',
             'argument': 'rsi = record + 0x58 (lea r15, [rbx+0x58] at '
                         '0x2b41c51)'}]},
    'phase_after_twin_a_1': {
        'entry': '0x2ae0920',
        'record': 'entry rsi, held in rbx',
        'callers': [
            {'site': '0x2acd8c1', 'in': 'lvl2_d',
             'argument': 'rsi = record + 0x2218 (lea r14, '
                         '[rbx+0x2218] at 0x2acd8ac)'},
            {'site': '0x2ad028b', 'in': 'lvl2_d',
             'argument': 'rsi = record + 0x1288 (lea r13, '
                         '[rbx+0x1288] at 0x2ad0273)'},
            {'site': '0x2ad17db', 'in': 'lvl2_e',
             'argument': 'rsi = record + 0x2218 (lea r14, '
                         '[rbx+0x2218] at 0x2ad17c4)'},
            {'site': '0x2ad42b3', 'in': 'lvl2_e',
             'argument': 'rsi = record + 0x1288 (lea r13, '
                         '[rbx+0x1288] at 0x2ad429b)'}]},
    'lvl2_a': {
        'entry': '0x2af0660', 'record': 'entry rsi, held in rbx',
        'callers': [
            {'site': '0x2aec151', 'in': '0x2aeaef0..0x2af0654',
             'argument': 'censused only; the containing body is not '
                         'pinned by this packet'}]},
    'lvl2_b': {
        'entry': '0x2b41b70',
        'record': 'loaded from [rsi] at 0x2b41b93 -- the record '
                  'arrives behind one extra pointer dereference',
        'callers': [
            {'site': '0x2af0a5f', 'in': 'lvl2_a',
             'argument': 'censused only'},
            {'site': '0x2cbc06b', 'in': 'outer_bulk_a_2',
             'argument': 'censused only'}]},
    'lvl2_c': {
        'entry': '0x2cb6500',
        'callers': [
            {'site': '0x2cde6f4', 'in': '0x2cde430..0x2ce0dd1',
             'argument': 'censused only; the containing body is not '
                         'pinned by this packet'},
            {'site': '0x2cdf58b', 'in': '0x2cde430..0x2ce0dd1',
             'argument': 'censused only'}]},
    'lvl2_d': {
        'entry': '0x2accee0',
        'callers': [
            {'site': '0x2b1db89', 'in': '0x2b1d9a0..0x2b1df5b',
             'argument': 'censused only; the containing body is not '
                         'pinned by this packet'},
            {'site': '0x2b26b09', 'in': '0x2b26920..0x2b26eaf',
             'argument': 'censused only'}]},
    'lvl2_e': {
        'entry': '0x2ad0db0',
        'callers': [
            {'site': '0x2b221f9', 'in': '0x2b22010..0x2b225cb',
             'argument': 'censused only; the containing body is not '
                         'pinned by this packet'},
            {'site': '0x2b24a29', 'in': '0x2b24840..0x2b24dcf',
             'argument': 'censused only'}]},
}

BLOCK_FILL = {
    'bulk_selector_and_incoming_limit': {
        'block_offsets': 'selector +0x178, incoming limit +0x1b0',
        'verdict': 'no direct store to -- and no read of -- the '
                   'mapped offsets exists in any of the twelve '
                   'pinned bodies, at any embedding (the input-'
                   'writers packet\'s two callers, their four direct '
                   'callers, and the five level-2 callers above '
                   'them), through the record register or the pinned '
                   'alias registers; both fields are the incoming '
                   'contents of the pipeline records at every traced '
                   'level'},
    'twin_sibling_and_incoming_limit': {
        'block_offsets': 'sibling +0x108, incoming limit +0x110',
        'verdict': 'the same census is empty at every embedding '
                   'except inside caller bulk a 1, whose record-'
                   'shaping arm holds the window\'s only direct '
                   'writes to a target offset (see '
                   'shaping_arm_exception); neither field is '
                   'accessed in caller bulk a 2, in any phase '
                   'function, or at level 2'},
    'twin_source_pointer': {
        'block_offset': '+0x8',
        'verdict': 'no direct access to the mapped slot exists in '
                   'any pinned body (in caller bulk a 1 the pattern '
                   '[rbx+0xc0] never appears); within the traced '
                   'window the slot\'s only writer remains the twin '
                   'caller itself, on its first entry arm, as '
                   'established by the input-writers packet -- on '
                   'the other arm the incoming block value is '
                   'whatever an earlier invocation or the record\'s '
                   'producer left there'},
    'shaping_arm_exception': {
        'where': 'caller bulk a 1 (0x2ad7140..0x2adce3a), record-'
                 'shaping arm spanning 0x2ad83a1..0x2ad851f',
        'sibling_store': '0x2ad8459 stores [rbx+0x60] into '
                         '[rbx+0x1c0], the twin sibling offset '
                         'through the struct +0x70 embedding; '
                         '[rbx+0x1c0] is read back at 0x2ad8521',
        'limit_copy': 'the copy call at 0x2ad84cb (through the copy '
                      'slot, destination lea at 0x2ad84ae) writes '
                      '0xa0 bytes from [rbx+0x120] over '
                      '[rbx+0x1c8], the twin incoming-limit offset; '
                      '[rbx+0x1c8] is read back at 0x2ad84ed for an '
                      'absolute-value computation',
        'sources': '[rbx+0x60] is itself stored in the twin-call '
                   'arm from [rbx+0x50] (dword store at 0x2adac6c); '
                   '[rbx+0x120] has no direct store anywhere in the '
                   'body (its only direct access is the lea at '
                   '0x2ad84b5).  Both sources are inherited record '
                   'fields, so the arm reshapes the record from its '
                   'own incoming contents',
        'reachability': 'the shaping arm and the twin call at '
                         '0x2adacc4 are different jump-table arms; '
                         'a direct-edge block graph of the body '
                         'reaches neither arm from the other, and '
                         'neither from the entry (the arms are '
                         'entered by indirect dispatch), so static '
                         'trace does not decide whether the shaping '
                         'arm\'s writes are the values the twin '
                         'call consumes for a given record',
        'counterpart': 'caller bulk a 2\'s analogous shaping copy '
                       '(0x2cc57cb, 0xa0 bytes from [r15+0x1d8] to '
                       '[r15+0x280]) covers no twin target offset '
                       'in its frame, and that body has no other '
                       'access to any twin target; its copy source '
                       'field is partly initialised inside the body '
                       '(a word store of 0x100 at 0x2cc3179 and a '
                       'byte zero store at 0x2cc9232, beside the '
                       'source lea at 0x2cc57b5), which only '
                       'underlines that the shaping copies move '
                       'record-local bytes'},
}

B_SIDE_BOUNDARY = {
    'function': 'the shared b-side caller 0x5a82670..0x5a89535 of '
                'the input-writers packet',
    'direct_call_sites': 'none anywhere in the binary (binary-wide '
                         'E8 census), and no E9 tail call',
    'data_occurrence': 'the address 0x5a82670 occurs exactly once in '
                       'the binary\'s data: as the addend of the '
                       'R_X86_64_RELATIVE relocation (type 8) whose '
                       'slot is 0x64b91c0 in .data.rel.ro',
    'neighbours': 'the surrounding slots hold the phase functions '
                  '0x5a5c580 (slot 0x64b9188) and 0x5a820d0 (slot '
                  '0x64b91a0), a further pointer 0x5a5c610 (slot '
                  '0x64b91a8), and the repeated default handler '
                  '0x43bce4 at the other slots of the table',
    'slot_references': 'a rip-relative reference census over .text '
                       'for the exact slot address 0x64b91c0 finds '
                       'no load, store, call or jump through it; '
                       'the function is invoked through a table walk '
                       'whose base and index are not attributable '
                       'to a single static caller from the slot',
    'verdict': 'the b-side arena (bulk b selector at arena +0xeb8, '
               'incoming limit +0xef0; twin b source pointer +0x2900 '
               '/ +0xc18, sibling +0x2a00 / +0xd18, incoming limit '
               '+0x2a08 / +0xd20) is filled above two boundaries: '
               'the arena reaches the shared caller as its entry '
               'rsi from a caller reachable only through the '
               'function-pointer table, and no body in the traced '
               'window writes any of the arena input offsets',
}

DECODER_RESULT_0X28 = {
    'field': 'nested decoder 0x2ce1730 result +0x28',
    'writer': 'the decoder itself (0x2ce1730..0x2ce198a), at its '
              'sole +0x28 store 0x2ce191e (mov [rbx+0x28], rbp) in '
              'the success store block; the result register rbx is '
              'the entry rdi and the state register r14 is the '
              'entry rsi',
    'value': 'rbp, the fourth decoded value: the decoder calls the '
             'u64 reader 0x2cd7ac0 at 0x2ce1749, 0x2ce1768, '
             '0x2ce1788, 0x2ce17a8 (and a fifth time at 0x2ce1843 '
             'on one arm); each read produces a record at [rsp+0x8] '
             'and its value qword at [rsp+0x10] is captured only '
             'when the record\'s tag byte equals 0x12 -- read 1 '
             'into r15 (0x2ce175b), read 2 into r12 (0x2ce177b), '
             'read 3 into r13 (0x2ce179b), read 4 into rbp '
             '(0x2ce17bb)',
    'success_block': 'at 0x2ce1901..0x2ce1922 the success arm '
                     'stores the result in one block: +0x0 and +0x8 '
                     'from the stack pair at [rsp+0x28] / '
                     '[rsp+0x30] that the mode-byte arms fill, '
                     '+0x10 = r15, +0x18 = r12, +0x20 = r13, '
                     '+0x28 = rbp; the success tag at +0x0 is 0 or '
                     '1, never 2.  Before the block, a mode byte is '
                     'consumed from the state buffer (an index '
                     'advance through state +0x20 / +0x8 when the '
                     'state dword at +0x0 is 1, then the byte '
                     'through the state +0x10 cursor with the +0x18 '
                     'remaining count); byte 1 runs the fifth read '
                     'and pairs its value with tag 1',
    'failure_arms': 'every other arm -- a read tag other than 0x12 '
                    '(arms at 0x2ce186e, 0x2ce1896, 0x2ce18bf), a '
                    'bad or exhausted mode byte (store block at '
                    '0x2ce1951) -- stores some subset of the '
                    'remaining fields and the tag 2 at 0x2ce1971 '
                    '(or the error tag byte), and none of them '
                    'stores +0x28: the caller\'s +0x28 slot keeps '
                    'its previous contents on those arms, which is '
                    'why the stage\'s forward at 0x2e46968 is '
                    'meaningful only on the tag != 2 arm',
    'next_level': 'the chain bottoms out at the encoded input: '
                  'what the fourth read returns is determined by '
                  'the bytes the state cursor walks, so the open '
                  'question below this packet is which producer '
                  'writes the state buffer (state +0x10 cursor, '
                  '+0x18 remaining, +0x20 index) -- the payload '
                  'producers of the serializer chain',
}

LIMITS = (
    'Static trace only: no captured instruction was executed and no '
    'concrete input values were observed.  The direct-access census '
    'covers the record register and the pinned alias registers of '
    'the twelve pinned bodies, at the embeddings the traced call '
    'sites establish; whole-record copies move bytes without naming '
    'fields -- copy destinations were reviewed in the level-0 and '
    'level-1 bodies and are stack buffers, register-held pointers, '
    'or record ranges outside the target offsets, apart from the '
    'two shaping copies recorded in the findings -- so for copied '
    'fields the census is a statement about direct accesses and the '
    'copies actually observed.  The caller bulk a 1 shaping arm is '
    'a jump-table arm: its relation to the twin call arm is not '
    'decidable from direct edges, and the packet records the writes '
    'and the arm structure without claiming which arm runs for a '
    'given record.  The b-side caller is reached only through its '
    'data slot; per-instruction provenance of the arena above that '
    'boundary is out of static reach for this packet.  The level-3 '
    'functions that call the level-2 bodies are censused for the '
    'caller sets but their bodies are not pinned.  The copy target '
    f'at slot {COPY_SLOT:#x} is identified by argument shape only.  '
    'The decoder helper 0x2cd7ac0 is treated as the u64 reader '
    'established by the chain; the provenance of the bytes it '
    'decodes belongs to the payload producers.  Raw values are '
    'recorded mechanically; no field types are guessed.')

OWNERS = {
    'caller_bulk_a_1': ('0x2ad7140', '0x2adce3a',
        'eab07e49a79bfe3de2f5e51d312ef9163f4a5f78f04240982b6a3e5b9c922e7e'),
    'caller_bulk_a_2': ('0x2cc1120', '0x2cc971b',
        '3efcb009eaf0ab2e2a477d73edbf7834894109e9fdcd943460d2bce59b9a0c57'),
    'outer_bulk_a_1': ('0x2af45f0', '0x2af652a',
        '9d48398c3974744138abbcaae7ecd71147af2f1a55d1322dfdf03594728da781'),
    'outer_bulk_a_2': ('0x2cbbbe0', '0x2cbfc3f',
        'cc89ac6ccf53deef7112e7f1d98580da53b137c02f40d69b126fef7392d61d40'),
    'phase_after_bulk_a_1': ('0x2adce40', '0x2ae00f8',
        '6804363ad4a709ada550b882a2a82c2dfff253f11864c9e2a75962fd95581072'),
    'phase_after_twin_a_1': ('0x2ae0920', '0x2ae135b',
        'c842a6d6b0c05a9b3978bcf786d556c62d71c4b055da335bf4b5617bbeb859be'),
    'lvl2_a': ('0x2af0660', '0x2af45e1',
        '8e90b7b9af8aba89a03905047677e56f0729ecda03fc1a48615c35d2636d6ab6'),
    'lvl2_b': ('0x2b41b70', '0x2b43283',
        '4deba244201c82d2810633699ca22d693931b3e243ae75b0fa1742923376eff7'),
    'lvl2_c': ('0x2cb6500', '0x2cbbbdf',
        '62835f8a447ea034c30a4fa0663abad74226444817882c469f883d7d92e4a8d0'),
    'lvl2_d': ('0x2accee0', '0x2ad0db0',
        '73de7d70235eee244bbfc1b605d48e680c3753eda7399dbe284ae2a2420a8847'),
    'lvl2_e': ('0x2ad0db0', '0x2ad4db7',
        'efa7a22d973e50959dd1c0eb347fb907e9e488aa73801c5b6ec965504c5bb45f'),
    'decoder_nested': ('0x2ce1730', '0x2ce198a',
        'c29673d74e228283d02a9b241d7a196fa0409cf9a637ee58f37a5a11f40fac98'),
}

FRAMES = {
    'caller_bulk_a_1': {'fde': {'va': '0x117c1fc', 'bytes_hex': '54000000fceb13003caf9501fa5c000004931b0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb03283078c068d058e048f038602039d4c0e38410e30420e28420e20420e18420e10410e08410eb0320000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'caller_bulk_a_2': {'fde': {'va': '0x1196e60', 'bytes_hex': '5800000060981500b8a2b201fb8500000457f30dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0ea04383078c068d058e048f03860203ee810e38410e30420e28420e20420e18420e10410e08410ea0430000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'outer_bulk_a_1': {'fde': {'va': '0x117c9dc', 'bytes_hex': '50000000dcf313000c7c97013a1f0000040f310eff410e10420e18420e20420e28420e30410e38470ea01b83078c068d058e048f0386020315080e38410e30420e28420e20420e18420e10410e08410ea01b0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'outer_bulk_a_2': {'fde': {'va': '0x1196944', 'bytes_hex': 'cc030000449315009452b2015f400000044ff30dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0ec06883078c068d058e048f038602037a012e00030c012e0002962e0002482e00562e00572e00026e2e00572e00642e00026f2e00482e0002742e00029c2e0002792e0002a42e0002482e00532e00572e00024f2e006d2e00682e00025d2e00772e00782e00642e005b2e00582e004f2e00039f012e00732e0002432e00532e005b2e00025d2e0002622e10580ec868420ed0684a0ec068752e0002792e00028a2e00602e00632e00542e00026f2e0002e12e0002592e000316012e0002632e00642e000358012e00027f2e0002872e00622e007f2e00502e00572e006e2e0002da2e0002ee2e0002452e0002712e005d2e00672e0002b32e0002722e0002482e00532e00572e007b2e00672e00024f2e0002482e00532e005e2e00682e0002f02e000309012e000395012e00762e00026f2e00552e00026f2e00552e0002500e38410e30420e28420e20420e18420e10410e08410ec068024b2e0003ba012e00732e00512e004f2e0002e42e0002f42e000332022e0003da012e0002742e00552e00026b2e0002692e0002e72e0002942e0002aa2e0002852e00025a2e0002742e0002b82e00642e005c2e00492e007f2e00031e012e0002f02e005c2e00552e00552e00552e00552e00552e00742e006d2e00552e00552e00652e006d2e007d2e007d2e0002442e006d2e00522e00522e004d2e00025f2e0002772e0002512e00612e00522e00522e00522e004f2e00552e00542e004f2e004f2e004f2e004f2e0002512e00492e004d2e00462e00662e00612e00562e00522e00522e0002562e00552e00672e00582e00632e00602e00024e2e0002512e006d2e0002462e00482e004d2e004d2e0002652e00692e00562e005f2e005c2e005f2e00582e004e2e005c2e006c2e004d2e00582e006c2e006f2e00562e004d2e004e2e00512e00582e005a2e005e2e00472e005c2e00472e00492e004f2e00522e00672e005c2e00602e004b2e00562e005d2e00642e00552e00602e00522e00512e00492e004d2e004a2e00542e00502e00492e004d2e00582e00562e004b2e004d2e004d2e004f2e004e2e004e2e004d2e004d2e00552e00632e00552e00532e00622e00532e005c2e00532e00552e00552e00712e005d2e005c2e00692e005d2e005c2e005c2e005c2e005c2e005c2e00532e00582e00582e005b2e004e2e005b2e00622e00562e005d2e00692e007d2e004b2e00462e00492e005b2e00482e00492e005f2e00642e00542e005c2e00562e00482e00462e00462e00462e000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'phase_after_bulk_a_1': {'fde': {'va': '0x117c254', 'bytes_hex': '5000000054ec1300e40b9601b832000004df200eff410e10420e18420e20420e28420e30410e38470ee00583078c068d058e048f03860203b92e0e38410e30420e28420e20420e18420e10410e08410ee0050000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'phase_after_twin_a_1': {'fde': {'va': '0x117c2fc', 'bytes_hex': '50000000fcec13001c4696013b0a0000041b230eff410e10420e18420e20420e28420e30410e38470ef01483078c068d058e048f0386020357080e38410e30420e28420e20420e18420e10410e08410ef0140000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl2_a': {'fde': {'va': '0x117c600', 'bytes_hex': 'd803000000f0130058409701813f00000487310eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0ea06883078c068d058e048f03860202832e0002662e005b2e00582e00532e0002cb2e0002962e0002482e00562e00572e00026e2e00572e00692e0002712e00482e0002742e00029c2e0002792e0002a42e0002482e00532e00572e00024f2e006d2e00682e0002622e00039c012e00732e0002432e00532e00622e00025d2e00025e2e10580ea868420eb0684a0ea068752e0002792e00028a2e005c2e00672e00542e00026f2e0002e12e0002592e000316012e0002632e00642e000358012e00027f2e0002872e00622e007f2e00502e00572e006e2e0002da2e0002ee2e0002452e0002712e005d2e00682e0002b42e0002722e0002482e00532e00572e007b2e00672e00024f2e0002482e00532e005e2e00682e0002f02e000309012e000395012e00762e00026f2e00552e00026f2e00552e00024b0e38410e30420e28420e20420e18420e10410e08410ea068024b2e0003ba012e00572e00642e0002402e00512e004f2e0002e42e0002f42e000332022e0003da012e0002742e00552e00026b2e0002692e0002e42e00572e00642e00029c2e0002aa2e0002852e00025a2e0002742e0002b82e00642e005c2e00492e007f2e00031e012e0002f02e006c2e006d2e00552e00552e00552e00552e00552e00552e007d2e007d2e006d2e00552e00552e006c2e006d2e00522e00522e00672e006a2e00672e006a2e004d2e0002722e0002512e00612e00522e004f2e00552e00542e004f2e004f2e004f2e004f2e00522e00542e00492e00542e0002462e00492e004d2e00462e0002932e006c2e00592e006b2e0002542e0002582e006b2e0002432e00482e004d2e004d2e0002722e005f2e004e2e00582e00502e00582e00562e004d2e004d2e00522e00492e005d2e005c2e00692e00562e005f2e005c2e005f2e00582e004e2e005f2e004a2e00462e00542e00562e00582e005a2e00542e004f2e005a2e00672e005c2e00602e004c2e004f2e00552e004b2e005d2e00642e00552e00562e00562e00522e00542e004d2e004a2e00522e00492e004d2e00582e00562e004b2e004d2e004d2e004f2e004e2e004e2e004d2e004d2e00552e00632e00552e00532e00622e00532e005c2e00532e00552e00552e00752e005d2e005c2e00692e005d2e005c2e005c2e005c2e005c2e005c2e00532e00582e00582e005b2e004e2e005b2e00622e00562e005d2e00692e007d2e004b2e00462e00492e005f2e00482e00492e004e2e00542e005d2e00642e00542e005c2e00562e00492e00462e00462e00462e0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl2_b': {'fde': {'va': '0x11834c8', 'bytes_hex': '50000000c85e1400a0e69b011317000004f7320eff410e10420e18420e20420e28420e30410e38470e901683078c068d058e048f03860203980e0e38410e30420e28420e20420e18420e10410e08410e90160000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl2_c': {'fde': {'va': '0x11968dc', 'bytes_hex': '64000000dc9215001cfcb101df56000004a3ed0dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0ee08d0183078c068d058e048f0386020391520e38410e30420e28420e20420e18420e10410e08410ee08d01000000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl2_d': {'fde': {'va': '0x117bf0c', 'bytes_hex': '6c0000000ce91300cc0f9501d03e0000045b110eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0eb8a0014f0eb8c0014f0ed0df0183078c068d058e048f038602031f350e38410e30420e28420e20420e18420e10410e08410ed0df0100'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'lvl2_e': {'fde': {'va': '0x117bf7c', 'bytes_hex': '6c0000007ce913002c4e95010740000004f3150eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0eb8a0014f0eb8c0014f0eb0df0183078c068d058e048f0386020377360e38410e30420e28420e20420e18420e10410e08410eb0df0100'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
    'decoder_nested': {'fde': {'va': '0xd8c468', 'bytes_hex': '4800000094550e00c052f5015a02000000410e10420e18420e20420e28420e30410e38440e7083078c068d058e048f0386020341020e38410e30420e28420e20420e18420e10410e08000000'}, 'cie': {'va': '0xca6ed8', 'bytes_hex': '1400000000000000017a5200017810011b0c070890010000'}},
}

PINS = {
    'caller_bulk_a_1': [
        (4889, '4c89a3c0010000', 'the shaping arm stores [rbx+0x60] into [rbx+0x1c0], the twin sibling offset'),
        (4974, '488dbbc8010000', 'lea rdi, [rbx+0x1c8] forms the shaping copy destination, the twin limit offset'),
        (5003, '41ffd7', 'the shaping copy call, through the copy slot'),
        (5037, '488b83c8010000', 'the twin limit offset is read back after the copy'),
        (5089, '4c8babc0010000', 'the twin sibling offset is read back after the store'),
        (15148, '894360', 'the twin-call arm stores [rbx+0x50] into [rbx+0x60]'),
        (15203, '4c8d7b70', 'lea r15, [rbx+0x70] forms the twin struct pointer'),
    ],
    'caller_bulk_a_2': [
        (18062, '498dbf80020000', 'lea rdi, [r15+0x280] forms the shaping copy destination'),
        (18083, 'baa0000000', 'the shaping copy length is 0xa0'),
        (18091, '41ffd6', 'the shaping copy call, through the copy slot'),
        (18129, '498b8780020000', 'the shaped field at [r15+0x280] is read back after the copy'),
        (20993, '48c7812801000001000000', 'the first twin site stores the head qword 1 at [rcx+0x128]'),
        (21018, '4c8db128010000', 'lea r14, [rcx+0x128] forms the first twin struct pointer'),
        (29126, '48c7862002000002000000', 'the second twin site stores the head qword 2 at [rsi+0x220]'),
        (29156, '4c8dbe20020000', 'lea r15, [rsi+0x220] forms the second twin struct pointer'),
    ],
    'outer_bulk_a_1': [
        (20, '4889f3', 'the record is the entry rsi, held in rbx'),
        (402, '4c8db390000000', 'lea r14, [rbx+0x90] forms the phase record pointer'),
        (1792, '4c8db3f8000000', 'lea r14, [rbx+0xf8] forms the bulk caller struct pointer'),
        (1815, 'e83424feff', 'the bulk a 1 caller call'),
    ],
    'outer_bulk_a_2': [
        (65, '4889f3', 'the record is the entry rsi, held in rbx'),
        (2242, '4c8d7b68', 'lea r15, [rbx+0x68] forms the bulk caller struct pointer'),
        (2260, 'e8674c0000', 'the bulk a 2 caller call'),
    ],
    'phase_after_bulk_a_1': [
        (25, '4889f3', 'the record is the entry rsi, held in rbx'),
        (8166, '4881c3600f0000', 'the phase advances its record by the 0xf60 element stride'),
        (8205, '4c8db1d0010000', 'lea r14, [rcx+0x1d0] forms the twin struct pointer inside the element'),
        (8228, 'e897120000', 'the twin a 1 caller call'),
    ],
    'phase_after_twin_a_1': [
        (20, '4889f3', 'the record is the entry rsi, held in rbx'),
        (58, '48c7431001000000', 'the caller stores the head qword 1 at record +0x10'),
        (66, '48894b28', 'the caller stores a self-pointer at record +0x28'),
        (77, '4c8d7310', 'lea r14, [rbx+0x10] forms the twin struct pointer'),
        (95, 'e87cf7ffff', 'the twin a 1 caller call'),
    ],
    'lvl2_a': [
        (65, '4889f3', 'the record is the entry rsi, held in rbx'),
        (189, '4c8d7328', 'lea r14, [rbx+0x28] forms the outer bulk record pointer'),
        (207, 'e8bc3e0000', 'the outer bulk a 1 call'),
    ],
    'lvl2_b': [
        (35, '488b1e', 'the record is loaded from [rsi]'),
        (225, '4c8d7b58', 'lea r15, [rbx+0x58] forms the phase record pointer'),
        (243, 'e8d8b1f9ff', 'the phase-after-bulk call'),
        (2218, '4c8d6b50', 'lea r13, [rbx+0x50] forms the outer bulk record pointer'),
        (2233, 'e8c221fbff', 'the outer bulk a 1 call'),
    ],
    'lvl2_c': [
        (4639, '48899320170000', 'a head qword is stored beside the embedded record at [rbx+0x1720]'),
        (4698, '4c8db328170000', 'lea r14, [rbx+0x1728] forms the outer bulk record pointer'),
        (4721, 'e86a440000', 'the outer bulk a 2 call'),
    ],
    'lvl2_d': [
        (2508, '4c8db318220000', 'lea r14, [rbx+0x2218] forms the first phase record pointer'),
        (2529, 'e85a300100', 'the first phase-after-twin call'),
        (13203, '4c8dab88120000', 'lea r13, [rbx+0x1288] forms the second phase record pointer'),
        (13227, 'e890060100', 'the second phase-after-twin call'),
    ],
    'lvl2_e': [
        (2580, '4c8db318220000', 'lea r14, [rbx+0x2218] forms the first phase record pointer'),
        (2603, 'e840f10000', 'the first phase-after-twin call'),
        (13547, '4c8dab88120000', 'lea r13, [rbx+0x1288] forms the second phase record pointer'),
        (13571, 'e868c60000', 'the second phase-after-twin call'),
    ],
    'decoder_nested': [
        (0, '55', 'the decoder prologue'),
        (14, '4989f6', 'the state pointer is the entry rsi, held in r14'),
        (17, '4889fb', 'the result pointer is the entry rdi, held in rbx'),
        (139, '488b6c2410', 'the fourth read value at [rsp+0x10] is captured into rbp'),
        (299, '48c744242801000000', 'the tag-1 arm writes the immediate 1 at [rsp+0x28]'),
        (475, '488903', 'the success block stores the result pair at +0x0'),
        (494, '48896b28', 'the sole +0x28 store: mov [rbx+0x28], rbp'),
        (577, '48c70302000000', 'the shared failure tail stores the tag 2 at +0x0'),
        (601, 'c3', 'the decoder returns'),
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

    text_sec = next(s for s in sections(data) if s['name'] == '.text')
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
    lea_refs = {name: [] for name in CENSUS_SUBJECTS.values()}
    for prefix in (b'\x48\x8d', b'\x4c\x8d'):
        j = body.find(prefix)
        while j != -1:
            if j + 7 <= size:
                target = (base + j + 7 +
                          struct.unpack_from('<i', body, j + 3)[0])
                if target in CENSUS_SUBJECTS:
                    lea_refs[CENSUS_SUBJECTS[target]].append(hex(base + j))
            j = body.find(prefix, j + 1)
    lea_refs = {k: sorted(set(v)) for k, v in lea_refs.items()}
    for name, sites in calls.items():
        check(sites == EXPECTED_CALLERS[name],
              f'caller census mismatch for {name}: {sites}')
        check(tails[name] == [], f'tail call to {name}')
        check(lea_refs[name] == [], f'lea reference to {name}')
    return {'direct_call_sites': calls, 'tail_call_sites': tails,
            'lea_references': lea_refs}


RIP_OPS = (0x8D, 0x8B, 0x89, 0x88, 0x39, 0x3B)


def rip_references(data, target):
    """Rip-relative references to an exact address anywhere in .text."""
    text_sec = next(s for s in sections(data) if s['name'] == '.text')
    base = text_sec['address']
    body = bytes(data[text_sec['offset']:
                      text_sec['offset'] + text_sec['size']])
    hits = []
    for i in range(len(body) - 7):
        byte = body[i]
        if byte in (0x48, 0x4C, 0x49, 0x4D) and body[i + 1] in RIP_OPS \
                and (body[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', body, i + 3)[0]
            if base + i + 7 + disp == target:
                hits.append(base + i)
        elif byte == 0xFF and body[i + 1] in (0x15, 0x25):
            disp = struct.unpack_from('<i', body, i + 2)[0]
            if base + i + 6 + disp == target:
                hits.append(base + i)
        elif byte == 0x48 and body[i + 1] == 0xC7 and body[i + 2] == 0x05:
            disp = struct.unpack_from('<i', body, i + 3)[0]
            if base + i + 11 + disp == target:
                hits.append(base + i)
    return hits


def slot_census(data):
    """The b-side caller's invocation boundary, from the relocations."""
    needle = struct.pack('<q', B_SIDE_CALLER)
    occurrences = []
    pos = data.find(needle)
    while pos != -1:
        occurrences.append(pos)
        pos = data.find(needle, pos + 1)
    check(len(occurrences) == 1,
          'b-side caller address occurrence count changed')
    rela = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    entries = {}
    for i in range(rela['size'] // 24):
        off, typ, add = struct.unpack_from('<QQq', data,
                                           rela['offset'] + 24 * i)
        entries[off] = (typ, add)
    check(entries.get(B_SIDE_SLOT) == (8, B_SIDE_CALLER),
          'b-side caller relocation slot changed')
    neighbours = {}
    for slot in (0x64B9188, 0x64B91A0, 0x64B91A8):
        neighbours[hex(slot)] = hex(entries[slot][1])
    check(rip_references(data, B_SIDE_SLOT) == [],
          'b-side slot gained a rip-relative reference')
    return {
        'function': hex(B_SIDE_CALLER),
        'file_wide_qword_occurrences': len(occurrences),
        'relocation': {'slot': hex(B_SIDE_SLOT), 'type': 8,
                       'section': '.data.rel.ro',
                       'addend': hex(B_SIDE_CALLER)},
        'neighbour_addends': neighbours,
        'rip_relative_references_to_slot': [],
    }


def analyze(data=None):
    data = TARGET.read_bytes() if data is None else data
    owner_records = owners(data)
    pin_records = check_pins(data)
    check_call_targets(data)
    census = caller_census(data)
    slot = slot_census(data)
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
        'slot_census': slot,
        'access_census': access,
        'call_paths': CALL_PATHS,
        'block_fill': BLOCK_FILL,
        'b_side_boundary': B_SIDE_BOUNDARY,
        'decoder_result_0x28': DECODER_RESULT_0X28,
        'boundaries': {
            'descriptor_block_and_arena_first_writer':
                'above the traced window: the records arrive by '
                'pointer at every traced level, and the b-side '
                'arena arrives through a function-pointer table '
                'walk; the first writer is the producer of the '
                'pipeline records and of the arena',
            'decoder_chain_bottom':
                'resolved one level down by this packet: the '
                'nested decoder writes its own result +0x28; below '
                'that, the producer of the decoder state buffer'},
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
