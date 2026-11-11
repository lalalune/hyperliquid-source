#!/usr/bin/env python3
"""Catalogue the node #115 shared value observer instances (fourth stage).

Continues the observer packets for 0x1547530 (record slot 0x64e1010) and its
constructor 0x1548bb0 (slot 0x64e1020). This tool binds:

1. every FF15 call through the constructor slot (35 sites) and the observer
   name each passes: a static string (lea rdx + mov ecx), a template
   formatted through slot 0x64df6e8 (lea rsi of the template before the
   format call), or a pointer received from the caller; plus the esi byte;
2. every FF15 call through the record slot (68 sites): the source Location
   each passes in rdx (decoded through its R_X86_64_RELATIVE file pointer),
   and, when the observer pointer is the return value of a direct call
   (mov rdi, rax), the called function, checked to be one that contains a
   constructor site.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import collections
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-catalogue-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

RECORD_SLOT = 0x64e1010
RECORD = 0x1547530
CTOR_SLOT = 0x64e1020
CTOR = 0x1548bb0
FORMAT_SLOT = 0x64df6e8
FORMAT = 0x141e3a0

# (call site, FDE, esi instruction, esi value, kind, detail)
#   static:    (lea rdx va, string va, mov ecx va, length, text)
#   formatted: (lea rsi va, template va, format call va, decoded template)
#   passed:    (rdx load va, its bytes)
CTOR_SITES = (
    (0x15d86de, (0x15d86b0, 0x15d8722), 0x15d86d9, 1, 'static', (0x15d86bd, 0x469bb4, 0x15d86d1, 29, 'tokio_spawn_forever_scheduled')),
    (0x15ed4ca, (0x15ed290, 0x15ed954), 0x15ed4c5, 1, 'passed', (0x15ed4b0, '488b5308')),
    (0x16eebfc, (0x16eeaa0, 0x16eee4d), 0x16eebf7, 0, 'formatted', (0x16eebad, 0x438af2, 0x16eebc4, 'profiled_mutex/{}/acquire_all')),
    (0x16eeeaf, (0x16eee50, 0x16eef3f), 0x16eeeaa, 0, 'formatted', (0x16eee7c, 0x44c834, 0x16eee8b, 'profiled_mutex/{}/compute/{}')),
    (0x2502548, (0x2502450, 0x2502740), 0x2502543, 0, 'formatted', (0x2502503, 0x438af2, 0x2502517, 'profiled_mutex/{}/acquire_all')),
    (0x25028f6, (0x2502780, 0x2502b4c), 0x25028ef, 0, 'formatted', (0x25028a8, 0x438af2, 0x25028bc, 'profiled_mutex/{}/acquire_all')),
    (0x2502ce0, (0x2502b50, 0x2502f3a), 0x2502cdb, 0, 'formatted', (0x2502c94, 0x438af2, 0x2502ca8, 'profiled_mutex/{}/acquire_all')),
    (0x2503157, (0x2502f40, 0x25033fb), 0x2503152, 0, 'formatted', (0x2503109, 0x438af2, 0x2503120, 'profiled_mutex/{}/acquire_all')),
    (0x250345f, (0x2503400, 0x25034ef), 0x250345a, 0, 'formatted', (0x250342c, 0x44c834, 0x250343b, 'profiled_mutex/{}/compute/{}')),
    (0x26d4700, (0x26d4660, 0x26d47fb), 0x26d46f6, 0, 'formatted', (0x26d46d0, 0x43bb25, 0x26d46e1, 'bucket_guard/{}')),
    (0x2aec668, (0x2aeaef0, 0x2af0654), 0x2aec666, 0, 'static', (0x2aec64a, 0x605b39, 0x2aec661, 27, 'run_node_compute_resps_hash')),
    (0x2af5722, (0x2af45f0, 0x2af652a), 0x2af5720, 0, 'static', (0x2af5704, 0x455ee0, 0x2af571b, 16, 'execution_sender')),
    (0x2cb7c88, (0x2cb6500, 0x2cbbbdf), 0x2cb7c86, 0, 'static', (0x2cb7c6a, 0x60ef93, 0x2cb7c81, 27, 'run_node_compute_resps_hash')),
    (0x2cc243e, (0x2cc1120, 0x2cc971b), 0x2cc243c, 0, 'static', (0x2cc2420, 0x455ee0, 0x2cc2437, 16, 'execution_sender')),
    (0x2f1954d, (0x2f19520, 0x2f1962b), 0x2f1954b, 0, 'static', (0x2f19531, 0x644408, 0x2f19543, 27, 'handle_request_rate_limiter')),
    (0x3704110, (0x3704070, 0x370420b), 0x3704106, 0, 'formatted', (0x37040e0, 0x43bb25, 0x37040f1, 'bucket_guard/{}')),
    (0x47709d6, (0x4770930, 0x4770c21), 0x47709cb, 0, 'formatted', (0x47709a5, 0x43bb25, 0x47709b6, 'bucket_guard/{}')),
    (0x47712ee, (0x47710e0, 0x477165a), 0x47712e7, 0, 'formatted', (0x477129d, 0x438af2, 0x47712b4, 'profiled_mutex/{}/acquire_all')),
    (0x47716bf, (0x4771660, 0x477174f), 0x47716ba, 0, 'formatted', (0x477168c, 0x44c834, 0x477169b, 'profiled_mutex/{}/compute/{}')),
    (0x477229a, (0x47721f0, 0x4772528), 0x4772295, 0, 'formatted', (0x4772250, 0x434d59, 0x4772267, 'profiled_rw_lock/{}/acquire_{}_all')),
    (0x4772914, (0x4772530, 0x47729e3), 0x4772909, 0, 'formatted', (0x47728d4, 0x432e2d, 0x47728e8, 'profiled_rw_lock/{}/{}')),
    (0x47857a6, (0x47855c0, 0x4785a0a), 0x478579e, 1, 'formatted', (0x4785758, 0x44f828, 0x4785769, 'tcp_lz4/{}_{}')),
    (0x4da5e29, (0x4da5d60, 0x4da5f8a), 0x4da5e24, 0, 'formatted', (0x4da5ded, 0x440e47, 0x4da5e01, '{}/{}/{}')),
    (0x4da6549, (0x4da64e0, 0x4da66d9), 0x4da6544, 1, 'passed', (0x4da652c, '488b5008')),
    (0x4da8017, (0x4da7e20, 0x4da81a5), 0x4da800c, 0, 'formatted', (0x4da7fdd, 0x440e47, 0x4da7ff1, '{}/{}/{}')),
    (0x4dfe5ac, (0x4dfe550, 0x4dfe6c6), 0x4dfe5aa, 0, 'static', (0x4dfe591, 0x455ee0, 0x4dfe5a5, 16, 'execution_sender')),
    (0x51c9d22, (0x51c9cb0, 0x51c9fc5), 0x51c9d1b, 0, 'formatted', (0x51c9cea, 0x44cbea, 0x51c9cfb, '{}_block_duration')),
    (0x51c9d82, (0x51c9cb0, 0x51c9fc5), 0x51c9d71, 1, 'formatted', (0x51c9d38, 0x430c15, 0x51c9d4c, '{}_backlog_from_node')),
    (0x51c9dd3, (0x51c9cb0, 0x51c9fc5), 0x51c9dce, 0, 'formatted', (0x51c9d98, 0x440603, 0x51c9dac, '{}_begin_block_to_commit')),
    (0x51eb090, (0x51eaff0, 0x51eb18b), 0x51eb086, 0, 'formatted', (0x51eb060, 0x43bb25, 0x51eb071, 'bucket_guard/{}')),
    (0x594505b, (0x5945030, 0x594509f), 0x5945059, 0, 'static', (0x594503d, 0x459ad0, 0x5945051, 8, 'proposer')),
    (0x5a6c496, (0x5a6bfb0, 0x5a6c8ec), 0x5a6c494, 0, 'static', (0x5a6c478, 0x456200, 0x5a6c48f, 16, 'vote_abci_digest')),
    (0x5ab1e4c, (0x5ab1ce0, 0x5ab20c6), 0x5ab1e47, 0, 'formatted', (0x5ab1dfd, 0x438af2, 0x5ab1e14, 'profiled_mutex/{}/acquire_all')),
    (0x5ab2277, (0x5ab20d0, 0x5ab24f6), 0x5ab2272, 0, 'formatted', (0x5ab2228, 0x438af2, 0x5ab223f, 'profiled_mutex/{}/acquire_all')),
    (0x5ab255f, (0x5ab2500, 0x5ab25ef), 0x5ab255a, 0, 'formatted', (0x5ab252c, 0x44c834, 0x5ab253b, 'profiled_mutex/{}/compute/{}')),
)

# (record call site, getter call va, getter, rdi instruction va, its bytes,
#  lea rdx va, decoded Location (file, line, column))
RECORD_SITES = (
    (0x154953b, None, None, 0x154952e, '488d7b08', None, None),
    (0x15ed5e9, None, None, 0x15ed5dd, '4c89e7', 0x15ed5d6, ('base/src/lu.rs', 328, 38)),
    (0x15ed63a, None, None, 0x15ed625, '498d7c2408', 0x15ed62a, ('base/src/lu.rs', 336, 34)),
    (0x2af7792, None, None, 0x2af778f, '4889df', 0x2af7783, ('node/src/consensus/execution_state.rs', 155, 30)),
    (0x2bb38a6, None, None, 0x2bb38a3, '4c89ef', 0x2bb3897, ('l1/src/abci/abci_hash.rs', 28, 37)),
    (0x2bdf803, 0x2bdf7e9, 0x26d4660, 0x2bdf7fa, '4889c7', 0x2bdf7ee, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be0607, 0x2be05ed, 0x26d4660, 0x2be05fe, '4889c7', 0x2be05f2, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be1055, 0x2be103b, 0x26d4660, 0x2be104c, '4889c7', 0x2be1040, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be1817, 0x2be17fd, 0x26d4660, 0x2be180e, '4889c7', 0x2be1802, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be1da7, 0x2be1d8d, 0x26d4660, 0x2be1d9e, '4889c7', 0x2be1d92, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be6b85, 0x2be6b6b, 0x26d4660, 0x2be6b7c, '4889c7', 0x2be6b70, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be7997, 0x2be797d, 0x26d4660, 0x2be798e, '4889c7', 0x2be7982, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2be8315, 0x2be82fb, 0x26d4660, 0x2be830c, '4889c7', 0x2be8300, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2c7242c, 0x2c72412, 0x26d4660, 0x2c72423, '4889c7', 0x2c72417, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2c7290f, 0x2c728f5, 0x26d4660, 0x2c72906, '4889c7', 0x2c728fa, ('base/src/bucket_guard.rs', 118, 21)),
    (0x2c7e42b, 0x2c7e411, 0x26d4660, 0x2c7e422, '4889c7', 0x2c7e416, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422a558, 0x422a53e, 0x3704070, 0x422a54f, '4889c7', 0x422a543, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422ab41, 0x422ab27, 0x3704070, 0x422ab38, '4889c7', 0x422ab2c, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422c0de, 0x422c0c4, 0x3704070, 0x422c0d5, '4889c7', 0x422c0c9, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422c6d8, 0x422c6be, 0x3704070, 0x422c6cf, '4889c7', 0x422c6c3, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422cea1, 0x422ce87, 0x3704070, 0x422ce98, '4889c7', 0x422ce8c, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422d37b, 0x422d361, 0x3704070, 0x422d372, '4889c7', 0x422d366, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422da38, 0x422da1e, 0x3704070, 0x422da2f, '4889c7', 0x422da23, ('base/src/bucket_guard.rs', 118, 21)),
    (0x422df1b, 0x422df01, 0x3704070, 0x422df12, '4889c7', 0x422df06, ('base/src/bucket_guard.rs', 118, 21)),
    (0x478079b, 0x4780781, 0x4770930, 0x4780792, '4889c7', 0x4780786, ('base/src/bucket_guard.rs', 118, 21)),
    (0x47858c4, None, None, 0x4785884, '4c89f7', 0x47858b2, ('net_utils/src/tcp/lz4_stats.rs', 68, 18)),
    (0x4dff810, None, None, 0x4dff80d, '4c89e7', 0x4dff801, ('node/src/consensus/execution_state.rs', 155, 30)),
    (0x51c9b84, None, None, 0x51c9b81, '4c89ff', 0x51c9b75, ('node/src/abci_latency_sampler.rs', 70, 38)),
    (0x51c9c12, None, None, 0x51c9bf3, '488dbbc0040000', 0x51c9c06, ('node/src/abci_latency_sampler.rs', 73, 48)),
    (0x5483df9, 0x5483ddf, 0x51eaff0, 0x5483df0, '4889c7', 0x5483de4, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5484519, 0x54844ff, 0x51eaff0, 0x5484510, '4889c7', 0x5484504, ('base/src/bucket_guard.rs', 118, 21)),
    (0x548713c, 0x5487122, 0x51eaff0, 0x5487133, '4889c7', 0x5487127, ('base/src/bucket_guard.rs', 118, 21)),
    (0x548760f, 0x54875f5, 0x51eaff0, 0x5487606, '4889c7', 0x54875fa, ('base/src/bucket_guard.rs', 118, 21)),
    (0x548a27c, 0x548a262, 0x51eaff0, 0x548a273, '4889c7', 0x548a267, ('base/src/bucket_guard.rs', 118, 21)),
    (0x548a74f, 0x548a735, 0x51eaff0, 0x548a746, '4889c7', 0x548a73a, ('base/src/bucket_guard.rs', 118, 21)),
    (0x548d9a6, None, None, 0x548d9a3, '4c89ef', 0x548d997, ('l1/src/abci/abci_hash.rs', 28, 37)),
    (0x548dbb6, None, None, 0x548dbb3, '4c89ef', 0x548dba7, ('l1/src/abci/abci_hash.rs', 28, 37)),
    (0x54aa9bc, 0x54aa9a2, 0x51eaff0, 0x54aa9b3, '4889c7', 0x54aa9a7, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54ab41c, 0x54ab402, 0x51eaff0, 0x54ab413, '4889c7', 0x54ab407, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54abc6f, 0x54abc52, 0x51eaff0, 0x54abc63, '4889c7', 0x54abc57, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54ac1ff, 0x54ac1e2, 0x51eaff0, 0x54ac1f3, '4889c7', 0x54ac1e7, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b156c, 0x54b1552, 0x51eaff0, 0x54b1563, '4889c7', 0x54b1557, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b23df, 0x54b23c5, 0x51eaff0, 0x54b23d6, '4889c7', 0x54b23ca, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b37af, 0x54b3792, 0x51eaff0, 0x54b37a3, '4889c7', 0x54b3797, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b73dc, 0x54b73c2, 0x51eaff0, 0x54b73d3, '4889c7', 0x54b73c7, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b7e3c, 0x54b7e22, 0x51eaff0, 0x54b7e33, '4889c7', 0x54b7e27, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b860c, 0x54b85f2, 0x51eaff0, 0x54b8603, '4889c7', 0x54b85f7, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54b8b5c, 0x54b8b42, 0x51eaff0, 0x54b8b53, '4889c7', 0x54b8b47, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54bdba9, 0x54bdb8f, 0x51eaff0, 0x54bdba0, '4889c7', 0x54bdb94, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54bea1c, 0x54bea02, 0x51eaff0, 0x54bea13, '4889c7', 0x54bea07, ('base/src/bucket_guard.rs', 118, 21)),
    (0x54bfdbc, 0x54bfda2, 0x51eaff0, 0x54bfdb3, '4889c7', 0x54bfda7, ('base/src/bucket_guard.rs', 118, 21)),
    (0x56176db, 0x56176c1, 0x51eaff0, 0x56176d2, '4889c7', 0x56176c6, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5617afb, 0x5617ae1, 0x51eaff0, 0x5617af2, '4889c7', 0x5617ae6, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5617f1b, 0x5617f01, 0x51eaff0, 0x5617f12, '4889c7', 0x5617f06, ('base/src/bucket_guard.rs', 118, 21)),
    (0x561832b, 0x5618311, 0x51eaff0, 0x5618322, '4889c7', 0x5618316, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5647b98, 0x5647b7e, 0x51eaff0, 0x5647b8f, '4889c7', 0x5647b83, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5648212, 0x56481f8, 0x51eaff0, 0x5648209, '4889c7', 0x56481fd, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5648878, 0x564885e, 0x51eaff0, 0x564886f, '4889c7', 0x5648863, ('base/src/bucket_guard.rs', 118, 21)),
    (0x5648ea2, 0x5648e88, 0x51eaff0, 0x5648e99, '4889c7', 0x5648e8d, ('base/src/bucket_guard.rs', 118, 21)),
    (0x56494d8, 0x56494be, 0x51eaff0, 0x56494cf, '4889c7', 0x56494c3, ('base/src/bucket_guard.rs', 118, 21)),
    (0x564a290, 0x564a276, 0x51eaff0, 0x564a287, '4889c7', 0x564a27b, ('base/src/bucket_guard.rs', 118, 21)),
    (0x57e765a, None, None, 0x57e764e, '4889df', 0x57e7642, ('node/src/consensus/latency_samplers.rs', 38, 21)),
    (0x595dc04, None, None, 0x595dbf1, '488d3d3001ba00', 0x595dbf8, ('node/src/consensus/validator_set.rs', 263, 33)),
    (0x5a34daf, None, None, 0x5a34da0, '488dbc24b80200', 0x5a34da8, ('node/src/abci_latency_sampler.rs', 60, 41)),
    (0x5a6e8f8, None, None, 0x5a6e8e9, '488dbc24780500', 0x5a6e8f1, ('node/src/abci_latency_sampler.rs', 60, 41)),
    (0x5a6edbe, None, None, 0x5a6edaf, '488bbc24900300', 0x5a6edb7, ('node/src/node.rs', 434, 45)),
    (0x5b299ec, 0x5b299d2, 0x4da5d60, 0x5b299e3, '4889c7', 0x5b299d7, ('node/src/group_and_seq_sampler.rs', 169, 10)),
    (0x5b2a24c, 0x5b2a232, 0x4da7e20, 0x5b2a243, '4889c7', 0x5b2a237, ('node/src/group_and_seq_sampler.rs', 169, 10)),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def rip_target(data, va, prefix, length):
    _, raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def relative_addends(data):
    rows = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rows[va] = addend
    return rows


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def slot_calls(data, slot):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    out, start = [], 0
    while True:
        index = raw.find(b'\xff\x15', start)
        if index < 0 or index + 6 > len(raw):
            return out
        start = index + 1
        if base + index + 6 + struct.unpack_from('<i', raw, index + 2)[0] == slot:
            out.append(base + index)


def decode_template(data, va):
    """Literal pieces are a length byte (< 0x80) and bytes; 0xc0 is an argument slot
    followed by the next piece's length; 0x00 ends the template."""
    text, pos = '', va
    _, raw = read_va(data, va, 256)
    i = 0
    while True:
        b = raw[i]
        i += 1
        if b == 0:
            return text, raw[:i]
        if b == 0xc0:
            text += '{}'
            n = raw[i]
            i += 1
            if n == 0:
                return text, raw[:i]
        elif b < 0x80:
            n = b
        else:
            raise ValueError(f'template at {va:#x} has an unknown byte {b:#x}')
        text += raw[i:i + n].decode()
        i += n


def esi_ok(data, va, value):
    _, raw = read_va(data, va, 5)
    if value == 0:
        return raw[:2] == b'\x31\xf6'
    return raw[0] == 0xbe and struct.unpack_from('<I', raw, 1)[0] == value


def location(data, relocs, va):
    if va not in relocs:
        raise ValueError(f'Location at {va:#x} has no relative file pointer')
    _, raw = read_va(data, va + 8, 16)
    length, line, column = struct.unpack('<QII', raw)
    return read_va(data, relocs[va], length)[1].decode(), line, column


def bind(data, fdes):
    relocs = relative_addends(data)
    for slot, target in ((RECORD_SLOT, RECORD), (CTOR_SLOT, CTOR), (FORMAT_SLOT, FORMAT)):
        if relocs.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')

    ctor_census = slot_calls(data, CTOR_SLOT)
    if ctor_census != [row[0] for row in CTOR_SITES]:
        raise ValueError('constructor call census changed')
    ctor_frames = {}
    instances = []
    for site, fde, esi_va, esi, kind, detail in CTOR_SITES:
        if frame(fdes, site) != fde:
            raise ValueError(f'FDE of constructor site {site:#x} changed')
        if not (fde[0] <= esi_va < site and esi_ok(data, esi_va, esi)):
            raise ValueError(f'esi at {esi_va:#x} changed')
        row = {'call_va': hex(site), 'function': [hex(fde[0]), hex(fde[1])], 'kind': kind,
               'esi': esi, 'esi_va': hex(esi_va)}
        if kind == 'static':
            lea_va, string_va, len_va, length, text = detail
            if rip_target(data, lea_va, b'\x48\x8d\x15', 7) != string_va:
                raise ValueError(f'name lea at {lea_va:#x} changed')
            _, imm = read_va(data, len_va, 5)
            if imm[0] != 0xb9 or struct.unpack_from('<I', imm, 1)[0] != length:
                raise ValueError(f'name length at {len_va:#x} changed')
            if read_va(data, string_va, length)[1] != text.encode():
                raise ValueError(f'name string at {string_va:#x} changed')
            if not (fde[0] <= lea_va < site and fde[0] <= len_va < site):
                raise ValueError(f'name arguments of {site:#x} left the function')
            row.update(name=text, name_va=hex(string_va), name_lea_va=hex(lea_va), length_va=hex(len_va))
        elif kind == 'formatted':
            lea_va, template_va, format_va, text = detail
            if rip_target(data, lea_va, b'\x48\x8d\x35', 7) != template_va:
                raise ValueError(f'template lea at {lea_va:#x} changed')
            if rip_target(data, format_va, b'\xff\x15', 6) != FORMAT_SLOT:
                raise ValueError(f'format call at {format_va:#x} changed')
            if not fde[0] <= lea_va < format_va < site:
                raise ValueError(f'format order of {site:#x} changed')
            decoded, raw = decode_template(data, template_va)
            if decoded != text:
                raise ValueError(f'template at {template_va:#x} changed')
            row.update(template=text, template_va=hex(template_va), template_bytes=raw.hex(),
                       template_lea_va=hex(lea_va), format_call_va=hex(format_va))
        else:
            load_va, raw = detail
            if read_va(data, load_va, len(raw) // 2)[1] != bytes.fromhex(raw):
                raise ValueError(f'name pointer load at {load_va:#x} changed')
            row.update(name_pointer_load_va=hex(load_va), name_pointer_load_bytes=raw)
        ctor_frames[fde[0]] = row
        instances.append(row)

    record_census = slot_calls(data, RECORD_SLOT)
    if record_census != [row[0] for row in RECORD_SITES]:
        raise ValueError('record call census changed')
    records = []
    for site, getter_call, getter, rdi_va, rdi_bytes, lea_va, loc in RECORD_SITES:
        fde = frame(fdes, site)
        if read_va(data, rdi_va, len(rdi_bytes) // 2)[1] != bytes.fromhex(rdi_bytes):
            raise ValueError(f'rdi setup at {rdi_va:#x} changed')
        if not fde[0] <= rdi_va < site:
            raise ValueError(f'rdi setup of {site:#x} left the function')
        row = {'call_va': hex(site), 'function': [hex(fde[0]), hex(fde[1])],
               'rdi_va': hex(rdi_va), 'rdi_bytes': rdi_bytes}
        if getter is not None:
            if rdi_bytes != '4889c7':
                raise ValueError(f'getter site {site:#x} does not pass rax')
            _, raw = read_va(data, getter_call, 5)
            if raw[0] != 0xe8 or getter_call + 5 + struct.unpack_from('<i', raw, 1)[0] != getter:
                raise ValueError(f'getter call at {getter_call:#x} changed')
            if not getter_call < rdi_va:
                raise ValueError(f'getter call order of {site:#x} changed')
            if frame(fdes, getter)[0] != getter or getter not in ctor_frames:
                raise ValueError(f'getter {getter:#x} is not a constructor-site function')
            owner = ctor_frames[getter]
            row.update(getter_call_va=hex(getter_call), getter=hex(getter),
                       getter_constructor_call_va=owner['call_va'],
                       getter_name=owner.get('name') or owner.get('template'))
        if lea_va is not None:
            target = rip_target(data, lea_va, b'\x48\x8d\x15', 7)
            if not fde[0] <= lea_va < site:
                raise ValueError(f'Location lea of {site:#x} left the function')
            if location(data, relocs, target) != loc:
                raise ValueError(f'Location at {target:#x} changed')
            row.update(location_lea_va=hex(lea_va), location_va=hex(target),
                       location={'file': loc[0], 'line': loc[1], 'column': loc[2]})
        records.append(row)

    families = collections.Counter(r.get('name') or r.get('template') or 'name passed in'
                                   for r in instances)
    files = collections.Counter(r['location']['file'] if 'location' in r else None for r in records)
    getters = collections.Counter(r['getter'] for r in records if 'getter' in r)
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'constructor': {'slot': hex(CTOR_SLOT), 'target': hex(CTOR), 'calls': len(instances),
                        'by_kind': dict(sorted(collections.Counter(r['kind'] for r in instances).items())),
                        'names': dict(sorted(families.items())), 'sites': instances},
        'record': {'slot': hex(RECORD_SLOT), 'target': hex(RECORD), 'calls': len(records),
                   'with_getter': sum(getters.values()),
                   'getters': dict(sorted(getters.items())),
                   'location_files': {str(k): v for k, v in sorted(files.items(), key=lambda kv: str(kv[0]))},
                   'sites': records},
        'format_slot': {'va': hex(FORMAT_SLOT), 'target': hex(FORMAT)},
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"constructor_calls={result['constructor']['calls']} record_calls={result['record']['calls']} "
          f"with_getter={result['record']['with_getter']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
