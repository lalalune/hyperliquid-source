#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce static evidence for node 94 two-insert result reconciliation.

The collector authenticates the ELF and interprets selected fixed byte patterns.
It never starts external programs or executes the captured executable.
"""
import argparse
import bisect
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

FUNCTIONS = (
    ('slot-original-size-writer', 0x4302290, 0x430237e, 'bc535784a8c754d995186ba767f08ab62671f553e2875bbe12e75c5d6f271c11'),
    ('pending-row-clear', 0x432bef0, 0x432bf67, '3c9e06e4543eac8237b0553b3dacb8d78180ad41f6bb1d289fa788b7d6388897'),
    ('two-result-merge', 0x4471d80, 0x447254b, 'ef642bf7bdd2da70f6bf9b3e7f0cd2cf2560e78e3b4789c0a69bc40fd2946cec'),
    ('result-drop', 0x447b7f0, 0x447b918, '41f5ec574a03e1060008542160dfe043c5c74a88ea0d6109a5c72de2e966cf0b'),
    ('fill-vector-concatenate', 0x4888840, 0x4888b82, 'a7e14386f48a5e9f2ce90da3ff9f801a83716a2a8d1fab95d2a3b66f15a7a5d7'),
)

WITNESSES = (
    ('host-first-insert', 0x4d13b21, 0x4d13b81, '942b7267dae1ec5a069c08fc0b7d1e1edad506f681f6bc6febd4d160f67d9bd7'),
    ('host-new-insert-merge', 0x4d145e6, 0x4d14659, 'ecfc755b7c7f13cdb5367b531d6e95ff86ab381d393ebc87df41853e85fd5f2f'),
    ('host-tag-select', 0x4d14659, 0x4d1472e, '7354a344b7a693bdf6dda51b648aead91f0265b74b3350de86814f6c75abffd1'),
    ('host-write-guard', 0x4d1472e, 0x4d1479d, '699229631e7c7311c860465ea3c4dc4018f5305b69f45ffc184740a016522dd9'),
    ('host-rewrite-call', 0x4d1479d, 0x4d1482d, '817a6bd11163bb2e8c8339ef0cc8bd364d7024f325c00dc1ac2bb8069b0f6535'),
    ('merge-outcome-arms', 0x4471d8a, 0x4471ec0, '216867480ddb03ea21f05c2f59913f8498f97ee346ee38365b3676ecda5961c0'),
    ('merge-map-iterator', 0x4471fb0, 0x4472005, '47f027ae231835db71b7f65e29e74ed6f042081c29873078bc36461072704d08'),
    ('merge-map-search', 0x4472022, 0x4472117, 'a2b5157a3ddf74fb2aa93ea18c74d7e681020c1718fb028e5ce74e5eb851a562'),
    ('merge-map-insert', 0x4472120, 0x44721f3, '71d0494defc40dc5cc34f63ee523bb71ed98fb98aa519e043e32b8359da669d1'),
    ('merge-map-append', 0x44721f3, 0x447228b, 'dcd1a7240f830b7cdee7f30a452d3224fc538142dd13a54c0e5d0a19dc97334b'),
    ('merge-output', 0x4472310, 0x4472435, '0e4c00eb1006849f9c9ec1e80bdbb8a59ace9e1823ec45fb16c73d4d9f426dfe'),
    ('merge-cleanup', 0x4472435, 0x4472470, 'ef1cc09eb8b4b6cc636fb6e49ea11e8197bce70064430aabaeacd97c897c0029'),
    ('fill-allocation', 0x488884e, 0x488890e, 'fa10bc86eb76f4c89d9f47b138f593f1c43eae29eaab14785f55160544e419b9'),
    ('fill-first-copy', 0x488898b, 0x4888a1c, '30188691a485d8e104936391da924829c0f3e7af9052c27a6ffcd160ef6d7e3d'),
    ('fill-second-copy', 0x4888a1c, 0x4888aa3, '4748746ff53ac8d619237b43e44750e93b1b005d0bd2632e07975e9e113c5b04'),
    ('setter-complete', 0x4302290, 0x430237e, 'bc535784a8c754d995186ba767f08ab62671f553e2875bbe12e75c5d6f271c11'),
    ('row-clear-complete', 0x432bef0, 0x432bf67, '3c9e06e4543eac8237b0553b3dacb8d78180ad41f6bb1d289fa788b7d6388897'),
    ('drop-entry', 0x447b7f0, 0x447b82c, 'e96bb8e7c26fcadc75b8197474df099bc802b63c6cefcef357a4ac242e9ab902'),
    ('twin-host-first-insert', 0x4d163b1, 0x4d16411, '5437a5f0314d84290cd61a96f1fe1512d550bd040a0ef3231426beb64fd5a15c'),
    ('twin-host-new-insert-merge', 0x4d16e76, 0x4d16ee9, '2112e9954e97f65a334ae401199146f65250cc3201bb03a5fcc9c5e062e8ed01'),
    ('twin-host-tag-select', 0x4d16ee9, 0x4d16fbe, 'c4b0acb6cb07331794544b50f2b0d8de749a9ea9764fd17dce036c41bd9dbb3f'),
    ('twin-host-write-guard', 0x4d16fbe, 0x4d1702d, '86e803fffb3679237bdf7c3f5fee004811e03e27d5514466ef70fdfaa929f96d'),
    ('twin-host-rewrite-call', 0x4d1702d, 0x4d170bd, '0aff388e226a46dae52ba8558db5884dce76ed356a847618346e944ed3117994'),
    ('host-quantity-source', 0x4d12f6e, 0x4d13003, '7b359ec0720abe3b2d4b0ceb3a0a868e15fdf91cba0f44da1180933a5aff1dcd'),
    ('twin-host-quantity-source', 0x4d157fe, 0x4d15893, '7b359ec0720abe3b2d4b0ceb3a0a868e15fdf91cba0f44da1180933a5aff1dcd'),
    ('host-quantity-reload', 0x4d13efd, 0x4d13f10, 'aaa232c0b86619b432db7efe99607741eb2a04a97b425688c314a53459efdcd9'),
    ('twin-host-quantity-reload', 0x4d1678d, 0x4d167a0, 'aaa232c0b86619b432db7efe99607741eb2a04a97b425688c314a53459efdcd9'),
    ('host-remainder-gate', 0x4d143f8, 0x4d14459, 'f12bc55351b9ad82e5787d11313a07449488dc10ab1d480299e173566bc8b588'),
    ('twin-host-remainder-gate', 0x4d16c88, 0x4d16ce9, '541265be3e123136a7006f90e295539bd1ce83799f0468db0e78c9319ba0f814'),
    ('host-zero-remainder', 0x4d144aa, 0x4d144b8, 'a7665c4ddb4a07cd1490703581123b0bd85019b8dee3e36a45afddb46ff52d1e'),
    ('twin-host-zero-remainder', 0x4d16d3a, 0x4d16d48, 'a7665c4ddb4a07cd1490703581123b0bd85019b8dee3e36a45afddb46ff52d1e'),
    ('host-second-input-quantity', 0x4d14554, 0x4d14568, '44cfd9cff0da936bf995ccf89b557e047859ddc217fab29d0b51d6410ce203fa'),
    ('twin-host-second-input-quantity', 0x4d16de4, 0x4d16df8, '44cfd9cff0da936bf995ccf89b557e047859ddc217fab29d0b51d6410ce203fa'),
    ('host-incoming-to-gate', 0x4d13f00, 0x4d1417d, 'bc88b9b3becd5e0662cb044dbd471652c853f65e6f549a9ad3f7725c5521b1d4'),
    ('host-gate-to-remainder', 0x4d14384, 0x4d14459, '8967f65aa2aec5a566fb3abbd01871c7952f069b34c91b18af2e2ecc5cdd3635'),
    ('host-prior-result-assembly', 0x4d13e25, 0x4d13edb, '9fd0588ef07eab81348a483db0e9ce97395210e779276a94852d14a84076b2da'),
)

def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_identity(data):
    if digest(data) != EXPECTED_SHA256:
        raise ValueError('node 94 input SHA-256 mismatch')


def check_window(actual, expected_digest, label):
    if digest(actual) != expected_digest:
        raise ValueError('witness mismatch: ' + label)


def file_offset(data, secs, va, size, *, executable=False):
    """Resolve a whole interval through one file-backed ELF section.

    Zero length intervals, NOBITS, out-of-file ranges and ambiguous section
    mappings fail closed.  A section flag by itself is not an FDE boundary.
    """
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid VA interval')
    end = va + size
    if end > 1 << 64:
        raise ValueError('VA interval overflows')
    candidates = []
    for s in secs:
        if s['type'] == 8 or (executable and not s['flags'] & 4):
            continue
        if s['address'] <= va and end <= s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            if off < 0 or off + size > len(data):
                raise ValueError('section interval outside file')
            candidates.append(off)
    if len(candidates) != 1:
        raise ValueError('VA interval is unmapped or ambiguous')
    return candidates[0]


def va_bytes(data, secs, va, size, *, executable=False):
    off = file_offset(data, secs, va, size, executable=executable)
    return bytes(data[off:off + size])


def decode_branch(raw, va):
    """Decode only short/near Jcc and short/near JMP at a preselected site."""
    if len(raw) < 2:
        raise ValueError('truncated branch')
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        if len(raw) < 6:
            raise ValueError('truncated near branch')
        n, disp, op = 6, struct.unpack_from('<i', raw, 2)[0], raw[:2].hex()
    elif raw[0] == 0xe9:
        if len(raw) < 5:
            raise ValueError('truncated near jump')
        n, disp, op = 5, struct.unpack_from('<i', raw, 1)[0], raw[:1].hex()
    elif 0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb:
        n, disp, op = 2, struct.unpack_from('<b', raw, 1)[0], raw[:1].hex()
    else:
        raise ValueError('unsupported branch encoding')
    return {'opcode': op, 'raw': raw[:n].hex(), 'target': va + n + disp, 'fallthrough': va + n}


def checked_branch(raw, va, expected_opcode, expected_target):
    row = decode_branch(raw, va)
    if row['opcode'] != expected_opcode or row['target'] != expected_target:
        raise ValueError('branch opcode or destination mismatch')
    return row


def decode_direct_call(raw, va):
    if len(raw) < 5 or raw[0] != 0xe8:
        raise ValueError('expected direct E8 call')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_indirect_call(raw, va):
    if len(raw) < 6 or raw[:2] != b'\xff\x15':
        raise ValueError('expected RIP-relative indirect call')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0]


def decode_indirect_jump(raw, va):
    if len(raw) < 6 or raw[:2] != b'\xff\x25':
        raise ValueError('expected RIP-relative indirect jump')
    return va + 6 + struct.unpack_from('<i', raw, 2)[0]


def checked_call(raw, va, expected_target, *, indirect=False):
    target = decode_indirect_call(raw, va) if indirect else decode_direct_call(raw, va)
    if target != expected_target:
        raise ValueError('call destination mismatch')
    return target


BRANCHES = (
    ('new-result-class-not-two', 0x4d146f6, '75', 0x4d1472e),
    ('first-result-error-skips-row-clear', 0x4d14715, '0f84', 0x4d1482d),
    ('fresh-result-low-bit-clear', 0x4d14767, '74', 0x4d14780),
    ('first-result-error-skips-row-rewrite', 0x4d14797, '0f84', 0x4d1482d),
    ('skip-second-insert-on-gate', 0x4d143fb, '0f84', 0x4d14491),
    ('remainder-summary-absent', 0x4d14437, '74', 0x4d1444b),
    ('remainder-zero-skips-insert', 0x4d14453, '74', 0x4d144aa),
    ('gate-false-clear-route', 0x4d144a5, 'e9', 0x4d14704),
    ('zero-remainder-class-route', 0x4d144b3, 'e9', 0x4d146d5),
    ('first-merge-input-not-error', 0x4471e2e, '71', 0x4471e51),
    ('second-merge-input-not-error', 0x4471e33, '75', 0x4471e8b),
    ('both-merge-inputs-not-error', 0x4471e54, '75', 0x4471ec0),
    ('second-user-map-iterator-empty', 0x4471fca, '0f84', 0x447228b),
    ('second-user-value-sentinel', 0x4471fe1, '0f84', 0x447228b),
    ('first-user-map-root-empty', 0x4472034, '0f84', 0x4472120),
    ('compare-next-user-key', 0x44720ad, '74', 0x4472070),
    ('user-key-equal', 0x44720b4, '74', 0x4472100),
    ('descend-first-user-map', 0x44720c1, '73', 0x44720e4),
    ('descend-or-insert-user', 0x44720de, '0f82', 0x447224f),
    ('user-key-vector-needs-growth', 0x4472202, '77', 0x4472267),
    ('old-user-vector-empty', 0x4472235, '0f84', 0x4471fb0),
    ('remaining-user-map-empty', 0x44722ba, '74', 0x4472310),
    ('remaining-user-map-loop', 0x447230e, '75', 0x44722d0),
    ('first-error-cleanup-test', 0x447243d, '75', 0x447245e),
    ('first-error-payload-negative', 0x447244a, '78', 0x447245e),
    ('first-error-payload-zero', 0x447244c, '74', 0x447245e),
    ('second-error-cleanup-test', 0x4472466, '75', 0x4472470),
    ('first-fill-range-absent', 0x488885b, '74', 0x48888b3),
    ('second-fill-range-absent', 0x488887c, '74', 0x4888893),
    ('total-row-count-within-limit', 0x48888a7, '76', 0x48888ea),
    ('both-fill-ranges-absent', 0x48888b6, '74', 0x488890e),
    ('second-count-over-limit', 0x48888e8, '77', 0x48888a9),
    ('zero-allocation-size', 0x48888f2, '74', 0x4888928),
    ('allocation-return-null', 0x4888903, '0f84', 0x4888b31),
    ('first-copy-range-absent', 0x4888946, '0f84', 0x4888aa3),
    ('capacity-below-count', 0x4888985, '0f87', 0x4888acd),
    ('first-copy-empty', 0x4888996, '0f84', 0x4888a1c),
    ('first-range-end', 0x48889bd, '74', 0x48889f4),
    ('first-copy-next', 0x48889f2, '75', 0x48889d0),
    ('first-allocation-empty', 0x48889fc, '74', 0x4888a12),
    ('second-copy-range-absent', 0x4888a1f, '0f84', 0x4888b04),
    ('second-range-end', 0x4888a37, '74', 0x4888a74),
    ('second-copy-next', 0x4888a72, '75', 0x4888a50),
    ('second-allocation-empty', 0x4888a81, '0f84', 0x4888b0e),
    ('both-copy-ranges-absent', 0x4888aa6, '74', 0x4888b01),
    ('second-count-within-capacity', 0x4888ac7, '0f86', 0x488898b),
    ('copy-first-after-growth', 0x4888af6, '0f85', 0x488899c),
    ('book-order-index-empty', 0x4302295, '0f84', 0x430237d),
    ('no-fingerprint-match', 0x43022f7, '74', 0x4302330),
    ('order-key-equal', 0x4302314, '74', 0x430234b),
    ('more-fingerprint-candidates', 0x4302321, '75', 0x43022f9),
    ('control-byte-empty', 0x430233c, '75', 0x4302378),
    ('next-probe-group', 0x4302349, 'eb', 0x43022df),
    ('slot-index-at-or-past-length', 0x430235b, '73', 0x4302378),
    ('slot-vacant', 0x430236c, '74', 0x4302378),
    ('pending-rows-exhausted', 0x432bf14, '74', 0x432bf2a),
    ('drop-next-pending-row', 0x432bf28, 'eb', 0x432bf10),
    ('result-tag-not-error', 0x447b802, '71', 0x447b82c),
    ('error-payload-negative', 0x447b80b, '0f88', 0x447b90e),
    ('error-payload-zero', 0x447b811, '0f84', 0x447b90e),
)

def parse_image(data):
    """Authenticate first, then use the repository ELF and CIE/FDE readers."""
    verify_identity(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_record = {row['fde']: row for row in fdes}
    if len(by_record) != len(fdes):
        raise ValueError('duplicate FDE records')
    fdes_by_start = {}
    for row in index:
        fde = by_record.get(row['fde'])
        if fde is None or fde['start'] != row['start']:
            raise ValueError('unwind index and FDE disagree')
        if fde['start'] in fdes_by_start:
            raise ValueError('duplicate FDE start')
        fdes_by_start[fde['start']] = fde
    starts = sorted(fdes_by_start)
    return {'data': data, 'secs': secs, 'fdes': fdes_by_start, 'starts': starts}


def containing_fde(image, va, size):
    starts = image['starts']
    index = bisect.bisect_right(starts, va) - 1
    if index < 0:
        raise ValueError('address has no indexed FDE')
    fde = image['fdes'][starts[index]]
    if va < fde['start'] or va + size > fde['end']:
        raise ValueError('interval is outside containing FDE')
    file_offset(image['data'], image['secs'], va, size, executable=True)
    return fde


def read_instruction(image, va, n):
    containing_fde(image, va, n)
    return va_bytes(image['data'], image['secs'], va, n, executable=True)


def collect_functions(image):
    rows = []
    for role, start, end, expected in FUNCTIONS:
        fde = image['fdes'].get(start)
        if fde is None or fde['end'] != end:
            raise ValueError('selected FDE range mismatch')
        raw = read_instruction(image, start, end - start)
        check_window(raw, expected, role)
        rows.append({
            'role': role, 'start': start, 'end': end, 'fde': fde['fde'], 'cie': fde['cie'],
            'file_offset': file_offset(image['data'], image['secs'], start, len(raw), executable=True),
            'size': len(raw), 'sha256': digest(raw), 'raw': raw.hex(),
        })
    return rows


def collect_witnesses(image):
    rows = []
    for label, start, end, expected in WITNESSES:
        raw = read_instruction(image, start, end - start)
        check_window(raw, expected, label)
        fde = containing_fde(image, start, end - start)
        rows.append({'label': label, 'fde_start': fde['start'], 'start': start, 'end': end,
                     'file_offset': file_offset(image['data'], image['secs'], start, len(raw), executable=True),
                     'size': len(raw), 'sha256': digest(raw), 'raw': raw.hex()})
    return rows



DIRECT_CALLS = (
    ('host-a-first-insert', 0x4d13b41, 0x4308460),
    ('host-b-first-insert', 0x4d163d1, 0x430abf0),
    ('host-a-second-insert', 0x4d14617, 0x4308460),
    ('host-b-second-insert', 0x4d16ea7, 0x430abf0),
    ('host-a-fill-total', 0x4d14426, 0x47d6d90),
    ('host-b-fill-total', 0x4d16cb6, 0x47d6d90),
    ('host-a-merge', 0x4d14654, 0x4471d80),
    ('host-b-merge', 0x4d16ee4, 0x4471d80),
    ('host-a-pre-branch-helper', 0x4d146e7, 0x45a4840),
    ('host-b-pre-branch-helper', 0x4d16f77, 0x45a4840),
    ('host-a-clear', 0x4d14725, 0x432bef0),
    ('host-b-clear', 0x4d16fb5, 0x432bef0),
    ('host-a-slot-write', 0x4d1477b, 0x4302290),
    ('host-b-slot-write', 0x4d1700b, 0x4302290),
    ('host-a-row-rewrite', 0x4d14828, 0x43292e0),
    ('host-b-row-rewrite', 0x4d170b8, 0x4329560),
    ('merge-user-iterator', 0x4471fbd, 0x4948400),
    ('merge-remaining-user-iterator', 0x4472298, 0x4948400),
    ('merge-user-insert', 0x44721d2, 0x4958ab0),
    ('merge-user-vector-grow', 0x447227d, 0x454f5d0),
    ('merge-fill-vectors', 0x447238a, 0x4888840),
    ('merge-error-drop', 0x447246b, 0x447b7f0),
    ('merge-unwind-error-drop', 0x4472538, 0x447b7f0),
    ('merge-unwind-map-drop', 0x44724be, 0x49b9a40),
    ('merge-unwind-target-map-drop', 0x44724f1, 0x49b0100),
    ('merge-unwind-resume', 0x4472540, 0x5660110),
    ('clear-row-normal', 0x432bf20, 0x433de50),
    ('clear-row-unwind', 0x432bf4f, 0x433de50),
    ('clear-row-unwind-resume', 0x432bf5c, 0x5660110),
    ('fill-vector-grow', 0x4888adf, 0x454f5d0),
    ('fill-unwind-input-drop', 0x4888b44, 0x47e3010),
    ('fill-unwind-resume-a', 0x4888b6a, 0x5660110),
    ('fill-unwind-resume-b', 0x4888b7d, 0x5660110),
)

INDIRECT_CALLS = (
    ('host-a-transition-helper', 0x4d1475d, 0x57747b8),
    ('host-b-transition-helper', 0x4d16fed, 0x57747b8),
    ('merge-compare-user-key', 0x447208d, 0x576e488),
    ('merge-append-u64s', 0x4472220, 0x576dfe0),
    ('merge-free-error', 0x4472458, 0x576e010),
    ('fill-size-failure', 0x48888ab, 0x576dfb8),
    ('fill-allocate', 0x48888fa, 0x576dfd8),
    ('fill-free-a', 0x4888a0c, 0x576e010),
    ('fill-free-b', 0x4888a98, 0x576e010),
    ('fill-unwind-free', 0x4888b61, 0x576e010),
)

INDIRECT_JUMPS = (
    ('drop-error-free-tail', 0x447b826, 0x576e010),
)

RIP_LOADS = (
    ('fill-a-copy-function', 0x48889c9, '4c8b3d', 0x576e0e0),
    ('fill-b-copy-function', 0x4888a43, '4c8b25', 0x576e0e0),
)

# Five matching host windows; mask only the four-byte displacement of each
# named call, whose opcode and actual destination are checked independently.
TWIN_BLOCKS = (
    ('host-first-insert', ((0x4d13b41, False),)),
    ('host-new-insert-merge', ((0x4d14617, False), (0x4d14654, False))),
    ('host-tag-select', ((0x4d146e7, False), (0x4d14725, False))),
    ('host-write-guard', ((0x4d1475d, True), (0x4d1477b, False))),
    ('host-rewrite-call', ((0x4d14828, False),)),
    ('host-quantity-source', ()),
    ('host-quantity-reload', ()),
    ('host-remainder-gate', ((0x4d14426, False),)),
    ('host-zero-remainder', ()),
    ('host-second-input-quantity', ()),
)

# Selected instructions and short contiguous instruction sequences needed to
# interpret the path.  They are read from the executable and checked in full.
SITES = (
    ('entry-sixth-argument', 0x4d12e91, '4d89cd'),
    ('input-quantity-save', 0x4d12ff7, '498b4d0848898c2498010000'),
    ('input-quantity-reload', 0x4d13f00, '4c8bbc2498010000'),
    ('remainder-helper-input', 0x4d1440c, '488dbc2490000000b301488bb42480000000488b942400040000e86529acff'),
    ('remainder-option', 0x4d1442b, '4883bc2490000000004d89fe'),
    ('remainder-subtract-saturating', 0x4d14439, '4531f64c89f8482b8424980000004c0f43f0'),
    ('remainder-zero-route', 0x4d144aa, 'b0018944242041b502e91d020000'),
    ('second-insert-quantity', 0x4d14554, '48c7842418050000010000004c89b42420050000'),
    ('host-first-output', 0x4d13b21, '488dbc2490020000'),
    ('host-first-tag', 0x4d13b5d, '488bb42490020000'),
    ('host-save-first-tag', 0x4d13b73, '4889b42460010000'),
    ('host-second-output', 0x4d145f2, '488dbc24a0040000'),
    ('host-new-tag', 0x4d1461c, '488b9c24a0040000'),
    ('host-new-id', 0x4d14624, '488b8424d0040000'),
    ('host-new-flag', 0x4d14634, '0fb6ac24e9040000'),
    ('host-merge-arg-a', 0x4d14644, '488db424a0040000'),
    ('host-merge-arg-b', 0x4d1464c, '488d9424e0010000'),
    ('host-classify', 0x4d14659, '48b800000000000000804839c3400fb6c541bd02000000440f45e8'),
    ('host-low-bit-test', 0x4d14763, '41f6c501'),
    ('host-setter-id', 0x4d14770, '488bb42458010000'),
    ('host-setter-word', 0x4d14778, '4c89fa'),
    ('merge-first-tag-test', 0x4471e1c, '31c0483b8424a0010000488b8424f0010000'),
    ('merge-both-error-output', 0x4471e35, '488b461849894424180f104608410f1144240849892c24'),
    ('merge-a-untagged-output', 0x4471e56, '0f104640410f114424400f10060f104e100f1056200f105e30410f115c2430410f11542420410f114c2410410f110424'),
    ('merge-b-untagged-output', 0x4471e8b, '0f104240410f114424400f10020f104a100f1052200f105a30410f115c2430410f11542420410f114c2410410f110424'),
    ('merge-map-value-tag', 0x4471fd9, '488b74c808'),
    ('merge-user-key-offset', 0x4471fef, '4881c210010000'),
    ('merge-vec-copy-call', 0x4472220, 'ff15babd2f01'),
    ('merge-a-fill-range', 0x4472310, '4869842418010000280200004c01e8'),
    ('merge-b-fill-range', 0x447231f, '48698c241001000028020000488b7424404801f1'),
    ('merge-fill-arg', 0x4472382, '488db42460010000'),
    ('merge-copy-metadata', 0x44723cb, '0fb6411041884424480f1001410f11442438'),
    ('merge-copy-id', 0x447241e, '488b8424000100004989442430'),
    ('merge-copy-flag', 0x447242b, '0fb644240f4188442449'),
    ('clear-length-first', 0x432beff, '4c8b781048c7401000000000'),
    ('clear-stride', 0x432bf16, '488d9f68020000'),
    ('slot-empty-controls', 0x43022db, '660f76c9'),
    ('slot-empty-check', 0x4302330, '660f74d1'),
    ('slot-write', 0x4302371, '488990d0000000'),
    ('fill-copy-a', 0x48889d0, 'ba280200004889df4889ee41ffd7'),
    ('fill-copy-b', 0x4888a50, '488dae28020000ba280200004c89ef41ffd4'),
    ('fill-empty-output', 0x488890e, '48c74424080000000048c7442410080000004531f6'),
    ('drop-error-tag', 0x447b7f0, '41574156534883ec60488b0f4889c848f7d87128'),
    ('drop-error-payload', 0x447b804, '488b77084885f60f88fd0000000f84f7000000'),
)

# Each site is an instruction whose literal or displacement is read after its
# fixed opcode bytes.  Values are checked but emitted from the input bytes.
CONSTANTS = (
    ('error-tag', 0x4471d94, '48bd', 8, 0x8000000000000000),
    ('hash-multiplier', 0x43022a0, '48b8', 8, 0xf1357aea2e62a9c5),
    ('hash-rotate-left', 0x43022ae, '48c1c0', 1, 20),
    ('hash-fingerprint-shift', 0x43022b5, '49c1e9', 1, 57),
    ('hash-probe-step', 0x4302341, '4883c0', 1, 16),
    ('book-index-count-offset', 0x4302290, '48837f', 1, 0x40),
    ('book-controls-offset', 0x43022b9, '488b4f', 1, 0x28),
    ('book-mask-offset', 0x43022bd, '4c8b47', 1, 0x30),
    ('book-slab-length-offset', 0x4302357, '483b4f', 1, 0x10),
    ('book-slab-pointer-offset', 0x430235d, '488b47', 1, 0x08),
    ('slab-slot-stride', 0x4302361, '4869c9', 4, 0xf8),
    ('slab-vacant-tag', 0x4302368, '833c08', 1, 2),
    ('slab-write-word-offset', 0x4302371, '488990', 4, 0xd0),
    ('pending-row-length-offset', 0x432beff, '4c8b78', 1, 0x10),
    ('pending-row-stride', 0x432bf16, '488d9f', 4, 0x268),
    ('user-key-byte-count', 0x4472080, 'ba', 4, 20),
    ('fill-row-stride', 0x4888893, '4869f3', 4, 0x228),
    ('fill-maximum-row-count', 0x488889a, '48b8', 8, 0x3b5cc0ed7303b5),
    ('fill-row-count-multiplier', 0x488886b, '48b8', 8, 0xf128cfc4a33f128d),
    ('host-class-clear', 0x4d146f2, '4180fd', 1, 2),
    ('host-new-result-stack', 0x4d145f2, '488dbc24', 4, 0x4a0),
    ('host-new-id-stack', 0x4d14624, '488b8424', 4, 0x4d0),
    ('host-new-flag-stack', 0x4d14634, '0fb6ac24', 4, 0x4e9),
    ('host-prior-record-stack', 0x4d1464c, '488d9424', 4, 0x1e0),
    ('host-saved-first-tag-stack', 0x4d1478f, '48398c24', 4, 0x160),
)

# ELF relocation types and symbol names are pinned to the selected references.
RELOCATIONS = (
    (0x576dfb8, 8, 0x1346068, ''),
    (0x576dfd8, 8, 0x54c06b0, ''),
    (0x576e010, 8, 0x54c8cb0, ''),
    (0x57747b8, 8, 0x3b7bd20, ''),
    (0x576dfe0, 6, 0, 'memcpy'),
    (0x576e0e0, 6, 0, 'memmove'),
    (0x576e488, 6, 0, 'memcmp'),
)


def collect_branches(image):
    specs = list(BRANCHES)
    for label, va, opcode, target in BRANCHES[:9]:
        specs.append(('twin-' + label, va + 0x2890, opcode, target + 0x2890))
    rows = []
    for label, va, opcode, target in specs:
        size = 6 if len(opcode) == 4 else 5 if opcode == 'e9' else 2
        raw = read_instruction(image, va, size)
        parsed = checked_branch(raw, va, opcode, target)
        fde = containing_fde(image, va, size)
        if not fde['start'] <= target < fde['end']:
            raise ValueError('selected branch exits FDE: ' + label)
        rows.append({'label': label, 'site': va, 'raw': parsed['raw'],
                     'fallthrough': parsed['fallthrough'], 'target': parsed['target'],
                     'fde_start': fde['start']})
    return rows


def collect_calls(image):
    rows = []
    for indirect, specs in ((False, DIRECT_CALLS), (True, INDIRECT_CALLS)):
        for label, va, target in specs:
            size = 6 if indirect else 5
            raw = read_instruction(image, va, size)
            actual = checked_call(raw, va, target, indirect=indirect)
            fde = containing_fde(image, va, size)
            rows.append({'label': label, 'kind': 'indirect-slot' if indirect else 'direct',
                         'site': va, 'raw': raw.hex(), 'destination': actual,
                         'fde_start': fde['start']})
    for label, va, expected in INDIRECT_JUMPS:
        raw = read_instruction(image, va, 6)
        actual = decode_indirect_jump(raw, va)
        if actual != expected:
            raise ValueError('indirect jump destination mismatch')
        rows.append({'label': label, 'kind': 'indirect-jump-slot', 'site': va,
                     'raw': raw.hex(), 'destination': actual,
                     'fde_start': containing_fde(image, va, 6)['start']})
    for label, va, prefix, expected in RIP_LOADS:
        raw = read_instruction(image, va, 7)
        if raw[:3].hex() != prefix:
            raise ValueError('unexpected RIP-relative load opcode')
        actual = va + 7 + struct.unpack_from('<i', raw, 3)[0]
        if actual != expected:
            raise ValueError('unexpected RIP-relative load target')
        rows.append({'label': label, 'kind': 'rip-load-slot', 'site': va,
                     'raw': raw.hex(), 'destination': actual,
                     'fde_start': containing_fde(image, va, 7)['start']})
    return rows


def collect_sites(image):
    rows = []
    for label, va, expected in SITES:
        raw = read_instruction(image, va, len(bytes.fromhex(expected)))
        if raw.hex() != expected:
            raise ValueError('instruction sequence mismatch: ' + label)
        rows.append({'label': label, 'site': va, 'size': len(raw), 'raw': raw.hex(),
                     'file_offset': file_offset(image['data'], image['secs'], va, len(raw), executable=True),
                     'fde_start': containing_fde(image, va, len(raw))['start']})
    return rows


def collect_twins(image):
    windows = {label: (start, end) for label, start, end, _ in WITNESSES}
    direct = {site: target for _, site, target in DIRECT_CALLS}
    indirect = {site: target for _, site, target in INDIRECT_CALLS}
    rows = []
    for label, call_specs in TWIN_BLOCKS:
        first, end = windows[label]
        second, second_end = windows['twin-' + label]
        if end - first != second_end - second:
            raise ValueError('twin window lengths differ')
        a = read_instruction(image, first, end - first)
        b = read_instruction(image, second, second_end - second)
        normal_a, normal_b = bytearray(a), bytearray(b)
        mask_positions = set()
        ranges_a, ranges_b = [], []
        for site, is_indirect in call_specs:
            other = second + site - first
            lookup = indirect if is_indirect else direct
            if site not in lookup or other not in lookup:
                raise ValueError('missing checked twin call')
            n, disp_start = (6, 2) if is_indirect else (5, 1)
            checked_call(read_instruction(image, site, n), site, lookup[site], indirect=is_indirect)
            checked_call(read_instruction(image, other, n), other, lookup[other], indirect=is_indirect)
            offset = site - first + disp_start
            if offset < 0 or offset + 4 > len(a):
                raise ValueError('twin mask outside window')
            for pos in range(offset, offset + 4):
                if pos in mask_positions:
                    raise ValueError('overlapping twin masks')
                mask_positions.add(pos)
                normal_a[pos] = normal_b[pos] = 0
            ranges_a.append(hex(first + offset) + '-' + hex(first + offset + 4))
            ranges_b.append(hex(second + offset) + '-' + hex(second + offset + 4))
        if normal_a != normal_b:
            raise ValueError('twin windows differ outside call displacements: ' + label)
        differences = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        rows.append({'label': label, 'start_a': first, 'start_b': second, 'size': len(a),
                     'sha256_a': digest(a), 'sha256_b': digest(b), 'normalized_sha256': digest(normal_a),
                     'raw_equal': not differences,
                     'differing_offsets': ','.join(hex(i) for i in differences),
                     'mask_ranges_a': ','.join(ranges_a), 'mask_ranges_b': ','.join(ranges_b)})
    return rows


def collect_merge_cases(image, branch_rows, constants):
    """Project four tag-equality cases through the byte-decoded branches.

    The selected sequences encode 0 - A (overflow only for signed minimum)
    and two comparisons of B with the loaded sentinel.  Inputs here are
    synthetic; the output blocks come from the decoded branch destinations.
    """
    if read_instruction(image, 0x4471e30, 3) != bytes.fromhex('4839e8'):
        raise ValueError('first second-tag compare changed')
    if read_instruction(image, 0x4471e51, 3) != bytes.fromhex('4839e8'):
        raise ValueError('second second-tag compare changed')
    branch = {row['label']: row for row in branch_rows}
    first = branch['first-merge-input-not-error']
    both_tagged = branch['second-merge-input-not-error']
    a_untagged = branch['both-merge-inputs-not-error']
    tag = next(row['value'] for row in constants if row['label'] == 'error-tag')
    if tag == 0:
        raise ValueError('synthetic tag classes are not distinct')
    rows = []
    for a_label, a in (('sentinel', tag), ('other-zero', 0)):
        for b_label, b in (('sentinel', tag), ('other-zero', 0)):
            if a == tag:
                site = both_tagged['fallthrough'] if b == tag else both_tagged['target']
                result = 'a-error' if b == tag else 'b'
            else:
                if first['target'] != 0x4471e51:
                    raise ValueError('unexpected first-result branch')
                site = a_untagged['fallthrough'] if b == tag else a_untagged['target']
                result = 'a' if b == tag else 'combine'
            read_instruction(image, site, 1)
            rows.append({'a_class': a_label, 'b_class': b_label, 'selected': result, 'output_block': site})
    return rows


def collect_constants(image):
    rows = []
    for label, site, prefix_hex, width, expected in CONSTANTS:
        prefix = bytes.fromhex(prefix_hex)
        raw = read_instruction(image, site, len(prefix) + width)
        if not raw.startswith(prefix):
            raise ValueError('constant instruction mismatch: ' + label)
        value = int.from_bytes(raw[len(prefix):], 'little')
        if value != expected:
            raise ValueError('constant value mismatch: ' + label)
        rows.append({'label': label, 'site': site, 'raw': raw.hex(), 'value': value})
    return rows


def one_section(secs, name, typ):
    matches = [s for s in secs if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] != typ:
        raise ValueError('missing or ambiguous section: ' + name)
    return matches[0]


def selected_relocations(data, secs, expected=RELOCATIONS):
    """Read selected ELF64 RELA records and dynamic symbol names directly."""
    rela = one_section(secs, '.rela.dyn', 4)
    dynsym = one_section(secs, '.dynsym', 11)
    dynstr = one_section(secs, '.dynstr', 3)
    if rela['size'] % 24 or dynsym['size'] % 24:
        raise ValueError('incomplete relocation or symbol record')
    wanted = {entry[0]: entry for entry in expected}
    if len(wanted) != len(expected):
        raise ValueError('duplicate expected relocation slot')
    selected = {}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        if slot in selected:
            raise ValueError('duplicate relocation slot')
        typ = info & 0xffffffff
        sym = info >> 32
        name = ''
        if sym:
            symoff = dynsym['offset'] + sym * 24
            if symoff + 24 > dynsym['offset'] + dynsym['size']:
                raise ValueError('dynamic symbol outside table')
            nameoff = struct.unpack_from('<I', data, symoff)[0]
            if nameoff >= dynstr['size']:
                raise ValueError('dynamic name outside table')
            first = dynstr['offset'] + nameoff
            last = data.find(b'\0', first, dynstr['offset'] + dynstr['size'])
            if last < 0:
                raise ValueError('unterminated dynamic symbol name')
            name = data[first:last].decode('ascii')
        _, required_type, required_addend, required_name = wanted[slot]
        if (typ, addend, name) != (required_type, required_addend, required_name):
            raise ValueError('relocation identity mismatch')
        if typ == 8 and sym != 0:
            raise ValueError('relative relocation has a symbol')
        selected[slot] = {'slot': slot, 'record_file_offset': off, 'type': typ,
                          'symbol_index': sym, 'symbol_name': name, 'addend': addend}
    if set(selected) != set(wanted):
        raise ValueError('missing selected relocation')
    return [selected[entry[0]] for entry in expected]


def tsv(rows, columns, hex_columns=()):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({key: hex(row[key]) if key in hex_columns else row[key] for key in columns})
    return stream.getvalue().encode('utf-8')


def build_evidence(data):
    image = parse_image(data)
    functions = collect_functions(image)
    witnesses = collect_witnesses(image)
    branches = collect_branches(image)
    calls = collect_calls(image)
    twins = collect_twins(image)
    sites = collect_sites(image)
    constants = collect_constants(image)
    merge_cases = collect_merge_cases(image, branches, constants)
    relocs = selected_relocations(data, image['secs'])
    summary = {'artifact_sha256': digest(data), 'coordinate_system': 'ELF virtual addresses; file offsets are zero-based',
               'fde_starts_indexed': len(image['starts']), 'selected_function_fdes': len(functions),
               'witness_windows': len(witnesses), 'selected_branches': len(branches),
               'selected_transfers_and_rip_loads': len(calls), 'selected_instruction_sequences': len(sites),
               'selected_constants': len(constants), 'projected_merge_cases': len(merge_cases),
               'selected_relocations': len(relocs), 'compared_host_windows': len(twins),
               'host_windows_raw_equal': sum(row['raw_equal'] for row in twins),
               'host_windows_normalized_only': sum(not row['raw_equal'] for row in twins),
               'normalization_masks': 'Four-byte call displacements only; exact ranges in twins.tsv',
               'note': 'Selected static paths only; no completeness or target execution claim.'}
    out = {
        'functions.tsv': tsv(functions, ['role', 'start', 'end', 'fde', 'cie', 'file_offset', 'size', 'sha256', 'raw'],
                             {'start', 'end', 'fde', 'cie', 'file_offset'}),
        'witnesses.tsv': tsv(witnesses, ['label', 'fde_start', 'start', 'end', 'file_offset', 'size', 'sha256', 'raw'],
                             {'fde_start', 'start', 'end', 'file_offset'}),
        'branches.tsv': tsv(branches, ['label', 'site', 'raw', 'fallthrough', 'target', 'fde_start'],
                            {'site', 'fallthrough', 'target', 'fde_start'}),
        'calls.tsv': tsv(calls, ['label', 'kind', 'site', 'raw', 'destination', 'fde_start'],
                         {'site', 'destination', 'fde_start'}),
        'sites.tsv': tsv(sites, ['label', 'site', 'size', 'raw', 'file_offset', 'fde_start'],
                         {'site', 'file_offset', 'fde_start'}),
        'merge-cases.tsv': tsv(merge_cases, ['a_class', 'b_class', 'selected', 'output_block'], {'output_block'}),
        'twins.tsv': tsv(twins, ['label', 'start_a', 'start_b', 'size', 'sha256_a', 'sha256_b',
                                 'normalized_sha256', 'raw_equal', 'differing_offsets',
                                 'mask_ranges_a', 'mask_ranges_b'],
                         {'start_a', 'start_b'}),
        'constants.tsv': tsv(constants, ['label', 'site', 'raw', 'value'], {'site', 'value'}),
        'relocations.tsv': tsv(relocs, ['slot', 'record_file_offset', 'type', 'symbol_index', 'symbol_name', 'addend'],
                               {'slot', 'record_file_offset', 'addend'}),
        'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8'),
    }
    return out


def project_merge_choice(a_tag, b_tag, error_tag):
    """Project only the verified four-way result selection, for synthetic tests."""
    if a_tag == error_tag:
        return 'a-error' if b_tag == error_tag else 'b'
    return 'a' if b_tag == error_tag else 'combine'


def project_remaining(original, summary_present, filled):
    """Project the unsigned, saturating remainder on the selected host path."""
    if not (0 <= original < 1 << 64 and 0 <= filled < 1 << 64):
        raise ValueError('synthetic quantity must fit u64')
    if not isinstance(summary_present, bool):
        raise ValueError('synthetic summary presence must be boolean')
    return max(0, original - filled) if summary_present else original


def project_success_contents(a_users, b_entries, a_fills, b_fills, error_tag):
    """Project content order for well-formed synthetic successful records.

    ``b_entries`` is an iteration-ordered sequence of (20-byte key, vector
    capacity, values).  Allocator, iterator, destructors and unwind effects are
    outside this projection.  A sentinel capacity stops the merge iteration.
    """
    result = {}
    for key, values in a_users.items():
        if not isinstance(key, bytes) or len(key) != 20:
            raise ValueError('synthetic key must be 20 bytes')
        result[key] = list(values)
    for key, capacity, values in b_entries:
        if capacity == error_tag:
            break
        if not isinstance(key, bytes) or len(key) != 20 or not 0 <= len(values) <= capacity:
            raise ValueError('invalid synthetic map entry')
        result.setdefault(key, []).extend(values)
    return result, list(a_fills) + list(b_fills)


def project_host_route(new_tag, flag, saved_first_tag, error_tag):
    """Project the selected host branch after merge; helper effects are opaque."""
    if not 0 <= flag <= 255:
        raise ValueError('flag must fit one byte')
    classification = 2 if new_tag == error_tag else flag
    if classification == 2:
        return ('clear', 'rewrite') if saved_first_tag != error_tag else ()
    steps = ['opaque-helper']
    if classification & 1:
        steps.append('slot-write')
    if saved_first_tag != error_tag:
        steps.append('rewrite')
    return tuple(steps)


def project_slot_write(key, controls, buckets, item_count, slots, word, constants):
    """Project a lookup/write on a small, well-formed synthetic hash table.

    Buckets map indices to (key, slab index); slots are (low-dword tag, word).
    The artificial termination bound guards this projection, not the target.
    """
    if not 0 <= key < 1 << 64 or not 0 <= word < 1 << 64 or item_count < 0:
        raise ValueError('invalid synthetic input')
    result = list(slots)
    if item_count == 0:
        return False, result
    width = constants['hash-probe-step']
    capacity = len(controls)
    if capacity < width or capacity % width or capacity & (capacity - 1):
        raise ValueError('synthetic table requires power-of-two capacity')
    mask = capacity - 1
    value = key * constants['hash-multiplier'] & ((1 << 64) - 1)
    shift = constants['hash-rotate-left']
    value = ((value << shift) | (value >> (64 - shift))) & ((1 << 64) - 1)
    fingerprint = value >> constants['hash-fingerprint-shift']
    group, step = value & mask, 0
    for _ in range(capacity // width):
        indices = [(group + lane) & mask for lane in range(width)]
        for index in indices:
            if controls[index] != fingerprint:
                continue
            if index not in buckets:
                raise ValueError('synthetic fingerprint has no bucket')
            stored_key, slot = buckets[index]
            if stored_key == key:
                if not 0 <= slot < 1 << 64:
                    raise ValueError('synthetic slab index must fit u64')
                if slot >= len(slots) or slots[slot][0] & 0xffffffff == constants['slab-vacant-tag']:
                    return False, result
                result[slot] = (slots[slot][0], word)
                return True, result
        if any(controls[index] == 0xff for index in indices):
            return False, result
        step += width
        group = (group + step) & mask
    raise ValueError('synthetic table needs a terminating control byte')


def project_fill_bound(first_extent, second_extent, constants):
    """Project the size guard for aligned, non-wrapping synthetic ranges."""
    stride = constants['fill-row-stride']
    magic = constants['fill-row-count-multiplier']
    for extent in (first_extent, second_extent):
        if not 0 <= extent < 1 << 64 or extent % stride:
            raise ValueError('projection requires aligned u64 byte extents')
    mask = (1 << 64) - 1
    total = (((first_extent >> 3) * magic) + ((second_extent >> 3) * magic)) & mask
    return total, total <= constants['fill-maximum-row-count']


def write_evidence(data, outdir):
    files = build_evidence(data)
    outdir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (outdir / name).write_bytes(content)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    files = write_evidence(BINARY.read_bytes(), args.out)
    print('wrote ' + str(len(files)) + ' deterministic evidence files')


if __name__ == '__main__':
    main()
