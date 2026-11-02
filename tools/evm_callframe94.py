#!/usr/bin/env python3
"""Export static, byte-backed node #94 CALL-frame evidence; never run the ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# Labels are interpretation. Every extent and body is verified against the ELF.
FUNCTIONS = {
    0x1ebec00: ('host-address adapter', '91d467d744750cb8d38f3b6132f4c104d9eb26dfd161c6e251d5ee2699551903'),
    0x24e6e80: ('opcode fa', 'cf2d2ae4f212c373f4cff7d0e20b0a59b9c02dfcd15a8042b6d0d05bf67468c5'),
    0x24e8800: ('memory-range helper', '96c66a91c6f1b7ee1d3c3504a99740ce5b93d72be5c56fba3cd87d7f8cb98e86'),
    0x24ea6d0: ('opcode f4', '83bf196d681bc009e7975aab95fbda06c9f7b5a0166d377b9befa479e0fb29dc'),
    0x24ec990: ('opcode f1', '5832e75999c865cb0484b83dcee0a6c66d2b8827495aba54d6ecd710f3e04db1'),
    0x24f2320: ('opcode f2', 'd072c4a50636d132c1fe7f1caa0b78f4b28ce139ea96f724be918400f1114e53'),
    0x276d8e0: ('interpreter loop adapter', 'a51beac67a1a0c514c39518631810cf5b30e74b67f17182a49a84a3a2bc62be4'),
    0x276def0: ('outcome adapter', 'b1af119853a6f9cdcd3360421235d29992b5db9189eb244f99fbb093ccc9a1db'),
    0x279ee30: ('interpreter loop', '3f20f6161070b41c6492343812d7feafe5652119034fc698188c070acc31d454'),
    0x4e8f2b0: ('child result insertion', 'ce0e9ee143666f14debb82537bf0ac9275283ff3b14d668e44945d9f58fb2132'),
    0x4e8fcb0: ('memory expansion charge', '462245eebc98cb267a50db15a22595e3302059796047be772f1b1e7ebdc90804'),
}

# These are explicitly selected byte windows, not a disassembler or a CFG census.
WINDOWS = [
    ('loop-adapter', 0x276d8e0, 0x276d8fb),
    ('loop-state-transfer', 0x279ee30, 0x279eec1),
    ('loop-fetch-call-exit', 0x279ef42, 0x279ef85),
    ('loop-move-result', 0x279efc1, 0x279eff1),
    ('loop-restore-state-and-return', 0x279eff1, 0x279f0bd),
    ('delegate-pop-gates', 0x24ea6e4, 0x24ea721),
    ('delegate-save-target-bytes', 0x24ea721, 0x24ea7e8),
    ('delegate-gas-word-fit', 0x24ea7e8, 0x24ea88a),
    ('delegate-prepare-host-key', 0x24ea88a, 0x24ea983),
    ('delegate-price-and-cap', 0x24ea983, 0x24eaa1f),
    ('delegate-frame', 0x24eaa1f, 0x24eabea),
    ('delegate-errors-and-unwind', 0x24eabea, 0x24eac74),
    ('call-pop-gates', 0x24ec9a1, 0x24ec9e1),
    ('call-target-save', 0x24ec9e1, 0x24ecab8),
    ('call-static-gate', 0x24ecb84, 0x24ecc06),
    ('call-prepare-host-key', 0x24ecc21, 0x24ecd50),
    ('call-price-and-cap', 0x24ecd50, 0x24ece23),
    ('call-frame', 0x24ece23, 0x24ed074),
    ('call-underflow', 0x24ed074, 0x24ed0a7),
    ('callcode-pop-gates', 0x24f2331, 0x24f2371),
    ('callcode-third-word-gates', 0x24f24cf, 0x24f253e),
    ('callcode-value-and-helper', 0x24f24f5, 0x24f255f),
    ('callcode-host-key', 0x24f2580, 0x24f2644),
    ('callcode-price-and-cap', 0x24f2644, 0x24f2724),
    ('callcode-frame', 0x24f2724, 0x24f28f4),
    ('static-pop-gates', 0x24e6e94, 0x24e6ed1),
    ('static-memory-and-host-key', 0x24e7061, 0x24e7166),
    ('static-price-and-cap', 0x24e7166, 0x24e720e),
    ('static-frame', 0x24e720e, 0x24e7459),
    ('memory-four-pop-and-errors', 0x24e880e, 0x24e8899),
    ('memory-first-range', 0x24e8899, 0x24e89f2),
    ('memory-second-range', 0x24e89f2, 0x24e8b2e),
    ('memory-exception-tails', 0x24e8b2e, 0x24e8b9e),
    ('host-account-and-status', 0x1ebec14, 0x1ebed25),
    ('host-error-move', 0x1ebed25, 0x1ebee32),
    ('growth-cost-and-charge', 0x4e8fcbb, 0x4e8fd43),
    ('growth-zero-and-return', 0x4e8fd43, 0x4e8fda7),
    ('outcome-adapter-copy-and-gate', 0x276def0, 0x276dfb0),
    ('outcome-adapter-dispatch', 0x276dfb0, 0x276e02e),
    ('outcome-load-and-range', 0x4e8f2c6, 0x4e8f353),
    ('outcome-success-refunds', 0x4e8f353, 0x4e8f3bc),
    ('outcome-revert-refund', 0x4e8f3bc, 0x4e8f40b),
    ('outcome-push-and-fail', 0x4e8f40b, 0x4e8f4d6),
    ('outcome-fatal-and-overflow', 0x4e8f4d6, 0x4e8f516),
]

# Each row names one reviewed site and its independently checked destination.
TRANSFERS = [
    ('loop-adapter-call', 0x276d8f1, 0x279ee30),
    ('loop-zero-tag-table', 0x279eea2, 0x279eec1),
    ('loop-alt-helper', 0x279eeb7, 0x26bc860),
    ('loop-alt-restore', 0x279eebc, 0x279eff1),
    ('loop-clear-old-action', 0x279eecd, 0x2784770),
    ('loop-initial-status-nonzero', 0x279ef4c, 0x279ef7b),
    ('loop-repeat', 0x279ef79, 0x279ef50),
    ('loop-action', 0x279ef83, 0x279efc1),
    ('loop-default-result-restore', 0x279efbf, 0x279eff1),
    ('f4-no-first-word', 0x24ea6ee, 0x24ea7fe),
    ('f4-no-second-word', 0x24ea701, 0x24ea7fe),
    ('f4-memory-helper', 0x24ea892, 0x24e8800),
    ('f4-memory-failed', 0x24ea89d, 0x24eaa06),
    ('f4-host', 0x24ea978, 0x1ebec00),
    ('f4-host-failed', 0x24ea981, 0x24ea9e9),
    ('f4-base-gas-failed', 0x24ea9c0, 0x24ea9e9),
    ('f4-forward-gas-pass', 0x24ea9e7, 0x24eaa18),
    ('f4-allocation-failed', 0x24eabac, 0x24eabfc),
    ('f4-old-action-drop', 0x24eabcb, 0x250d640),
    ('f1-no-first-word', 0x24ec9ab, 0x24ed08e),
    ('f1-no-second-word', 0x24ec9be, 0x24ed08e),
    ('f1-no-third-word', 0x24ecb67, 0x24ed08e),
    ('f1-static-pass', 0x24ecbf8, 0x24ecc06),
    ('f1-static-error-return', 0x24ecc01, 0x24ed095),
    ('f1-memory-helper', 0x24ecc34, 0x24e8800),
    ('f1-memory-failed', 0x24ecc3f, 0x24ed095),
    ('f1-host', 0x24ecd2a, 0x1ebec00),
    ('f1-host-failed', 0x24ecd4a, 0x24ecdd7),
    ('f1-base-gas-failed', 0x24ecdae, 0x24ecdd7),
    ('f1-forward-gas-pass', 0x24ecdd5, 0x24ece05),
    ('f1-frame-allocation-helper', 0x24ed02c, 0x251aea0),
    ('f1-old-action-drop', 0x24ed053, 0x250d640),
    ('f2-no-first-word', 0x24f233b, 0x24f290b),
    ('f2-no-second-word', 0x24f234e, 0x24f290b),
    ('f2-no-third-word-wide', 0x24f24d7, 0x24f290b),
    ('f2-no-third-word-narrow', 0x24f24ef, 0x24f290b),
    ('f2-memory-helper', 0x24f254e, 0x24e8800),
    ('f2-memory-failed', 0x24f2559, 0x24f2912),
    ('f2-host', 0x24f2630, 0x1ebec00),
    ('f2-host-failed', 0x24f263e, 0x24f26e2),
    ('f2-base-gas-failed', 0x24f26b9, 0x24f26e2),
    ('f2-forward-gas-pass', 0x24f26e0, 0x24f2704),
    ('f2-frame-allocation-helper', 0x24f28ac, 0x251aea0),
    ('f2-old-action-drop', 0x24f28d3, 0x250d640),
    ('fa-no-first-word', 0x24e6e9e, 0x24e6fcd),
    ('fa-no-second-word', 0x24e6eb1, 0x24e6fcd),
    ('fa-memory-helper', 0x24e7069, 0x24e8800),
    ('fa-memory-failed', 0x24e7074, 0x24e71f5),
    ('fa-host', 0x24e715b, 0x1ebec00),
    ('fa-host-failed', 0x24e7164, 0x24e71cc),
    ('fa-base-gas-failed', 0x24e71a3, 0x24e71cc),
    ('fa-forward-gas-pass', 0x24e71ca, 0x24e7207),
    ('fa-allocation-failed', 0x24e741b, 0x24e746d),
    ('fa-old-action-drop', 0x24e743a, 0x250d640),
    ('range-four-available', 0x24e8819, 0x24e8824),
    ('range-size-high-zero', 0x24e887b, 0x24e8899),
    ('range-first-size-zero', 0x24e88bd, 0x24e894f),
    ('range-first-offset-high', 0x24e88c9, 0x24e887d),
    ('range-first-old-length-underflow', 0x24e88ea, 0x24e8b3b),
    ('range-first-already-allocated', 0x24e88f3, 0x24e8956),
    ('range-growth-failed', 0x24e8947, 0x24e887d),
    ('range-first-end-overflow', 0x24e895c, 0x24e8b2e),
    ('range-buffer-allocation-failed', 0x24e89c1, 0x24e8b48),
    ('range-second-size-high-a', 0x24e8a08, 0x24e8a74),
    ('range-second-size-high-b', 0x24e8a61, 0x24e8a74),
    ('range-second-size-zero', 0x24e8a66, 0x24e8a94),
    ('range-second-offset-fits', 0x24e8a72, 0x24e8a9d),
    ('range-second-old-length-underflow', 0x24e8abc, 0x24e8b67),
    ('range-second-growth-required', 0x24e8ac5, 0x24e8aee),
    ('range-second-end-overflow', 0x24e8aca, 0x24e8b58),
    ('range-second-growth-pass', 0x24e8b13, 0x24e8ac7),
    ('range-second-growth-failed', 0x24e8b29, 0x24e8a74),
    ('outcome-adapter-error', 0x276dfae, 0x276dfee),
    ('outcome-revert-class', 0x4e8f348, 0x4e8f3bc),
    ('outcome-other-class', 0x4e8f34d, 0x4e8f465),
    ('outcome-success-mode-zero', 0x4e8f3b5, 0x4e8f40b),
    ('outcome-success-mode-nonzero', 0x4e8f3b7, 0x4e8f49a),
    ('outcome-revert-mode-zero', 0x4e8f405, 0x4e8f49a),
    ('outcome-stack-full', 0x4e8f42e, 0x4e8f4c0),
    ('outcome-fatal', 0x4e8f468, 0x4e8f4d6),
    ('outcome-other-mode-zero', 0x4e8f471, 0x4e8f49a),
    ('outcome-two-to-push', 0x4e8f498, 0x4e8f434),
    ('outcome-zero-to-push', 0x4e8f4ba, 0x4e8f434),
    ('outcome-gas-overflow', 0x4e8f35a, 0x4e8f4ef),
    ('outcome-refund-overflow', 0x4e8f373, 0x4e8f509),
    ('outcome-copy-end-overflow-success', 0x4e8f38b, 0x4e8f4fc),
    ('outcome-gas-overflow-revert', 0x4e8f3c3, 0x4e8f4ef),
    ('outcome-copy-end-overflow-revert', 0x4e8f3db, 0x4e8f4fc),
    ('growth-old-length-underflow', 0x4e8fced, 0x4e8fde3),
    ('growth-old-square-overflow', 0x4e8fd0c, 0x4e8fda7),
    ('growth-cost-delta-underflow', 0x4e8fd20, 0x4e8fdf0),
    ('growth-out-of-gas', 0x4e8fd30, 0x4e8fd92),
    ('growth-new-end-overflow', 0x4e8fd3d, 0x4e8fdfd),
    ('growth-no-additional-bytes', 0x4e8fd49, 0x4e8fd8e),
    ('growth-capacity-too-small', 0x4e8fd54, 0x4e8fdb3),
    ('growth-capacity-call', 0x4e8fdc7, 0x4e8f220),
]

# The four old-action drop calls have a landing which publishes the replacement.
DROP_LANDINGS = {
    0x24ec990: (0x24ed053, 0x24ed0a7, 0x24ed0c0),
    0x24f2320: (0x24f28d3, 0x24f2924, 0x24f293d),
    0x24ea6d0: (0x24eabcb, 0x24eac0e, 0x24eac22),
    0x24e6e80: (0x24e743a, 0x24e747f, 0x24e7493),
}

# These slots are data dependencies of the new functions, not selected old bodies.
RELOCS = {
    0x56bfa98: ('loop-callback', 0x276d8e0),
    0x56bfb28: ('outcome-callback', 0x276def0),
    0x5773f40: ('range-growth-callback', 0x4e8fcb0),
    0x5774df8: ('insert-result-callback', 0x4e8f2b0),
}
TABLE = 0x56ac788
VARIANTS = {
    0xf1: ('CALL', 0x24ec990, 0x20, 0x24ed01d, 0x24ed00d),
    0xf2: ('CALLCODE', 0x24f2320, 0x40, 0x24f289d, 0x24f288d),
    0xf4: ('DELEGATECALL', 0x24ea6d0, 0x40, 0x24eab94, 0x24eab84),
    0xfa: ('STATICCALL', 0x24e6e80, 0x20, 0x24e73fb, 0x24e73ec),
}

# Labels are inferred. Source and destination offsets are decoded from each
# selected instruction and checked against these independently reviewed sites.
FRAME_COPIES = [
    (0xf1, 'caller', 16, 0x24ece52, 0x24ece59, 0x80, 0x88),
    (0xf1, 'caller', 4, 0x24ece61, 0x24ece67, 0x90, 0x98),
    (0xf2, 'recipient', 16, 0x24f2738, 0x24f273f, 0x80, 0x74),
    (0xf2, 'recipient', 4, 0x24f2747, 0x24f274d, 0x90, 0x84),
    (0xf2, 'caller', 16, 0x24f2754, 0x24f275b, 0x80, 0x88),
    (0xf2, 'caller', 4, 0x24f2763, 0x24f2769, 0x90, 0x98),
    (0xf4, 'recipient', 16, 0x24eaa40, 0x24eaa47, 0x80, 0x74),
    (0xf4, 'recipient', 4, 0x24eaa33, 0x24eaa39, 0x90, 0x84),
    (0xf4, 'caller', 16, 0x24eaa5c, 0x24eaa63, 0x94, 0x88),
    (0xf4, 'caller', 4, 0x24eaa4f, 0x24eaa55, 0xa4, 0x98),
    (0xfa, 'caller', 16, 0x24e7228, 0x24e722f, 0x80, 0x88),
    (0xfa, 'caller', 4, 0x24e7237, 0x24e723d, 0x90, 0x98),
]


def check_digest(data, expected=SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('target SHA-256 mismatch')
    return actual


def file_offset(secs, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid file range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('range is unmapped or ambiguous')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size, executable=False):
    off = file_offset(secs, va, size, executable)
    if off + size > len(data):
        raise ValueError('file range truncated')
    return data[off:off + size]


def require_bytes(data, secs, va, expected):
    actual = read_va(data, secs, va, len(expected), True)
    if actual != expected:
        raise ValueError('selected instruction shape changed')
    return actual


def relocation_map(data, secs):
    matches = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('invalid RELA section')
    sec = matches[0]
    out = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in out:
            raise ValueError('duplicate relocation slot')
        out[slot] = (info, addend, off, data[off:off + 24])
    return out


def relative_record(relocs, slot, expected):
    if slot not in relocs:
        raise ValueError('missing relative relocation')
    info, addend, off, raw = relocs[slot]
    if info != 8 or addend != expected:
        raise ValueError('unexpected relocation')
    return info, addend, off, raw


def branch(data, secs, site):
    raw = read_va(data, secs, site, 2, True)
    if raw[0] in (0xe8, 0xe9):
        n, displacement = 5, struct.unpack('<i', read_va(data, secs, site + 1, 4, True))[0]
        kind = 'call' if raw[0] == 0xe8 else 'jmp'
    elif raw[0] == 0xeb:
        n, displacement, kind = 2, struct.unpack('b', raw[1:2])[0], 'jmp'
    elif 0x70 <= raw[0] <= 0x7f:
        n, displacement, kind = 2, struct.unpack('b', raw[1:2])[0], 'jcc-%x' % (raw[0] & 15)
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        n, displacement = 6, struct.unpack('<i', read_va(data, secs, site + 2, 4, True))[0]
        kind = 'jcc-%x' % (raw[1] & 15)
    else:
        raise ValueError('unsupported transfer encoding')
    return kind, site + n + displacement, read_va(data, secs, site, n, True)


def checked_branch(data, secs, site, expected):
    kind, target, raw = branch(data, secs, site)
    if target != expected:
        raise ValueError('transfer destination changed')
    return kind, target, raw


def rip_slot(data, secs, site, expected_slot):
    raw = read_va(data, secs, site, 6, True)
    if raw[:2] != b'\xff\x15':
        raise ValueError('not a RIP-indirect call')
    slot = site + 6 + struct.unpack('<i', raw[2:])[0]
    if slot != expected_slot:
        raise ValueError('indirect slot changed')
    return raw


def digest_bodies(data, secs, fdes, index):
    by_start = {}
    for f in fdes:
        if f['start'] in FUNCTIONS:
            if f['start'] in by_start:
                raise ValueError('duplicate selected FDE')
            by_start[f['start']] = f
    ix = {e['start']: e for e in index if e['start'] in FUNCTIONS}
    if set(by_start) != set(FUNCTIONS) or set(ix) != set(FUNCTIONS):
        raise ValueError('missing selected FDE')
    rows, bodies, unwind = [], [], []
    for start in sorted(FUNCTIONS):
        label, expected = FUNCTIONS[start]
        f = by_start[start]
        if ix[start]['fde'] != f['fde'] or f['end'] <= start:
            raise ValueError('FDE and unwind index differ')
        raw = read_va(data, secs, start, f['end'] - start, True)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('selected FDE body changed')
        off = file_offset(secs, start, len(raw), True)
        rows.append([hex(start), hex(f['end']), len(raw), hex(off), hex(f['fde']),
                     hex(f['cie']), hex(f['lsda']) if f['lsda'] is not None else '', digest, label])
        bodies.append({'start': hex(start), 'end': hex(f['end']), 'bytes': raw.hex()})
        records = []
        for name in ('fde', 'cie'):
            va = f[name]
            head = read_va(data, secs, va, 4)
            n = struct.unpack('<I', head)[0]
            if n in (0, 0xffffffff):
                raise ValueError('unsupported unwind record length')
            records.append({'kind': name, 'va': hex(va), 'raw': read_va(data, secs, va, n + 4).hex()})
        unwind.append({'function': hex(start), 'records': records})
    return rows, bodies, unwind, by_start


def exception_table(data, secs, fde):
    """Read the selected LSDA call-site formats, leaving action chains opaque."""
    if fde['lsda'] is None:
        return [], None
    matches = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing exception section')
    sec = matches[0]
    pos = file_offset(secs, fde['lsda'], 1)
    end = sec['offset'] + sec['size']
    if not sec['offset'] <= pos < end or pos + 2 > end:
        raise ValueError('LSDA outside exception section')
    beginning = pos
    if data[pos] != 0xff:
        raise ValueError('unsupported landing-base encoding')
    type_encoding = data[pos + 1]
    pos += 2
    type_base = None
    if type_encoding != 0xff:
        if type_encoding != 0x9b:
            raise ValueError('unsupported LSDA type encoding')
        delta, pos = uleb(data, pos, end)
        type_base = pos + delta
        if type_base > end:
            raise ValueError('LSDA type table outside section')
    if pos >= end or data[pos] != 1:
        raise ValueError('unsupported call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, end)
    limit = pos + length
    if limit > end or (type_base is not None and limit > type_base):
        raise ValueError('invalid LSDA table extent')
    rows, previous_end = [], 0
    while pos < limit:
        row_start = pos
        start, pos = uleb(data, pos, limit)
        size, pos = uleb(data, pos, limit)
        landing, pos = uleb(data, pos, limit)
        action, pos = uleb(data, pos, limit)
        if start < previous_end or fde['start'] + start + size > fde['end']:
            raise ValueError('invalid LSDA call-site interval')
        if landing and fde['start'] + landing >= fde['end']:
            raise ValueError('invalid LSDA landing pad')
        previous_end = start + size
        rows.append([hex(fde['start']), hex(fde['lsda']), hex(row_start),
                     hex(fde['start'] + start), hex(fde['start'] + start + size),
                     hex(fde['start'] + landing) if landing else '', action,
                     data[row_start:pos].hex()])
    header = {'function': hex(fde['start']), 'lsda_va': hex(fde['lsda']),
              'file_offset': hex(beginning), 'type_encoding': hex(type_encoding),
              'prefix': data[beginning:limit].hex(),
              'limits': 'Call-site table only; action chains and exception types remain opaque.'}
    return rows, header


def drop_landing_rows(data, secs, selected, exception_rows):
    rows = []
    for owner, (site, landing, resume_call) in sorted(DROP_LANDINGS.items()):
        matching = [r for r in exception_rows if int(r[0], 16) == owner
                    and int(r[3], 16) <= site < int(r[4], 16)
                    and r[5] and int(r[5], 16) == landing]
        if len(matching) != 1 or site + 5 > int(matching[0][4], 16):
            raise ValueError('drop call is not covered by expected landing')
        checked_branch(data, secs, site, 0x250d640)
        checked_branch(data, secs, resume_call, 0x5660110)
        raw = read_va(data, secs, landing, resume_call + 5 - landing, True)
        if owner in (0x24ec990, 0x24f2320):
            prefix = bytes.fromhex('4889c3488b4424184c89b050010000c680880100006c4889df')
            pointer_index, tag_index = 11, 17
        else:
            prefix = bytes.fromhex('4989c64c89bb50010000c683880100006c4c89f7')
            pointer_index, tag_index = 6, 12
        if not raw.startswith(prefix) or len(raw) != len(prefix) + 5:
            raise ValueError('unexpected publication landing shape')
        pointer_offset = struct.unpack_from('<I', raw, pointer_index)[0]
        tag_offset = struct.unpack_from('<I', raw, tag_index)[0]
        tag = raw[tag_index + 4]
        rows.append([hex(owner), hex(site), hex(landing), hex(resume_call),
                     hex(pointer_offset), hex(tag_offset), tag, raw.hex()])
    return rows


def key_lanes(data, secs):
    """Track selected byte moves symbolically; no target instructions are run."""
    spills = {}
    pc = 0x24ea721
    for i in range(17):
        if i == 0:
            code = require_bytes(data, secs, pc, bytes.fromhex('0fb63c02'))
            src, load = 0, code
        else:
            load = read_va(data, secs, pc, 5, True)
            if load[:4] != bytes.fromhex('0fb67c02'):
                raise ValueError('unexpected address-load shape')
            src = load[4]
        load_site = pc
        pc += len(load)
        store = read_va(data, secs, pc, 5, True)
        if store[:4] != bytes.fromhex('40887c24') or src in [v[0] for v in spills.values()]:
            raise ValueError('unexpected address-spill shape')
        spills[store[4]] = (src, load_site, load.hex(), pc, store.hex())
        pc += len(store)
    if pc != 0x24ea7ca:
        raise ValueError('wrong address-load span')
    require_bytes(data, secs, 0x24ea7ca, bytes.fromhex('0f10040a0f104c0a10'))
    raw17 = require_bytes(data, secs, 0x24ea7d3, bytes.fromhex('0fb64c0211884c240e'))
    spills[raw17[-1]] = (raw17[4], 0x24ea7d3, raw17[:5].hex(), 0x24ea7d8, raw17[5:].hex())
    r12 = require_bytes(data, secs, 0x24ea7dc, bytes.fromhex('440fb6640212'))[-1]
    r13 = require_bytes(data, secs, 0x24ea7e2, bytes.fromhex('440fb66c0213'))[-1]
    if len(spills) != 18 or set(x[0] for x in spills.values()) | {r12, r13} != set(range(20)):
        raise ValueError('address byte sources are not a permutation')

    # First two bytes are kept in callee-saved r13/r12; the rest use spills.
    host = [(r13, 0x24ea7e2, 0x24ea8c4, 'register-r13'),
            (r12, 0x24ea7dc, 0x24ea8c9, 'register-r12')]
    require_bytes(data, secs, 0x24ea8c4, bytes.fromhex('44886c24404488642441'))
    pc = 0x24ea8ce
    for _ in range(18):
        load = read_va(data, secs, pc, 5, True)
        store = read_va(data, secs, pc + 5, 4, True)
        if load[:4] != bytes.fromhex('0fb64424') or store[:3] != bytes.fromhex('884424'):
            raise ValueError('unexpected host-key move')
        temp, dest = load[4], store[3]
        if temp not in spills:
            raise ValueError('unknown host-key spill')
        host.append((spills[temp][0], spills[temp][1], pc + 5, 'stack-%02x' % temp))
        if dest != 0x40 + len(host) - 1:
            raise ValueError('host key is not contiguous')
        pc += 9
    if pc != 0x24ea970:
        raise ValueError('unexpected host-key end')

    first = require_bytes(data, secs, 0x24eaa95, bytes.fromhex('4488ac24a00000004488a424a1000000'))
    frame = [(r13, 0x24eaa95, struct.unpack_from('<I', first, 4)[0]),
             (r12, 0x24eaa9d, struct.unpack_from('<I', first, 12)[0])]
    tag_store = require_bytes(data, secs, 0x24eab84, bytes.fromhex('48c744244001000000'))
    frame_base = tag_store[4]
    pc = 0x24eaaa5
    for _ in range(18):
        load = read_va(data, secs, pc, 5, True)
        store = read_va(data, secs, pc + 5, 7, True)
        if load[:4] != bytes.fromhex('0fb64424') or store[:3] != bytes.fromhex('888424'):
            raise ValueError('unexpected frame-key move')
        temp = load[4]
        dest = struct.unpack('<I', store[3:])[0]
        if temp not in spills or dest != 0xa0 + len(frame):
            raise ValueError('frame-key spill or displacement changed')
        frame.append((spills[temp][0], pc + 5, dest))
        pc += 12
    if pc != 0x24eab7d or [x[0] for x in host] != [x[0] for x in frame]:
        raise ValueError('host and frame keys differ')
    rows = []
    for index, ((src, load_site, host_store, via), (_, frame_store, dest)) in enumerate(zip(host, frame)):
        rows.append([index, src, hex(load_site), via, hex(host_store), hex(frame_store),
                     hex(dest - frame_base)])
    return rows


def frame_copy_rows(data, secs):
    """Decode selected source and frame displacements from the raw moves."""
    rows = []
    for opcode, role, width, load_site, store_site, expected_src, expected_dst in FRAME_COPIES:
        base = VARIANTS[opcode][2]
        source_register = 'rcx' if opcode in (0xf1, 0xf2) else 'rbx'
        modrm = 0x81 if source_register == 'rcx' else 0x83
        if width == 16:
            load = read_va(data, secs, load_site, 7, True)
            store = read_va(data, secs, store_site, 8, True)
            if load[:3] != bytes((0x0f, 0x10, modrm)) or store[:4] != bytes.fromhex('0f118424'):
                raise ValueError('unexpected frame copy encoding')
            src = struct.unpack_from('<I', load, 3)[0]
            dest = struct.unpack_from('<I', store, 4)[0] - base
        else:
            load = read_va(data, secs, load_site, 6, True)
            store = read_va(data, secs, store_site, 7, True)
            if load[:2] != bytes((0x8b, modrm)) or store[:3] != bytes.fromhex('898424'):
                raise ValueError('unexpected frame copy encoding')
            src = struct.unpack_from('<I', load, 2)[0]
            dest = struct.unpack_from('<I', store, 3)[0] - base
        if store_site != load_site + len(load) or (src, dest) != (expected_src, expected_dst):
            raise ValueError('unexpected frame copy displacement')
        rows.append([hex(opcode), role, width, source_register, hex(src), hex(dest),
                     hex(load_site), hex(store_site), load.hex(), store.hex()])

    # Two interleaved XMM moves copy the inherited 32-byte value for f4.
    load0 = require_bytes(data, secs, 0x24eaa6b, bytes.fromhex('0f104360'))
    load1 = require_bytes(data, secs, 0x24eaa6f, bytes.fromhex('0f104b70'))
    store1 = require_bytes(data, secs, 0x24eaa73, bytes.fromhex('0f114c2458'))
    store0 = require_bytes(data, secs, 0x24eaa78, bytes.fromhex('0f11442448'))
    for load_site, store_site, load, store in ((0x24eaa6b, 0x24eaa78, load0, store0),
                                                (0x24eaa6f, 0x24eaa73, load1, store1)):
        rows.append(['0xf4', 'inherited-value', 16, 'rbx', hex(load[-1]),
                     hex(store[-1] - VARIANTS[0xf4][2]), hex(load_site), hex(store_site),
                     load.hex(), store.hex()])
    return rows


def bytecode_dispatch(data, secs):
    raw = require_bytes(data, secs, 0x279ef50, bytes.fromhex(
        '498b87d00100000fb60848ffc0498987d00100004c89ff4c89e641ff54cd08'))
    return {
        'function_va': hex(0x279ee30), 'instruction_start_va': hex(0x279ef50),
        'program_pointer_offset': struct.unpack_from('<I', raw, 3)[0],
        'slot_base_offset': raw[-1], 'slot_stride': 1 << (raw[-2] >> 6),
        'raw': raw.hex(),
        'interpretation': 'load byte, increment stored pointer, call indexed slot',
    }


def loop_reset_literals(data, secs):
    """Resolve paired RIP-relative literal loads at state entry and exit."""
    rows = []
    entry = (0x279ee76, 0x279ee80, 0x279ee8b)
    exit_ = (0x279eff1, 0x279eff8, 0x279efff)
    for index, (entry_site, exit_site) in enumerate(zip(entry, exit_)):
        decoded = []
        for site in (entry_site, exit_site):
            insn = read_va(data, secs, site, 7, True)
            if insn[:2] != b'\x0f\x10' or insn[2] & 0xc7 != 0x05:
                raise ValueError('unexpected loop reset literal load')
            address = site + 7 + struct.unpack_from('<i', insn, 3)[0]
            decoded.append((address, insn))
        if decoded[0][0] != decoded[1][0]:
            raise ValueError('entry and exit reset literals differ')
        literal_va = decoded[0][0]
        raw = read_va(data, secs, literal_va, 16)
        rows.append([index, hex(entry_site), hex(exit_site), hex(literal_va),
                     hex(file_offset(secs, literal_va, 16)), raw.hex(),
                     decoded[0][1].hex(), decoded[1][1].hex()])
    return rows


def outcome_model(status, mode_flag, bounds):
    if not 0 <= status <= 255 or mode_flag not in (0, 1):
        raise ValueError('invalid model input')
    base, width, success_limit, fatal = bounds
    if base <= status < base + width:
        return ('revert-range', 1 if mode_flag else 0, 'remaining')
    if status < success_limit:
        return ('success-range', 0 if mode_flag else 1, 'remaining-and-refund')
    if status == fatal:
        return ('fatal', None, 'none')
    return ('other', 2 if mode_flag else 0, 'none')


def gas_model(opcode, host_word, value_nonzero, available, requested, constants):
    """Synthetic arithmetic projection of the selected post-memory branches."""
    if opcode not in VARIANTS or not 0 <= host_word < (1 << 24):
        raise ValueError('invalid opcode or host word')
    if value_nonzero not in (0, 1) or not 0 <= available < (1 << 64) or not 0 <= requested < (1 << 256):
        raise ValueError('invalid synthetic gas input')
    if host_word & 255 == 2:
        return ('host-failed', None, available, None)
    low, high = constants['warm_or_cold_low'], constants['warm_or_cold_high']
    middle = (host_word >> 8) & 255
    secondary = 0 if middle == 2 else (high if host_word & 0x100 else low)
    cost = secondary + (high if host_word & 1 else low)
    if value_nonzero and opcode in (0xf1, 0xf2):
        cost += (constants['f1_value_new_cost'] if opcode == 0xf1 and host_word & 0x10000
                 else constants['f1_value_cost'])
    if available < cost:
        return ('gas-failed', cost, available, None)
    remaining = available - cost
    cap = remaining - (remaining >> constants['gas_cap_shift'])
    forwarded = min(requested, cap)
    parent = remaining - forwarded
    child = forwarded
    if value_nonzero and opcode in (0xf1, 0xf2):
        child = min((1 << 64) - 1, child + constants['f1_stipend'])
    return ('frame', cost, parent, child)


def memory_cost(requested_bytes, constants):
    """Project the saturating word/square arithmetic in the growth helper."""
    limit = (1 << 64) - 1
    if not 0 <= requested_bytes <= limit:
        raise ValueError('invalid synthetic memory size')
    words = min(limit, requested_bytes + constants['memory_round_add']) >> constants['memory_word_shift']
    square = min(limit, words * words)
    return constants['memory_linear_factor'] * words + (square >> constants['memory_square_shift'])


def csv_text(header, rows):
    return '\t'.join(header) + '\n' + ''.join('\t'.join(str(v) for v in row) + '\n' for row in rows)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='ascii')


def generate(data, out):
    check_digest(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    functions, bodies, unwind, selected = digest_bodies(data, secs, fdes, index)
    relocs = relocation_map(data, secs)
    relocation_rows, variant_rows = [], []
    for op, (name, expected, base, scheme_site, tag_site) in sorted(VARIANTS.items()):
        slot = TABLE + op * 8
        info, addend, off, raw = relative_record(relocs, slot, expected)
        relocation_rows.append([name, hex(slot), hex(off), hex(info), hex(addend), raw.hex()])
        # All four constructors materialize the same 160-byte frame type.
        if op == 0xfa:
            code = read_va(data, secs, scheme_site, 8, True)
            if code[:4] != bytes.fromhex('c68424be') or code[4:7] != b'\0\0\0':
                raise ValueError('unexpected static scheme store')
            scheme = code[7]
            scheme_disp = struct.unpack('<I', code[3:7])[0]
        else:
            code = read_va(data, secs, scheme_site, 10, True)
            if code[:3] != bytes.fromhex('66c784') or code[3] != 0x24:
                raise ValueError('unexpected scheme store')
            scheme_disp = struct.unpack('<I', code[4:8])[0] + 1
            scheme = struct.unpack('<H', code[8:10])[0] >> 8
        if op == 0xfa:
            require_bytes(data, secs, 0x24e731f, bytes.fromhex('660fefc0'))
            require_bytes(data, secs, tag_site, bytes.fromhex('660f7f442420'))
            value_tag = 0  # XORed XMM0 is stored at the frame base.
        else:
            tag = read_va(data, secs, tag_site, 9, True)
            if tag[:3] != bytes.fromhex('48c744') or tag[3] != 0x24 or tag[4] != base:
                raise ValueError('unexpected value-tag store')
            value_tag = struct.unpack('<i', tag[5:9])[0]
        if scheme_disp - base != 0x9e or scheme not in (0, 1, 2, 3):
            raise ValueError('wrong scheme offset or value')
        variant_rows.append([hex(op), name, hex(slot), hex(addend), hex(base), hex(tag_site),
                             value_tag, hex(scheme_site), hex(scheme_disp - base), scheme, code.hex()])
    for slot, (name, expected) in sorted(RELOCS.items()):
        info, addend, off, raw = relative_record(relocs, slot, expected)
        relocation_rows.append([name, hex(slot), hex(off), hex(info), hex(addend), raw.hex()])
    relocation_rows.sort(key=lambda r: int(r[1], 16))
    indirect = [(0x24e8923, 0x5773f40), (0x24e8b05, 0x5773f40), (0x276dfe6, 0x5774df8)]
    indirect_rows = [[hex(site), hex(slot), rip_slot(data, secs, site, slot).hex()] for site, slot in indirect]

    window_rows = []
    for name, start, end in WINDOWS:
        owners = [f for f in selected.values() if f['start'] <= start < end <= f['end']]
        if len(owners) != 1:
            raise ValueError('selected window escapes its FDE')
        raw = read_va(data, secs, start, end - start, True)
        window_rows.append([name, hex(owners[0]['start']), hex(start), hex(end),
                            hex(file_offset(secs, start, len(raw), True)), raw.hex(), hashlib.sha256(raw).hexdigest()])
    edges = []
    for name, site, expected in TRANSFERS:
        owners = [f for f in selected.values() if f['start'] <= site < f['end']]
        if len(owners) != 1:
            raise ValueError('transfer outside selected FDE')
        kind, target, raw = checked_branch(data, secs, site, expected)
        if kind.startswith('jcc') and not owners[0]['start'] <= target < owners[0]['end']:
            raise ValueError('local branch escapes selected FDE')
        edges.append([name, hex(owners[0]['start']), hex(site), kind, hex(target), raw.hex()])
    lanes = key_lanes(data, secs)
    frame_copies = frame_copy_rows(data, secs)
    dispatch = bytecode_dispatch(data, secs)
    reset_literals = loop_reset_literals(data, secs)
    address_cases = []
    for word in (0, 8, 9, 10, (1 << 160) + 9, (1 << 256) - 1):
        stack_word = word.to_bytes(32, 'little')
        key = bytes(stack_word[row[1]] for row in lanes)
        address_cases.append([hex(word), stack_word.hex(), key.hex()])
    exception_rows, exception_headers = [], []
    for fde in sorted(selected.values(), key=lambda f: f['start']):
        rows, header = exception_table(data, secs, fde)
        exception_rows.extend(rows)
        if header is not None:
            exception_headers.append(header)
    landing_rows = drop_landing_rows(data, secs, selected, exception_rows)

    # Numeric policy operands are extracted only after checking their byte shapes.
    require_bytes(data, secs, 0x4e8f342, bytes.fromhex('8d46f083f806'))
    require_bytes(data, secs, 0x4e8f34a, bytes.fromhex('83fe05'))
    require_bytes(data, secs, 0x4e8f465, bytes.fromhex('83fe65'))
    base = (-struct.unpack('b', read_va(data, secs, 0x4e8f344, 1, True))[0]) & 0xff
    width = read_va(data, secs, 0x4e8f347, 1, True)[0]
    success_limit = read_va(data, secs, 0x4e8f34c, 1, True)[0]
    fatal = read_va(data, secs, 0x4e8f467, 1, True)[0]
    bounds = (base, width, success_limit, fatal)
    cases = []
    for status in range(256):
        for mode_flag in (0, 1):
            cls, pushed, credit = outcome_model(status, mode_flag, bounds)
            cases.append([hex(status), mode_flag, cls, '' if pushed is None else pushed, credit])
    # Anchors below also bind the constants used in the prose to machine bytes.
    const_sites = [
        ('memory_operands', 0x24e8815, '4883f804', 3, 1),
        ('underflow_status', 0x24e881b, 'c686f30100005b', 6, 1),
        ('address_range_status', 0x24e8879, 'b254', 1, 1),
        ('memory_expand_status', 0x24e8943, 'b251', 1, 1),
        ('host_failure_status', 0x24ea97d, 'b165', 1, 1),
        ('gas_failure_status', 0x24ea9bb, 'b150', 1, 1),
        ('warm_or_cold_low', 0x24ea991, 'be64000000', 1, 4),
        ('warm_or_cold_high', 0x24ea98c, 'ba280a0000', 1, 4),
        ('gas_cap_shift', 0x24ea9cc, '48c1ea06', 3, 1),
        ('f1_value_cost', 0x24ecd86, 'b828230000', 1, 4),
        ('f1_value_new_cost', 0x24ecd8b, '41b8d0840000', 2, 4),
        ('f1_stipend', 0x24ece11, '4981c7fc080000', 3, 4),
        ('outcome_stack_limit', 0x4e8f427, '4881f900040000', 3, 4),
        ('outcome_stack_overflow', 0x4e8f4c0, 'c683f30100005c', 6, 1),
        ('outcome_mode_success_offset', 0x4e8f3ae, '80bbf001000000', 2, 4),
        ('outcome_mode_revert_offset', 0x4e8f3fe, '80bbf001000000', 2, 4),
        ('outcome_mode_other_offset', 0x4e8f46a, '80bbf001000000', 2, 4),
        ('outcome_push_one', 0x4e8f41b, 'b801000000', 1, 4),
        ('outcome_push_two', 0x4e8f483, 'b802000000', 1, 4),
        ('empty_action_tag', 0x279eed2, '41c6878801000070', 7, 1),
        ('call_action_tag', 0x24eabd7, 'c683880100006c', 6, 1),
        ('call_suspend_status', 0x24eabde, 'c683f301000020', 6, 1),
        ('memory_round_add', 0x4e8fcbe, '4883c11f', 3, 1),
        ('memory_word_shift', 0x4e8fcd0, '49c1e905', 3, 1),
        ('memory_square_shift', 0x4e8fcf7, '49c1ec09', 3, 1),
    ]
    constants = []
    for name, va, encoded, start, size in const_sites:
        raw = require_bytes(data, secs, va, bytes.fromhex(encoded))
        value = int.from_bytes(raw[start:start + size], 'little')
        constants.append([name, hex(va), value, raw.hex()])
    linear_raw = require_bytes(data, secs, 0x4e8fcf3, bytes.fromhex('4b8d0449'))
    linear_factor = 1 + (1 << (linear_raw[-1] >> 6))  # same base/index registers
    if linear_factor != 3:
        raise ValueError('unexpected memory linear factor')
    constants.append(['memory_linear_factor', hex(0x4e8fcf3), linear_factor, linear_raw.hex()])
    zero_raw = require_bytes(data, secs, 0x4e8f4aa, bytes.fromhex('31c0'))
    constants.append(['outcome_push_zero', hex(0x4e8f4aa), 0, zero_raw.hex()])
    const = {row[0]: row[2] for row in constants}
    gas_cases = []
    for op in sorted(VARIANTS):
        for host in (0, 1, 2, 0x100, 0x200, 0x10100):
            for value_nonzero in (0, 1):
                for available, requested in ((0, 0), (100, 1), (2700, 64), (50000, 0),
                                              (50000, 50000), (50000, 1 << 64)):
                    result, cost, parent, child = gas_model(op, host, value_nonzero, available, requested, const)
                    gas_cases.append([hex(op), hex(host), value_nonzero, available, requested, result,
                                      '' if cost is None else cost, parent, '' if child is None else child])
    memory_cases = [[size, memory_cost(size, const)] for size in
                    (0, 1, 31, 32, 33, 63, 64, 65, 511, 512, 513,
                     65535, 65536, 65537, (1 << 64) - 32, (1 << 64) - 31, (1 << 64) - 1)]
    out.mkdir(parents=True, exist_ok=True)
    (out / 'functions.tsv').write_text(csv_text(['start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','sha256','inferred_role'], functions), encoding='ascii')
    (out / 'variants.tsv').write_text(csv_text(['opcode','label','slot_va','callee_va','frame_stack_base','value_tag_store_va','value_tag','scheme_store_va','scheme_offset','scheme','scheme_raw'], variant_rows), encoding='ascii')
    (out / 'relocations.tsv').write_text(csv_text(['label','slot_va','rela_file_offset','r_info','r_addend','raw_rela'], relocation_rows), encoding='ascii')
    (out / 'indirect-sites.tsv').write_text(csv_text(['instruction_va','slot_va','raw_instruction'], indirect_rows), encoding='ascii')
    (out / 'control.tsv').write_text(csv_text(['label','function_va','site_va','kind','target_va','raw'], edges), encoding='ascii')
    (out / 'windows.tsv').write_text(csv_text(['label','function_va','start_va','end_va','file_offset','raw','sha256'], window_rows), encoding='ascii')
    (out / 'delegate-key-lanes.tsv').write_text(csv_text(['key_index','source_stack_byte','source_load_va','temporary','host_store_va','frame_store_va','frame_offset'], lanes), encoding='ascii')
    (out / 'frame-copies.tsv').write_text(csv_text(['opcode','inferred_field','width','source_register','source_offset','frame_offset','load_va','store_va','load_raw','store_raw'], frame_copies), encoding='ascii')
    (out / 'loop-reset-literals.tsv').write_text(csv_text(['index','entry_load_va','exit_load_va','literal_va','file_offset','raw_literal','entry_raw','exit_raw'], reset_literals), encoding='ascii')
    (out / 'constants.tsv').write_text(csv_text(['label','instruction_va','value','raw'], constants), encoding='ascii')
    (out / 'exception-sites.tsv').write_text(csv_text(['function_va','lsda_va','record_file_offset','start_va','end_va','landing_va','action','raw'], exception_rows), encoding='ascii')
    (out / 'drop-landings.tsv').write_text(csv_text(['function_va','drop_call_va','landing_va','resume_call_va','pointer_offset','tag_offset','tag','raw'], landing_rows), encoding='ascii')
    (out / 'synthetic-outcomes.tsv').write_text(csv_text(['status','mode_flag','model_class','pushed_word','gas_credit'], cases), encoding='ascii')
    (out / 'synthetic-gas.tsv').write_text(csv_text(['opcode','host_word','value_nonzero','available','requested','model_result','charge','parent_after','child'], gas_cases), encoding='ascii')
    (out / 'synthetic-memory.tsv').write_text(csv_text(['requested_bytes','modeled_total_cost'], memory_cases), encoding='ascii')
    (out / 'synthetic-addresses.tsv').write_text(csv_text(['word','stack_word_little_endian','modeled_host_and_frame_key'], address_cases), encoding='ascii')
    write_json(out / 'bodies.json', bodies)
    write_json(out / 'unwind.json', unwind)
    write_json(out / 'exception-headers.json', exception_headers)
    write_json(out / 'dispatch.json', dispatch)
    write_json(out / 'summary.json', {
        'binary_sha256': SHA256, 'target': 'node-94', 'coordinate_system': 'linked ELF virtual address before load bias',
        'selected_fde_intervals': len(functions), 'selected_fde_bytes': sum(row[2] for row in functions),
        'selected_windows': len(window_rows), 'selected_control_transfers': len(edges),
        'relative_relocations': len(relocation_rows), 'indirect_sites': len(indirect_rows),
        'delegate_key_lanes': len(lanes), 'frame_copy_chunks': len(frame_copies), 'loop_reset_literals': len(reset_literals),
        'synthetic_outcome_rows': len(cases),
        'exception_call_site_rows': len(exception_rows), 'drop_publication_landings': len(landing_rows),
        'synthetic_gas_rows': len(gas_cases), 'synthetic_memory_rows': len(memory_cases),
        'synthetic_address_rows': len(address_cases),
        'outcome_status_bounds': {'success_limit': success_limit, 'revert_base': base,
                                  'revert_width': width, 'fatal': fatal},
        'limits': 'Selected ranges and synthetic models only; not full CFG, runtime execution, or target equivalence.'})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
