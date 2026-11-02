#!/usr/bin/env python3
"""RE-006: static evidence for a user order-index insertion and split.

Only authenticated ELF bytes are read.  No code from the captured ELF is run.
The case table is a projection of explicitly pinned tests and writes, not a
runtime experiment.  The ELF and unwind decoders are repository utilities.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('split-and-propagate', 0x1ad5cd0, 0x1ad73ea, '7385f1116e64ee9cb133761a423be6c4e56d77f3120767440d16e5b91c42d39f'),
    ('insert-a', 0x28526f0, 0x285296c, 'cd979ad6f574384c375efd03f8df4845ca004dc6d2e8cbf9a795008a1f640a75'),
    ('insert-b', 0x28577e0, 0x2857a5c, '00730fc2225b0c1572e6b7e67603b6b9cd143709bb1e4ccccd7e0eb19b95ad1f'),
)

# Every witness is independently hashed so local corruption is detected even
# in tests deliberately bypassing the whole-file and whole-function hashes.
WITNESSES = (
    ('search-root', 0x2852704, 0x2852714, '62b14d75e05271019d2c41801a8c6ef7843ccb66c932f10fbeb0f9bb98e259c9'),
    ('ordered-key-search', 0x2852714, 0x2852773, '2f5de7958d84275b4b0c1ccf88fd0b659bf3d86020a6652adc35a6ecd31c08b9'),
    ('replace-existing', 0x2852773, 0x28527a3, '64dda2dd527a5f8497a6083abdd9b09b29bb2d76ef951702160ae6a1b9dab36d'),
    ('absent-dispatch', 0x28527a3, 0x2852803, '7543e62ff93d7d4a9369f891035471e9d141ce8e61e099454137657d9ba80892'),
    ('empty-leaf-allocation', 0x2852803, 0x2852852, 'aded87ccd970d0301728efe88f33c6a3cd1424a30400fb59ccf07dd9c95f53b1'),
    ('empty-leaf-insert', 0x2852852, 0x28528fe, '6e67b3278775f4d7253ea2ffe4d64a266ee6bfd51a0e2b32d1c2ca785dca7bb0'),
    ('new-result-and-count', 0x28528fe, 0x285291b, 'ceb986b8524d7e7e55f027b55209bfb92035f340074dd78ecde050d6675245a6'),
    ('wrapper-failures', 0x285291b, 0x2852948, 'a91958758a4ce657a7838bc7d050be22335677c749be8c39655d4506d971bc6f'),
    ('leaf-guard-and-pivot-low', 0x1ad5cec, 0x1ad5d29, '58bc1608a7090d21d9552339062641a63bafdca7618bf3f4687a9faf002eae48'),
    ('leaf-room', 0x1ad5d29, 0x1ad5d5f, '0c8efa069aa78daaae42f1b6e40f759abebd1447849867df90019490a2db1983'),
    ('leaf-pivot-middle', 0x1ad5d5f, 0x1ad5d82, '82ed8d0194e4e5917a07ccc96eba73dcd38ff880d1237c04f92819d820c37752'),
    ('leaf-room-moves', 0x1ad5d82, 0x1ad5df5, '0bf1b77d0847413149d349aa0fd0c3bab7ed99043336a1811ed5d5b412941a94'),
    ('leaf-write-and-return', 0x1ad5df5, 0x1ad5e5f, '1f0f19635967092a2ca7c0c8447959236299873a81defcf776354c589950f831'),
    ('leaf-pivot-high', 0x1ad5e5f, 0x1ad5e7c, 'd2a12c00ff09ae74207243c85622f116e66064f9320f8278d1328e047567cf57'),
    ('leaf-sibling-allocate', 0x1ad5e7c, 0x1ad5ec9, 'e3805ae48844a5db382ba2f0fccaafc387d732280a25d4cf1bcc4fa9b505ea11'),
    ('leaf-sibling-count', 0x1ad5ec9, 0x1ad5ee6, '741bb406b5a8b58ba0d111e2039cfd6b67bb9120d9e355717082914fa207f765'),
    ('leaf-split-moves', 0x1ad5fb7, 0x1ad6027, 'f72bde37633c98c362d3005498f4607b962055333152c19da0e6b2397116aca6'),
    ('leaf-side-select', 0x1ad60cf, 0x1ad6103, 'd6f008831d169dde03a71417fce3f87c0e942408bb690f97ba3f91947fb1f201'),
    ('leaf-insert-after-split', 0x1ad616c, 0x1ad61bf, '91dab307a0890dc386e8362532312e58d005e84d2674a992d1cd975c58cdcba5'),
    ('parent-guard', 0x1ad6390, 0x1ad63c3, 'd89f3679609ce694ec6539422bb72a6579d6f35d165680d1a7465df4ab0b7227'),
    ('parent-shift-children', 0x1ad6520, 0x1ad655e, '89312a9cfe408abd0a7aa20fbf70a47182f950589c131aabd051ca2fa6e22f91'),
    ('parent-pivot-low', 0x1ad6560, 0x1ad6590, '01cdb73ba656d629d86530a5ef4f888ed06b1a7a2ac724cc3868193093e0426d'),
    ('parent-insert-and-count', 0x1ad665d, 0x1ad6694, 'ef66371670cab0d60851292c1ad0564753d7776b5d23931d0f0b0abd6176980f'),
    ('parent-relink-child', 0x1ad66b0, 0x1ad66ce, 'adc9ed151a7737c0b2847fa91e2620dcf2063bc25bfbbb2b6828d9ab823e08d1'),
    ('parent-pivot-high', 0x1ad6760, 0x1ad6790, '2528c430bc21d2e5a61b6532e843c567969bc75c370ea478e1d89bfbddcc0747'),
    ('parent-sibling-allocate', 0x1ad6790, 0x1ad67a4, '3d7bbdfcbc557cfc535621baf97cbc149e1a903cd3de7d7bccc63dce4b3a01bc'),
    ('parent-sibling-count', 0x1ad67c8, 0x1ad67f1, 'ad655d56cffe897df2b8af75022fb692be8f036238c5a3051f90be5f7951aa7b'),
    ('parent-sibling-bound', 0x1ad68b5, 0x1ad68bf, '1149b93f2c7b323919507f591406047d934082e8039d33dcdeda917c4416007f'),
    ('parent-child-bound', 0x1ad69da, 0x1ad6a1f, 'a6b800c29022138f53ab5ca2aa9c4dafbe4b3e3ba0be0f115f2a742fd3bfc5b4'),
    ('parent-child-relink', 0x1ad6a30, 0x1ad6a56, '5ca0d2c06060fd34d06ba5b5624cab96c67cc7d47551aad2b609651b1c513bbb'),
    ('parent-split-side-and-shift', 0x1ad6b06, 0x1ad6b2f, '34f053f3da0ed58421a15f3f3a159dd07f186fddbcfeed6d5c7d0ddd77003394'),
    ('parent-split-child-shift', 0x1ad6c60, 0x1ad6c90, 'b2f29e7a2d1b7273eb2422e1d37952668e5a57cb36c7e98eaed71add08a7d484'),
    ('parent-split-key-child-write', 0x1ad6d6b, 0x1ad6dbf, '9bd4f50dcb5cab0a9cb21ed548254388bac02d0b02e48ae9c09089f3f478ed13'),
    ('propagation-loop', 0x1ad6fe1, 0x1ad700e, '6f27c22495834e9a85fe3666e24a2cd339a613e218398f08e2190a064e93281b'),
    ('root-split-and-guards', 0x1ad7018, 0x1ad70aa, '55055d7b5497e224c616dfc860a0f016e7d5014e08b3515b7f32af5b1dff233f'),
    ('root-child-links-and-output', 0x1ad718b, 0x1ad71d8, '528078fc32e744ca5ffdb1006a8b9a8fc11f8efdd730a95bb19833b88ff3320d'),
    ('failure-arms', 0x1ad71d8, 0x1ad730f, '230ad1d7a2a4a4559e55ca8152ab2a8d5a622956dd201613da23510fc524e77a'),
    ('wrapper-unwind-cleanup', 0x2852948, 0x285296c, '37ccfd397fad028367bc470c02326a4ca5760db626e4417399440ac5df277f56'),
    ('leaf-propagation-tag', 0x1ad628d, 0x1ad629f, '8862650994dad7be4653cc47406e6f30146c4f052636d3a5b53d2e289ec6ed3a'),
    ('first-parent-test', 0x1ad635c, 0x1ad6390, '7ca6d9807dd3881cf8478e7f5c72b3f0c44044ef85372f2e945e4acecd59d83e'),
    ('parent-repair-loop', 0x1ad66ce, 0x1ad673e, 'dee1119f5e1f195b183fa38643e247789726417405c7516c3d4e17fb7e256f7e'),
    ('parent-propagation-tag', 0x1ad673e, 0x1ad6760, 'd61e70fa8c7633332e0f3b33477b7b2d2444116ec539ec3a08788c2bd0649a7b'),
    ('split-repair-loop', 0x1ad6dc0, 0x1ad6e51, 'a850d0440d41dd08d2c480c8ce6d5f8805406bd5960c63e84326232eb7e86bfa'),
    ('split-propagation-tag', 0x1ad6f25, 0x1ad6f34, '4074b5a23b466691b6c25d69ca79f1d4c6f76ceb61fb444adeea60f5e653ec38'),
    ('split-unwind-cleanup', 0x1ad7311, 0x1ad73ea, '31784839dd3b447df82a038f65c3e1c9b192ab27d0734d0d1aaf88bed09cadd4'),
    ('caller-a-context', 0x26e74b7, 0x26e74eb, 'c616447540736b68788ca8bee4c07344aac10f3f77218606c941141fe3d2b688'),
    ('caller-b-context', 0x26e6143, 0x26e6172, 'f7c9560b728f413b86508b942ef47d9af253296359d65c40e89e31282e9285df'),
    ('caller-a-replaced-value-cleanup', 0x26e74eb, 0x26e750e, '6b6c71f10add9b4b433a71b4fa28157fdee8aa41b05df7daafe89d87cada9bb1'),
    ('caller-b-replaced-value-cleanup', 0x26e6172, 0x26e6195, '06b9818cf1d98902141d756444022a3fcf6d542469f9234c81e13ec65568e0f0'),
)

# Sites were manually checked as instruction starts. Only these branch encodings
# are decoded; this is not an instruction scanner or a complete CFG.
BRANCHES = (
    ('root-null', 0x285270a, '0f84'),
    ('node-keys-exhausted', 0x2852733, '74'),
    ('advance-to-next-key', 0x2852750, '74'),
    ('key-equal', 0x2852759, '74'),
    ('height-exhausted', 0x2852767, '72'),
    ('missing-root', 0x28527c5, '74'),
    ('empty-leaf-allocation-failed', 0x285281f, '0f84'),
    ('empty-leaf-count-invalid', 0x285284c, '0f83'),
    ('wrapper-unwind-vector-empty', 0x2852950, '74'),
    ('leaf-has-room', 0x1ad5d02, '72'),
    ('leaf-index-at-least-five', 0x1ad5d14, '73'),
    ('leaf-insert-before-end', 0x1ad5d3f, '76'),
    ('leaf-return-tag-not-two', 0x1ad5e45, '0f85'),
    ('leaf-index-five', 0x1ad5d5f, '0f84'),
    ('leaf-index-not-six', 0x1ad5d69, '0f85'),
    ('leaf-sibling-allocation-failed', 0x1ad5ea5, '0f84'),
    ('leaf-sibling-count-invalid', 0x1ad5fbb, '0f83'),
    ('leaf-no-shift-after-split', 0x1ad6101, '76'),
    ('leaf-promoted-tag-two', 0x1ad6299, '0f84'),
    ('first-parent-null', 0x1ad636a, '0f84'),
    ('parent-edge-height-mismatch', 0x1ad6395, '0f85'),
    ('parent-full', 0x1ad63af, '0f83'),
    ('parent-insert-at-end', 0x1ad63bd, '0f83'),
    ('parent-index-at-least-five', 0x1ad6579, '0f83'),
    ('parent-repair-none', 0x1ad6681, '0f83'),
    ('parent-repair-no-short-loop', 0x1ad6692, '74'),
    ('parent-short-repair-loop', 0x1ad66c9, '75'),
    ('parent-repair-no-four-loop', 0x1ad66d5, '72'),
    ('parent-four-repair-loop', 0x1ad673c, '75'),
    ('parent-return-tag-not-two', 0x1ad674f, '0f85'),
    ('parent-index-five', 0x1ad6764, '74'),
    ('parent-index-not-six', 0x1ad676a, '75'),
    ('parent-sibling-allocation-failed', 0x1ad679e, '0f84'),
    ('parent-sibling-count-invalid', 0x1ad68b9, '0f83'),
    ('child-count-invalid', 0x1ad69ea, '0f83'),
    ('child-count-mismatch', 0x1ad69f9, '0f85'),
    ('moved-child-last', 0x1ad6a4f, '73'),
    ('moved-child-loop', 0x1ad6a54, '76'),
    ('parent-split-no-shift', 0x1ad6b29, '0f86'),
    ('parent-split-no-child-repair', 0x1ad6d95, '0f83'),
    ('parent-split-skip-short-repair', 0x1ad6da5, '74'),
    ('split-short-repair-loop', 0x1ad6dd8, '75'),
    ('split-repair-no-four-loop', 0x1ad6de1, '72'),
    ('split-four-repair-loop', 0x1ad6e4f, '75'),
    ('split-return-tag-two', 0x1ad6f2e, '0f84'),
    ('parent-remains', 0x1ad7006, '0f85'),
    ('old-root-null', 0x1ad702d, '0f84'),
    ('new-root-allocation-failed', 0x1ad704a, '0f84'),
    ('height-overflow', 0x1ad7070, '0f84'),
    ('root-height-mismatch', 0x1ad708f, '0f85'),
    ('new-root-full', 0x1ad70a4, '0f83'),
    ('unwind-vector-present-a', 0x1ad7328, '0f85'),
    ('unwind-vector-present-b', 0x1ad7351, '75'),
    ('unwind-vector-empty-a', 0x1ad7365, '74'),
    ('unwind-vector-present-c', 0x1ad738a, '75'),
    ('unwind-vector-empty-b', 0x1ad73a3, '74'),
    ('unwind-vector-empty-c', 0x1ad73cc, '74'),
)

# All mask ranges are exactly one rel32 operand; opcodes and target equality
# are checked separately. Offsets are relative to each insertion FDE.
TWIN_OPERANDS = (
    ('copy-slot', 0x8b, 'rip3'),
    ('split-call', 0x104, 'call1'),
    ('allocate-slot', 0x126, 'rip2'),
    ('allocation-error-slot', 0x235, 'rip2'),
    ('assertion-message', 0x23d, 'rip3'),
    ('assertion-location', 0x244, 'rip3'),
    ('assertion-slot', 0x250, 'rip2'),
    ('deallocate-slot', 0x26e, 'rip2'),
    ('unwind-call', 0x277, 'call1'),
)

# Direct calls, including two non-subject caller-context sites. The enclosing
# caller is not selected as a subject and its other code is outside the packet.
CALLS = (
    ('context-a-to-insert', 0x26e74d1, 0x28526f0),
    ('context-b-to-insert', 0x26e615d, 0x28577e0),
    ('insert-a-to-split', 0x28527f4, 0x1ad5cd0),
    ('insert-b-to-split', 0x28578e4, 0x1ad5cd0),
)

# RIP-relative FF 15 instructions at selected sites only, not a call census.
INDIRECT = (
    ('caller-a-replaced-value-free', 0x26e7508, 0x576e010),
    ('caller-b-replaced-value-free', 0x26e618f, 0x576e010),
    ('leaf-initial-allocate', 0x2852816, 0x576dfd8),
    ('leaf-initial-allocation-error', 0x2852925, 0x576e020),
    ('leaf-initial-assert', 0x2852940, 0x576e108),
    ('leaf-sibling-allocate', 0x1ad5e9c, 0x576dfd8),
    ('leaf-sibling-allocation-error', 0x1ad7291, 0x576e020),
    ('parent-sibling-allocate', 0x1ad6795, 0x576dfd8),
    ('parent-sibling-allocation-error', 0x1ad7241, 0x576e020),
    ('new-root-allocate', 0x1ad7041, 0x576dfd8),
    ('new-root-allocation-error', 0x1ad72b2, 0x576e020),
    ('leaf-copy', 0x1ad5d54, 0x576dfe0),
    ('leaf-overlap-move', 0x1ad5da2, 0x576e0e0),
)


# Fixed instruction templates. Values are read from the verified immediate or
# displacement bytes, not from objdump text.
CONSTANTS = (
    ('node-live-count-offset', 0x1ad5cef, '0fb79d4a080000', 3, '<I'),
    ('maximum-live-keys', 0x1ad5cf6, '4883fb0b', 3, '<B'),
    ('middle-index', 0x1ad5d08, '4883fb05', 3, '<B'),
    ('left-pivot', 0x1ad5d16, '41bc04000000', 2, '<I'),
    ('middle-right-index', 0x1ad5d65, '4883fb06', 3, '<B'),
    ('right-pivot', 0x1ad5e70, '41bc06000000', 2, '<I'),
    ('key-array-offset', 0x1ad5d31, '4a8d34ed08000000', 4, '<I'),
    ('value-array-offset', 0x1ad5dd5, '4883c660', 3, '<B'),
    ('value-stride', 0x1ad5dd9, '4969c7b8000000', 3, '<I'),
    ('leaf-allocation-bytes', 0x1ad5e97, 'bf50080000', 1, '<I'),
    ('node-parent-index-offset', 0x1ad639b, '450fb7b248080000', 4, '<I'),
    ('parent-live-count-offset', 0x1ad63a3, '440fb79b4a080000', 4, '<I'),
    ('internal-allocation-bytes', 0x1ad6790, 'bfb0080000', 1, '<I'),
    ('new-root-allocation-bytes', 0x1ad703c, 'bfb0080000', 1, '<I'),
    ('child-array-offset', 0x1ad7063, '4c89a050080000', 3, '<I'),
    ('new-result-first-word', 0x2852902, '48c70302000000', 3, '<I'),
    ('header-count-offset', 0x28528fe, '48ff4110', 3, '<B'),
)

RELOCATION_EXPECTED = {
    0x576dfd8: (8, 0, 0x54c06b0),
    0x576dfe0: (6, 6, 0),
    0x576e010: (8, 0, 0x54c8cb0),
    0x576e020: (8, 0, 0x1345e2a),
    0x576e0e0: (6, 9, 0),
    0x576e108: (8, 0, 0x157b7f0),
}


def read_constant(data, spec):
    label, va, expected, pos, fmt = spec
    wanted = bytes.fromhex(expected)
    raw = read_va(data, va, len(wanted), True)
    if raw != wanted:
        raise ValueError('Constant instruction changed: ' + label)
    return struct.unpack_from(fmt, raw, pos)[0]


# Diagnostic strings and Location slots are tied to selected RIP-relative
# instructions. Location paths are deliberately emitted as relative suffixes.
DIAGNOSTICS = (
    ('initial-leaf-capacity', 0x285292d, 0x2852934, 0x285293b, 0x20ca60, 0x5688438, 0x20, 'assertion failed: idx < CAPACITY', 670, 9),
    ('parent-edge-height', 0x1ad71d8, 0x1ad71df, 0x1ad71e6, 0x3b3de1, 0x5688510, 0x35, 'assertion failed: edge.height == self.node.height - 1', 1027, 9),
    ('parent-child-length', 0x1ad724c, 0x1ad7253, 0x1ad725a, 0x3b3db9, 0x56884c8, 0x28, 'assertion failed: src.len() == dst.len()', 1876, 5),
    ('root-height', 0x1ad72d5, 0x1ad72c9, 0x1ad72d0, 0x3b3d2b, 0x5688450, 0x30, 'assertion failed: edge.height == self.height - 1', 694, 9),
    ('root-capacity', 0x1ad72ee, 0x1ad72e2, 0x1ad72e9, 0x20ca60, 0x5688468, 0x20, 'assertion failed: idx < CAPACITY', 698, 9),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_offset(data, va, size=1, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('Invalid VA or size')
    matches = [s for s in sections(data) if s['type'] != 8
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA range is not uniquely file-backed')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, va, size, executable=False):
    off = file_offset(data, va, size, executable)
    return data[off:off + size]


def checked_witness(data, witness):
    label, start, end, expected = witness
    raw = read_va(data, start, end - start, True)
    if digest(raw) != expected:
        raise ValueError('Witness bytes changed: ' + label)
    return raw


def validate_identity(data):
    if digest(data) != DIGEST:
        raise ValueError('Target digest mismatch')


def decode_branch(data, site, expected_opcode):
    op = bytes.fromhex(expected_opcode)
    if len(op) == 1 and 0x70 <= op[0] <= 0x7f:
        size, fmt = 2, '<b'
    elif len(op) == 2 and op[0] == 0x0f and 0x80 <= op[1] <= 0x8f:
        size, fmt = 6, '<i'
    else:
        raise ValueError('Unsupported selected branch opcode')
    raw = read_va(data, site, size, True)
    if not raw.startswith(op):
        raise ValueError('Branch opcode changed')
    target = site + size + struct.unpack_from(fmt, raw, len(op))[0]
    read_va(data, target, 1, True)
    return raw, target


def direct_call(data, site, expected):
    raw = read_va(data, site, 5, True)
    if raw[0] != 0xe8:
        raise ValueError('Expected direct call')
    target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
    if target != expected:
        raise ValueError('Direct call target changed')
    read_va(data, target, 1, True)
    return raw


def indirect_slot(data, site, expected):
    raw = read_va(data, site, 6, True)
    if raw[:2] != b'\xff\x15':
        raise ValueError('Expected RIP-relative indirect call')
    slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    if slot != expected:
        raise ValueError('Indirect slot changed')
    read_va(data, slot, 8)
    return raw


def relative_relocations(data, wanted):
    found = {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError('Partial ELF64 relocation')
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot not in wanted:
                continue
            if slot in found:
                raise ValueError('Duplicate relocation slot')
            found[slot] = (sec['name'], info & 0xffffffff, info >> 32, addend)
    if set(found) != set(wanted):
        raise ValueError('Missing selected relocation')
    return found




def dynamic_symbol_name(data, index):
    secs = sections(data)
    syms = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strs = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(syms) != 1 or len(strs) != 1 or syms[0]['size'] % 24:
        raise ValueError('Missing or ambiguous dynamic symbol sections')
    if index < 0 or (index + 1) * 24 > syms[0]['size']:
        raise ValueError('Dynamic symbol index outside table')
    name_offset = struct.unpack_from('<I', data, syms[0]['offset'] + index * 24)[0]
    if name_offset >= strs[0]['size']:
        raise ValueError('Dynamic symbol name outside table')
    start = strs[0]['offset'] + name_offset
    limit = strs[0]['offset'] + strs[0]['size']
    end = data.find(b'\0', start, limit)
    if end < 0:
        raise ValueError('Unterminated dynamic symbol name')
    try:
        return bytes(data[start:end]).decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('Non-ASCII dynamic symbol name') from exc


def checked_relocations(data, slots):
    relocations = relative_relocations(data, slots)
    for slot in sorted(slots):
        if slot not in RELOCATION_EXPECTED or relocations[slot][1:] != RELOCATION_EXPECTED[slot]:
            raise ValueError('Selected relocation changed')
    for slot, expected in ((0x576dfe0, 'memcpy'), (0x576e0e0, 'memmove')):
        if slot in slots and dynamic_symbol_name(data, relocations[slot][2]) != expected:
            raise ValueError('Dynamic symbol name changed')
    return relocations



def rip_lea(data, site, expected):
    raw = read_va(data, site, 7, True)
    if raw[:3] not in (b'\x48\x8d\x3d', b'\x48\x8d\x15'):
        raise ValueError('Expected selected RIP-relative address')
    target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
    if target != expected:
        raise ValueError('Diagnostic address changed')
    return raw


def diagnostics(data):
    slots = {d[5] for d in DIAGNOSTICS}
    relocations = relative_relocations(data, slots)
    rows = []
    for name, msg_site, loc_site, len_site, msg_va, slot, expected_len, expected_text, line, column in DIAGNOSTICS:
        msg_ins = rip_lea(data, msg_site, msg_va)
        loc_ins = rip_lea(data, loc_site, slot)
        length_ins = read_va(data, len_site, 5, True)
        if length_ins[0] != 0xbe or struct.unpack_from('<I', length_ins, 1)[0] != expected_len:
            raise ValueError('Diagnostic length instruction changed')
        message = read_va(data, msg_va, expected_len)
        if message != expected_text.encode('ascii'):
            raise ValueError('Diagnostic text changed')
        section, typ, symbol, path_va = relocations[slot]
        if typ != 8 or symbol != 0:
            raise ValueError('Location relocation changed')
        raw = read_va(data, slot, 24)
        path_len, got_line, got_column = struct.unpack_from('<QII', raw, 8)
        if not 0 < path_len <= 256 or (got_line, got_column) != (line, column):
            raise ValueError('Location fields changed')
        path = read_va(data, path_va, path_len)
        suffix = b'alloc/src/collections/btree/node.rs'
        if not path.endswith(suffix):
            raise ValueError('Unexpected diagnostic path suffix')
        rows.append((name, hex(msg_site), hex(loc_site), msg_ins.hex(), loc_ins.hex(),
                     hex(msg_va), hex(slot), message.decode('ascii'), suffix.decode('ascii'),
                     got_line, got_column, digest(path), section, hex(path_va), path_len))
    return rows


def twin_comparison(data):
    a = FUNCTIONS[1]
    b = FUNCTIONS[2]
    left = bytearray(read_va(data, a[1], a[2] - a[1], True))
    right = bytearray(read_va(data, b[1], b[2] - b[1], True))
    if len(left) != len(right):
        raise ValueError('Twin lengths differ')
    masks = []
    for label, offset, form in TWIN_OPERANDS:
        op_len = {'rip3': 3, 'rip2': 2, 'call1': 1}[form]
        length = op_len + 4
        x, y = bytes(left[offset:offset + length]), bytes(right[offset:offset + length])
        if len(x) != length or x[:op_len] != y[:op_len]:
            raise ValueError('Twin instruction opcode changed')
        if form == 'call1' and x[:1] != b'\xe8':
            raise ValueError('Twin direct-call opcode changed')
        if form == 'rip2' and x[:2] != b'\xff\x15':
            raise ValueError('Twin indirect-call opcode changed')
        if form == 'rip3' and x[:3] not in (b'\x4c\x8b\x25', b'\x48\x8d\x3d', b'\x48\x8d\x15'):
            raise ValueError('Twin RIP-relative opcode changed')
        tx = a[1] + offset + length + struct.unpack_from('<i', x, op_len)[0]
        ty = b[1] + offset + length + struct.unpack_from('<i', y, op_len)[0]
        if tx != ty:
            raise ValueError('Twin operand targets differ')
        read_va(data, tx, 1)
        first = offset + op_len
        masks.append((label, first, first + 4, tx))
        left[first:first + 4] = bytes(4)
        right[first:first + 4] = bytes(4)
    if left != right:
        raise ValueError('Twins differ outside declared operands')
    return masks, digest(left)


def split_choice(data, index, *, parent=False):
    """Return the selected pivot and destination from pinned instructions."""
    # Exact instructions bind the extracted immediate values to their use.
    checks = (
        (0x1ad5d08, '4883fb05'),
        (0x1ad5d16, '41bc04000000'),
        (0x1ad5d65, '4883fb06'),
        (0x1ad5d6f, '41bc05000000'),
        (0x1ad5e6c, '4883c3f9'),
        (0x1ad5e70, '41bc06000000'),
        (0x1ad5cf6, '4883fb0b'),
    )
    for va, expected in checks:
        raw = bytes.fromhex(expected)
        if read_va(data, va, len(raw), True) != raw:
            raise ValueError('Split decision instruction changed')
    if parent:
        parent_checks = (
            (0x1ad63ab, '4983fb0b'),
            (0x1ad6560, '664183fe05'),
            (0x1ad657f, '41bf04000000'),
            (0x1ad6760, '4983fe05'),
            (0x1ad6766, '4183fe06'),
            (0x1ad676f, '41bf05000000'),
            (0x1ad6781, '4983c6f9'),
            (0x1ad6788, '41bf06000000'),
        )
        for va, expected in parent_checks:
            raw = bytes.fromhex(expected)
            if read_va(data, va, len(raw), True) != raw:
                raise ValueError('Parent split decision instruction changed')
        mid = read_va(data, 0x1ad6560, 5, True)[-1]
        low_pivot = struct.unpack('<I', read_va(data, 0x1ad6581, 4, True))[0]
        high = read_va(data, 0x1ad6766, 4, True)[-1]
        high_pivot = struct.unpack('<I', read_va(data, 0x1ad678a, 4, True))[0]
        capacity = read_va(data, 0x1ad63ab, 4, True)[-1]
    else:
        mid = read_va(data, 0x1ad5d08, 4, True)[-1]
        low_pivot = struct.unpack('<I', read_va(data, 0x1ad5d18, 4, True))[0]
        high = read_va(data, 0x1ad5d65, 4, True)[-1]
        high_pivot = struct.unpack('<I', read_va(data, 0x1ad5e72, 4, True))[0]
        capacity = read_va(data, 0x1ad5cf6, 4, True)[-1]
    if type(index) is not int or not 0 <= index <= capacity:
        raise ValueError('Insertion index outside valid full node')
    if index < mid:
        return low_pivot, 'left', index
    if index == mid:
        return mid, 'left', index
    if index == high:
        return mid, 'right', 0
    return high_pivot, 'right', index - (high + 1)


def split_projection(data, index, *, parent=False):
    """Synthetic ordered labels, a projection of the recorded split, not target execution."""
    pivot, side, local = split_choice(data, index, parent=parent)
    capacity = read_va(data, 0x1ad5cf6, 4, True)[-1]
    old = [f'old-{i:02d}' for i in range(capacity)]
    left, right = old[:pivot], old[pivot + 1:]
    (left if side == 'left' else right).insert(local, 'new')
    result = {'index': index, 'old_pivot_index': pivot, 'side': side,
              'side_index': local, 'promoted': old[pivot], 'left': left, 'right': right}
    if parent:
        children = [f'child-{i:02d}' for i in range(capacity + 1)]
        children.insert(index + 1, 'new-right-child')
        cut = len(left) + 1
        result['left_children'], result['right_children'] = children[:cut], children[cut:]
    return result


def tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def collect(data, out, *, check_digest=True):
    if check_digest:
        validate_identity(data)
    summary, fdes, _ = fde_extents(data)
    if summary['duplicate_start'] or summary['unwind_start_differs_from_fde_start']:
        raise ValueError('Unwind records are ambiguous')
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    functions = []
    by_start = {}
    for f in fdes:
        by_start.setdefault(f['start'], []).append(f)
    for name, start, end, expected in FUNCTIONS:
        rows = by_start.get(start, [])
        if len(rows) != 1 or rows[0]['end'] != end or 'index' not in rows[0]:
            raise ValueError('Expected one indexed FDE at ' + name)
        raw = read_va(data, start, end - start, True)
        if digest(raw) != expected:
            raise ValueError('Function bytes changed: ' + name)
        f = rows[0]
        functions.append((name, hex(start), hex(end), hex(file_offset(data, start, len(raw), True)),
                          len(raw), hex(f['fde']), hex(f['cie']),
                          '' if f['lsda'] is None else hex(f['lsda']), f['index'], digest(raw), raw.hex()))
    witnesses = []
    for w in WITNESSES:
        raw = checked_witness(data, w)
        witnesses.append((w[0], hex(w[1]), hex(w[2]), hex(file_offset(data, w[1], len(raw), True)),
                          len(raw), digest(raw), raw.hex()))
    branches = []
    for label, site, opcode in BRANCHES:
        raw, target = decode_branch(data, site, opcode)
        owners = [f for f in FUNCTIONS if f[1] <= site < f[2]]
        if len(owners) != 1 or not owners[0][1] <= target < owners[0][2]:
            raise ValueError('Selected branch leaves its FDE')
        branches.append((label, hex(site), raw.hex(), hex(target), owners[0][0]))
    calls = [(name, hex(site), direct_call(data, site, target).hex(), hex(target))
             for name, site, target in CALLS]
    indirect = [(name, hex(site), indirect_slot(data, site, slot).hex(), hex(slot))
                for name, site, slot in INDIRECT]
    slots = {slot for _, _, slot in INDIRECT}
    reloc = checked_relocations(data, slots)
    reloc_rows = [(hex(slot), reloc[slot][0], reloc[slot][1], reloc[slot][2],
                   dynamic_symbol_name(data, reloc[slot][2]) if reloc[slot][1] == 6 else '',
                   hex(reloc[slot][3]) if reloc[slot][3] >= 0 else str(reloc[slot][3]))
                  for slot in sorted(slots)]
    constants = [(spec[0], hex(spec[1]), spec[2], read_constant(data, spec)) for spec in CONSTANTS]
    diagnostic_rows = diagnostics(data)
    masks, normalized = twin_comparison(data)
    comparisons = [(name, hex(lo), hex(hi), hex(target)) for name, lo, hi, target in masks]
    capacity = read_va(data, 0x1ad5cf6, 4, True)[-1]
    cases = [(stage, split_projection(data, i, parent=(stage == 'parent')))
             for stage in ('leaf', 'parent') for i in range(capacity + 1)]
    tsv(output / 'functions.tsv', ('role', 'start_va', 'end_va', 'file_offset', 'size', 'fde_va',
                                  'cie_va', 'lsda_va', 'unwind_index', 'sha256', 'body_hex'), functions)
    tsv(output / 'diagnostics.tsv', ('label', 'message_lea_va', 'location_lea_va', 'message_lea_hex', 'location_lea_hex',
                                      'message_va', 'location_va', 'text', 'path_suffix', 'line', 'column',
                                      'full_path_sha256', 'relocation_section', 'path_va', 'path_len'), diagnostic_rows)
    tsv(output / 'constants.tsv', ('label', 'site_va', 'instruction_hex', 'unsigned_value'), constants)
    tsv(output / 'witnesses.tsv', ('label', 'start_va', 'end_va', 'file_offset', 'size', 'sha256', 'raw_hex'), witnesses)
    tsv(output / 'branches.tsv', ('label', 'site_va', 'raw_hex', 'target_va', 'owner'), branches)
    tsv(output / 'calls.tsv', ('label', 'site_va', 'raw_hex', 'target_va'), calls)
    tsv(output / 'indirect-calls.tsv', ('label', 'site_va', 'raw_hex', 'slot_va'), indirect)
    tsv(output / 'relocations.tsv', ('slot_va', 'section', 'type', 'symbol_index', 'symbol_name', 'addend'), reloc_rows)
    tsv(output / 'twin-masks.tsv', ('label', 'offset_begin', 'offset_end', 'shared_target_va'), comparisons)
    tsv(output / 'split-cases.tsv', ('stage', 'insert_index', 'old_pivot_index', 'side', 'side_index', 'promoted',
                                    'left_labels', 'right_labels', 'left_child_labels', 'right_child_labels'),
        [(stage, c['index'], c['old_pivot_index'], c['side'], c['side_index'], c['promoted'],
          ','.join(c['left']), ','.join(c['right']), ','.join(c.get('left_children', [])),
          ','.join(c.get('right_children', []))) for stage, c in cases])
    metrics = {'artifact_sha256': DIGEST, 'functions': len(functions), 'witnesses': len(witnesses),
               'constants': len(constants), 'diagnostics': len(diagnostic_rows), 'selected_branches': len(branches), 'selected_direct_calls': len(calls),
               'selected_indirect_calls': len(indirect), 'selected_relocation_slots': len(reloc_rows),
               'masked_operands_per_twin': len(masks), 'normalized_twin_sha256': normalized,
               'split_cases': len(cases), 'target_execution': False,
               'case_kind': 'synthetic projection of pinned instructions'}
    (output / 'summary.json').write_text(json.dumps(metrics, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    metrics = collect(data, args.out)
    print(json.dumps(metrics, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        print('book_trigger_insert_split94: ' + str(exc), file=sys.stderr)
        sys.exit(1)
