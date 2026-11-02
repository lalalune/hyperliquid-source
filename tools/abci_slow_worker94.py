"""Recover the node 94 slow ABCI worker handoff from static ELF bytes.

Selected instructions and exception records are byte-checked. Repository ELF
and unwind readers provide section and FDE bounds. This is not a full CFG.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import fde_extents, sleb, uleb

ROOT = TOOLS.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Unwind extents are not a whole-program coverage denominator.
FUNCTIONS = (
    ('counter_exhausted', 0x4eeb8a0, 0x4eeb8bd, '8b74ab30803511212e7872cded8933ead9d7d61e03a9d261455add00d3a88107'),
    ('slow_driver_spawn', 0x474abe0, 0x474b13b, 'e2246dbcbafdffe1bb8761010ebe2b12d8fbd1a1126f867345fadd4ee0904783'),
    ('thread_builder', 0x43320f0, 0x4332768, '81149e6a678e45054e1114816f9fb4013462c9a3286651867fd8c1e2670c9309'),
    ('pthread_create_adapter', 0x4ee4ab0, 0x4ee4cab, '3c5eee1281aba531659e88b44863b1aef9a3a71b5d1e8d41dd99ffb21db2f1ad'),
    ('pthread_entry', 0x4ee48b0, 0x4ee4aad, 'ff0db3069a51bb7de3b2dac52e2fc4700527ac45ac942f72b72716e1357016cd'),
    ('slow_callback', 0x433a350, 0x433a5e1, 'dff5190808ff9783659dfbee41a66af6f53a46cba69bba61a366db7f592aaad7'),
    ('slow_callback_drop', 0x4340ae0, 0x4340b53, 'd93abd5c220e27978266c3783780f151deef71333835c0fa6a1b992e7e3a0f31'),
    ('slow_process_wrapper', 0x474a0f0, 0x474a4e7, 'a70cdb74ba076ffc7079d7be980e0b7c53e337887558aa5ee6ac9f7c89b401cd'),
    ('protected_dispatch', 0x4528a00, 0x4528d25, 'f25881e38c6032f7e4ada49052656fe375e8451f47168d57bb811a470c4d6f78'),
    ('protected_replace', 0x4527ab0, 0x4527d3e, '5f8a4d047fb081c5e019a1a133e82468dc7e6fd3bf3d53b974b187758f0c1832'),
)

# Selected whole extents. Hashes guard the exact captured windows.
WINDOWS = (
    ('overflow', 0x4eeb8a0, 0x4eeb8bd, '8b74ab30803511212e7872cded8933ead9d7d61e03a9d261455add00d3a88107'),
    ('slow_driver_spawn', 0x474abe0, 0x474b13b, 'e2246dbcbafdffe1bb8761010ebe2b12d8fbd1a1126f867345fadd4ee0904783'),
    ('thread_builder', 0x43320f0, 0x4332768, '81149e6a678e45054e1114816f9fb4013462c9a3286651867fd8c1e2670c9309'),
    ('pthread_create_adapter', 0x4ee4ab0, 0x4ee4cab, '3c5eee1281aba531659e88b44863b1aef9a3a71b5d1e8d41dd99ffb21db2f1ad'),
    ('pthread_entry', 0x4ee48b0, 0x4ee4aad, 'ff0db3069a51bb7de3b2dac52e2fc4700527ac45ac942f72b72716e1357016cd'),
    ('slow_callback', 0x433a350, 0x433a5e1, 'dff5190808ff9783659dfbee41a66af6f53a46cba69bba61a366db7f592aaad7'),
    ('slow_callback_drop', 0x4340ae0, 0x4340b53, 'd93abd5c220e27978266c3783780f151deef71333835c0fa6a1b992e7e3a0f31'),
    ('slow_process_wrapper', 0x474a0f0, 0x474a4e7, 'a70cdb74ba076ffc7079d7be980e0b7c53e337887558aa5ee6ac9f7c89b401cd'),
    ('protected_dispatch', 0x4528a00, 0x4528d25, 'f25881e38c6032f7e4ada49052656fe375e8451f47168d57bb811a470c4d6f78'),
    ('protected_replace', 0x4527ab0, 0x4527d3e, '5f8a4d047fb081c5e019a1a133e82468dc7e6fd3bf3d53b974b187758f0c1832'),
)

# Fixed branch encodings, with destinations computed from signed bytes.
BRANCHES = (
    (0x474ac32, '0f848c010000'),
    (0x474ac53, '0f8eec030000'),
    (0x474ad2a, '0f86a9000000'),
    (0x474ad35, '0f8e0a030000'),
    (0x474ad4b, '0f84a5000000'),
    (0x474adb9, '0f84a0000000'),
    (0x474adf0, '0f855bffffff'),
    (0x474ae00, '7417'),
    (0x474ae06, '7511'),
    (0x474ae27, '0f8408020000'),
    (0x474ae5d, '750b'),
    (0x474af2e, '0f84cf000000'),
    (0x474afa7, '7407'),
    (0x4332128, '0f85c1000000'),
    (0x433213b, '7408'),
    (0x4332179, '7468'),
    (0x433219e, '742a'),
    (0x43321a8, '7420'),
    (0x43321b3, '0f851a030000'),
    (0x43321bf, '7409'),
    (0x43321c4, '0f850c030000'),
    (0x43321d6, '740b'),
    (0x4332204, '0f84b6020000'),
    (0x4332217, '75e7'),
    (0x433221c, '7504'),
    (0x4332248, '0f8486030000'),
    (0x433227a, '741c'),
    (0x43322d6, '0f84b7020000'),
    (0x43322ff, '0f8edf020000'),
    (0x4332395, '740b'),
    (0x433239c, '0f8e27020000'),
    (0x43323c8, '0f84d7010000'),
    (0x43323f0, '0f8eee010000'),
    (0x433241f, '0f8492010000'),
    (0x4332444, '7449'),
    (0x433245f, '750b'),
    (0x4332475, '7532'),
    (0x43324f4, '7345'),
    (0x43324f9, '0f848c000000'),
    (0x4332514, '0f87b3fcffff'),
    (0x4332534, '75d4'),
    (0x4332553, '0f847afcffff'),
    (0x433255f, '0f8068fcffff'),
    (0x4332579, '0f874efcffff'),
    (0x4332584, '74c7'),
    (0x4ee4ad2, '0f8502010000'),
    (0x4ee4ae7, '7413'),
    (0x4ee4aed, '0f8408010000'),
    (0x4ee4b12, '745d'),
    (0x4ee4b1a, '0f8504010000'),
    (0x4ee4b44, '742b'),
    (0x4ee4b55, '0f8506010000'),
    (0x4ee4b93, '741d'),
    (0x4ee4bc7, '757c'),
    (0x4ee4c19, '0f85d4feffff'),
    (0x4ee48c7, '0f8e5f010000'),
    (0x4ee48e0, '751a'),
    (0x4ee48f5, '7436'),
    (0x4ee48fa, '7435'),
    (0x4ee4947, '7413'),
    (0x4ee4958, '7526'),
    (0x4ee4966, '744a'),
    (0x4ee496b, '7545'),
    (0x4ee49bf, '7509'),
    (0x4ee49f2, '7421'),
    (0x433a4a5, '7449'),
    (0x433a4ae, '7440'),
    (0x433a4bb, '7409'),
    (0x433a4cd, '7421'),
    (0x433a50a, '750b'),
    (0x433a5d0, '0f85d1feffff'),
    (0x433a5d6, 'e915ffffff'),
    (0x4340b00, '7514'),
    (0x4340b36, '750d'),
    (0x4ee4bb0, 'eb06'),
    (0x4ee4b6f, 'eb58'),
    (0x433248d, 'eb1a'),
    (0x4ee4a66, 'eb39'),
    (0x4ee4a73, 'eb2c'),
    (0x4ee4a80, '7517'),
    (0x4ee4a8d, '750a'),
    (0x474a133, '0f8522010000'), (0x474a13e, '7454'),
    (0x474a165, '0f8447010000'), (0x474a16e, '0f8520010000'),
    (0x474a2cd, '0f8430010000'), (0x474a39d, '0f8495000000'),
    (0x474a3a7, '7574'), (0x474a3bb, '7420'), (0x474a3c0, '0f8480feffff'),
    (0x474a3e2, '0f845efeffff'), (0x474a49e, '741c'),
    (0x474a4a3, '7434'), (0x474a4c1, '7416'),
    (0x4528a47, '0f850c020000'), (0x4528a8b, '7536'),
    (0x4528b19, '0f844f010000'), (0x4528b26, '0f8563010000'),
    (0x4528b4c, '0f8530010000'), (0x4528b9c, '7536'),
    (0x4528c0b, '740b'), (0x4528ccc, '743a'), (0x4528d06, '7508'),
    (0x4527af3, '0f858e010000'), (0x4527b4d, '7031'),
    (0x4527b5a, '750d'), (0x4527b6f, '740f'), (0x4527ba8, '0f85ed000000'),
    (0x4527bee, '7415'), (0x4527cea, '7436'), (0x4527d18, '7510'),
)

# Fixed instruction encodings for selected addresses and transfers.
REFERENCES = (
    ('boundary_slow_call', 0x2277292, 'ff15c8c84f03', 2),
    ('slow_name_a', 0x474ac63, '488d0d900afbfb', 3),
    ('slow_name_b', 0x474ad00, '488d05020afbfb', 3),
    ('slow_thread_builder', 0x474af1c, 'e8cf71beff', 1),
    ('slow_spawn_failure_text', 0x474b00b, '488d3d9200fbfb', 3),
    ('worker_table_ref', 0x4332405, '488d055ca73e01', 3),
    ('worker_thread_start_slot', 0x433243c, 'ff158ed14301', 2),
    ('pthread_entry_ref', 0x4ee4b79, '488d1530fdffff', 3),
    ('pthread_create_slot', 0x4ee4b8b, 'ff152f288900', 2),
    ('worker_loop_slot', 0x433a493, 'ff1567c14301', 2),
    ('worker_drop_fields', 0x4340aeb, 'e8f0220100', 1),
    ('worker_drop_context', 0x4340af3, 'e8d8bc0000', 1),
    ('overflow_helper', 0x43324c9, 'e8d293bb00', 1),
    ('pthread_attr_init_slot', 0x4ee4ac7, 'ff15e3288900', 2),
    ('pthread_attr_setstack_slot', 0x4ee4b0a, 'ff15a8288900', 2),
    ('pthread_attr_setstack_retry_slot', 0x4ee4b3c, 'ff1576288900', 2),
    ('pthread_attr_destroy_slot', 0x4ee4bbc, 'ff1526268900', 2),
    ('stack_size_sysconf_slot', 0x4ee4b25, 'ff157dbd8800', 2),
    ('worker_exception_conversion', 0x433a59e, 'ff1574414301', 2),
    ('pthread_entry_release', 0x4ee49d4, 'ff1536968800', 2),
    ('prior_loop_process_call', 0x432e67c, 'e86fba4100', 1),
    ('prior_loop_no_result_branch', 0x432e689, '0f849a000000', 2),
    ('prior_loop_replace_call', 0x432e6e0, 'e8cb931f00', 1),
    ('wrapper_dispatch_plain', 0x474a1d7, 'e824e8ddff', 1),
    ('wrapper_dispatch_tls', 0x474a31f, 'e8dce6ddff', 1),
    ('protected_dispatch_tls_match', 0x4528b36, 'e895f41400', 1),
    ('protected_dispatch_tls_empty', 0x4528c78, 'e863f21700', 1),
    ('protected_dispatch_tls_other', 0x4528c99, 'e8b2f61800', 1),
    ('replace_resume_unwind', 0x4527d25, 'e8e6831301', 1),
    ('dispatch_resume_unwind', 0x4528d0b, 'e800741301', 1),
    ('payload_memcpy_slot', 0x43323e1, 'ff15f9bb4301', 2),
)

# Fixed immediate operands and their little-endian field offsets.
CONSTANTS = (
    ('slow_block_name_length', 0x474ac6f, '48c78424800000000f000000', 8, 4),
    ('slow_driver_name_length', 0x474ad0f, '48c78424980000001b000000', 8, 4),
    ('spawn_error_length', 0x474b028, 'be16000000', 1, 4),
    ('worker_payload_size', 0x43323ba, 'bfa8000000', 1, 4),
    ('worker_envelope_size', 0x4332411, 'bf18000000', 1, 4),
    ('worker_method_offset', 0x4ee49e7, '41ff5718', 3, 1),
    ('pthread_error_shift', 0x4ee4ba3, '49c1e620', 3, 1),
    ('pthread_error_tag', 0x4ee4ba7, '4983ce02', 3, 1),
    ('stack_size_retry_error', 0x4ee4b17, '83f816', 2, 1),
    ('stack_size_floor', 0x4ee4adf, 'b900400000', 1, 4),
    ('stack_size_page_selector', 0x4ee4b20, 'bf1e000000', 1, 4),
)

# Boundary slots are used only to connect to prior-owned functions.
SLOTS = {
    0x5773b60: ('slow_driver_entry', 8, '', 0x474abe0),
    0x571cb68: ('worker_table_drop', 8, '', 0x4340ae0),
    0x571cb80: ('worker_table_call', 8, '', 0x433a350),
    0x576f5d0: ('pthread_adapter', 8, '', 0x4ee4ab0),
    0x5776600: ('worker_loop_boundary', 8, '', 0x432e4d0),
    0x57773b0: ('pthread_attr_init', 6, 'pthread_attr_init', 0),
    0x57773b8: ('pthread_set_stack', 6, 'pthread_attr_setstacksize', 0),
    0x57773c0: ('pthread_create', 6, 'pthread_create', 0),
    0x57771e8: ('thread_attributes_destroy', 6, 'pthread_attr_destroy', 0),
    0x576e718: ('exception_conversion', 8, '', 0x4e0b5b0),
    0x576e010: ('release', 8, '', 0x54c8cb0),
    0x57708a8: ('sysconf', 6, 'sysconf', 0),
    0x576dfe0: ('memcpy', 6, 'memcpy', 0),
}

OUTPUTS = ('functions.tsv', 'windows.tsv', 'branches.tsv', 'references.tsv',
           'decisions.tsv', 'constants.tsv', 'relocations.tsv', 'worker-vtable.tsv', 'thread-layout.tsv',
           'protected-layout.tsv', 'origin-layout.tsv', 'origin-operands.tsv',
           'literals.tsv', 'worker-lsda.tsv', 'processing-lsda.tsv', 'summary.json')

# Guard instructions are adjacent to their branches; their labels describe
# the checked predicate, not a recovered Rust type or whole control flow.
DECISIONS = (
    ('payload_allocation_null', 0x43323c5, '4885c0', 0x43323c8, '0f84d7010000'),
    ('refcount_increment_nonpositive', 0x43323ec, 'f048ff00', 0x43323f0, '0f8eee010000'),
    ('envelope_allocation_null', 0x433241c, '4885c0', 0x433241f, '0f8492010000'),
    ('adapter_low_bit_clear', 0x4332442, 'a801', 0x4332444, '7449'),
    ('slow_builder_result_zero', 0x474af2b, '4885c9', 0x474af2e, '0f84cf000000'),
    ('attribute_init_nonzero', 0x4ee4ad0, '85c0', 0x4ee4ad2, '0f8502010000'),
    ('stack_size_initial_zero', 0x4ee4b10, '85c0', 0x4ee4b12, '745d'),
    ('stack_size_error_not_22', 0x4ee4b17, '83f816', 0x4ee4b1a, '0f8504010000'),
    ('stack_size_retry_zero', 0x4ee4b42, '85c0', 0x4ee4b44, '742b'),
    ('thread_create_zero', 0x4ee4b91, '85c0', 0x4ee4b93, '741d'),
    ('attribute_destroy_nonzero', 0x4ee4bc5, '85c0', 0x4ee4bc7, '757c'),
    ('thread_refcount_increment_nonpositive', 0x4ee48c2, 'f049ff0424', 0x4ee48c7, '0f8e5f010000'),
    ('previous_completion_tag_zero', 0x433a4a0, '48837d1800', 0x433a4a5, '7449'),
    ('completion_refcount_nonzero', 0x433a505, 'f048ff4d00', 0x433a50a, '750b'),
    ('exception_previous_completion_nonzero', 0x433a5cb, '48837d1800', 0x433a5d0, '0f85d1feffff'),
    ('drop_refcount_nonzero', 0x4340afc, 'f048ff08', 0x4340b00, '7514'),
    ('dispatch_lock_contended', 0x4528a3d, 'f0490fb18c2468050000', 0x4528a47, '0f850c020000'),
    ('dispatch_unlock_contended', 0x4528b47, 'f0480fb10f', 0x4528b4c, '0f8530010000'),
    ('replace_lock_contended', 0x4527aea, 'f0490fb18f68050000', 0x4527af3, '0f858e010000'),
    ('replace_old_min_sentinel', 0x4527b46, '493b8770050000', 0x4527b4d, '7031'),
    ('replace_unlock_contended', 0x4527ba3, 'f0480fb10f', 0x4527ba8, '0f85ed000000'),
)

class EvidenceError(ValueError):
    """The captured bytes do not support the selected observation."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def authenticate(data):
    require(digest(data) == SHA256, 'node 94 SHA-256 mismatch')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def map_file(data, secs, va, size):
    """One allocated, file-backed section must own the entire requested range."""
    require(0 <= va < (1 << 64) and 0 < size <= (1 << 64) - va,
            'invalid virtual-address range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'range lacks one unambiguous file-backed section')
    s = matches[0]
    offset = s['offset'] + va - s['address']
    require(0 <= offset <= len(data) and size <= len(data) - offset, 'range outside file')
    return s, offset


class Image:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 LE')
        require(struct.unpack_from('<HH', data, 16) == (3, 62), 'expected x86-64 ET_DYN')
        self.secs = sections(data)
        names = [s['name'] for s in self.secs]
        require(len(names) == len(set(names)), 'duplicate section names')
        self.by_name = {s['name']: s for s in self.secs}
        for name in ('.text', '.rodata', '.data.rel.ro', '.rela.dyn', '.dynsym',
                     '.dynstr', '.eh_frame', '.eh_frame_hdr', '.gcc_except_table'):
            require(name in self.by_name and self.by_name[name]['type'] != 8,
                    'missing file-backed section ' + name)
        require(self.by_name['.text']['flags'] & 4, 'text section is not executable')

    def read(self, va, size):
        section, offset = map_file(self.data, self.secs, va, size)
        return bytes(self.data[offset:offset + size])

    def where(self, va, size):
        section, offset = map_file(self.data, self.secs, va, size)
        return section['name'], offset


def fixed(image, va, expected):
    expected_bytes = bytes.fromhex(expected)
    actual = image.read(va, len(expected_bytes))
    require(actual == expected_bytes, f'instruction mismatch at {va:#x}')
    return actual


def capture_windows(image):
    out = []
    for label, start, end, expected in WINDOWS:
        require(end > start, 'empty window')
        b = image.read(start, end - start)
        require(digest(b) == expected, 'window hash mismatch: ' + label)
        section, off = image.where(start, len(b))
        require(section == '.text', 'window not in text')
        out.append((label, hex(start), hex(end), hex(off), b.hex(), digest(b)))
    return out


def select_functions(image):
    _, records, _ = fde_extents(image.data)
    result = []
    by_start = {}
    for row in records:
        by_start.setdefault(row['start'], []).append(row)
    for name, start, expected_end, expected_hash in FUNCTIONS:
        found = by_start.get(start, [])
        require(len(found) == 1 and 'index' in found[0], 'FDE start absent or ambiguous')
        row = found[0]
        require(row['end'] == expected_end, 'unexpected FDE end')
        b = image.read(start, row['end'] - start)
        require(digest(b) == expected_hash, 'FDE body hash mismatch')
        section, off = image.where(start, len(b))
        require(section == '.text', 'FDE does not fit file-backed text')
        result.append((name, row, off, digest(b)))
    return result


def branch_row(image, va, expected):
    b = fixed(image, va, expected)
    if len(b) == 2 and 0x70 <= b[0] <= 0x7f:
        cc, disp, kind = b[0] - 0x70, struct.unpack_from('<b', b, 1)[0], 'conditional'
    elif len(b) == 6 and b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
        cc, disp, kind = b[1] - 0x80, struct.unpack_from('<i', b, 2)[0], 'conditional'
    elif len(b) == 2 and b[0] == 0xeb:
        cc, disp, kind = None, struct.unpack_from('<b', b, 1)[0], 'jump'
    elif len(b) == 5 and b[0] == 0xe9:
        cc, disp, kind = None, struct.unpack_from('<i', b, 1)[0], 'jump'
    else:
        raise EvidenceError('unsupported branch encoding')
    target = va + len(b) + disp
    owners = [(start, end) for _, start, end, _ in FUNCTIONS if start <= va < end]
    require(len(owners) == 1 and owners[0][0] <= target < owners[0][1],
            'branch target outside its selected extent')
    return (hex(va), hex(image.where(va, len(b))[1]), b.hex(), kind,
            '' if cc is None else hex(cc), str(disp), hex(va + len(b)), hex(target))


def decision_row(image, label, guard_va, guard_hex, branch_va, branch_hex):
    guard = fixed(image, guard_va, guard_hex)
    require(guard_va + len(guard) == branch_va, 'guard is not adjacent to branch')
    branch = branch_row(image, branch_va, branch_hex)
    require(branch[3] == 'conditional', 'decision does not have a conditional branch')
    return (label, hex(guard_va), hex(image.where(guard_va, len(guard))[1]), guard.hex(),
            *branch)


def reference_row(image, label, va, expected, displacement_offset):
    b = fixed(image, va, expected)
    require(displacement_offset + 4 == len(b), 'invalid reference displacement')
    displacement = struct.unpack_from('<i', b, displacement_offset)[0]
    target = va + len(b) + displacement
    require(0 <= target < (1 << 64), 'reference target overflow')
    return (label, hex(va), hex(image.where(va, len(b))[1]), b.hex(),
            str(displacement), hex(target))


def constant_row(image, label, va, expected, offset, size):
    b = fixed(image, va, expected)
    require(0 <= offset < len(b) and 0 < size <= len(b) - offset, 'invalid constant field')
    value = int.from_bytes(b[offset:offset + size], 'little')
    return (label, hex(va), hex(image.where(va, len(b))[1]), b.hex(), str(value), hex(value))


def dynamic_name(image, index):
    sym = image.by_name['.dynsym']
    strings = image.by_name['.dynstr']
    require(sym['type'] == 11 and strings['type'] == 3 and sym['size'] % 24 == 0,
            'invalid dynamic symbol or string section')
    require(0 <= index < sym['size'] // 24, 'dynamic symbol index outside table')
    at = sym['offset'] + index * 24
    name_offset, _info, _other, section_index, _value, _size = struct.unpack_from('<IBBHQQ', image.data, at)
    require(name_offset < strings['size'], 'dynamic name outside string table')
    begin = strings['offset'] + name_offset
    end = image.data.find(b'\0', begin, strings['offset'] + strings['size'])
    require(end >= 0, 'unterminated dynamic symbol')
    try:
        name = bytes(image.data[begin:end]).decode('ascii')
    except UnicodeDecodeError as exc:
        raise EvidenceError('non-ASCII dynamic symbol') from exc
    return name, section_index


def selected_relocations(image):
    rel = image.by_name['.rela.dyn']
    require(rel['type'] == 4 and rel['size'] % 24 == 0, 'invalid relocation section')
    found = {}
    for delta in range(0, rel['size'], 24):
        pos = rel['offset'] + delta
        slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
        if slot not in SLOTS:
            continue
        require(slot not in found, 'duplicate selected relocation slot')
        label, expected_type, expected_name, expected_addend = SLOTS[slot]
        typ, symbol = info & 0xffffffff, info >> 32
        require(typ == expected_type and addend == expected_addend, 'relocation type/addend mismatch')
        if typ == 8:
            require(symbol == 0, 'relative relocation has a symbol')
            symbol_name = ''
        else:
            require(symbol != 0, 'dynamic relocation lacks a symbol')
            symbol_name, section_index = dynamic_name(image, symbol)
            require(symbol_name == expected_name and section_index == 0,
                    'dynamic relocation names unexpected or defined symbol')
        pre_relocation = image.read(slot, 8)
        require(pre_relocation == b'\0' * 8, 'unexpected pre-relocation slot bytes')
        found[slot] = {'label': label, 'slot': slot, 'type': typ, 'symbol': symbol,
                       'symbol_name': symbol_name, 'addend': addend, 'file_offset': pos,
                       'record_va': rel['address'] + delta, 'raw': bytes(image.data[pos:pos + 24]).hex(),
                       'slot_raw': pre_relocation.hex()}
    require(set(found) == set(SLOTS), 'missing selected relocation')
    return found


def worker_table_rows(image, relocations, table_va):
    require(table_va == 0x571cb68, 'unexpected worker table')
    b = image.read(table_va, 32)
    words = struct.unpack('<4Q', b)
    require(words == (0, 168, 8, 0), 'unexpected worker table words')
    rows = []
    for index, word in enumerate(words):
        slot = table_va + index * 8
        reloc = relocations.get(slot)
        rows.append((str(index * 8), hex(slot), hex(image.where(slot, 8)[1]),
                     b[index * 8:index * 8 + 8].hex(), str(word),
                     '' if reloc is None else str(reloc['type']),
                     '' if reloc is None else hex(reloc['addend'])))
    require(relocations[table_va]['addend'] == 0x4340ae0 and
            relocations[table_va + 24]['addend'] == 0x433a350,
            'worker table relocation mismatch')
    return rows


THREAD_LAYOUT = (
    ('control_to_stack', 0x43323fb, '4889442458'),
    ('payload_to_stack', 0x4332400, '48895c2460'),
    ('vtable_to_stack', 0x433240c, '4889442468'),
    ('vtable_reload', 0x4332425, '488b4c2468'),
    ('vtable_to_envelope', 0x433242a, '48894810'),
    ('pair_reload', 0x433242e, '0f10442458'),
    ('pair_to_envelope', 0x4332433, '0f1100'),
    ('payload_reload', 0x4ee49b2, '4c8b7308'),
    ('vtable_reload_thread', 0x4ee49b6, '4c8b7b10'),
    ('payload_argument', 0x4ee49e4, '4c89f7'),
    ('vtable_dispatch', 0x4ee49e7, '41ff5718'),
    ('worker_normal_first_zero', 0x433a499, '4531f6'),
    ('completion_tag_one', 0x433a4f0, '48c7451801000000'),
    ('completion_first_word', 0x433a4f8, '4c897520'),
    ('completion_second_word', 0x433a4fc, '4c897d28'),
    ('exception_conversion', 0x433a59e, 'ff1574414301'),
    ('exception_first_word', 0x433a5a4, '4989c6'),
    ('exception_second_word', 0x433a5a7, '4989d7'),
    ('exception_join', 0x433a5d6, 'e915ffffff'),
    ('worker_original_word', 0x433a3ca, '4c8b3f'),
    ('worker_loop_payload', 0x433a440, '488d4328'),
    ('worker_completion_pointer', 0x433a49c, '488b6b20'),
    ('worker_exception_completion_pointer', 0x433a5c7, '488b6b20'),
    ('builder_result_test', 0x4332442, 'a801'),
    ('builder_failure_payload', 0x433244b, '48895008'),
    ('builder_failure_tag', 0x433244f, '48c70000000000'),
    ('builder_success_first', 0x433249e, '488906'),
    ('builder_success_handle', 0x43324a5, '48895610'),
    ('slow_result_load', 0x474af21, '488b4c2410'),
    ('slow_result_test', 0x474af2b, '4885c9'),
    ('pthread_failure_tag', 0x4ee4bab, 'bb01000000'),
    ('pthread_success_tag', 0x4ee4bb6, '31db'),
    ('pthread_return_tag', 0x4ee4bc9, '4889d8'),
    ('pthread_return_payload', 0x4ee4bcc, '4c89f2'),
)

def checked_layout_rows(image, specs):
    rows = []
    for label, va, expected in specs:
        b = fixed(image, va, expected)
        rows.append((label, hex(va), hex(image.where(va, len(b))[1]), b.hex()))
    return rows


def thread_layout_rows(image):
    return checked_layout_rows(image, THREAD_LAYOUT)


# The first four sites are boundary context in the previously inventoried loop.
PROTECTED_LAYOUT = (
    ('loop_dispatch_base', 0x432e627, '498b7570'),
    ('loop_dispatch_adjust', 0x432e62b, '4883c610'),
    ('loop_replace_base', 0x432e68f, '498b7d78'),
    ('loop_replace_adjust', 0x432e6be, '488d7710'),
    ('loop_output_address', 0x432e668, '488dbc24d0000000'),
    ('loop_result_guard', 0x432e681, '4c39a424d0000000'),
    ('loop_result_load_tail', 0x432e693, '488b8424f0000000'),
    ('loop_result_stack_tail', 0x432e69b, '4889442430'),
    ('loop_result_load_first', 0x432e6a0, '660f108424d0000000'),
    ('loop_result_load_middle', 0x432e6a9, '660f108c24e0000000'),
    ('loop_result_stack_middle', 0x432e6b2, '660f294c2420'),
    ('loop_result_stack_first', 0x432e6b8, '660f29442410'),
    ('loop_replace_result_arg', 0x432e6d4, '488d542410'),
    ('wrapper_save_base', 0x474a10a, '4889f5'),
    ('wrapper_plain_base_arg', 0x474a1ce, '4889ea'),
    ('wrapper_tls_base_arg', 0x474a316, '4889ea'),
    ('wrapper_plain_load_tail', 0x474a22a, '488b442440'),
    ('wrapper_plain_store_tail', 0x474a22f, '49894720'),
    ('wrapper_plain_load_first', 0x474a233, '0f28442420'),
    ('wrapper_plain_load_middle', 0x474a238, '0f284c2430'),
    ('wrapper_plain_store_middle', 0x474a23d, '410f114f10'),
    ('wrapper_plain_store_first', 0x474a242, '410f1107'),
    ('wrapper_tls_load_tail', 0x474a372, '488b442440'),
    ('wrapper_tls_store_tail', 0x474a377, '49894720'),
    ('wrapper_tls_load_first', 0x474a37b, '0f28442420'),
    ('wrapper_tls_load_middle', 0x474a380, '0f284c2430'),
    ('wrapper_tls_store_middle', 0x474a385, '410f114f10'),
    ('wrapper_tls_store_first', 0x474a38a, '410f1107'),
    ('dispatch_save_base', 0x4528a14, '4989d4'),
    ('dispatch_lock_address', 0x4528a29, '498d842468050000'),
    ('dispatch_lock_desired', 0x4528a36, 'b908000000'),
    ('dispatch_lock_expected', 0x4528a3b, '31c0'),
    ('dispatch_payload_address', 0x4528af1, '4981c470050000'),
    ('dispatch_tls_load', 0x4528b12, '64488b11'),
    ('dispatch_tls_test', 0x4528b16, '4885d2'),
    ('dispatch_tls_compare', 0x4528b1f, '48398210010000'),
    ('replace_save_base', 0x4527ac6, '4989f7'),
    ('replace_lock_address', 0x4527ad8, '498d8768050000'),
    ('replace_lock_desired', 0x4527ae3, 'b908000000'),
    ('replace_lock_expected', 0x4527ae8, '31c0'),
    ('replace_payload_address', 0x4527b3d, '4d8db770050000'),
    ('replace_sentinel_compare_zero', 0x4527b44, '31c0'),
    ('normal_copy_load_tail', 0x4527b80, '488b4320'),
    ('normal_copy_store_tail', 0x4527b84, '49894620'),
    ('normal_copy_load_first', 0x4527b88, '0f1003'),
    ('normal_copy_load_middle', 0x4527b8b, '0f104b10'),
    ('normal_copy_store_middle', 0x4527b8f, '410f114e10'),
    ('normal_copy_store_first', 0x4527b94, '410f1106'),
    ('cleanup_copy_load_tail', 0x4527cc2, '488b4320'),
    ('cleanup_copy_store_tail', 0x4527cc6, '49894620'),
    ('cleanup_copy_load_first', 0x4527cca, '0f1003'),
    ('cleanup_copy_load_middle', 0x4527ccd, '0f104b10'),
    ('cleanup_copy_store_middle', 0x4527cd1, '410f114e10'),
    ('cleanup_copy_store_first', 0x4527cd6, '410f1106'),
    ('replace_cleanup_unlock', 0x4527ce5, 'f0480fb10a'),
    ('dispatch_cleanup_unlock', 0x4528cc7, 'f0480fb10a'),
)


def protected_layout_rows(image):
    return checked_layout_rows(image, PROTECTED_LAYOUT)


# These selected instructions establish the transfer of the constructor's
# second and third arguments through the copied payload to the loop's input.
ORIGIN_LAYOUT = (
    ('save_third_argument', 0x474abf4, '4989d7'),
    ('save_second_argument', 0x474abf7, '4989f6'),
    ('save_second_to_stack', 0x474acab, '4c89b42410010000'),
    ('save_third_to_stack', 0x474acf8, '4c89bc2418010000'),
    ('constructor_load_pair', 0x474ae74, '0f288c2410010000'),
    ('constructor_store_pair', 0x474ae7c, '0f298c2490010000'),
    ('constructor_record_pointer', 0x474aefe, '488d842420010000'),
    ('constructor_stack_argument', 0x474af06, '48890424'),
    ('builder_saved_registers', 0x43320f0, '55415741564155415453'),
    ('builder_frame_allocation', 0x43320fa, '4881eca8010000'),
    ('builder_stack_argument', 0x4332305, '488b8c24e0010000'),
    ('builder_load_pair', 0x433230d, '0f104170'),
    ('builder_store_pair', 0x4332311, '0f11842498010000'),
    ('builder_payload_source', 0x43323d1, '488db42400010000'),
    ('builder_payload_copy_size', 0x43323d9, 'baa8000000'),
    ('builder_payload_destination', 0x43323de, '4889c7'),
    ('worker_record_pointer', 0x433a440, '488d4328'),
    ('worker_load_pair', 0x433a444, '0f104070'),
    ('worker_store_pair', 0x433a448, '0f29842480000000'),
    ('worker_loop_argument', 0x433a48e, '488d7c2410'),
    ('loop_save_argument_boundary', 0x432e4e1, '4989fd'),
    ('loop_second_argument_boundary', 0x432e627, '498b7570'),
    ('loop_third_argument_boundary', 0x432e68f, '498b7d78'),
)

# The operand fields are read from the pinned encodings, then reconciled as
# offsets. The prologue's six pushes and the return address occupy 56 bytes.
ORIGIN_OPERANDS = (
    ('constructor_second_stack', 0x474acab, '4c89b42410010000', 4, 4),
    ('constructor_third_stack', 0x474acf8, '4c89bc2418010000', 4, 4),
    ('constructor_pair_load_stack', 0x474ae74, '0f288c2410010000', 4, 4),
    ('constructor_pair_store_stack', 0x474ae7c, '0f298c2490010000', 4, 4),
    ('constructor_record_base', 0x474aefe, '488d842420010000', 4, 4),
    ('builder_frame_size', 0x43320fa, '4881eca8010000', 3, 4),
    ('builder_stack_argument', 0x4332305, '488b8c24e0010000', 4, 4),
    ('builder_pair_input', 0x433230d, '0f104170', 3, 1),
    ('builder_pair_stack', 0x4332311, '0f11842498010000', 4, 4),
    ('builder_payload_stack', 0x43323d1, '488db42400010000', 4, 4),
    ('builder_payload_copy_size', 0x43323d9, 'baa8000000', 1, 4),
    ('worker_record_offset', 0x433a440, '488d4328', 3, 1),
    ('worker_pair_input', 0x433a444, '0f104070', 3, 1),
    ('worker_pair_stack', 0x433a448, '0f29842480000000', 4, 4),
    ('worker_loop_stack', 0x433a48e, '488d7c2410', 4, 1),
    ('loop_second_offset', 0x432e627, '498b7570', 3, 1),
    ('loop_third_offset', 0x432e68f, '498b7d78', 3, 1),
)


def origin_rows(image):
    layout = checked_layout_rows(image, ORIGIN_LAYOUT)
    operands = [constant_row(image, *row) for row in ORIGIN_OPERANDS]
    v = {row[0]: int(row[-2]) for row in operands}
    require(v['constructor_pair_load_stack'] == v['constructor_second_stack'] and
            v['constructor_third_stack'] == v['constructor_second_stack'] + 8 and
            v['constructor_pair_store_stack'] - v['constructor_record_base'] == v['builder_pair_input'] and
            v['builder_stack_argument'] == v['builder_frame_size'] + 56 and
            v['builder_pair_stack'] - v['builder_payload_stack'] ==
            v['worker_record_offset'] + v['worker_pair_input'] and
            v['worker_pair_input'] == v['worker_pair_stack'] - v['worker_loop_stack'] ==
            v['loop_second_offset'] and v['loop_third_offset'] == v['loop_second_offset'] + 8 and
            v['worker_record_offset'] + v['worker_pair_input'] + 16 <= v['builder_payload_copy_size'],
            'argument-origin offset chain mismatch')
    return layout, operands


def literal_rows(image, refs, vals):
    specs = (
        ('slow_block', 'slow_name_a', 'slow_block_name_length', b'slow abci block'),
        ('slow_state_driver', 'slow_name_b', 'slow_driver_name_length', b'node slow abci_state driver'),
        ('spawn_failure', 'slow_spawn_failure_text', 'spawn_error_length', b'failed to spawn thread'),
    )
    rows = []
    for label, ref, size, expected in specs:
        va, length = refs[ref], vals[size]
        actual = image.read(va, length)
        require(length == len(expected) and actual == expected, 'literal mismatch')
        rows.append((label, hex(va), hex(image.where(va, length)[1]), str(length),
                     actual.hex(), actual.decode('ascii')))
    return rows


def pthread_result(error, handle):
    """Model the checked adapter result on a normal attribute-destroy return."""
    require(0 <= error <= 0xffffffff and 0 <= handle < (1 << 64), 'invalid synthetic word')
    return (0, handle) if error == 0 else (1, (error << 32) | 2)


def callsite_table(image, fde):
    """Decode an observed ULEB call-site table, with bounded reads.

    Pointer encodings other than the captured omitted LPStart and indirect
    PC-relative signed-four-byte type pointer are deliberately unsupported.
    Shared ULEB/SLEB readers supply all variable-length integer decoding.
    """
    start, end, lsda = fde['start'], fde['end'], fde['lsda']
    require(lsda is not None, 'missing LSDA')
    sec, offset = map_file(image.data, image.secs, lsda, 1)
    require(sec['name'] == '.gcc_except_table', 'LSDA not in exception table')
    limit = sec['offset'] + sec['size']
    require(offset + 2 <= limit and bytes(image.data[offset:offset + 2]) == b'\xff\x9b',
            'unsupported LSDA header')
    p = offset + 2
    type_offset, p = uleb(image.data, p, limit)
    type_end = p + type_offset
    require(p < type_end <= limit and image.data[p] == 1, 'unsupported LSDA call-site encoding')
    call_site_encoding = image.data[p]
    p += 1
    table_size, p = uleb(image.data, p, type_end)
    table_start, table_end = p, p + table_size
    require(table_end <= type_end, 'LSDA call-site table outside type table')
    rows, previous_end = [], start
    while p < table_end:
        entry_start = p
        pc_offset, p = uleb(image.data, p, table_end)
        pc_size, p = uleb(image.data, p, table_end)
        landing, p = uleb(image.data, p, table_end)
        action, p = uleb(image.data, p, table_end)
        first, last = start + pc_offset, start + pc_offset + pc_size
        require(previous_end <= first < last <= end, 'invalid or overlapping LSDA call-site range')
        previous_end = last
        pad = start + landing if landing else None
        require(pad is None or start <= pad < end, 'LSDA landing pad outside FDE')
        require(landing or action == 0, 'action without a landing pad')
        if action:
            require(table_end + action - 1 < type_end, 'LSDA action outside action table')
        rows.append({'start': first, 'end': last, 'landing': pad, 'action': action,
                     'raw': bytes(image.data[entry_start:p]).hex(), 'file_offset': entry_start})
    require(p == table_end, 'unexpected LSDA table boundary')
    details = {'lsda_va': hex(lsda), 'lsda_file_offset': hex(offset),
               'lpstart_encoding': image.data[offset], 'type_encoding': image.data[offset + 1],
               'call_site_encoding': call_site_encoding, 'table_size': table_size,
               'table_va': hex(sec['address'] + table_start - sec['offset']),
               'action_table_va': hex(sec['address'] + table_end - sec['offset']),
               'type_table_end_va': hex(sec['address'] + type_end - sec['offset'])}
    return rows, details, table_end, type_end, limit


def worker_lsda_rows(image, fde):
    require((fde['start'], fde['end'], fde['lsda']) ==
            (0x433a350, 0x433a5e1, 0xb29cb0), 'unexpected worker FDE for LSDA')
    rows, details, table_end, type_end, limit = callsite_table(image, fde)
    require(len(rows) == 8, 'unexpected worker LSDA table')
    covered = [r for r in rows if r['start'] <= 0x433a493 and 0x433a499 <= r['end']]
    require(len(covered) == 1 and covered[0]['landing'] == 0x433a586 and
            covered[0]['action'] == 7, 'worker call exception row mismatch')
    action_at = table_end + covered[0]['action'] - 1
    type_filter, p = sleb(image.data, action_at, type_end - 4)
    next_action, action_after = sleb(image.data, p, type_end - 4)
    require((type_filter, next_action) == (1, 0), 'unexpected worker exception action')
    type_entry = type_end - 4 * type_filter
    require(type_entry >= table_end and type_entry + 4 <= limit and
            bytes(image.data[type_entry:type_entry + 4]) == b'\0' * 4,
            'worker exception type entry changed')
    details.update({'worker_call_action': covered[0]['action'],
                    'worker_call_landing': hex(covered[0]['landing']),
                    'worker_call_action_bytes': bytes(image.data[action_at:action_after]).hex(),
                    'worker_call_type_filter': type_filter, 'worker_call_next_action': next_action,
                    'worker_call_type_entry_bytes': bytes(image.data[type_entry:type_entry + 4]).hex()})
    return rows, details


def processing_lsda_rows(image, functions):
    specs = (
        ('slow_process_wrapper', 0x474a0f0, 0x474a4e7, 0xb7192c, 15,
         ((0x474a1d7, 0x474a1dc, None, 0), (0x474a31f, 0x474a324, 0x474a45c, 0))),
        ('protected_dispatch', 0x4528a00, 0x4528d25, 0xb4a81c, 14,
         ((0x4528b36, 0x4528b3b, 0x4528cb8, 0),
          (0x4528c78, 0x4528c7d, 0x4528cb8, 0),
          (0x4528c99, 0x4528c9e, 0x4528cb8, 0))),
        ('protected_replace', 0x4527ab0, 0x4527d3e, 0xb4a6bc, 10,
         ((0x4527b63, 0x4527b69, 0x4527ca8, 0),)),
    )
    result, details = [], {}
    by_name = {name: row for name, row, _, _ in functions}
    for name, start, end, lsda, count, checks in specs:
        fde = by_name[name]
        require((fde['start'], fde['end'], fde['lsda']) == (start, end, lsda),
                'unexpected processing FDE for LSDA')
        rows, detail, _, _, _ = callsite_table(image, fde)
        require(len(rows) == count, 'unexpected processing LSDA table')
        for first, last, landing, action in checks:
            covered = [row for row in rows if row['start'] <= first and last <= row['end']]
            require(len(covered) == 1 and
                    (covered[0]['landing'], covered[0]['action']) == (landing, action),
                    'processing call exception row mismatch')
        for row in rows:
            result.append((name, hex(row['start']), hex(row['end']),
                           '' if row['landing'] is None else hex(row['landing']),
                           str(row['action']), hex(row['file_offset']), row['raw']))
        details[name] = detail
    return result, details


def tsv(headers, rows):
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()


def analyse(data):
    authenticate(data)
    image = Image(data)
    functions = select_functions(image)
    windows = capture_windows(image)
    branches = [branch_row(image, va, expected) for va, expected in BRANCHES]
    decisions = [decision_row(image, *row) for row in DECISIONS]
    references = [reference_row(image, *row) for row in REFERENCES]
    constants = [constant_row(image, *row) for row in CONSTANTS]
    relocations = selected_relocations(image)
    refs = {r[0]: int(r[-1], 16) for r in references}
    vals = {r[0]: int(r[-2]) for r in constants}
    require(refs['boundary_slow_call'] == 0x5773b60 and
            relocations[0x5773b60]['addend'] == 0x474abe0 and
            refs['slow_thread_builder'] == 0x43320f0 and
            refs['worker_thread_start_slot'] == 0x576f5d0 and
            refs['pthread_entry_ref'] == 0x4ee48b0 and
            refs['pthread_create_slot'] == 0x57773c0 and
            refs['payload_memcpy_slot'] == 0x576dfe0 and
            refs['worker_loop_slot'] == 0x5776600, 'worker handoff reference mismatch')
    require(refs['prior_loop_process_call'] == 0x474a0f0 and
            refs['prior_loop_replace_call'] == 0x4527ab0 and
            refs['wrapper_dispatch_plain'] == refs['wrapper_dispatch_tls'] == 0x4528a00 and
            refs['protected_dispatch_tls_match'] == 0x4677fd0 and
            refs['protected_dispatch_tls_empty'] == 0x46a7ee0 and
            refs['protected_dispatch_tls_other'] == 0x46b8350,
            'protected processing handoff mismatch')
    require(vals['worker_payload_size'] == 168 and vals['worker_envelope_size'] == 24 and
            vals['worker_method_offset'] == 24 and vals['pthread_error_shift'] == 32 and
            vals['pthread_error_tag'] == 2, 'worker ABI constants changed')
    worker_table = worker_table_rows(image, relocations, refs['worker_table_ref'])
    thread_layout = thread_layout_rows(image)
    protected_layout = protected_layout_rows(image)
    origin_layout, origin_operands = origin_rows(image)
    literals = literal_rows(image, refs, vals)
    worker = next(row for name, row, _, _ in functions if name == 'slow_callback')
    worker_lsda, worker_lsda_detail = worker_lsda_rows(image, worker)
    processing_lsda, processing_lsda_detail = processing_lsda_rows(image, functions)
    rel_rows = []
    for slot, row in sorted(relocations.items()):
        rel_rows.append((row['label'], hex(slot), hex(row['record_va']), hex(row['file_offset']),
                         row['raw'], str(row['type']), str(row['symbol']), row['symbol_name'],
                         hex(row['addend']), row['slot_raw']))
    function_rows = []
    for name, fde, off, sha in functions:
        function_rows.append((name, hex(fde['start']), hex(fde['end']),
                              str(fde['end'] - fde['start']), hex(off), hex(fde['fde']),
                              hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']), sha))
    worker_lsda_output = [(hex(r['start']), hex(r['end']), '' if r['landing'] is None else hex(r['landing']),
                           str(r['action']), hex(r['file_offset']), r['raw']) for r in worker_lsda]
    summary = {
        'target_sha256': digest(data),
        'coordinates': 'ELF link-time virtual addresses and file offsets',
        'counts': {'new_fde_extents': len(functions), 'byte_windows': len(windows),
                   'selected_branches_and_jumps': len(branches), 'selected_guarded_decisions': len(decisions),
                   'selected_rip_or_rel32_references': len(references),
                   'selected_immediates': len(constants), 'selected_relocations': len(relocations),
                   'worker_lsda_call_site_rows': len(worker_lsda), 'worker_table_words': len(worker_table),
                   'processing_lsda_call_site_rows': len(processing_lsda),
                   'thread_layout_sites': len(thread_layout), 'protected_layout_sites': len(protected_layout),
                   'origin_layout_sites': len(origin_layout), 'origin_immediate_operands': len(origin_operands),
                   'length_bound_literals': len(literals)},
        'worker_lsda': worker_lsda_detail, 'processing_lsda': processing_lsda_detail,
        'constraints': ['selected static instructions only', 'no execution or network',
                        'prior loader and loop are boundary context',
                        'FDE extents are not a whole-function coverage denominator'],
    }
    outputs = {
        'functions.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'size', 'file_offset',
                              'fde_va', 'cie_va', 'lsda_va', 'sha256'), function_rows),
        'windows.tsv': tsv(('role', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes', 'sha256'), windows),
        'branches.tsv': tsv(('site_va', 'file_offset', 'bytes', 'kind', 'condition_code', 'signed_disp',
                             'fallthrough_va', 'target_va'), branches),
        'decisions.tsv': tsv(('role', 'guard_va', 'guard_file_offset', 'guard_bytes', 'branch_va',
                              'branch_file_offset', 'branch_bytes', 'kind', 'condition_code',
                              'signed_disp', 'fallthrough_va', 'target_va'), decisions),
        'references.tsv': tsv(('role', 'site_va', 'file_offset', 'bytes', 'signed_disp', 'target_va'), references),
        'constants.tsv': tsv(('role', 'site_va', 'file_offset', 'bytes', 'value', 'value_hex'), constants),
        'relocations.tsv': tsv(('role', 'slot_va', 'rela_va', 'rela_file_offset', 'rela_bytes', 'type',
                                'symbol_index', 'symbol_name', 'addend', 'captured_slot_bytes'), rel_rows),
        'worker-vtable.tsv': tsv(('byte_offset', 'slot_va', 'file_offset', 'captured_bytes', 'captured_word',
                                  'relocation_type', 'relocation_addend'), worker_table),
        'thread-layout.tsv': tsv(('role', 'site_va', 'file_offset', 'bytes'), thread_layout),
        'protected-layout.tsv': tsv(('role', 'site_va', 'file_offset', 'bytes'), protected_layout),
        'origin-layout.tsv': tsv(('role', 'site_va', 'file_offset', 'bytes'), origin_layout),
        'origin-operands.tsv': tsv(('role', 'site_va', 'file_offset', 'bytes', 'value', 'value_hex'), origin_operands),
        'literals.tsv': tsv(('role', 'va', 'file_offset', 'length', 'bytes', 'text'), literals),
        'worker-lsda.tsv': tsv(('range_start_va', 'range_end_exclusive', 'landing_va', 'action', 'file_offset', 'bytes'), worker_lsda_output),
        'processing-lsda.tsv': tsv(('role', 'range_start_va', 'range_end_exclusive', 'landing_va', 'action', 'file_offset', 'bytes'), processing_lsda),
        'summary.json': json.dumps(summary, sort_keys=True, indent=2) + '\n',
    }
    require(set(outputs) == set(OUTPUTS), 'evidence output mismatch')
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    outputs = analyse(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:
        (args.out / name).write_text(outputs[name], encoding='utf-8', newline='\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
