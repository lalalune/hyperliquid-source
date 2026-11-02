#!/usr/bin/env python3
"""Recover selected node-94 state-loader error construction and release paths.

Only authenticated ELF bytes are read.  FDE and section parsing reuse the
repository readers.  No captured code, external process, or network is run.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# These are selected FDE starts, not a census of loader functions.  Body hashes
# are exact, unmasked byte guards; the FDE reader independently provides ends.
FUNCTIONS = {
    0x365e7e0: ('error_factory', 0x365e84e, '1470f2bd92fa8e3379507c4dbdd4681d3fe5d0c5d2bdd65b894c2fdb2bc05776'),
    0x365e850: ('error_allocate', 0x365e8f7, '06e57dd30e8d32f6f15ad7330d9abf84ef015a2f468fe61de0a1581cb29a3541'),
    0x365e520: ('error_table_drop', 0x365e592, '57a552def48d945e51c3903cda7e227b3588719d66958fd988173d7490d2db2e'),
    0x365e3d0: ('error_table_payload_view', 0x365e3dc, '9e5802ab0723dc1bb4c046b7402fe8e64cd3e595ced96a547a1bfb63b663cdf4'),
    0x365e5e0: ('error_table_object_view', 0x365e5eb, 'd4f8ac90f9c0fe033e076fb566f47494d248adfb6345d53b2e9dd6d1e9a6125a'),
    0x365e620: ('error_table_type_test', 0x365e641, '77b5bdfec7d7f71137c96bc908521f7852b5cd42d5234452540bbc8f339faff3'),
    0x365e6b0: ('error_table_deallocate', 0x365e6f8, '66ef7ed482d80d621270a74f4890a20ff071a39a82a92759829da6c4177cff75'),
    0x365e5a0: ('error_table_zero', 0x365e5a3, '251447ee91a9067dcd6ab96703133f617565974cd6c4819021760c4688c91abf'),
    0x35abb30: ('stack_error_drop', 0x35abb8a, '6ac6f3cd27f359df043aaac7e0fcb75144650acaa94fdd5b3bf7d6675b7ec6b9'),
    0x34d9000: ('trace_list_drop', 0x34d913c, 'e9350d691290da047486df49ff29cc79352ac2ac355eda84b770d8d31c797ddb'),
    0x3bbcd60: ('trace_item_drop', 0x3bbce1a, '976f475c897198349c015087471f43d292fd23619efad9c05378a0a50e1d3686'),
    0x3c1b1f0: ('io_error_drop', 0x3c1b2b6, '1117b237ae99fa976d59f9c6ccc313e49463e36de344acba2cb931311007015a'),
    0x3c1b2c0: ('rmp_error_drop', 0x3c1b3e1, 'c77b54b2b9eebc22f4cbc5a56ecd8f07779705d59498dec1c43f822332da533f'),
    0x3c1b4f0: ('json_error_drop', 0x3c1b5ea, '7f1bfceb732cf39c7c8f061b2ef0b4c83385d8f08fae322c2575313000bed66b'),
}

# Selected, independently disassembled instruction windows.  Each must match
# exactly before its operands are interpreted.  The last four windows are
# linkage witnesses in prior-owned callers, never new function ownership.
ANCHORS = {
    0x365e7e9: ('factory input words', '4989fe488b1f4c8b7f08'),
    0x365e7f3: ('factory trace call', '488d7c2430ff15da141102'),
    0x365e7fe: ('factory moves trace and calls allocator', '0f104424300f104c24400f105424500f295424200f294c24100f2904244889e64c89f7e82a000000'),
    0x365e830: ('factory unwind string cleanup', '4989c64885db740e4c89ff4889de31d2ff15caf710024c89f7e8c2180002'),
    0x365e855: ('descriptor address', '488d050c2e090248890424'),
    0x365e860: ('record staging copies', '0f10060f104e100f1056200f114424080f114c24180f115424280f10070f11442438488b47104889442448'),
    0x365e88b: ('allocation and null gate', 'bf50000000ff1542f710024885c07431'),
    0x365e89b: ('record copy and return', '0f104424400f1140400f1004240f104c24100f105424200f105c24300f1158300f1150200f1148100f11004883c4505bc3'),
    0x365e8cc: ('allocation failure', 'bf08000000be50000000ff1544f710020f0b'),
    0x365e8de: ('allocator unwind stack drop', '4889c34889e7e847d2f4ff4889dfe81f180002'),
    0x365e524: ('heap record conditional trace drop', '4889fb837f08027509488d7b10e8caaae7ff'),
    0x365e536: ('heap record string allocation drop', '488b73384885f6740c488b7b4031d2ff15c5fa1002'),
    0x365e54b: ('heap record outer release', 'be500000004889df31d24883c4085b415eff25aefa1002'),
    0x35abb34: ('stack record conditional trace drop', '4889fb837f08027509488d7b10e8bad4f2ff'),
    0x35abb46: ('stack record string release', '488b73384885f67413488b7b4031d24883c4085b415eff25ae241c02'),
    0x34d900b: ('trace list mode gates', '4989fe8b472085c0744283f8020f848e00000083f8030f8594000000'),
    0x34d9040: ('trace list mode three loop', '4983fd0174414c8d673849ffcde80e3d6e004c89e7ebe9'),
    0x34d9070: ('trace list mode zero loop', '4983fd0174114c8d673849ffcde8de3c6e004c89e7ebe9'),
    0x34d9087: ('trace list outer allocation release', '498b064885c0741d486bf0384889df31d24883c4085b415c415d415e415f5dff25644f2902'),
    0x34d90bb: ('trace list unexpected mode diagnostic', '488d3d28600bfd488d1507542102be79000000ff15c44f2902'),
    0x3bbcd69: ('trace item nested vector fields', '4989fe488b5f284c8b7f304d85ff74724c8d63284c8b2d8c12bb01eb18'),
    0x3bbcd90: ('trace item first buffer gate', '31d241ffd54983c44849ffcf744d498b7424f84889f048f7d8700b7309498b3c2431d241ffd5'),
    0x3bbcdb6: ('trace item tagged second buffer', '498b4424d84883f80274d44885c07414498b7424e04885f674c5498b7c24e84801f6ebb6498b7424e04885f674b1498b7c24e8eba5'),
    0x3bbcdeb: ('trace item allocation length', '498b46204885c0741c48c1e003488d34c04889df31d25b415c415d415e415fff250012bb01'),
    0x3c1b1f8: ('IO pointer tag gate', '89f883e00383f801740c'),
    0x3c1b20e: ('IO nested data and callback', '488d5fff4c8b77ff4c8b6707498b04244885c074054c89f7ffd0'),
    0x3c1b228: ('IO nested size and alignment', '498b7424084885f67422498b442410f3480fbcc831d24839f00f47d14883f8110f43d14c89f7ff15bc2db501'),
    0x3c1b254: ('IO wrapper release', 'be180000004889df31d24883c4085b415c415e415fff25a12db501'),
    0x3c1b26f: ('IO callback unwind cleanup', '4989c7498b7424084885f67422498b442410f3480fbcc831d24839f00f47d14883f8110f43d14c89f7ff15722db501be180000004889df31d2ff15622db5014c89ffe85a4ea401'),
    0x3c1b2c8: ('RMP case dispatch', '0fb6074883f806775a488d0daccd99fc486304814801c8ffe0'),
    0x3c1b2e1: ('RMP direct buffer case', '488b77084885f67441488b7f10e992000000'),
    0x3c1b2f3: ('RMP first tagged case', '488b470889c183e10383f901752a'),
    0x3c1b31d: ('RMP second tagged case', '488b470889c183e10383f901740c'),
    0x3c1b351: ('RMP nested release size and alignment', '498b7424084885f67422498b442410f3480fbcc831d24839f00f47d14883f8110f43d14c89ffff15932cb501'),
    0x3c1b37d: ('RMP wrapper release', 'be180000004889df31d24883c4085b415c415e415fff25782cb501'),
    0x3c1b39a: ('RMP callback unwind cleanup', '4989c6498b7424084885f67422498b442410f3480fbcc831d24839f00f47d14883f8110f43d14c89ffff15472cb501be180000004889df31d2ff15372cb5014c89f7e82f4da401'),
    0x3c1b4f9: ('JSON outer tag and direct buffer', '4889fb488b074883f80174144885c07571488b73104885f67468488b7b08eb5a'),
    0x3c1b519: ('JSON nested pointer tag', '488b430889c183e10383f9017554'),
    0x3c1b541: ('JSON nested size and alignment', '498b75084885f67421498b4510f3480fbcc831d24839f00f47d14883f8110f43d14c89ffff15a52ab501'),
    0x3c1b56b: ('JSON wrapper and outer releases', 'be180000004c89f731d2ff15952ab501be280000004889df31d25b415c415d415e415fff257c2ab501'),
    0x3c1b594: ('JSON callback unwind cleanup', '4989c4498b75084885f67421498b4510f3480fbcc831d24839f00f47d14883f8110f43d14c89ffff154f2ab5014c8b3d482ab501be180000004c89f731d241ffd7be280000004889df31d241ffd74c89e7e8264ba401'),
    0x365e3d0: ('table payload view', '488d4738488d15ad2f0902c3'),
    0x365e5e0: ('table object view', '4889f8488d15f62f0902c3'),
    0x365e620: ('table type comparison', 'f30f6f06660f7405b48cbafc660fd7c8488d573831c081f9ffff0000480f44c2c3'),
    0x365e6b0: ('table alternate release', '415653504889fb837f08027509488d7b10e83aa9e7ffbe500000004889df31d24883c4085b415eff2533f910024989c6be500000004889df31d2ff1520f910024c89f7e8181a0002'),
    0x365e5a0: ('table zero result', '31c0c3'),
    0x3c15641: ('prior loader first boxed result', 'e89a91a4ff4889430848c70302000000'),
    0x3c15810: ('prior loader read boxed result', 'e8cb8fa4ff4889430848c70302000000'),
    0x3c15906: ('prior loader text-read boxed result', 'e8d58ea4ff4889430848c70302000000'),
    0x3272a13: ('prior outer caller result and diagnostic setup', '488b8424583b00004889442468488d3d8d2931fd488d0db2d346024c8d0593d14602488d542468be2b000000ff1503b64f02'),
    0x3272a45: ('prior outer diagnostic normal continuation', 'eb20'),
    0x3272a67: ('prior outer diagnostic unreachable instruction', '0f0b'),
    0x3272a9c: ('prior outer caller unwind indirect dispatch', '4989c7488b7c2468488b07ff10'),
    0x3c15a38: ('prior loader JSON tagged result and cleanup', '488dbc24f8000000e89b8da4ff4889430848c70302000000488b3c24e8975a0000'),
    0x3c15b36: ('prior loader RMP tagged result and cleanup', '488dbc24c8000000e89d8ca4ff4889430848c70302000000488d7c2470e868570000'),
}

# A semantic label for each selected branch.  Site/target arithmetic is read
# from the bytes; this is not an attempt to decode every branch in every body.
BRANCHES = {
    0x365e836: 'factory unwind input capacity zero',
    0x365e899: 'allocator returned zero',
    0x365e52b: 'heap trace tag differs from two', 0x365e53d: 'heap message capacity zero', 0x365e56c: 'heap cleanup message capacity zero',
    0x365e6bb: 'alternate release trace tag differs from two',
    0x35abb3b: 'stack trace tag differs from two', 0x35abb4d: 'stack message capacity zero', 0x35abb74: 'stack cleanup message capacity zero',
    0x34d9013: 'trace list mode zero', 0x34d9018: 'trace list mode two', 0x34d9021: 'trace list mode not three',
    0x34d9044: 'mode three loop exhausted', 0x34d9074: 'mode zero loop exhausted', 0x34d908d: 'trace list capacity zero',
    0x34d90e3: 'unwind mode zero loop exhausted', 0x34d9103: 'unwind mode three loop exhausted', 0x34d911d: 'unwind trace list capacity zero',
    0x3bbcd77: 'nested vector length zero', 0x3bbcd9c: 'nested vector loop exhausted', 0x3bbcda9: 'first nested size is minimum signed',
    0x3bbcdab: 'first nested size is zero', 0x3bbcdbf: 'second nested variant two', 0x3bbcdc4: 'second nested variant zero',
    0x3bbcdce: 'second nested doubled length zero', 0x3bbcde2: 'second nested byte length zero', 0x3bbcdf2: 'nested vector capacity zero',
    0x3c1b200: 'IO low pointer bits equal one', 0x3c1b221: 'IO callback null', 0x3c1b230: 'IO payload size zero', 0x3c1b27a: 'IO unwind payload size zero',
    0x3c1b2cf: 'RMP tag above six', 0x3c1b2e8: 'RMP buffer capacity zero', 0x3c1b2ff: 'RMP first low pointer bits not one',
    0x3c1b314: 'RMP first callback null', 0x3c1b329: 'RMP second low pointer bits one', 0x3c1b34a: 'RMP second callback null',
    0x3c1b359: 'RMP payload size zero', 0x3c1b3a5: 'RMP unwind payload size zero',
    0x3c1b503: 'JSON outer tag one', 0x3c1b508: 'JSON outer tag nonzero', 0x3c1b511: 'JSON direct buffer capacity zero',
    0x3c1b525: 'JSON low pointer bits not one', 0x3c1b53a: 'JSON callback null', 0x3c1b548: 'JSON payload size zero', 0x3c1b59e: 'JSON unwind payload size zero',
}

# New edges into/out of selected functions.  Sites in earlier loader callers
# are boundary witnesses; the previous GOT slots and call sites are not owned.
CALLS = {
    0x365e821: ('factory to record allocation', 0x365e850),
    0x365e8e4: ('allocation unwind to stack drop', 0x35abb30),
    0x365e531: ('heap drop to trace list drop', 0x34d9000),
    0x35abb41: ('stack drop to trace list drop', 0x34d9000),
    0x34d904d: ('mode three to trace item drop', 0x3bbcd60),
    0x34d907d: ('mode zero to trace item drop', 0x3bbcd60),
    0x3c15641: ('prior loader first formatted failure', 0x365e7e0),
    0x3c15810: ('prior loader read failure', 0x365e7e0),
    0x3c15906: ('prior loader text read failure', 0x365e7e0),
    0x3c15a40: ('prior loader JSON decode failure', 0x365e7e0),
    0x3c15b3e: ('prior loader RMP decode failure', 0x365e7e0),
    0x3c15a54: ('prior loader JSON failure release', 0x3c1b4f0),
    0x3c15b53: ('prior loader RMP failure release', 0x3c1b2c0),
    0x3c15bc6: ('prior loader read error unwind release', 0x3c1b1f0),
    0x3c15c33: ('prior loader text error unwind release', 0x3c1b1f0),
    0x3c15c0d: ('prior loader JSON unwind release', 0x3c1b4f0),
    0x3c15bb6: ('prior loader RMP unwind release', 0x3c1b2c0),
}


def check_digest(data, expected=SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError('node 94 input SHA-256 mismatch')
    return digest


def unique_section(secs, name):
    rows = [s for s in secs if s['name'] == name]
    if len(rows) != 1 or rows[0]['type'] == 8:
        raise ValueError('missing, duplicate, or NOBITS section: ' + name)
    return rows[0]


def map_offset(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or range')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not in one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def checked_body(body, expected):
    if hashlib.sha256(body).hexdigest() != expected:
        raise ValueError('selected function bytes differ')


def checked_anchor(data, expected):
    if data != bytes.fromhex(expected):
        raise ValueError('selected instruction bytes differ')


def decode_jcc(raw, va, start, end):
    names = {0x2: 'below', 0x3: 'above_or_equal', 0x4: 'equal', 0x5: 'not_equal',
             0x7: 'above', 0x8: 'sign', 0x0: 'overflow'}
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        n, condition = 2, raw[0] & 15
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        n, condition = 6, raw[1] & 15
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('not a supported conditional branch')
    if condition not in names:
        raise ValueError('unselected conditional branch')
    target = va + n + disp
    if not (start <= va < va+n <= end and start <= target < end):
        raise ValueError('conditional branch outside selected FDE')
    return {'condition': names[condition], 'raw_hex': raw[:n].hex(), 'size': n,
            'target': target, 'fallthrough': va+n}


def decode_rel32(raw, va, opcode=0xe8):
    if len(raw) != 5 or raw[0] != opcode:
        raise ValueError('unexpected relative transfer')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_rip(raw, va, prefix):
    if len(raw) != len(prefix)+4 or not raw.startswith(prefix):
        raise ValueError('unexpected RIP-relative instruction')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def selected_relocations(rows, offsets):
    wanted = set(offsets)
    result = {}
    for off, info, addend in rows:
        if off not in wanted:
            continue
        if off in result:
            raise ValueError('duplicate selected relocation')
        if (info & 0xffffffff) != 8 or info >> 32:
            raise ValueError('selected relocation is not symbol-zero RELATIVE')
        result[off] = addend
    if set(result) != wanted:
        raise ValueError('selected relocation missing')
    return result


def parse_lsda(data, secs, frame):
    va = frame['lsda']
    sec = unique_section(secs, '.gcc_except_table')
    off = map_offset(secs, va, 1)
    if not sec['offset'] <= off < sec['offset'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    limit = sec['offset'] + sec['size']
    pos = off
    if pos+2 > limit or data[pos] != 0xff or data[pos+1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header')
    type_encoding = data[pos+1]
    pos += 2
    type_base = None
    if type_encoding != 0xff:
        distance, pos = uleb(data, pos, limit)
        type_base = pos + distance
        if type_base > limit:
            raise ValueError('LSDA type table outside section')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, limit)
    table_start = pos
    table_end = pos + length
    if table_end > limit or (type_base is not None and table_end > type_base):
        raise ValueError('truncated LSDA call-site table')
    rows = []
    previous_end = frame['start']
    while pos < table_end:
        row_start = pos
        values = []
        for _ in range(4):
            value, pos = uleb(data, pos, table_end)
            values.append(value)
        relative, size, pad, action = values
        begin, end = frame['start'] + relative, frame['start'] + relative + size
        landing = frame['start'] + pad if pad else None
        if not frame['start'] <= begin < end <= frame['end'] or begin < previous_end:
            raise ValueError('invalid LSDA call-site range')
        if landing is not None and not frame['start'] <= landing < frame['end']:
            raise ValueError('LSDA landing pad outside function')
        previous_end = end
        rows.append({'begin': begin, 'end': end, 'landing': landing, 'action': action,
                     'file_offset': row_start, 'raw_hex': data[row_start:pos].hex()})
    return {'va': va, 'file_offset': off, 'header_hex': data[off:table_start].hex(),
            'table_size': length, 'type_encoding': type_encoding, 'rows': rows}


def covering(rows, site):
    found = [r for r in rows if r['begin'] <= site < r['end']]
    if len(found) != 1:
        raise ValueError('site has no unique LSDA row')
    return found[0]


def decode_jump_table(raw, base, start, end):
    if len(raw) != 7*4:
        raise ValueError('bad RMP jump-table length')
    targets = [base + d for d in struct.unpack('<7i', raw)]
    if any(not start <= t < end for t in targets):
        raise ValueError('RMP jump target outside its FDE')
    return targets


def check_word(value):
    if type(value) is not int or not 0 <= value <= MASK64:
        raise ValueError('expected an unsigned 64-bit word')
    return value


def align_code(size, alignment, cutoff):
    check_word(size)
    check_word(alignment)
    if alignment == 0:
        raise ValueError('zero alignment is outside this synthetic model')
    trailing = (alignment & -alignment).bit_length() - 1
    return trailing if alignment > size or alignment >= cutoff else 0


def nested_io_actions(spec, tagged, data_ptr, size, alignment, callback=False, callback_unwinds=False):
    """Symbolic actions for the bounded tagged-pointer release blocks.

    The pointers are raw test words, not dereferenced or freed.  A caller must
    supply the abstract contents of the referenced descriptor.  Exception
    behavior is conditional on the indicated indirect callback being invoked.
    """
    for word in (tagged, data_ptr, size, alignment):
        check_word(word)
    if tagged & spec['tag_mask'] != spec['tag_value']:
        return [], False
    actions = []
    if callback:
        actions.append(('callback', data_ptr))
    threw = bool(callback and callback_unwinds)
    if size:
        actions.append(('release', data_ptr, size, align_code(size, alignment, spec['align_cutoff'])))
    actions.append(('release', (tagged-1) & MASK64, spec['io_wrapper_size'], 0))
    return actions, threw


def io_actions(spec, tagged, data_ptr, size, alignment, callback=False, callback_unwinds=False):
    actions, threw = nested_io_actions(spec, tagged, data_ptr, size, alignment, callback, callback_unwinds)
    if threw:
        actions.append(('resume_unwind',))
    return actions


def rmp_actions(spec, tag, tagged=0, data_ptr=0, size=0, alignment=1,
                callback=False, callback_unwinds=False, buffer_ptr=0, buffer_capacity=0):
    if type(tag) is not int or not 0 <= tag <= 255:
        raise ValueError('RMP tag is not a byte')
    check_word(buffer_ptr)
    check_word(buffer_capacity)
    kind = spec['rmp_cases'][tag] if tag < len(spec['rmp_cases']) else 'none'
    if kind == 'tagged':
        actions, threw = nested_io_actions(spec, tagged, data_ptr, size, alignment, callback, callback_unwinds)
        if threw:
            actions.append(('resume_unwind',))
        return actions
    if kind == 'buffer' and buffer_capacity:
        return [('release', buffer_ptr, buffer_capacity, 0)]
    return []


def json_actions(spec, tag, outer_ptr, tagged=0, data_ptr=0, size=0,
                 alignment=1, callback=False, callback_unwinds=False,
                 buffer_ptr=0, buffer_capacity=0):
    for word in (tag, outer_ptr, buffer_ptr, buffer_capacity):
        check_word(word)
    actions = []
    threw = False
    if tag == spec['json_tagged']:
        actions, threw = nested_io_actions(spec, tagged, data_ptr, size, alignment, callback, callback_unwinds)
    elif tag == 0 and buffer_capacity:
        actions.append(('release', buffer_ptr, buffer_capacity, 0))
    actions.append(('release', outer_ptr, spec['json_outer_size'], 0))
    if threw:
        actions.append(('resume_unwind',))
    return actions


def type_match(spec, raw, base):
    check_word(base)
    if len(raw) != len(spec['type_id']):
        raise ValueError('type-test input must have the observed length')
    return (base + spec['payload_offset']) & MASK64 if raw == spec['type_id'] else 0


def trace_item_actions(spec, sub_base, capacity, items):
    """Model selected bounded vector releases, without dereferencing pointers."""
    check_word(sub_base)
    check_word(capacity)
    if len(items) > 64:
        raise ValueError('synthetic item bound exceeded')
    actions = []
    for item in items:
        first_ptr = check_word(item['first_ptr'])
        first_size = check_word(item['first_size'])
        variant = check_word(item['variant'])
        second_ptr = check_word(item['second_ptr'])
        second_size = check_word(item['second_size'])
        if first_size not in (0, 1 << 63):
            actions.append(('release', first_ptr, first_size, 0))
        if variant != spec['skip_variant'] and second_size:
            n = second_size if variant == 0 else (second_size*2) & MASK64
            actions.append(('release', second_ptr, n, 0))
    if capacity:
        actions.append(('release', sub_base, (capacity*spec['item_stride']) & MASK64, 0))
    return actions


def trace_list_actions(spec, mode, base, capacity, items):
    for word in (mode, base, capacity):
        check_word(word)
    if mode > 0xffffffff:
        raise ValueError('trace mode is not a 32-bit word')
    if len(items) > 64:
        raise ValueError('synthetic item bound exceeded')
    if mode == spec['mode_empty']:
        return []
    if mode not in (0, spec['mode_list']):
        return [('diagnostic',)]
    actions = []
    for item in items:
        actions.append(('trace_item',))
        actions.extend(trace_item_actions(spec, item['sub_base'], item['capacity'], item['items']))
    if capacity:
        actions.append(('release', base, (capacity*spec['trace_stride']) & MASK64, 0))
    return actions


def record_drop_actions(spec, trace_tag, message_ptr, message_capacity, outer_ptr,
                        on_heap=True, nested_unwinds=False):
    for word in (trace_tag, message_ptr, message_capacity, outer_ptr):
        check_word(word)
    if trace_tag > 0xffffffff:
        raise ValueError('trace tag is not a 32-bit word')
    actions = []
    threw = False
    if trace_tag == spec['trace_tag']:
        actions.append(('trace_drop',))
        threw = bool(nested_unwinds)
    if message_capacity:
        actions.append(('release', message_ptr, message_capacity, 0))
    if on_heap:
        actions.append(('release', outer_ptr, spec['record_size'], 0))
    if threw:
        actions.append(('resume_unwind',))
    return actions


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate:
            self.sha256 = check_digest(data)
        else:
            self.sha256 = hashlib.sha256(data).hexdigest()
        self.data = data
        self.secs = sections(data)
        _, frames = eh_frame_records(data, self.secs)
        self.frames = {}
        for frame in frames:
            self.frames.setdefault(frame['start'], []).append(frame)
        _, index = unwind_index(data)
        self.index = {row['start']: row['fde'] for row in index}
        if len(self.index) != len(index):
            raise ValueError('duplicate unwind index starts')
        self.checked_frames = {}
        for start, (_, end, digest) in FUNCTIONS.items():
            f = self.frame(start)
            if f['end'] != end or self.index.get(start) != f['fde']:
                raise ValueError('selected FDE or index differs')
            body = self.read(start, end-start)
            checked_body(body, digest)
            self.checked_frames[start] = f
        for va, (_, expected) in ANCHORS.items():
            checked_anchor(self.read(va, len(bytes.fromhex(expected))), expected)
        rela = unique_section(self.secs, '.rela.dyn')
        if rela['type'] != 4 or rela['size'] % 24:
            raise ValueError('unexpected RELA section')
        self.rela_rows = [struct.unpack_from('<QQq', data, pos)
                          for pos in range(rela['offset'], rela['offset']+rela['size'], 24)]

    def read(self, va, size):
        off = map_offset(self.secs, va, size)
        raw = self.data[off:off+size]
        if len(raw) != size:
            raise ValueError('truncated file-backed range')
        return raw

    def frame(self, start):
        found = self.frames.get(start, [])
        if len(found) != 1:
            raise ValueError('missing or duplicate FDE start')
        return found[0]

    def owner(self, va):
        # Only selected FDEs and the two separately owned linkage boundaries
        # are queried here; the routine is not a whole-node ownership census.
        starts = set(FUNCTIONS) | {0x32725d0, 0x3c155a0}
        matches = [self.frame(start) for start in starts
                   if self.frame(start)['start'] <= va < self.frame(start)['end']]
        if len(matches) != 1:
            raise ValueError('site has no unique FDE owner')
        return matches[0]

    def off(self, va, size):
        return map_offset(self.secs, va, size)


def make_spec(image):
    # The exact instruction windows above prove each selected immediate and
    # operand position used by this bounded synthetic model.
    def imm8(va):
        return image.read(va, 1)[0]
    def imm32(va):
        return struct.unpack('<I', image.read(va, 4))[0]
    table = decode_rip(image.read(0x3c1b2d1, 7), 0x3c1b2d1, b'\x48\x8d\x0d')
    case_targets = decode_jump_table(image.read(table, 7*4), table, 0x3c1b2c0, image.frame(0x3c1b2c0)['end'])
    labels = {0x3c1b2f3: 'tagged', 0x3c1b31d: 'tagged',
              0x3c1b32b: 'none', 0x3c1b2e1: 'buffer'}
    if any(t not in labels for t in case_targets):
        raise ValueError('unexpected RMP table target')
    compare_va = decode_rip(image.read(0x365e624, 8), 0x365e624, b'\x66\x0f\x74\x05')
    result = {
        'tag_mask': imm8(0x3c1b1fc), 'tag_value': imm8(0x3c1b1ff),
        'align_cutoff': imm8(0x3c1b247),
        'io_wrapper_size': imm32(0x3c1b255),
        'json_outer_size': imm32(0x3c1b57c),
        'json_tagged': imm8(0x3c1b502),
        'rmp_cases': [labels[t] for t in case_targets],
        'trace_tag': imm8(0x365e52a),
        'record_size': imm32(0x365e88c),
        'payload_offset': imm8(0x365e3d3),
        'mode_empty': imm8(0x34d9017),
        'mode_list': imm8(0x34d9020),
        'trace_stride': imm8(0x34d9049),
        'item_stride': imm8(0x3bbcd98),
        'skip_variant': imm8(0x3bbcdbE),
        'type_id': image.read(compare_va, 16),
        'type_id_va': compare_va,
        'rmp_table_va': table,
        'rmp_targets': case_targets,
    }
    expected = {'tag_mask': 3, 'tag_value': 1, 'align_cutoff': 17,
                'io_wrapper_size': 24, 'json_outer_size': 40, 'json_tagged': 1,
                'trace_tag': 2, 'record_size': 80, 'payload_offset': 56,
                'mode_empty': 2, 'mode_list': 3, 'trace_stride': 56,
                'item_stride': 72, 'skip_variant': 2}
    if any(result[k] != v for k, v in expected.items()):
        raise ValueError('synthetic model operand mismatch')
    return result


def as_hex(value):
    return '-' if value is None else hex(value)


def table_text(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')


def action_text(actions):
    return json.dumps(actions, separators=(',', ':'), ensure_ascii=True)


def controls(spec):
    rows = []
    for tag in range(256):
        actions = rmp_actions(spec, tag, tagged=0x101, data_ptr=0x220, size=8,
                              alignment=8, callback=True, buffer_ptr=0x330, buffer_capacity=3)
        rows.append(('rmp-tag-byte', str(tag), action_text(actions)))
    for tag in (0, 1, 2, MASK64):
        for low in range(4):
            for throws in (False, True):
                actions = json_actions(spec, tag, 0x400, tagged=0x100+low,
                    data_ptr=0x220, size=8, alignment=8, callback=True,
                    callback_unwinds=throws, buffer_ptr=0x330, buffer_capacity=3)
                case = f'tag={tag},low={low},callback_unwinds={int(throws)}'
                rows.append(('json-tag-and-pointer', case, action_text(actions)))
    for is_heap in (False, True):
        for trace_tag in (0, spec['trace_tag']):
            for cap in (0, 4):
                for throws in (False, True):
                    actions = record_drop_actions(spec, trace_tag, 0x220, cap, 0x400,
                                                  on_heap=is_heap, nested_unwinds=throws)
                    case = f'heap={int(is_heap)},trace_tag={trace_tag},capacity={cap},nested_unwinds={int(throws)}'
                    rows.append(('boxed-record-drop', case, action_text(actions)))
    for offset in range(len(spec['type_id'])):
        corrupted = bytearray(spec['type_id'])
        corrupted[offset] ^= 1
        rows.append(('type-test-corruption', f'byte={offset}', str(type_match(spec, bytes(corrupted), 0x400))))
    rows.append(('type-test-positive', 'unchanged', str(type_match(spec, spec['type_id'], 0x400))))
    fixture = {'sub_base': 0x500, 'capacity': 1, 'items': [
        {'first_ptr': 0x600, 'first_size': 5, 'variant': 1, 'second_ptr': 0x700, 'second_size': 3},
        {'first_ptr': 0x610, 'first_size': 1 << 63, 'variant': 2, 'second_ptr': 0x710, 'second_size': 7},
    ]}
    for mode in (0, 1, 2, 3, 4):
        actions = trace_list_actions(spec, mode, 0x900, 1, [fixture])
        rows.append(('trace-list-mode', str(mode), action_text(actions)))
    return rows


def collect(image):
    spec = make_spec(image)
    table_va = decode_rip(image.read(0x365e855, 7), 0x365e855, b'\x48\x8d\x05')
    table_slots = [table_va+8*i for i in range(6)]
    external = {0x576fcd8: ('trace factory slot', 0x4eeee40),
                0x576dfd8: ('allocation slot', 0x54c06b0),
                0x576e020: ('allocation failure slot', 0x1345e2a),
                0x576e010: ('release slot', 0x54c8cb0),
                0x576e048: ('prior diagnostic slot', 0x157aa10)}
    relocs = selected_relocations(image.rela_rows, table_slots + list(external))
    expected_table = [0x365e520, 0x365e3d0, 0x365e5e0, 0x365e620, 0x365e6b0, 0x365e5a0]
    if [relocs[s] for s in table_slots] != expected_table:
        raise ValueError('error table relocation targets differ')
    if any(relocs[slot] != target for slot, (_, target) in external.items()):
        raise ValueError('external slot relocation differs')

    slot_sites = {
        0x365e7f8: (b'\xff\x15', 0x576fcd8, 'trace factory'),
        0x365e890: (b'\xff\x15', 0x576dfd8, 'record allocation'),
        0x365e8d6: (b'\xff\x15', 0x576e020, 'record allocation failure'),
        0x365e545: (b'\xff\x15', 0x576e010, 'heap message release'),
        0x365e55c: (b'\xff\x25', 0x576e010, 'heap record tail release'),
        0x35abb5c: (b'\xff\x25', 0x576e010, 'stack message tail release'),
        0x3c1b24e: (b'\xff\x15', 0x576e010, 'IO payload release'),
        0x3c1b269: (b'\xff\x25', 0x576e010, 'IO wrapper tail release'),
        0x3c1b377: (b'\xff\x15', 0x576e010, 'RMP payload release'),
        0x3c1b392: (b'\xff\x25', 0x576e010, 'RMP wrapper or buffer tail release'),
        0x3c1b565: (b'\xff\x15', 0x576e010, 'JSON payload release'),
        0x3c1b575: (b'\xff\x15', 0x576e010, 'JSON inner release'),
        0x3c1b58e: (b'\xff\x25', 0x576e010, 'JSON outer tail release'),
        0x3272a3f: (b'\xff\x15', 0x576e048, 'prior caller diagnostic'),
        0x3bbcd7d: (b'\x4c\x8b\x2d', 0x576e010, 'trace item release function load'),
    }
    slot_rows = []
    for va, (prefix, expected_slot, role) in sorted(slot_sites.items()):
        raw = image.read(va, len(prefix)+4)
        slot = decode_rip(raw, va, prefix)
        if slot != expected_slot:
            raise ValueError('selected indirect slot differs')
        owner = image.owner(va)
        ownership = 'selected' if owner['start'] in FUNCTIONS else 'prior-caller-boundary'
        slot_rows.append((hex(va), hex(image.off(va, len(raw))), hex(owner['start']), ownership,
                          raw.hex(), hex(slot), hex(relocs[slot]), role))

    function_rows = []
    for start, (role, _, _) in sorted(FUNCTIONS.items()):
        f = image.frame(start)
        body = image.read(start, f['end']-start)
        function_rows.append({'role': role, 'start_va': hex(start), 'end_va_exclusive': hex(f['end']),
            'file_offset': hex(image.off(start, len(body))), 'size': len(body), 'fde_va': hex(f['fde']),
            'cie_va': hex(f['cie']), 'lsda_va': as_hex(f['lsda']),
            'sha256': hashlib.sha256(body).hexdigest(), 'raw_hex': body.hex()})

    anchor_rows = []
    for va, (description, expected) in sorted(ANCHORS.items()):
        raw = image.read(va, len(bytes.fromhex(expected)))
        owner = image.owner(va)
        ownership = 'selected' if owner['start'] in FUNCTIONS else 'prior-caller-boundary'
        anchor_rows.append((hex(va), hex(image.off(va, len(raw))), hex(owner['start']), ownership,
                            len(raw), raw.hex(), description))

    branch_rows = []
    for va, description in sorted(BRANCHES.items()):
        f = image.owner(va)
        if f['start'] not in FUNCTIONS:
            raise ValueError('selected branch is outside a new FDE')
        record = decode_jcc(image.read(va, 6), va, f['start'], f['end'])
        branch_rows.append((hex(va), hex(image.off(va, record['size'])), hex(f['start']),
                            record['raw_hex'], record['condition'], hex(record['target']),
                            hex(record['fallthrough']), description))

    edge_rows = []
    for va, (description, expected) in sorted(CALLS.items()):
        raw = image.read(va, 5)
        target = decode_rel32(raw, va)
        if target != expected or target not in FUNCTIONS:
            raise ValueError('selected call target differs')
        owner = image.owner(va)
        ownership = 'selected' if owner['start'] in FUNCTIONS else 'prior-caller-boundary'
        edge_rows.append((hex(va), hex(image.off(va, 5)), hex(owner['start']), ownership,
                          raw.hex(), hex(target), description))

    reloc_rows = []
    for index, slot in enumerate(table_slots):
        raw = image.read(slot, 8)
        reloc_rows.append((hex(slot), hex(image.off(slot, 8)), raw.hex(), '8', '0',
                           hex(relocs[slot]), 'selected-descriptor', f'error table entry {index}'))
    for slot, (role, _) in sorted(external.items()):
        raw = image.read(slot, 8)
        reloc_rows.append((hex(slot), hex(image.off(slot, 8)), raw.hex(), '8', '0',
                           hex(relocs[slot]), 'external-boundary', role))

    jump_rows = []
    for tag, target in enumerate(spec['rmp_targets']):
        va = spec['rmp_table_va'] + tag*4
        raw = image.read(va, 4)
        delta = struct.unpack('<i', raw)[0]
        jump_rows.append((tag, hex(va), hex(image.off(va, 4)), raw.hex(), delta,
                          hex(target), spec['rmp_cases'][tag]))
    default_branch = decode_jcc(image.read(0x3c1b2cf, 6), 0x3c1b2cf, 0x3c1b2c0, image.frame(0x3c1b2c0)['end'])
    if default_branch['target'] != spec['rmp_targets'][2]:
        raise ValueError('RMP default branch differs')

    lsda_cache = {}
    lsda_rows = []
    for start in sorted(FUNCTIONS):
        f = image.frame(start)
        if f['lsda'] is None:
            continue
        decoded = parse_lsda(image.data, image.secs, f)
        lsda_cache[start] = decoded
        for row in decoded['rows']:
            lsda_rows.append((hex(start), 'selected', hex(decoded['va']), hex(decoded['file_offset']),
                              hex(row['file_offset']), row['raw_hex'], hex(row['begin']), hex(row['end']),
                              as_hex(row['landing']), row['action']))
    # Prior bodies remain boundary citations; retain only the rows needed to
    # show that the new cleanup sites are the relevant landing pads.
    checks = [
        (0x32725d0, 0x3272a3f, 0x3272a9c, 'outer diagnostic'),
        (0x3c155a0, 0x3c15810, 0x3c15bbf, 'read failure factory'),
        (0x3c155a0, 0x3c15906, 0x3c15c2c, 'text-read failure factory'),
        (0x3c155a0, 0x3c15a40, 0x3c15c06, 'JSON failure factory'),
        (0x3c155a0, 0x3c15b3e, 0x3c15bae, 'RMP failure factory'),
        (0x3c155a0, 0x3c15a54, 0x3c15c14, 'JSON error release'),
        (0x3c155a0, 0x3c15b53, 0x3c15bbd, 'RMP error release'),
        (0x365e7e0, 0x365e7f8, 0x365e830, 'auxiliary record constructor'),
        (0x365e7e0, 0x365e821, None, 'record allocation call'),
        (0x365e850, 0x365e8d6, 0x365e8de, 'record allocation failure'),
        (0x365e520, 0x365e531, 0x365e562, 'heap trace drop'),
        (0x35abb30, 0x35abb41, 0x35abb6a, 'stack trace drop'),
        (0x3c1b1f0, 0x3c1b226, 0x3c1b26f, 'IO callback'),
        (0x3c1b2c0, 0x3c1b319, 0x3c1b39a, 'RMP first callback'),
        (0x3c1b2c0, 0x3c1b34f, 0x3c1b398, 'RMP second callback'),
        (0x3c1b4f0, 0x3c1b53f, 0x3c1b594, 'JSON callback'),
    ]
    witness_rows = []
    for start, site, expected_landing, role in checks:
        if start not in lsda_cache:
            lsda_cache[start] = parse_lsda(image.data, image.secs, image.frame(start))
        decoded = lsda_cache[start]
        row = covering(decoded['rows'], site)
        if row['landing'] != expected_landing:
            raise ValueError('selected LSDA landing pad differs')
        ownership = 'selected' if start in FUNCTIONS else 'prior-caller-boundary'
        witness_rows.append((hex(start), ownership, hex(site), hex(decoded['va']), hex(row['file_offset']),
                             row['raw_hex'], hex(row['begin']), hex(row['end']), as_hex(row['landing']), row['action'], role))
        if ownership == 'prior-caller-boundary':
            lsda_rows.append((hex(start), ownership, hex(decoded['va']), hex(decoded['file_offset']),
                              hex(row['file_offset']), row['raw_hex'], hex(row['begin']), hex(row['end']),
                              as_hex(row['landing']), row['action']))

    header_rows = [(hex(start), 'selected' if start in FUNCTIONS else 'prior-caller-boundary',
                    hex(decoded['va']), hex(decoded['file_offset']), decoded['header_hex'],
                    decoded['type_encoding'], decoded['table_size'])
                   for start, decoded in sorted(lsda_cache.items())]

    diagnostic_va = decode_rip(image.read(0x3272a20, 7), 0x3272a20, b'\x48\x8d\x3d')
    diag_len = struct.unpack('<I', image.read(0x3272a3b, 4))[0]
    diagnostic = image.read(diagnostic_va, diag_len)
    if diagnostic != b'called `Result::unwrap()` on an `Err` value':
        raise ValueError('outer diagnostic literal differs')

    # Instruction operands below are all covered by exact ANCHORS above.
    # Offsets describe the record assembled by the selected allocator; they
    # do not assert source-language field types.
    layout_sites = [
        ('trace chunk 0 destination', 0x365e86b, 5, 4),
        ('trace chunk 1 destination', 0x365e870, 5, 4),
        ('trace chunk 2 destination', 0x365e875, 5, 4),
        ('message capacity word', 0x365e536, 4, 3),
        ('message pointer word', 0x365e53f, 4, 3),
        ('message third word staging', 0x365e886, 5, 4),
        ('trace tag word', 0x365e527, 4, 2),
        ('nested trace argument', 0x365e52d, 4, 3),
    ]
    layout_rows = []
    for role, site, length, operand_index in layout_sites:
        raw = image.read(site, length)
        layout_rows.append((role, hex(site), hex(image.off(site, length)), raw.hex(), raw[operand_index]))
    for role, site, length in (('record allocation size', 0x365e88b, 5),
                               ('IO wrapper release size', 0x3c1b254, 5),
                               ('JSON outer release size', 0x3c1b57b, 5)):
        raw = image.read(site, length)
        layout_rows.append((role, hex(site), hex(image.off(site, length)), raw.hex(),
                            struct.unpack_from('<I', raw, 1)[0]))

    model_rows = controls(spec)
    portable_spec = {k: (v.hex() if isinstance(v, bytes) else
                          hex(v) if k in ('type_id_va', 'rmp_table_va') else
                          [hex(x) for x in v] if k == 'rmp_targets' else v)
                     for k, v in spec.items()}
    summary = {
        'schema': 're017-abci-loader-errors94/1',
        'target': {'release': 94, 'sha256': image.sha256},
        'coordinate_system': 'ELF link-time virtual addresses; file offsets separately reported',
        'scope': 'New FDEs plus selected prior-caller boundary witnesses; no execution or full coverage claim.',
        'metrics': {'selected_fdes': len(function_rows), 'selected_fde_bytes': sum(r['size'] for r in function_rows),
                    'selected_instruction_windows': len(anchor_rows), 'selected_conditional_branches': len(branch_rows),
                    'selected_direct_calls': len(edge_rows), 'selected_indirect_slot_sites': len(slot_rows),
                    'relocations_recorded': len(reloc_rows),
                    'descriptor_relocations': len(table_slots), 'external_boundary_relocations': len(external),
                    'rmp_table_entries': len(jump_rows), 'lsda_rows': len(lsda_rows),
                    'lsda_witnesses': len(witness_rows), 'synthetic_cases': len(model_rows)},
        'descriptor_va': hex(table_va), 'diagnostic_va': hex(diagnostic_va),
        'diagnostic_ascii': diagnostic.decode('ascii'), 'model_operands': portable_spec,
        'limitations': ['Function extents are FDE ranges, not a whole-program function census.',
                        'Prior caller windows are linkage witnesses and do not claim ownership of those functions.',
                        'LSDA rows describe conditional unwind associations; action and type-table semantics are not decoded.',
                        'Synthetic models do not establish caller reachability, valid Rust layouts, or actual deallocation behavior.',
                        'Existing formatter, allocator, traceback producer and loader bodies are outside the selected FDEs.'],
    }
    files = {
        'functions.json': json_bytes(function_rows),
        'instructions.tsv': table_text(('va', 'file_offset', 'fde_start_va', 'ownership', 'size', 'raw_hex', 'role'), anchor_rows),
        'branches.tsv': table_text(('va', 'file_offset', 'fde_start_va', 'raw_hex', 'condition', 'target_va', 'fallthrough_va', 'role'), branch_rows),
        'edges.tsv': table_text(('va', 'file_offset', 'fde_start_va', 'ownership', 'raw_hex', 'target_va', 'role'), edge_rows),
        'slot-sites.tsv': table_text(('va', 'file_offset', 'fde_start_va', 'ownership', 'raw_hex', 'slot_va', 'addend_va', 'role'), slot_rows),
        'relocations.tsv': table_text(('slot_va', 'file_offset', 'file_word_hex', 'type', 'symbol', 'addend_va', 'ownership', 'role'), reloc_rows),
        'rmp-cases.tsv': table_text(('tag', 'entry_va', 'file_offset', 'raw_hex', 'signed_delta', 'target_va', 'action'), jump_rows),
        'layout.tsv': table_text(('role', 'site_va', 'file_offset', 'raw_hex', 'operand_value'), layout_rows),
        'unwind.tsv': table_text(('fde_start_va', 'ownership', 'lsda_va', 'lsda_file_offset', 'row_file_offset', 'raw_hex', 'begin_va', 'end_va_exclusive', 'landing_va', 'action_index'), lsda_rows),
        'unwind-headers.tsv': table_text(('fde_start_va', 'ownership', 'lsda_va', 'lsda_file_offset', 'header_hex', 'type_encoding', 'call_table_bytes'), header_rows),
        'unwind-witnesses.tsv': table_text(('fde_start_va', 'ownership', 'site_va', 'lsda_va', 'row_file_offset', 'raw_hex', 'begin_va', 'end_va_exclusive', 'landing_va', 'action_index', 'role'), witness_rows),
        'synthetic-cases.tsv': table_text(('family', 'input', 'actions'), model_rows),
        'summary.json': json_bytes(summary),
    }
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', required=True, type=Path, help='directory for generated evidence files')
    args = parser.parse_args(argv)
    # Input authentication happens before any destination directory is created.
    data = TARGET.read_bytes()
    image = Image(data)
    files = collect(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(files.items()):
        (args.out / name).write_bytes(contents)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
