#!/usr/bin/env python3
"""Recover the #94 CSignerAction content reader from static ELF bytes.

The small interpreters cover only the explicitly delimited selector/dispatch
slices. The field model is a separate, partial projection of pinned code.
No target instructions or external programs are executed.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

FUNCTIONS = (
    ('inline_action_reader', 0x282a180),
    ('boxed_action_reader', 0x282c380),
    ('boxed_name_selector', 0x219d9e0),
    ('inline_name_selector', 0x219db60),
    ('inline_content_reader', 0x21b1c10),
    ('boxed_content_reader', 0x21b28d0),
    ('boxed_vote_map', 0x1f24320),
    ('boxed_vote_sequence', 0x1f4ea40),
    ('boxed_field_reader', 0x2162820),
    ('field_string_helper', 0x21a1480),
)
# Hashes pin reviewed slices independently of the whole-file digest. The two
# interpreters refuse to run if their source slice is changed.
WINDOWS = (
    ('whole_inline_action_reader', 0x282a180, 0x282c2a7, '28eddb7615ee708c928d5abb8f2f5269f0a69eab3023a84ae8e706d268a3e374'),
    ('whole_boxed_action_reader', 0x282c380, 0x282ec5d, '248fb128bee851035e33caaec17dd3c76afc60bf910f405f89e4da4b8e1ba5cf'),
    ('inline_handoff', 0x282ae51, 0x282ae8f, '7aa6f7e154cd4e67cdf8a9d2382bfeec9fe75b88f173f4d1e18e2621d56e869f'),
    ('boxed_handoff', 0x282d725, 0x282d763, '8fb4a9fbc7424451a3acddaa1ded6d713e35dcc9811fd95ec9fd525da4c315fb'),
    ('inline_store_action_tag', 0x282c164, 0x282c167, '89f223a0d6d3da3d37952264d496e3470ac52513b96f31dbb1a5821e39a78479'),
    ('boxed_store_action_tag', 0x282e9cd, 0x282e9d0, '89f223a0d6d3da3d37952264d496e3470ac52513b96f31dbb1a5821e39a78479'),
    ('whole_boxed_name_selector', 0x219d9e0, 0x219db5f, '65ce7e252e5ec30d89c3ae8e50d58d45b1af08f8a9a1ddf824eb8a4152898aa1'),
    ('whole_inline_name_selector', 0x219db60, 0x219dcf0, '779c86d94c0f6d669432f0b5d3062e96991b04d33300cbfac72e0d0474798968'),
    ('whole_inline_content_reader', 0x21b1c10, 0x21b28c3, 'd38027cd6c8432b28bddafc41b786a849e0bf37adc61c55ed0593bf4d5c6d99b'),
    ('whole_boxed_content_reader', 0x21b28d0, 0x21b31b3, 'e9ce4ea56b276fa6fcd865ca5a11689679ac892daa6ca5669b508984746d747c'),
    ('whole_boxed_vote_map', 0x1f24320, 0x1f2482e, '6bcad8422eb7317f0abc4c6ccf40e53066b47dd3d75a9bdb2c998e74a0e427f8'),
    ('whole_boxed_vote_sequence', 0x1f4ea40, 0x1f4ecd2, '8c27ce78ab13b0e3a724d303a3fbfa2818bcaa0906131d68ec7730ad92c02c69'),
    ('whole_boxed_field_reader', 0x2162820, 0x2162aa7, '4c79de4eaec768f4cc492a4d2f1ed43d5a0d2e3d4f539802a87140ed65177587'),
    ('whole_field_string_helper', 0x21a1480, 0x21a158c, '847e76277ce7cabbcb0526c411d1be240a93744dd51e562d50f349a4f066087a'),
    ('boxed_name', 0x219d9e7, 0x219dade, 'be8b298129aa69bcea896dce50c1d27d57580598cd2f8f6ef2c8acf150379c76'),
    ('inline_name', 0x219db67, 0x219dc5e, '1e5fc6844110acebd7cceec7125d67e942ef2f8b2c531f86cd4e68bb1d714c9d'),
    ('field_name', 0x21a1487, 0x21a150b, 'b3bdbf9c51e907fdd27f158c3da3a35d59072058ed505ea05130807a15c41eab'),
    ('boxed_envelope', 0x21b28e7, 0x21b29d7, 'b85c6d06ba032186e9dd5ee27074d20211e08ea370ee0a8a2e4d600e5eb5a0f2'),
    ('boxed_vote_error', 0x21b2fba, 0x21b2fc3, 'b59e08d475826b7d939072955489d189aa29f32b6995ae5472635e14453373b1'),
    ('boxed_value_dispatch', 0x21b2e68, 0x21b2f8d, '158743843bdab977403c81c0ab5f1ae38f9cdf810da387ea0f6ba8325808c912'),
    ('boxed_vote_map', 0x1f24320, 0x1f247b3, 'a8ec499d231df42fac979a7fafaf482cad1893c11bcede3c46e9d8206c98dc81'),
    ('boxed_vote_sequence', 0x1f4ea40, 0x1f4ec82, 'fde3b48fe45b4d3c41ae8e1f9d7778740c7a3ec082e93cd51c8bad7c0ffbc9d4'),
    ('boxed_field_reader', 0x2162820, 0x2162a28, 'd548aa9c58e65e6bbadcbd5b592e3a7068286c47a80f7fe0e93d930e0ccfd35f'),
)
# Instruction starts reviewed in isolation; these are not a full CFG.
EDGES = (
    ('inline_action_to_signer_reader', 0x282ae59, 'call'),
    ('inline_action_reader_error', 0x282ae67, 'jne'),
    ('inline_action_to_tag_store', 0x282ae8a, 'jmp'),
    ('boxed_action_to_signer_reader', 0x282d72d, 'call'),
    ('boxed_action_reader_error', 0x282d73b, 'jne'),
    ('boxed_action_to_tag_store', 0x282d75e, 'jmp'),
    ('envelope_direct_0c', 0x21b28ef, 'je'),
    ('envelope_direct_0d', 0x21b28f9, 'je'),
    ('envelope_unsupported', 0x21b2903, 'jne'),
    ('envelope_map_empty', 0x21b2936, 'je'),
    ('envelope_first_sentinel', 0x21b294c, 'je'),
    ('envelope_map_one', 0x21b2992, 'je'),
    ('envelope_second_not_sentinel', 0x21b29d1, 'jne'),
    ('boxed_selector_from_content', 0x21b2b61, 'call'),
    ('boxed_selector_from_bytes', 0x21b2b87, 'call'),
    ('inline_selector_from_content', 0x21b1ee8, 'call'),
    ('inline_selector_from_bytes', 0x21b1f0e, 'call'),
    ('value_tag_zero', 0x21b2e6a, 'je'),
    ('value_tag_not_one', 0x21b2e6f, 'jne'),
    ('jail_absent', 0x21b2e73, 'je'),
    ('jail_unit', 0x21b2e7d, 'je'),
    ('jail_nonmap', 0x21b2e82, 'jne'),
    ('jail_nonempty_map', 0x21b2e8e, 'jne'),
    ('unjail_absent', 0x21b2eb1, 'je'),
    ('unjail_unit', 0x21b2ebb, 'je'),
    ('unjail_nonmap', 0x21b2ec0, 'jne'),
    ('unjail_nonempty_map', 0x21b2ecc, 'jne'),
    ('vote_sequence', 0x21b2eef, 'je'),
    ('vote_nonmap', 0x21b2ef7, 'jne'),
    ('vote_invalid_not_absent', 0x21b2fbd, 'jne'),
    ('vote_map_call', 0x21b2f46, 'call'),
    ('vote_sequence_call', 0x21b2f88, 'call'),
    ('map_field_call', 0x1f244b4, 'call'),
    ('map_field_error', 0x1f244c1, 'jne'),
    ('map_signer_field', 0x1f244cf, 'je'),
    ('map_duplicate_time', 0x1f244d6, 'jne'),
    ('map_time_call', 0x1f24516, 'call'),
    ('map_duplicate_signer', 0x1f24555, 'jne'),
    ('map_signer_call', 0x1f24595, 'call'),
    ('map_missing_signer', 0x1f245bd, 'je'),
    ('map_missing_time_word', 0x1f245c5, 'je'),
    ('seq_first_call', 0x1f4ea57, 'call'),
    ('seq_first_helper_success', 0x1f4ea60, 'jne'),
    ('seq_missing_first', 0x1f4ea93, 'je'),
    ('seq_missing_second_empty', 0x1f4eaa4, 'je'),
    ('seq_missing_second_end', 0x1f4eaae, 'je'),
    ('seq_second_not_sentinel', 0x1f4ead1, 'jne'),
    ('seq_second_call', 0x1f4eb96, 'call'),
    ('seq_second_helper_success', 0x1f4eba5, 'je'),
    ('seq_zero_time_word', 0x1f4ebcb, 'je'),
    ('seq_extra_elements', 0x1f4ec34, 'jne'),
    ('seq_extra_overflow_or_panic', 0x1f4ec56, 'jbe'),
    ('field_borrowed_helper', 0x21628c9, 'call'),
    ('field_owned_helper', 0x21628e5, 'call'),
)
TABLES = (('boxed_content', 0x3cfa0c, 0x21b28d0),
          ('inline_content', 0x3cf9d0, 0x21b1c10),
          ('boxed_field', 0x3cbbe8, 0x2162820))


def authenticate(data, expected=SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('node #94 SHA-256 mismatch')


class Image:
    def __init__(self, data, verify=True):
        if verify:
            authenticate(data)
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1, executable=False):
        if va < 0 or size <= 0:
            raise ValueError('invalid address or size')
        found = [s for s in self.sections if s['type'] != 8
                 and (not executable or s['flags'] & 4)
                 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise ValueError('address is not uniquely file backed')
        s = found[0]
        return s['offset'] + va - s['address']

    def read(self, va, size, executable=False):
        p = self.offset(va, size, executable)
        return bytes(self.data[p:p + size])

    def window(self, name):
        for label, start, end, digest in WINDOWS:
            if label == name:
                raw = self.read(start, end - start, True)
                if hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError('reviewed instruction window mismatch: ' + name)
                return start, raw
        raise ValueError('unknown window')


def branch(image, site, kind):
    head = image.read(site, 2, True)
    if kind in ('call', 'jmp') and head[0] == (0xe8 if kind == 'call' else 0xe9):
        raw = image.read(site, 5, True)
        delta = struct.unpack_from('<i', raw, 1)[0]
    elif kind in ('je', 'jne', 'jbe') and head[0] == {'je': 0x74, 'jne': 0x75, 'jbe': 0x76}[kind]:
        raw = head
        delta = struct.unpack_from('<b', raw, 1)[0]
    elif kind in ('je', 'jne') and head == bytes((0x0f, 0x84 if kind == 'je' else 0x85)):
        raw = image.read(site, 6, True)
        delta = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unexpected branch opcode at ' + hex(site))
    target = site + len(raw) + delta
    image.offset(target, 1, True)
    return raw, target


def jump_table(image, base, fde_start, fde_end):
    if fde_start >= fde_end:
        raise ValueError('invalid FDE range')
    raw = image.read(base, 15 * 4)
    rows = []
    for index in range(15):
        word = raw[4 * index:4 * index + 4]
        target = base + struct.unpack('<i', word)[0]
        if not fde_start <= target < fde_end:
            raise ValueError('jump table target outside associated FDE')
        rows.append((index + 1, base + 4 * index, word.hex(), target))
    return rows


def run_classifier(image, window_name, value, trace=None):
    """Interpret the bounded x86 comparison/branch subset; stop at error/store."""
    start, code = image.window(window_name)
    pc = start
    end = start + len(code)
    zf = None
    eax = 0
    steps = 0
    while True:
        if pc == end:
            return None
        if not start <= pc < end or steps > 128:
            raise ValueError('selector escaped reviewed slice')
        i = pc - start
        op = code[i:i + 8]
        old_pc = pc
        steps += 1
        if op[:3] == b'\x48\x83\xfa':
            zf = len(value) == op[3]
            pc += 4
        elif op[:2] == b'\x80\x3e':
            if not value:
                raise ValueError('selector read beyond input')
            zf = value[0] == op[2]
            pc += 3
        elif op[:2] == b'\x80\x7e':
            if op[2] >= len(value):
                raise ValueError('selector read beyond input')
            zf = value[op[2]] == op[3]
            pc += 4
        elif op[:3] == b'\x0f\xb6\x06':
            if not value:
                raise ValueError('selector read beyond input')
            eax = value[0]
            pc += 3
        elif op[:2] == b'\x83\xf8':
            zf = eax == op[2]
            pc += 3
        elif op[:2] == b'\x0f\x85':
            delta = struct.unpack_from('<i', op, 2)[0]
            pc += 6
            if not zf:
                pc += delta
        elif op[0] in (0x74, 0x75):
            delta = struct.unpack_from('<b', op, 1)[0]
            take = zf if op[0] == 0x74 else not zf
            pc += 2
            if take:
                pc += delta
        elif op[:3] == b'\x66\xc7\x07':
            result = struct.unpack_from('<H', op, 3)[0]
            if trace is not None:
                trace.append((old_pc, 'store', result))
            return result
        else:
            raise ValueError('unsupported selector instruction at ' + hex(pc))
        if trace is not None:
            trace.append((old_pc, 'next', pc))


def compared_name(code, offset, length, failure, initial=b''):
    """Extract byte comparisons and check every mismatch reaches failure."""
    name = bytearray(initial)
    while len(name) < length:
        if not name:
            if code[offset:offset + 2] != b'\x80\x3e':
                raise ValueError('unexpected first character comparison')
            name.append(code[offset + 2])
            offset += 3
        else:
            if code[offset:offset + 2] != b'\x80\x7e' or code[offset + 2] != len(name):
                raise ValueError('unexpected character comparison')
            name.append(code[offset + 3])
            offset += 4
        if code[offset:offset + 2] == b'\x0f\x85':
            delta = struct.unpack_from('<i', code, offset + 2)[0]
            offset += 6
        elif code[offset] == 0x75:
            delta = struct.unpack_from('<b', code, offset + 1)[0]
            offset += 2
        else:
            raise ValueError('unexpected character mismatch branch')
        if offset + delta != failure:
            raise ValueError('character mismatch does not reach error arm')
    if code[offset:offset + 3] != b'\x66\xc7\x07':
        raise ValueError('character comparisons do not end in a word store')
    return bytes(name), struct.unpack_from('<H', code, offset + 3)[0]


def extract_names(image, window_name):
    _, code = image.window(window_name)
    failure = len(code)
    if window_name in ('boxed_name', 'inline_name'):
        # The two short names share an initial-byte discriminator in eax.
        if code[0x7f:0x81] != b'\x83\xf8' or code[0x84:0x86] != b'\x83\xf8':
            raise ValueError('unexpected short-name discriminator')
        return (compared_name(code, 0x06, code[3], failure),
                compared_name(code, 0x89, code[0x79], failure, bytes([code[0x86]])),
                compared_name(code, 0xc0, code[0x79], failure, bytes([code[0x81]])))
    if window_name == 'field_name':
        return (compared_name(code, 0x06, code[3], failure),
                compared_name(code, 0x3c, code[0x39], failure))
    raise ValueError('unsupported name window')


def run_selector(image, inline, value, trace=None):
    return run_classifier(image, 'inline_name' if inline else 'boxed_name', value, trace)


def run_field_selector(image, value, trace=None):
    return run_classifier(image, 'field_name', value, trace)


def run_value_dispatch(image, variant, content_tag, length):
    """Interpret dispatch tests, stopping before cleanup, helpers, or errors."""
    if variant not in (0, 1, 2) or not 0 <= content_tag <= 255 or length < 0:
        raise ValueError('invalid abstract dispatch input')
    start, code = image.window('boxed_value_dispatch')
    _, missing_check = image.window('boxed_vote_error')
    if missing_check[:2] != b'\x83\xf8':
        raise ValueError('unexpected vote error comparison')
    missing_tag = missing_check[2]
    pc, eax, zf = start, content_tag, None
    # Reached terminals are instruction boundaries in the checked slice.
    terminals = {0x21b2e94: 'jail_unit', 0x21b2e9e: 'jail_unit',
                 0x21b2ed2: 'unjail_unit', 0x21b2edc: 'unjail_unit',
                 0x21b2efd: 'vote_map', 0x21b2f4d: 'vote_sequence',
                 0x21b2fba: 'vote_missing' if content_tag == missing_tag else 'vote_invalid',
                 0x21b3037: 'jail_invalid', 0x21b304f: 'unjail_invalid'}
    for _ in range(32):
        if pc in terminals:
            return terminals[pc]
        i = pc - start
        if i < 0 or i >= len(code):
            raise ValueError('dispatch escaped reviewed slice')
        op = code[i:i + 8]
        if op[:2] == b'\x85\xc9':
            zf = variant == 0
            pc += 2
        elif op[:2] == b'\x83\xf9':
            zf = variant == op[2]
            pc += 3
        elif op[0] == 0x3c:
            zf = (eax & 255) == op[1]
            pc += 2
        elif op[:5] == b'\x0f\xb6\x44\x24\x30':
            eax = content_tag
            pc += 5
        elif op[:3] == b'\x0f\xb6\xc0':
            eax &= 255
            pc += 3
        elif op[:2] == b'\x83\xf8':
            zf = eax == op[2]
            pc += 3
        elif op[:5] == b'\x48\x83\x7c\x24\x48':
            zf = length == op[5]
            pc += 6
        elif op[:2] in (b'\x0f\x84', b'\x0f\x85'):
            take = zf if op[1] == 0x84 else not zf
            delta = struct.unpack_from('<i', op, 2)[0]
            pc += 6
            if take:
                pc += delta
        elif op[0] in (0x74, 0x75):
            take = zf if op[0] == 0x74 else not zf
            delta = struct.unpack_from('<b', op, 1)[0]
            pc += 2
            if take:
                pc += delta
        else:
            raise ValueError('unsupported dispatch instruction at ' + hex(pc))
    raise ValueError('dispatch step limit')


def field_names(image):
    # Two checked comparison immediates, not labels from inferred source.
    image.window('boxed_field_reader')
    signer = image.read(0x21628a5, 4) + image.read(0x21628b1, 2)
    until = image.read(0x216297a, 8) + image.read(0x216298c, 2)
    return signer.decode('ascii'), until.decode('ascii')


def take_branch(image, site, kind, taken, trace):
    raw, target = branch(image, site, kind)
    next_va = target if taken else site + len(raw)
    if trace is not None:
        trace.append((hex(site), kind, int(taken), hex(next_va)))
    return next_va


def project_envelope(image, outer_tag, count=0, first=0, second=0, trace=None):
    """Project Content envelope branches; iterator storage itself is abstract."""
    image.window('boxed_envelope')
    a, b, mapping = (image.read(x, 1, True)[0] for x in (0x21b28ee, 0x21b28f8, 0x21b2902))
    sentinel = image.read(0x21b294b, 1, True)[0]
    take_branch(image, 0x21b28ef, 'je', outer_tag == a, trace)
    if outer_tag == a:
        return 'direct_key'
    take_branch(image, 0x21b28f9, 'je', outer_tag == b, trace)
    if outer_tag == b:
        return 'direct_key'
    take_branch(image, 0x21b2903, 'jne', outer_tag != mapping, trace)
    if outer_tag != mapping:
        return 'invalid_outer_content'
    if count < 0:
        raise ValueError('negative abstract map length')
    take_branch(image, 0x21b2936, 'je', count == 0, trace)
    if count == 0:
        return 'missing_outer_key'
    take_branch(image, 0x21b294c, 'je', first == sentinel, trace)
    if first == sentinel:
        return 'missing_outer_key'
    take_branch(image, 0x21b2992, 'je', count == 1, trace)
    if count == 1:
        return 'one_outer_entry'
    take_branch(image, 0x21b29d1, 'jne', second != sentinel, trace)
    return 'one_outer_entry' if second == sentinel else 'extra_outer_entry'


def project_map(image, rows, trace=None):
    """Projection with successful iterator operations; not a target emulator.

    A row is (field name, parser result, first time word). This leaves value
    decoders, iterator cleanup and non-text field representations opaque.
    """
    image.window('boxed_vote_map')
    signer, until = field_names(image)
    signer_code = image.read(0x2162936, 1, True)[0]
    until_code = image.read(0x216299c, 1, True)[0]
    if (signer_code != 0 or until_code == signer_code
            or run_field_selector(image, signer.encode('ascii')) >> 8 != signer_code
            or run_field_selector(image, until.encode('ascii')) >> 8 != until_code):
        raise ValueError('unsupported field discriminators')
    got_signer, time_word = False, 0
    for name, result, word in rows:
        if not isinstance(name, str):
            raise ValueError('expected a text field name')
        field_result = run_field_selector(image, name.encode('utf-8'))
        if field_result is None:
            return 'unknown_field'
        is_signer = field_result >> 8 == signer_code
        take_branch(image, 0x1f244cf, 'je', is_signer, trace)
        if is_signer:
            take_branch(image, 0x1f24555, 'jne', got_signer, trace)
            if got_signer:
                return 'duplicate_signer'
            if result != 'ok':
                return 'signer_' + result
            got_signer = True
        else:
            take_branch(image, 0x1f244d6, 'jne', bool(time_word), trace)
            if time_word:
                return 'duplicate_jail_until'
            if result != 'ok':
                return 'jail_until_' + result
            if not 0 <= word <= 0xffffffff:
                raise ValueError('invalid time word')
            time_word = word
    take_branch(image, 0x1f245bd, 'je', not got_signer, trace)
    if not got_signer:
        return 'missing_signer'
    take_branch(image, 0x1f245c5, 'je', not time_word, trace)
    if not time_word:
        return 'missing_jail_until'
    return 'constructed_before_cleanup'


def project_sequence(image, first, second, time_word=1, extra=False, trace=None):
    """Project selected branches given opaque helper/iterator outcomes."""
    image.window('boxed_vote_sequence')
    if first not in ('ok', 'missing', 'error') or second not in ('ok', 'missing', 'error'):
        raise ValueError('invalid abstract helper status')
    if not 0 <= time_word <= 0xffffffff:
        raise ValueError('invalid time word')
    take_branch(image, 0x1f4ea60, 'jne', first != 'error', trace)
    if first == 'error':
        return 'first_helper_error'
    take_branch(image, 0x1f4ea93, 'je', first == 'missing', trace)
    if first == 'missing':
        return 'missing_first'
    take_branch(image, 0x1f4eaa4, 'je', second == 'missing', trace)
    if second == 'missing':
        return 'missing_second'
    take_branch(image, 0x1f4eaae, 'je', False, trace)
    take_branch(image, 0x1f4ead1, 'jne', True, trace)
    take_branch(image, 0x1f4eba5, 'je', second == 'ok', trace)
    if second == 'error':
        return 'second_helper_error'
    take_branch(image, 0x1f4ebcb, 'je', time_word == 0, trace)
    if time_word == 0:
        return 'missing_second'
    take_branch(image, 0x1f4ec34, 'jne', extra, trace)
    return 'extra_elements_path' if extra else 'constructed_if_cleanup_returns'


def write_tsv(out, name, header, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def generate(image, out):
    out.mkdir(parents=True, exist_ok=True)
    for label, *_ in WINDOWS:
        image.window(label)
    _, fdes = eh_frame_records(image.data, image.sections)
    functions = {}
    for label, va in FUNCTIONS:
        matches = [f for f in fdes if f['start'] == va]
        if len(matches) != 1 or matches[0]['end'] <= va:
            raise ValueError('missing or ambiguous FDE for ' + label)
        functions[va] = matches[0]
    rows = []
    for label, va in FUNCTIONS:
        f = functions[va]
        rows.append((label, hex(va), hex(f['end']), hex(f['fde']),
                     '' if f['lsda'] is None else hex(f['lsda']),
                     hex(image.offset(va, f['end'] - va, True))))
    write_tsv(out, 'functions.tsv', ('role', 'start_va', 'fde_end_va', 'fde_va', 'lsda_va', 'file_offset'), rows)
    rows = []
    for label, va, kind in EDGES:
        raw, target = branch(image, va, kind)
        rows.append((label, hex(va), kind, raw.hex(), hex(target), hex(image.offset(va, len(raw), True))))
    write_tsv(out, 'edges.tsv', ('role', 'site_va', 'kind', 'bytes', 'target_va', 'file_offset'), rows)
    handoff_rows = []
    for label, site in (('inline', 0x282ae51), ('boxed', 0x282d725)):
        _, raw = image.window(label + '_handoff')
        if raw[52] != 0xb8:
            raise ValueError('unexpected action tag load')
        tag = struct.unpack_from('<I', raw, 53)[0]
        if raw[49:52] != b'\x0f\x11\x00':
            raise ValueError('unexpected zero-offset copy')
        handoff_rows.append((label, hex(site), hex(tag), hex(raw[16]), hex(raw[4]),
                             hex(raw[20]), hex(raw[21]), hex(raw[39]), hex(raw[44]),
                             hex(raw[31]), hex(raw[51]), hex(raw[48]), hex(raw[34])))
    write_tsv(out, 'handoff.tsv', ('form', 'site_va', 'action_tag', 'parent_payload_offset',
                                   'result_stack_offset', 'status_stack_offset', 'success_status',
                                   'copy16_source0_stack', 'copy16_source1_stack', 'copy4_source_stack',
                                   'copy16_dest0_payload', 'copy16_dest1_payload', 'copy4_dest_payload'), handoff_rows)
    rows = []
    for label, base, owner in TABLES:
        f = functions[owner]
        for tag, entry, raw_hex, destination in jump_table(image, base, f['start'], f['end']):
            rows.append((label, tag, hex(entry), raw_hex, hex(destination)))
    write_tsv(out, 'jump-tables.tsv', ('table', 'content_tag', 'entry_va', 'rel32_le', 'target_va'), rows)
    window_rows = []
    for label, start, end, digest in WINDOWS:
        raw = image.read(start, end - start, True)
        window_rows.append({'role': label, 'start_va': hex(start), 'end_va': hex(end),
                            'file_offset': hex(image.offset(start, end - start, True)),
                            'sha256': digest, 'bytes_hex': raw.hex()})
    (out / 'windows.json').write_text(json.dumps(window_rows, indent=2) + '\n', encoding='utf-8')
    names = tuple(name for name, _ in extract_names(image, 'boxed_name'))
    if names != tuple(name for name, _ in extract_names(image, 'inline_name')):
        raise ValueError('action selector copies disagree')
    variants, traces = [], []
    for inline in (False, True):
        for name in names:
            trace = []
            result = run_selector(image, inline, name, trace)
            variants.append(('inline' if inline else 'boxed', name.decode('ascii'), hex(result), result >> 8))
            for index, (site, operation, next_value) in enumerate(trace):
                traces.append(('inline' if inline else 'boxed', name.decode('ascii'), index,
                               hex(site), operation, hex(next_value)))
    for name, _ in extract_names(image, 'field_name'):
        trace = []
        result = run_field_selector(image, name, trace)
        variants.append(('field', name.decode('ascii'), hex(result), result >> 8))
        for index, (site, operation, next_value) in enumerate(trace):
            traces.append(('field', name.decode('ascii'), index, hex(site), operation, hex(next_value)))
    write_tsv(out, 'variants.tsv', ('form', 'name', 'stored_word_le', 'variant_byte'), variants)
    write_tsv(out, 'selector-traces.tsv', ('form', 'name', 'step', 'site_va', 'operation', 'next_or_value'), traces)
    rows = [(v, hex(tag), length, run_value_dispatch(image, v, tag, length))
            for v in range(3) for tag in range(0x17) for length in (0, 1)]
    dispatch_case_count = len(rows)
    write_tsv(out, 'dispatch-cases.tsv', ('variant', 'content_tag', 'abstract_length', 'terminal'), rows)
    signer, until = field_names(image)
    fixtures = (
        ('empty', ()), ('only_signer', ((signer, 'ok', 0),)),
        ('only_time', ((until, 'ok', 1),)),
        ('both', ((signer, 'ok', 0), (until, 'ok', 1))),
        ('reverse', ((until, 'ok', 1), (signer, 'ok', 0))),
        ('duplicate_signer', ((signer, 'ok', 0), (signer, 'ok', 0))),
        ('duplicate_time', ((until, 'ok', 1), (until, 'ok', 1))),
        ('unknown', (('unexpected', 'ok', 0),)),
        ('bad_signer', ((signer, 'error', 0),)),
        ('bad_time', ((until, 'error', 0),)),
        ('zero_word_then_end', ((signer, 'ok', 0), (until, 'ok', 0))),
        ('zero_word_then_nonzero', ((until, 'ok', 0), (until, 'ok', 1), (signer, 'ok', 0))),
    )
    rows = []
    for name, items in fixtures:
        trace = []
        outcome = project_map(image, items, trace)
        rows.append((name, json.dumps(items, separators=(',', ':')), outcome,
                     json.dumps(trace, separators=(',', ':'))))
    write_tsv(out, 'map-projection.tsv', ('synthetic_case', 'abstract_rows', 'projected_outcome', 'branch_trace'), rows)
    sequence_cases = (('valid', 'ok', 'ok', 1, False),
                      ('missing_first', 'missing', 'ok', 1, False),
                      ('missing_second', 'ok', 'missing', 1, False),
                      ('first_error', 'error', 'ok', 1, False),
                      ('second_error', 'ok', 'error', 1, False),
                      ('zero_time_word', 'ok', 'ok', 0, False),
                      ('extra', 'ok', 'ok', 1, True))
    rows = []
    for label, first, second, word, extra in sequence_cases:
        trace = []
        result = project_sequence(image, first, second, word, extra, trace)
        rows.append((label, first, second, word, int(extra), result, json.dumps(trace, separators=(',', ':'))))
    write_tsv(out, 'sequence-projection.tsv', ('synthetic_case', 'first_helper', 'second_helper', 'time_word', 'extra', 'projected_outcome', 'branch_trace'), rows)
    envelope_cases = (('direct_0c', 0x0c, 0, 0, 0), ('direct_0d', 0x0d, 0, 0, 0),
                      ('wrong_type', 0x14, 0, 0, 0), ('empty_map', 0x15, 0, 0, 0),
                      ('first_sentinel', 0x15, 1, 0x16, 0), ('one_entry', 0x15, 1, 0x0c, 0),
                      ('two_entries', 0x15, 2, 0x0c, 0x0c),
                      ('second_sentinel', 0x15, 2, 0x0c, 0x16))
    rows = []
    for label, typ, count, first, second in envelope_cases:
        trace = []
        result = project_envelope(image, typ, count, first, second, trace)
        rows.append((label, hex(typ), count, hex(first), hex(second), result,
                     json.dumps(trace, separators=(',', ':'))))
    write_tsv(out, 'envelope-projection.tsv', ('synthetic_case', 'outer_tag', 'length', 'first_key_tag', 'second_key_tag', 'projected_outcome', 'branch_trace'), rows)
    literals = []
    for label, va, size in (('fields', 0x3c0081, 16), ('variant_description', 0x3c0091, 54),
                            ('missing_prefix', 0x1df8f4, 15), ('duplicate_prefix', 0x1e0fd6, 17)):
        raw = image.read(va, size)
        literals.append((label, hex(va), hex(image.offset(va, size)), raw.hex(), raw.decode('ascii')))
    write_tsv(out, 'literals.tsv', ('role', 'va', 'file_offset', 'bytes_hex', 'ascii'), literals)
    descriptor = image.read(0x3c0081, 16).decode('ascii')
    if descriptor != signer + until:
        raise ValueError('field text and comparison immediates disagree')
    summary = {'target_sha256': SHA256, 'coordinate_system': 'ELF linked virtual addresses',
               'functions_with_fde': len(functions), 'reviewed_windows': len(WINDOWS),
               'reviewed_direct_edges': len(EDGES), 'jump_table_entries': len(TABLES) * 15,
               'selector_accepted_traces': len(variants), 'dispatch_abstract_cases': dispatch_case_count,
               'map_projection_cases': len(fixtures), 'sequence_projection_cases': len(sequence_cases),
               'envelope_projection_cases': len(envelope_cases), 'field_names': [signer, until],
               'limitations': 'Selector and dispatch slices only are interpreted. Envelope, map and sequence cases are abstract projections; helpers, cleanup, error formatting and state execution are not interpreted.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    image = Image(BINARY.read_bytes())
    generate(image, args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('staking_csigner_input94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
