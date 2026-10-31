#!/usr/bin/env python3
"""Digest-bound static observations of node #94 base/src/build_mode.rs bodies.

Static only: reads authenticated ELF bytes and runs GNU readelf/objdump on them.
The captured executable is never launched, emulated or patched.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT, check
from elf_index import sections

# Exact readelf FDE extents (half-open ELF VAs) of the retained bodies.
RANGES = {
    'build-dir': (0x13CD410, 0x13CD6CB),
    'invocation-names': (0x143EF30, 0x143F4E7),
    'static-config-init': (0x164FF00, 0x1650057),
    'reverse-byte-search': (0x157A8A0, 0x157A9AD),
    'whitespace-trim': (0x1407AC0, 0x1407D57),
}
# Caller context only; its opaque command/child layout is not closed here.
CALLER = ('build-dir-caller', 0x13CD7AD, 0x13CD6D0, 0x13CDEED)

# slot VA -> RELA addend (all R_X86_64_RELATIVE).
RELOCATIONS = {
    0x576EA20: 0x13CD410,  # GOT slot called once, at 0x13cd7ad
    0x577AB80: 0x143EF30,  # lazy String slot: stored init function
    0x576E928: 0x577B288,  # GOT slot naming the static_config lazy value
    0x577B288: 0x164FF00,  # static_config lazy slot: stored init function
    0x576F540: 0x4EDCE70,  # args constructor (std env.rs path only via 0x4f100b0)
    0x576F548: 0x4F100B0,  # args next
    0x576F550: 0x157A8A0,  # reverse byte search
    0x576E8B8: 0x4EE3B20,  # Once call slot used by both lazy values
    0x566A090: 0x200676,   # Location -> base/src/build_mode.rs
    0x566A0A8: 0x200676,
    0x566A0C0: 0x200676,
    0x567B428: 0x1DFE2E,   # Location -> global_constants/src/static_config.rs
    0x5752FF0: 0x1E1B35,   # Location -> library/std/src/env.rs
    0x566A7A0: 0x1F87CF,   # Location -> library/std/src/sync/once.rs
    0x5666A68: 0x1F87CF,
    0x5669F50: 0x1F87CF,
}

# Location records: VA -> (path bytes, line, column).
LOCATIONS = {
    0x566A0C0: (b'/home/ubuntu/hl/code_Mainnet/base/src/build_mode.rs', 199, 30),
    0x566A0A8: (b'/home/ubuntu/hl/code_Mainnet/base/src/build_mode.rs', 29, 17),
    0x566A090: (b'/home/ubuntu/hl/code_Mainnet/base/src/build_mode.rs', 32, 26),
    0x567B428: (b'/home/ubuntu/hl/code_Mainnet/global_constants/src/static_config.rs', 24, 9),
    0x5752FF0: (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/env.rs', 871, 51),
    0x566A7A0: (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
    0x5669F50: (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
    0x5666A68: (b'/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
}

# Formatting templates referenced by the bodies. Decoded tokens are an
# inference from these bytes: 0xc0 = one argument, 0x01..0x7f = that many
# literal bytes, 0x00 = end. Any other control byte fails closed.
TEMPLATES = {
    0x1E938E: ['{}', '/', '{}'],
    0x1FAE07: ['{}', '/aws_build/', '{}'],
    0x1E4C77: ['{}', '/code/run-client'],
    0x1F05A7: ['tried to get build_dir of ', '{}', ', a bug?'],
    0x1F4EA1: ['{}', ' ', '{}'],
    0x1ED05B: ['{}', '/code'],
    0x1F6798: ['cham_dir does not exist: ', '{}'],
}

LITERALS = {
    0x2194D5: b'debug',
    0x2194DA: b'release',
    0x2194AA: b'/cham/',
    0x2194B0: b"assertion failed: !arg.ends_with('/')",
}

# Architectural byte controls (VA -> exact bytes), not target execution.
CONTROLS = {
    # build-dir: arguments rdi=out, (rsi,rdx)=name, cl=mode byte 0, r8b=mode byte 1
    0x13CD428: '4489c008c8744f',  # (byte0|byte1)==0 -> owned copy of name, tag 0
    0x13CD42F: '4883fa0a752148b872756e2d636c69654833060fb756084881f26e7400004809c20f8440010000',
    # ^ len==10 && name=="run-client" is tested before any byte0 dispatch
    0x13CD45F: '80f901742e0fb6c183f8020f85c6010000',  # byte0 1 -> debug; 2 -> release; else panic
    0x13CD470: '488d0563c0e4feb907000000',  # "release", 7
    0x13CD492: '488d053cc0e4feb905000000',  # "debug", 5
    0x13CD4CD: '488d35babee1fe',  # template "{}/{}" (profile, name)
    0x13CD4EE: '4c8b3d33143a04418b475085c00f85040100004983c718',  # lazy value, state +0x50, field +0x18
    0x13CD525: '488d35dbd8e2fe',  # template "{}/aws_build/{}"
    0x13CD54D: 'c6431801',  # result tag byte +0x18 = 1 (aws_build route)
    0x13CD596: '4c8b358b133a04418b465085c00f85bc0000004983c618',  # run-client route: same field +0x18
    0x13CD5BE: '488d35b276e1fe',  # template "{}/code/run-client"
    0x13CD5F2: 'c6431800',  # result tag byte +0x18 = 0 (local and run-client routes)
    0x13CD64C: '488d3d542fe2fe488d1566ca2904',  # panic template + build_mode.rs:199:30
    # invocation-names (lazy String initializer)
    0x143EF69: 'ff15d1053304',  # args constructor slot
    0x143EFBA: 'ff1588053304488b4c24784889c848f7d80f800b030000',  # next(); niche None -> finish
    0x143EFE5: '4883fb02720c6641813e2d2d0f84f7010000',  # len>=2 && starts "--" -> skip arg
    0x143EFF7: 'be06000000488d3da7a4ddfe4c89f24889d9e8e21d000084c00f843a010000',  # contains "/cham/"
    0x143F016: '4885db740c41807c1eff2f0f84f9030000',  # trailing '/' -> assertion
    0x143F08C: '43807c06ff2f4d89f8',  # backward scan for '/'
    0x143F118: '49ffc74c39fb760b43803c3ec00f8c26030000',  # slice after '/', char-boundary check
    0x143F150: '4989df4c89f74c89fee86289fcff',  # each piece passed through 0x1407ac0
    0x143F1A8: '488d35f25cdbfe',  # template "{} {}" (accumulator, piece)
    0x143F250: '4939df7746bf2d0000004c89f64c89faff15ea023304a80174314989d74839da73de43803c3e2d75',
    # ^ reverse '-' search over [start, bound); bound shrinks to the hit
    0x143F34E: '488b7c2418488b742420e86387fcff',  # final accumulator through 0x1407ac0
    0x143F420: '488d3d89a0ddfe488d157aac2204be25000000ff15cfec3204',  # assert + build_mode.rs:29:17
    0x143F451: '4c8d0538ac2204',  # slice failure location build_mode.rs:32:26
    # helpers
    0x157A8E8: '4d8d42ff42387c16ff4d89c275ea',  # compares byte[len-1] downward
    0x1407BD2: '4181f980160000',  # U+1680 (forward pass)
    0x1407BF2: '4181f900300000',  # U+3000 (forward pass)
    0x1407D0A: '4181fa80160000',  # U+1680 (backward pass)
    0x1407D2A: '4181fa00300000',  # U+3000 (backward pass)
    # static_config initializer
    0x164FF40: 'ff15f20b120484c00f8489000000',  # existence predicate; false -> panic
    0x164FFA3: '0f10442408410f114618488b4c2418',  # checked path stored at value +0x18
    0x164FFE8: '488d3da967bafe488d1532b40204488d742420',  # "cham_dir does not exist: {}" + :24:9
    # example lazy-String use: slot 0x577ab80, Once state 0x577ab98, Once slot 0x576e8b8
    0x13CBAE6: '488d0593f03a04488904244889e04889442410488d3d98f03a04488d0d61e429044c8d0542e42904488d542410be01000000ff159a2d3a04',
    # sole caller
    0x13CD79A: '410fb6cd440fb6c5488d7c24604c89fe4c89f2ff156d123a04',
}

LIMITS = ('Static observations of two build_mode.rs bodies, the static_config lazy initializer, and two '
          'helpers. The meaning of mode byte 1, the existence predicate, the args/allocation/format/panic/'
          'Once callees, the caller command object and runtime argv/cham_dir values are not closed. '
          'No Rust implementation, runtime comparison, equivalence or gate is claimed.')


def read_va(data, va, size):
    matches = [s for s in sections(data) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'Expected one file mapping for {va:#x}')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, bytes(data[offset:offset + size])


def decode_template(data, va):
    _, raw = read_va(data, va, 256)
    tokens, pos = [], 0
    while True:
        byte = raw[pos]
        if byte == 0:
            return tokens, pos + 1
        if byte == 0xC0:
            tokens.append('{}')
            pos += 1
        elif byte < 0x80:
            literal = raw[pos + 1:pos + 1 + byte]
            if len(literal) != byte:
                raise ValueError(f'Template literal outside window at {va:#x}')
            tokens.append(literal.decode('utf-8'))
            pos += 1 + byte
        else:
            raise ValueError(f'Unsupported template control {byte:#x} at {va:#x}; do not guess')


def controls(data):
    for va, value in CONTROLS.items():
        if read_va(data, va, len(bytes.fromhex(value)))[1] != bytes.fromhex(value):
            raise ValueError(f'Build-mode control changed at {va:#x}')
    for va, literal in LITERALS.items():
        if read_va(data, va, len(literal))[1] != literal:
            raise ValueError(f'Build-mode literal changed at {va:#x}')
    templates = {}
    for va, expected in TEMPLATES.items():
        tokens, size = decode_template(data, va)
        if tokens != expected:
            raise ValueError(f'Build-mode template changed at {va:#x}')
        templates[hex(va)] = {'tokens': tokens, 'bytes': size}
    return [{'va': hex(va), 'bytes': value} for va, value in CONTROLS.items()], templates


def relevant_relocations(data):
    rows = []
    for section in sections(data):
        if section['type'] != 4:
            continue
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot in RELOCATIONS:
                if info != 8 or addend != RELOCATIONS[slot]:
                    raise ValueError(f'Build-mode relocation changed at {slot:#x}')
                rows.append({'slot_va': hex(slot), 'type': 'R_X86_64_RELATIVE', 'addend': hex(addend)})
    if len(rows) != len(RELOCATIONS):
        raise ValueError('Missing build-mode relocation')
    return sorted(rows, key=lambda r: int(r['slot_va'], 16))


def locations(data):
    rows = []
    for va, (path, line, column) in LOCATIONS.items():
        _, record = read_va(data, va, 24)
        _, length, got_line, got_column = struct.unpack('<QQII', record)
        target = RELOCATIONS[va]
        if (length, got_line, got_column) != (len(path), line, column) or read_va(data, target, length)[1] != path:
            raise ValueError(f'Build-mode location changed at {va:#x}')
        rows.append({'record_va': hex(va), 'path_va': hex(target), 'path': path.decode(),
                     'line': line, 'column': column})
    return rows


def objdump_targets(line):
    """Return (site, mnemonic, target) from one objdump row using its RIP/direct target."""
    match = re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s)+\s*(call|jmp|lea|mov)\S*\s+(\S+)', line)
    if not match:
        return None
    site, mnemonic, operand = int(match[1], 16), match[2], match[3]
    comment = re.search(r'#\s+([0-9a-f]+)\b', line)
    if '(%rip)' in operand and comment:
        return site, mnemonic, int(comment[1], 16)
    if mnemonic in ('call', 'jmp') and re.fullmatch(r'[0-9a-f]+', operand):
        return site, mnemonic, int(operand, 16)
    return None


def census(binary):
    wanted = {0x576EA20, 0x13CD410, 0x143EF30, 0x577AB80, 0x577AB98}
    found = []
    with subprocess.Popen(['objdump', '-d', '-j', '.text', str(binary)],
                          stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            ref = objdump_targets(line)
            if ref and ref[2] in wanted:
                found.append({'site_va': hex(ref[0]), 'instruction': ref[1], 'target_va': hex(ref[2])})
        if process.wait() != 0:
            raise ValueError('Complete .text disassembly failed')
    by_target = {}
    for row in found:
        by_target.setdefault(row['target_va'], []).append(row['site_va'])
    if by_target.get('0x576ea20') != ['0x13cd7ad']:
        raise ValueError('Build-dir GOT caller set changed')
    if '0x13cd410' in by_target or '0x143ef30' in by_target:
        raise ValueError('Unexpected direct reference to a build_mode body')
    return found, {k: len(v) for k, v in sorted(by_target.items())}


def generate(binary, output):
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == 'artifacts/node/94/hl-node')
    check(binary, identity)
    data = binary.read_bytes()
    byte_controls, templates = controls(data)
    relocs, locs = relevant_relocations(data), locations(data)
    frames_text = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    fdes = [(int(a, 16), int(b, 16)) for a, b in
            re.findall(r'FDE[^\n]*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', frames_text)]
    scope = list(RANGES.values()) + [CALLER[2:]]
    for pair in scope:
        if fdes.count(pair) != 1:
            raise ValueError(f'Expected one exact FDE range: {pair}')
    references, reference_counts = census(binary)
    output.mkdir(parents=True, exist_ok=True)
    rela_text = subprocess.check_output(['readelf', '-rW', str(binary)], text=True)
    rela_rows = [line for line in rela_text.splitlines()
                 if re.match(r'^[0-9a-f]+\s', line) and int(line.split()[0], 16) in RELOCATIONS]
    if len(rela_rows) != len(RELOCATIONS):
        raise ValueError('Independent readelf relocation row count differs')
    (output / 'relocations.txt').write_text('\n'.join(rela_rows) + '\n')
    (output / 'references.tsv').write_text('site_va\tinstruction\ttarget_va\n' + ''.join(
        f"{r['site_va']}\t{r['instruction']}\t{r['target_va']}\n" for r in references))
    ranges = {}
    for name, (begin, end) in [*RANGES.items(), (CALLER[0], CALLER[2:])]:
        offset, body = read_va(data, begin, end - begin)
        ranges[name] = {'start_va': hex(begin), 'end_va': hex(end), 'file_offset': hex(offset),
                        'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        text = subprocess.check_output(['objdump', '-d', f'--start-address={begin:#x}',
                                        f'--stop-address={end:#x}', str(binary)], text=True)
        (output / f'{name}.objdump.txt').write_text(text.replace(str(binary), '<authenticated-node94>'))
    (output / 'frames.txt').write_text('\n'.join(line for line in frames_text.splitlines()
        if 'FDE' in line and any(f'pc={a:016x}..{b:016x}' in line for a, b in scope)) + '\n')
    records = {
        'target_sha256': identity['sha256'], 'target_bytes': len(data),
        'ranges': ranges, 'decoded_fde_count': len(fdes),
        'instruction_controls': byte_controls, 'templates': templates,
        'literals': {hex(va): value.decode() for va, value in LITERALS.items()},
        'locations': locs, 'relocations': relocs,
        'reference_counts': reference_counts,
        'build_dir_caller_sites': [r['site_va'] for r in references if r['target_va'] == '0x576ea20'],
        'observations': {
            'build_dir': [
                'mode bytes (0,0): owned copy of name; tag 0',
                'any other mode and name == "run-client": format "{}/code/run-client" with lazy static_config value field +0x18; tag 0',
                'byte0 1 or 2: format "{}/{}" (debug|release, name), then "{}/aws_build/{}" with the same field; tag 1',
                'otherwise: panic "tried to get build_dir of {}, a bug?" at build_mode.rs:199:30',
            ],
            'static_config_field_0x18': 'path checked by an existence predicate; false panics "cham_dir does not exist: {}" at static_config.rs:24:9',
            'invocation_names': [
                'lazy String initializer at slot 0x577ab80 (Once state 0x577ab98)',
                'iterate args; skip len>=2 starting "--"',
                'if arg contains "/cham/": assert no trailing "/" (build_mode.rs:29:17), keep text after the last "/" (boundary failure at :32:26), then keep text before the last "-" if any',
                'acc = format("{} {}", acc, helper_0x1407ac0(piece)); return owned copy of helper_0x1407ac0(acc)',
            ],
        },
        'captured_binary_executed': False,
        'limits': LIMITS,
    }
    (output / 'records.json').write_text(json.dumps(records, indent=2) + '\n')
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, default=ROOT / 'work/build-mode-static-94')
    args = parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output), indent=2))
