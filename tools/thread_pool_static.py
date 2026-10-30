#!/usr/bin/env python3
"""RE-001: node94 pool-size clamp and num_cpus-linked cached/affinity provider."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-001-thread-pool-sizing-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = [(0x13cba40, 0x13cbb7e), (0x4e06870, 0x4e069a8)]
CONTROLS = {
    0x13cba49: "4889f34989feff15332f3a0448c1e8024c39f34d89f74c0f47fb4c0f42f34c39f84c0f42f84c39f04d0f42fe",
    0x13cba7f: "4983ff014983d70048c7442410000000004c897c242048c74424280000000048c74424380000000048c74424480000000048c74424580000000066c744246800004889e7488d742410e843f60800",
    0x13cbacd: "488b04244883f803754c488b4424084883c4705b415e415fc3",
    0x13cbae6: "488d0593f03a04488904244889e04889442410488d3d98f03a04488d0d61e429044c8d0542e42904488d542410be01000000ff159a2d3a04e95cffffff",
    0x13cbb23: "488b4c24084889442410488d5c241848894c2418488d3d5fb4e4fe488d0d73b429044c8d057cb02904488d542410be2b000000ff15ec243a040f0b",
    0x4e06878: "8b0582ff970085c07515488b056f1b98004885c074464881c4900000005bc3c644240f01488d44240f4889442410488d3d53ff9700488d0db41694004c8d051d179400488d54241031f6ff15f07f9600488b05291b98004885c075ba",
    0x4e068d4: "0f57c00f298424800000000f294424700f294424600f294424500f294424400f294424300f294424200f2944241031db488d542410be8000000031ffff155a02970085c07424bf54000000ff15839f96004889c14883f802b801000000480f4dc14881c4900000005bc3",
    0x4e0693e: "31c0eb1a66666666662e0f1f8400000000004883c002483d0004000074344889c148c1e906488b54cc1089c183e13e480fa3ca730783fbff7423ffc389c180e13e48d3eaf6c20274c983fbff740fffc3ebc089d84881c4900000005bc3",
}
RIP = {(0x13cba4f, 'ff15'): 0x576e988,
       (0x13cbb07, '4c8d05'): 0x5669f50,
       (0x13cbb18, 'ff15'): 0x576e8b8,
       (0x13cbb37, '488d3d'): 0x216f9d,
       (0x13cbb45, '4c8d05'): 0x5666bc8,
       (0x13cbb56, 'ff15'): 0x576e048,
       (0x4e06878, '8b05'): 0x5786800,
       (0x4e06882, '488b05'): 0x57883f8,
       (0x4e068b4, '4c8d05'): 0x5747fd8,
       (0x4e068c2, 'ff15'): 0x576e8b8,
       (0x4e068c8, '488b05'): 0x57883f8,
       (0x4e06910, 'ff15'): 0x5776b70,
       (0x4e0691f, 'ff15'): 0x57708a8,
       (0x4e0699b, '488d3d'): 0x5747fc0}
RELATIVE = {0x576e988: 0x4e06870, 0x576e8b8: 0x4ee3b20,
            0x576e048: 0x157aa10, 0x5666bc8: 0x1ef2de,
            0x5669f50: 0x1f87cf, 0x5747fd8: 0x1f1396, 0x5747fc0: 0x1f1396}


def read(data, va, size):
    found = [s['offset'] + va - s['address'] for s in sections(data) if s['type'] != 8
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('expected one file-backed mapping')
    off = found[0]
    return off, bytes(data[off:off + size])


def requested_threads(provider_word, bound_a, bound_b):
    """Abstract CMOV/ADC expression over unsigned 64-bit inputs, not execution."""
    quarter = provider_word >> 2
    high, low = max(bound_a, bound_b), min(bound_a, bound_b)
    selected = quarter if quarter < high else high
    if quarter < low:
        selected = low
    return selected + int(selected < 1)


def affinity_count(words):
    """Model only the decoded 1024-bit, two-bits-per-iteration reduction."""
    count = 0
    for i in range(0, 1024, 2):
        word, bit = words[i >> 6], i & 0x3e
        count += int(bool(word & (1 << bit)))
        count += int(bool((word >> bit) & 2))
    return count


def sysconf_fallback(raw_word):
    signed = raw_word if raw_word < (1 << 63) else raw_word - (1 << 64)
    return raw_word if signed >= 2 else 1


def analyze(data):
    _, frames, _ = fde_extents(data)
    if not set(RANGES) <= {(f['start'], f['end']) for f in frames}:
        raise ValueError('pool/provider FDE changed')
    for va, value in CONTROLS.items():
        raw = bytes.fromhex(value)
        if read(data, va, len(raw))[1] != raw:
            raise ValueError(f'pool/provider instruction changed at {va:#x}')
    for (va, prefix), target in RIP.items():
        prefix = bytes.fromhex(prefix)
        raw = read(data, va, len(prefix) + 4)[1]
        if not raw.startswith(prefix) or va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0] != target:
            raise ValueError('pool/provider RIP target changed')
    raw = read(data, 0x13cbac8, 5)[1]
    if raw[0] != 0xe8 or 0x13cbac8 + 5 + struct.unpack_from('<i', raw, 1)[0] != 0x145b110:
        raise ValueError('builder call changed')
    if read(data, 0x216f9d, 43)[1] != b'called `Result::unwrap()` on an `Err` value':
        raise ValueError('builder failure literal changed')
    secs = sections(data)
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    rels = {a: (i, v) for a, i, v in struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']])}
    if any(rels.get(a) != (8, v) for a, v in RELATIVE.items()):
        raise ValueError('provider/source/helper relocation changed')
    sym = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    imports = []
    for slot, index, name in [(0x5776b70, 99, b'sched_getaffinity'), (0x57708a8, 59, b'sysconf')]:
        if rels.get(slot) != ((index << 32) | 6, 0):
            raise ValueError('affinity/sysconf import relocation changed')
        name_off = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
        off = strings['offset'] + name_off
        if data[off:off + len(name) + 1] != name + b'\0':
            raise ValueError('affinity/sysconf dynamic symbol changed')
        imports.append({'slot': hex(slot), 'dynsym_index': index, 'name': name.decode()})
    sources = []
    for slot, va, path, line, col in [
        (0x5666bc8, 0x1ef2de, '/home/ubuntu/hl/code_Mainnet/base/src/u.rs', 539, 68),
        (0x5669f50, 0x1f87cf, '/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/std/src/sync/once.rs', 219, 20),
        (0x5747fd8, 0x1f1396, '/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/num_cpus-1.17.0/src/linux.rs', 114, 10),
        (0x5747fc0, 0x1f1396, '/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/num_cpus-1.17.0/src/linux.rs', 45, 17),
    ]:
        raw = path.encode()
        if read(data, va, len(raw))[1] != raw or read(data, slot + 8, 16)[1] != struct.pack('<QII', len(raw), line, col):
            raise ValueError('pool/provider source Location changed')
        sources.append({'slot': hex(slot), 'path_va': hex(va), 'path': path, 'line': line, 'column': col})
    rows = []
    for start, end in RANGES:
        off, raw = read(data, start, end - start)
        rows.append({'start_va': hex(start), 'end_va': hex(end), 'file_offset': hex(off),
                     'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    return {'target_sha256': SHA256, 'ranges': rows,
            'size_expression': 'max(1, clamp(P >> 2, min(RDI, RSI), max(RDI, RSI)))',
            'provider': {'cache_state_va': '0x5786800', 'cached_count_va': '0x57883f8',
                         'nonzero_cache': 'return cached word', 'zero_cache': 'affinity, with sysconf fallback on nonzero affinity status',
                         'affinity_pid': 0, 'affinity_bytes': 128, 'affinity_bits': 1024,
                         'bits_per_iteration': 2, 'sysconf_argument': 84, 'sysconf_signed_floor': 1},
            'builder': {'call': '0x13cbac8', 'target': '0x145b110', 'num_threads_input_offset': '0x10',
                        'success_raw_tag': 3, 'returned_result_offset': '0x8', 'concrete_pool_type': 'unproved'},
            'imports': imports, 'sources': sources,
            'published_source': {'repository': 'seanmonstar/num_cpus', 'version': '1.17.0',
                                 'commit': '342af76b486335e5a955c7314fc96cd104e7a17b', 'file': 'src/linux.rs',
                                 'sha256': '378ea174d00d560e16fda4b09fb523dda5f4c6f420e46af7d317393a39d88dd1',
                                 'status': 'source Location and control-flow compatibility, not pristine build proof; initializer closure unproved'},
            'relative_bindings': {hex(a): hex(v) for a, v in RELATIVE.items()},
            'instruction_controls': {hex(a): v for a, v in CONTROLS.items()},
            'rip_targets': [{'site': hex(a), 'prefix_hex': p, 'target': hex(v)} for (a, p), v in RIP.items()],
            'captured_binary_executed': False,
            'limits': 'Two bounded FDEs. No caller census, cached-count producer/cgroup initializer closure, full pool builder/lifetime/type, OS state/timing, captured execution or runtime equivalence. Formula applies conditional on provider/initialization helpers returning.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected pinned node94')
    report = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94.elf'
        snapshot.write_bytes(data)
        frames = subprocess.check_output(['readelf', '-wf', str(snapshot)], text=True)
        chosen = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in RANGES)]
        if len(chosen) != 2:
            raise ValueError('native FDE confirmation failed')
        (output / 'frames.txt').write_text('\n'.join(chosen) + '\n')
        for start, end in RANGES:
            asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                          f'--start-address={start:#x}', f'--stop-address={end:#x}', str(snapshot)], text=True)
            ins = decode_export(asm, start, end, read(data, start, end - start)[1])
            required = set(CONTROLS) | {a for a, _ in RIP} | {0x13cbac8}
            if not {a for a in required if start <= a < end} <= set(ins):
                raise ValueError('pool/provider controls must be decoded instruction starts')
            (output / f'{start:x}.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/thread-pool-sizing-94')
    args = parser.parse_args()
    print(json.dumps({'ranges': len(generate(args.binary, args.output)['ranges']), 'executed': False}))
