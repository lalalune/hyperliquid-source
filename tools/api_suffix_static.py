#!/usr/bin/env python3
"""RE-001: digest-bound static evidence for node94 API suffix dispatch; no target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x1450ae0, 0x1450efc
TABLE = 0x219998
ARMS = [0x1450b17, 0x1450db5, 0x1450b97, 0x1450c92, 0x1450b5b, 0x1450df3]


class Image:
    def __init__(self, data):
        self.data, self.sections = data, sections(data)

    def offset(self, va, size):
        found = [s['offset'] + va - s['address'] for s in self.sections
                 if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise ValueError(f'no unique file mapping for {va:#x}+{size}')
        return found[0]

    def read(self, va, size):
        offset = self.offset(va, size)
        return self.data[offset:offset + size]

    def expect(self, va, value):
        if self.read(va, len(value)) != value:
            raise ValueError(f'byte control changed at {va:#x}')

    def rip(self, va, prefix):
        self.expect(va, prefix)
        return va + len(prefix) + 4 + struct.unpack('<i', self.read(va + len(prefix), 4))[0]

    def binding(self, va, size):
        raw = self.read(va, size)
        return {'va': hex(va), 'file_offset': hex(self.offset(va, size)), 'bytes': size,
                'sha256': hashlib.sha256(raw).hexdigest(), 'hex': raw.hex()}


def analyze(data):
    """Inspect specific instructions/data. Corruption tests call this below the digest gate."""
    image = Image(data)
    _, frames, _ = fde_extents(data)
    if not any(f['start'] == START and f['end'] == END for f in frames):
        raise ValueError('suffix FDE extent changed')
    caller = next(f for f in frames if f['start'] <= 0x2272d10 < f['end'])
    controls = {
        0x1450af1: '8b0689c183c1fe6683f802b8050000000f43c10fb7c0',
        0x1450b0e: '486304814801c8ffe0',
        0x1450b17: 'bf18000000', 0x1450b32: '0f1100',
        0x1450b35: '48b97569642e78797a2f', 0x1450b3f: '48894810',
        0x1450b43: '48c703180000004889430848c7431018000000',
        0x1450b5b: 'bf12000000', 0x1450b76: '0f1100',
        0x1450b79: '66c74010312f',
        0x1450b7f: '48c703120000004889430848c7431012000000',
        0x1450db5: 'bf20000000', 0x1450dd0: '0f114010', 0x1450ddb: '0f1100',
        0x1450dde: '48c703200000004889430848c7431020000000',
        0x1450c24: '4983ed0a', 0x1450d14: '4983ed10',
        0x1450c62: 'e918010000', 0x1450d50: '742d', 0x1450db3: 'eb65',
        0x1450d84: '8b849810010000890424',
    }
    for va, value in controls.items():
        image.expect(va, bytes.fromhex(value))
    rip_targets = {
        (0x1450b07, '488d0d'): TABLE,
        (0x1450b2b, '0f1005'): 0x219d3d,
        (0x1450b6f, '0f1005'): 0x219d5f,
        (0x1450dc9, '0f1005'): 0x20c4f0,
        (0x1450dd4, '0f1005'): 0x20c4e0,
        (0x1450bcd, '4c8d35'): 0x219d55,
        (0x1450cc8, '4c8d35'): 0x204b60,
        (0x1450da2, '488d35'): 0x1e4df8,
        (0x1450e0b, '488d35'): 0x1f7555,
        (0x1450dff, '488d05'): 0x14791a0,
        (0x1450eba, '488d15'): 0x566ab28,
        (0x1450e1a, 'ff15'): 0x576e040,
        (0x2272d49, 'ff15'): 0x576e040,
        (0x2272d10, 'e8'): START,
        (0x2272d2c, '488d35'): 0x2006b7,
        (0x1450b9c, '488b1d'): 0x576eb70,
        (0x1450c97, '488b1d'): 0x576eb70,
    }
    for (va, prefix), expected in rip_targets.items():
        if image.rip(va, bytes.fromhex(prefix)) != expected:
            raise ValueError(f'RIP/call target changed at {va:#x}')
    if [TABLE + struct.unpack('<i', image.read(TABLE + i * 4, 4))[0] for i in range(6)] != ARMS:
        raise ValueError('six-arm dispatch table changed')
    literals = [(0x219d3d, b's://api.hyperliquid.xyz/'),
                (0x20c4e0, b's://api.hyperliquid-testnet.xyz/'),
                (0x219d5f, b'://localhost:3001/'),
                (0x219d55, b'WebSandbox'), (0x204b60, b'WebSandboxPublic'),
                (0x1e4df8, b'\x03://\xc0\x06:3001/\0'),
                (0x1f7555, b'\x03://\xc0\x01/\0'), (0x2006b7, b'\x04http\xc0\0')]
    for va, value in literals:
        image.expect(va, value)
    # ELF64 RELA applies the source filename pointer and internal helper slots.
    relative = {}
    for section in image.sections:
        if section['type'] == 4:
            for pos in range(section['offset'], section['offset'] + section['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, pos)
                if info & 0xffffffff == 8:
                    relative[slot] = addend
    wanted = {0x566ab28: 0x1ecd56, 0x576eb70: 0x577a898,
              0x576f6d0: 0x157c730, 0x576e040: 0x1344760}
    if any(relative.get(slot) != value for slot, value in wanted.items()):
        raise ValueError('source/global/helper relocation changed')
    image.expect(relative[0x566ab28], b'/home/ubuntu/hl/code_Mainnet/base/src/api_url.rs')
    image.expect(0x566ab30, struct.pack('<QII', 48, 90, 38))
    return {'target_sha256': SHA256, 'target_bytes': len(data),
            'function': image.binding(START, END - START),
            'caller_fde': {'start_va': hex(caller['start']), 'end_va': hex(caller['end'])},
            'dispatch': {'table': image.binding(TABLE, 24), 'arm_vas': [hex(a) for a in ARMS],
                         'valid_tag_to_arm_index': {'0': 5, '1': 5, '2': 0, '3': 1, '4': 2, '5': 3, '6': 4}},
            'literals_and_descriptors': [dict(image.binding(va, len(value)), ascii=value.decode('ascii', errors='backslashreplace')) for va, value in literals],
            'source': {'slot_va': '0x566ab28', 'path_va': hex(relative[0x566ab28]), 'line': 90, 'column': 38},
            'relocations': {hex(slot): hex(value) for slot, value in wanted.items()},
            'controls': {hex(va): value for va, value in controls.items()},
            'rip_targets': [{'instruction_va': hex(va), 'prefix_hex': prefix, 'target_va': hex(target)}
                            for (va, prefix), target in rip_targets.items()],
            'captured_binary_executed': False,
            'limits': 'One FDE and one caller site, no whole-node census. Enum names/layout beyond observed tags, map population, helper closure, format interpreter, runtime behavior and component completion remain unproved.'}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != 91774280 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('expected the pinned node94 capture')
    result = analyze(data)
    output.mkdir(parents=True, exist_ok=True)
    # Bind external decoder input to the same bytes using a private snapshot.
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = Path(temporary) / 'node94.elf'
        snapshot.write_bytes(data)
        asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16', f'--start-address={START:#x}',
                                       f'--stop-address={END:#x}', str(snapshot)], text=True)
        starts = {int(m.group(1), 16) for m in re.finditer(r'^\s*([0-9a-f]+):\s', asm, re.M)}
        expected = set(int(v, 16) for v in result['controls']) | {int(r['instruction_va'], 16) for r in result['rip_targets'] if int(r['instruction_va'], 16) < END}
        if not expected <= starts:
            raise ValueError('byte controls must start at decoded instructions')
        (output / 'function.objdump.txt').write_text(asm.replace(str(snapshot), '<authenticated-node94>'))
        frames = subprocess.check_output(['readelf', '--debug-dump=frames', str(snapshot)], text=True)
        pairs = [(int(a, 16), int(b, 16)) for a, b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)', frames)]
        if (START, END) not in pairs:
            raise ValueError('independent readelf suffix FDE does not match')
        chosen = {(START, END), (int(result['caller_fde']['start_va'], 16), int(result['caller_fde']['end_va'], 16))}
        lines = [line for line in frames.splitlines() if any(f'pc={a:016x}..{b:016x}' in line for a, b in chosen)]
        if len(lines) != 2:
            raise ValueError('readelf did not confirm both selected FDEs')
        (output / 'frames.txt').write_text('\n'.join(lines) + '\n')
        caller_asm = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--insn-width=16',
                                             '--start-address=0x2272d02', '--stop-address=0x2272d4f', str(snapshot)], text=True)
        (output / 'caller.objdump.txt').write_text(caller_asm.replace(str(snapshot), '<authenticated-node94>'))

    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/api-suffix-94')
    args = parser.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'sha256': report['target_sha256'], 'function_bytes': report['function']['bytes'],
                      'dispatch_arms': len(report['dispatch']['arm_vas']), 'executed': False}))
