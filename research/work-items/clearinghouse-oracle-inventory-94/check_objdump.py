#!/usr/bin/env python3
"""Independent GNU objdump instruction-boundary check of the Location LEAs."""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import clearinghouse_oracle_inventory as inventory


def main():
    try:
        binary = inventory.TARGET.read_bytes()
        result = inventory.build(binary)
        by_range = {}
        for location in result['locations']:
            for item in location['lea_sites']:
                key = (int(item['fde_start'], 16), int(item['fde_end'], 16))
                by_range.setdefault(key, []).append((int(item['site'], 16),
                                                      int(location['slot'], 16), item['bytes']))
        version = subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0]
        out = [f'# {version}', f'# ELF SHA-256 {hashlib.sha256(binary).hexdigest()}',
               '# objdump -d, start and stop set to each full FDE range; selected raw lines follow']
        count = 0
        for (start, end), sites in sorted(by_range.items()):
            decoded = subprocess.check_output(['objdump', '-d', f'--start-address={start:#x}',
                                               f'--stop-address={end:#x}', str(inventory.TARGET)], text=True)
            lines = {}
            for line in decoded.splitlines():
                match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)', line)
                if match:
                    lines[int(match[1], 16)] = (line.strip(), match[2].replace(' ', ''), match[3])
            out.append(f'\n# FDE {start:#x}..{end:#x}')
            for site, slot, raw in sorted(sites):
                line, bytecode, instruction = lines[site]
                if bytecode != raw or not instruction.startswith('lea ') or not re.search(
                        rf'#\s+{slot:x}\b', instruction):
                    raise ValueError(f'LEA mismatch at {site:#x}')
                out.append(line)
                count += 1
        if count != 72 or len(by_range) != 67:
            raise ValueError('xref count drift')
        print('\n'.join(out))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f'objdump check: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
