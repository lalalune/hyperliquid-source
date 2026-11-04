"""Retain selected native CFI records and complete disassemblies, without executing the node."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('repository', type=Path)
parser.add_argument('native', type=Path)
parser.add_argument('analysis', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
repo = args.repository.resolve()
native = args.native.resolve()
packet = args.output.resolve()
packet.mkdir(exist_ok=False)
(packet / 'native').mkdir()
summary = json.loads((args.analysis / 'summary.json').read_text())
sys.path.insert(0, str(repo / 'tools'))
from elf_index import sections
image = (repo / 'artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(image).hexdigest() == summary['target_sha256']
secs = sections(image)
samples = summary['samples']
selected = {x['offset'] for x in samples.values()}
for provider in ('gnu', 'llvm'):
    blocks = []
    keep = False
    with (native / (provider + '-frames.txt')).open() as handle:
        for line in handle:
            header = re.match(r'^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+\s+(CIE|FDE)', line)
            if header:
                keep = header[2] == 'CIE' or int(header[1], 16) in selected
            if keep:
                blocks.append(line)
    (packet / 'native' / (provider + '-selected-frames.txt')).write_text(''.join(blocks))
records = []
for label, row in samples.items():
    start, end = row['start'], row['end']
    section = next(s for s in secs if s['flags'] & 4 and s['address'] <= start < end <= s['address'] + s['size'])
    offset = section['offset'] + start - section['address']
    body = image[offset:offset + end-start]
    stem = hex(start)
    producers = {}
    for provider, tool, options in [('gnu', 'objdump', ['-d', '-z', '--insn-width=16']),
                                    ('llvm', 'llvm-objdump', ['-d', '--disassemble-zeroes'])]:
        command = [tool, *options, '--start-address='+hex(start), '--stop-address='+hex(end), 'artifacts/node/115/hl-node']
        result = subprocess.run(command, cwd=repo, env={'PATH':'/usr/bin:/bin', 'LC_ALL':'C'}, capture_output=True, check=True)
        if result.stderr:
            raise ValueError('Unexpected native stderr')
        output = packet / 'native' / (provider + '-' + stem + '.objdump')
        output.write_bytes(result.stdout)
        parsed = []
        for line in result.stdout.decode().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)', line)
            if match:
                address, chunk = int(match[1], 16), bytes.fromhex(match[2])
                if address != start + sum(map(len, parsed)):
                    raise ValueError('Native instruction gap/overlap')
                parsed.append(chunk)
        if b''.join(parsed) != body:
            raise ValueError('Native full-FDE bytes differ from ELF')
        producers[provider] = dict(command=command, exit_code=result.returncode, file=str(output.relative_to(packet)), instructions=len(parsed), sha256=hashlib.sha256(result.stdout).hexdigest())
    records.append(dict(label=label, start_va=hex(start), end_va=hex(end),
                        extent_kind='FDE-described range, not established function boundary',
                        fde_section_offset=hex(row['offset']), cie_section_offset=hex(row['cie']),
                        section=section['name'], file_offset=offset, bytes=len(body),
                        body_sha256=hashlib.sha256(body).hexdigest(), producers=producers))
(packet / 'selected-bodies.json').write_text(json.dumps(records, indent=2)+'\n')
summary.pop('samples')
(packet / 'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
versions = {}
for tool in ('readelf','llvm-dwarfdump','objdump','llvm-objdump','python3'):
    result = subprocess.run([tool,'--version'], capture_output=True, check=True)
    versions[tool] = result.stdout.decode().strip()
(packet / 'versions.json').write_text(json.dumps(versions, indent=2)+'\n')
print(json.dumps(dict(packet=str(packet), selected_bodies=records),indent=2))
