'''Re-derive the node #115 FDE-band census from the pinned target.

The checker runs readelf and objdump against artifacts/node/115/hl-node and
re-derives every recorded FDE entry and end, body SHA-256 and native
instruction count from the target bytes. It rejects saved records, frame
lines, window excerpts or manifest entries that do not match, and never
executes or copies the target binary.
'''
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
PACKET = ROOT / 'research' / 'work-items' / 'RE-001-node115-fde-band3a-census'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
PACKET_NAME = 'RE-001-node115-fde-band3a-census'
BAND_START = 0x3a00000
BAND_END = 0x3a40000
REQUIRED = (
    'README.md',
    'evidence.json',
    'frames.txt',
    'window.txt',
    'MANIFEST.sha256',
)
HEX = '0123456789abcdefABCDEF'
DIGITS = '0123456789abcdef'


def run(command):
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if process.returncode != 0:
        raise AssertionError('command failed: %s: %s' % (' '.join(command), process.stderr.strip()))
    return process.stdout


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def text_section(target):
    output = run(['readelf', '--wide', '--section-headers', str(target)])
    for line in output.splitlines():
        parts = line.split()
        if '.text' in parts:
            index = parts.index('.text')
            return int(parts[index + 2], 16), int(parts[index + 3], 16), int(parts[index + 4], 16)
    raise AssertionError('missing .text section')


def band_frames(target):
    output = run(['readelf', '--wide', '--debug-dump=frames', str(target)])
    rows = []
    for line in output.splitlines():
        if 'FDE cie=' not in line:
            continue
        marker = line.find('pc=')
        if marker < 0:
            raise AssertionError('FDE line without pc')
        token = line[marker + 3:].split()[0]
        start_text, separator, end_text = token.partition('..')
        if not separator:
            raise AssertionError('malformed FDE range')
        start = int(start_text, 16)
        end = int(end_text, 16)
        if BAND_START <= start < BAND_END:
            if end <= start:
                raise AssertionError('empty FDE range')
            rows.append((start, end, line.rstrip()))
    if not rows:
        raise AssertionError('no FDEs start in the band')
    rows.sort()
    starts = [row[0] for row in rows]
    if len(set(starts)) != len(starts):
        raise AssertionError('duplicate FDE start in the band')
    return rows


def check_band(rows, address, size):
    if not rows:
        raise AssertionError('no FDEs start in the band')
    previous_start = None
    previous_end = None
    for start, end, unused in rows:
        if start < address or end > address + size:
            raise AssertionError('FDE outside .text: %x..%x' % (start, end))
        if not BAND_START <= start < BAND_END:
            raise AssertionError('FDE start outside the band: %x' % start)
        if end <= start:
            raise AssertionError('empty FDE range: %x..%x' % (start, end))
        if previous_start is not None:
            if start == previous_start:
                raise AssertionError('duplicate FDE start: %x' % start)
            if start < previous_start:
                raise AssertionError('FDE starts are not increasing: %x after %x' % (start, previous_start))
            if start < previous_end:
                raise AssertionError('overlapping FDE range: %x < %x' % (start, previous_end))
        previous_start = start
        previous_end = end
    return True


def instruction_count(target, start, end):
    output = run(['objdump', '-d', '--start-address=0x%x' % start, '--stop-address=0x%x' % end, str(target)])
    total = 0
    for line in output.splitlines():
        left, separator, rest = line.strip().partition(':')
        if separator and left and all(char in HEX for char in left):
            total += 1
    if total == 0:
        raise AssertionError('no instructions for %x..%x' % (start, end))
    return total


def build_records(target, address, offset, size, rows):
    result = []
    with target.open('rb') as handle:
        for start, end, unused in rows:
            if start < address or end > address + size:
                raise AssertionError('FDE outside .text: %x..%x' % (start, end))
            handle.seek(offset + start - address)
            body = handle.read(end - start)
            if len(body) != end - start:
                raise AssertionError('short body for %x..%x' % (start, end))
            result.append([hex(start), hex(end), len(body), hashlib.sha256(body).hexdigest(), instruction_count(target, start, end)])
    return result


def validate(actual, evidence):
    assert evidence['target_sha256'] == TARGET_SHA256, 'evidence target digest mismatch'
    assert evidence['target_size'] == TARGET_SIZE, 'evidence target size mismatch'
    assert evidence['packet'] == PACKET_NAME, 'evidence packet name mismatch'
    assert int(evidence['band']['start'], 16) == BAND_START, 'evidence band start mismatch'
    assert int(evidence['band']['end'], 16) == BAND_END, 'evidence band end mismatch'
    assert evidence['fde_count'] == len(actual), 'fde count mismatch'
    claimed = sorted(evidence['fdes'], key=lambda item: int(item[0], 16))
    assert len(claimed) == len(actual), 'fde record count mismatch'
    for saved in claimed:
        assert len(saved) == 5, 'fde record width mismatch: %r' % (saved,)
        assert int(saved[1], 16) - int(saved[0], 16) == saved[2], 'fde byte length mismatch: %r' % (saved,)
        assert isinstance(saved[4], int) and saved[4] > 0, 'fde instruction count mismatch: %r' % (saved,)
        assert len(saved[3]) == 64 and all(char in DIGITS for char in saved[3]), 'fde digest shape mismatch: %r' % (saved,)
    for derived, saved in zip(actual, claimed):
        assert derived == saved, 'fde record mismatch: %r != %r' % (derived, saved)
    return True


def validate_frames(saved, rows):
    lines = [line.rstrip() for line in saved.splitlines() if line.strip()]
    expected = [line for start, end, line in rows]
    assert lines == expected, 'frames excerpt does not match the target FDE lines'
    return True


def prologue_bytes(target, offset, address, start, count):
    if start < address:
        raise AssertionError('start before .text: %x' % start)
    with target.open('rb') as handle:
        handle.seek(offset + start - address)
        body = handle.read(count)
    if len(body) != count:
        raise AssertionError('short prologue for %x' % start)
    return ['%02x' % byte for byte in body]


def validate_window(saved, smallest):
    start = int(smallest[0], 16)
    text = saved.lower()
    assert ('%x' % start) in text, 'window does not name %s' % smallest[0]
    address, offset, size = text_section(TARGET)
    expected = prologue_bytes(TARGET, offset, address, start, 6)
    token = '%x:' % start
    for line in saved.splitlines():
        stripped = line.strip()
        if not stripped.startswith(token):
            continue
        parts = stripped.split('\t')
        if len(parts) < 2:
            continue
        bytes_tokens = [item.lower() for item in parts[1].split() if len(item) == 2 and all(char in DIGITS for char in item.lower())]
        if not bytes_tokens:
            continue
        width = min(len(bytes_tokens), len(expected))
        if bytes_tokens[:width] == expected[:width]:
            return True
    raise AssertionError('window prologue bytes do not match the target for %s' % smallest[0])


def check_manifest(packet):
    manifest = (packet / 'MANIFEST.sha256').read_text(encoding='utf-8')
    listed = {}
    for line in manifest.splitlines():
        if not line.strip():
            continue
        value, separator, name = line.partition('  ')
        if not separator or len(value) != 64 or not name:
            raise AssertionError('malformed manifest line: %r' % line)
        listed[name] = value
    present = sorted(
        path.relative_to(packet).as_posix()
        for path in packet.rglob('*')
        if path.is_file() and path.name != 'MANIFEST.sha256'
    )
    if present != sorted(listed):
        raise AssertionError('manifest names %r != present files %r' % (sorted(listed), present))
    for name, value in listed.items():
        actual = digest(packet / name)
        if actual != value:
            raise AssertionError('manifest digest mismatch for %s: %s != %s' % (name, actual, value))


def verify(packet=None, target=None):
    packet = Path(packet) if packet else PACKET
    target = Path(target) if target else TARGET
    assert target.is_file(), 'missing pinned target'
    assert target.stat().st_size == TARGET_SIZE, 'target size mismatch'
    assert digest(target) == TARGET_SHA256, 'target digest mismatch'
    assert packet.is_dir(), 'missing packet'
    for name in REQUIRED:
        assert (packet / name).is_file(), 'missing packet file: %s' % name
    address, offset, size = text_section(target)
    rows = band_frames(target)
    check_band(rows, address, size)
    actual = build_records(target, address, offset, size, rows)
    evidence = json.loads((packet / 'evidence.json').read_text(encoding='utf-8'))
    validate(actual, evidence)
    validate_frames((packet / 'frames.txt').read_text(encoding='utf-8'), rows)
    smallest = min(actual, key=lambda item: item[2])
    validate_window((packet / 'window.txt').read_text(encoding='utf-8'), smallest)
    check_manifest(packet)
    return actual


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet')
    parser.add_argument('--target')
    arguments = parser.parse_args()
    actual = verify(arguments.packet, arguments.target)
    print('ok fdes=%d first=%s..%s' % (len(actual), actual[0][0], actual[0][1]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
