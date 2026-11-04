"""Match rustc 1.95.0 x86_64-unknown-linux-gnu std rlib functions to node115 FDEs.

Node115's .comment names rustc 1.95.0 (59807616e 2026-04-14) and LLD 22.1.2. Each
function section in the published std rlibs is compared with every node115 .text
FDE of identical length, wildcarding only the 4-byte fields named by its own
PC-relative/GOT relocation records. A record is kept only when the masked body
has exactly one complete-FDE hit and every non-relocation byte is equal.

Usage (repository root):
  python3 research/work-items/RE-002-node115-std-census/census.py <sysroot-lib-dir>
Writes census.json and bodies.bin beside this script. Static parsing only.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
# Crate prefix -> dependency attribution used in research/byte-windows.json.
CRATES = {'libcore-': 'rust-core', 'libcompiler_builtins-': 'compiler-builtins', 'liballoc-': 'rust-alloc',
          'libstd-': 'rust-std'}
# R_X86_64_PC32, PLT32, GOTPCREL, GOTPCRELX, REX_GOTPCRELX: 4-byte PC-relative fields.
PCREL = {2: 'PC32', 4: 'PLT32', 9: 'GOTPCREL', 41: 'GOTPCRELX', 42: 'REX_GOTPCRELX'}
MIN_BYTES = 16


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ar_members(data):
    if data[:8] != b'!<arch>\n':
        raise ValueError('not an ar archive')
    pos, longnames = 8, b''
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name, size = header[:16].decode().strip(), int(header[48:58])
        body = data[pos + 60:pos + 60 + size]
        if name == '//':
            longnames = body
        elif name.startswith('/') and name[1:].isdigit():
            off = int(name[1:])
            yield longnames[off:longnames.index(b'/\n', off)].decode(), body
        elif name not in ('/', '/SYM64/'):
            yield name.rstrip('/'), body
        pos += 60 + size + (size & 1)


def object_functions(obj):
    """Yield (symbols, body, [(offset, type)]) per section fully covered by FUNC symbols.

    compiler-builtins defines an unmangled C symbol and a mangled alias on one
    section; aliases describe one body, not ambiguous candidates.
    """
    shoff = struct.unpack_from('<Q', obj, 40)[0]
    entsize, count, shstrndx = struct.unpack_from('<HHH', obj, 58)
    sh = [struct.unpack_from('<IIQQQQIIQQ', obj, shoff + i * entsize) for i in range(count)]
    names = obj[sh[shstrndx][4]:sh[shstrndx][4] + sh[shstrndx][5]]
    def secname(i):
        n = sh[i][0]
        return names[n:names.index(b'\0', n)].decode()
    symtab = next(i for i, s in enumerate(sh) if s[1] == 2)
    strtab = sh[sh[symtab][6]]
    strs = obj[strtab[4]:strtab[4] + strtab[5]]
    syms = []
    for pos in range(sh[symtab][4], sh[symtab][4] + sh[symtab][5], 24):
        name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', obj, pos)
        syms.append((strs[name:strs.index(b'\0', name)].decode(errors='replace'), info, shndx, value, size))
    relocs = {}
    for s in sh:
        if s[1] == 4:  # SHT_RELA; s[7] = section it applies to
            rows = relocs.setdefault(s[7], [])
            for pos in range(s[4], s[4] + s[5], 24):
                off, info, addend = struct.unpack_from('<QQq', obj, pos)
                rows.append((off, info & 0xffffffff, addend))
    covered = {}
    for name, info, shndx, value, size in syms:
        if info & 0xf != 2 or not 0 < shndx < count or value != 0:
            continue
        s = sh[shndx]
        if s[1] != 1 or not s[2] & 4 or s[5] != size or not secname(shndx).startswith('.text'):
            continue
        covered.setdefault(shndx, []).append(name)
    for shndx, names_ in covered.items():
        s = sh[shndx]
        rows = relocs.get(shndx, [])
        if any(t not in PCREL for _, t, _ in rows):
            continue  # absolute/other relocation kinds have no 4-byte PC-relative mask
        # Prefer the unmangled C name; keep every alias for the record.
        names_.sort(key=lambda n: (n.startswith('_R') or n.startswith('_Z'), n))
        yield names_, obj[s[4]:s[4] + s[5]], sorted(rows)


def main():
    libdir = Path(sys.argv[1])
    data = (ROOT / TARGET).read_bytes()
    secs = sections(data)
    text = next(s for s in secs if s['name'] == '.text')
    _, fdes, _ = fde_extents(data)
    starts = {}
    for f in fdes:
        starts[f['start']] = starts.get(f['start'], 0) + 1
    by_len = {}
    for f in fdes:
        if f['section'] == '.text' and starts[f['start']] == 1:
            n = f['end'] - f['start']
            off = text['offset'] + f['start'] - text['address']
            by_len.setdefault(n, []).append((f['start'], data[off:off + n]))
    inputs, records, blob = [], [], bytearray()
    claimed = {}
    for rlib in sorted(libdir.glob('*.rlib')):
        dep = next((d for p, d in CRATES.items() if rlib.name.startswith(p)), None)
        if dep is None:
            continue
        raw = rlib.read_bytes()
        inputs.append({'file': rlib.name, 'bytes': len(raw), 'sha256': sha(raw)})
        for member, obj in ar_members(raw):
            if not member.endswith('.o') or obj[:4] != b'\x7fELF':
                continue
            for symbols, body, rel in object_functions(obj):
                symbol = symbols[0]
                n = len(body)
                if n < MIN_BYTES or n not in by_len:
                    continue
                mask = set()
                for o, _, _ in rel:
                    mask.update(range(o, o + 4))
                if len(mask) * 2 > n:
                    continue
                keep = [i for i in range(n) if i not in mask]
                probe = bytes(body[i] for i in keep)
                hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
                if len(hits) != 1:
                    continue
                va, target = hits[0]
                if va in claimed:
                    prior = claimed[va]
                    if prior['source_body_sha256'] == sha(body):
                        # Byte-identical body under another symbol/CGU: same comparison, record the alias.
                        prior.setdefault('identical_sources', []).append(
                            {'symbol': symbol, 'member': member, 'rlib': rlib.name})
                    else:
                        prior['ambiguous_sources'] = True
                    continue
                record = {'symbol': symbol, **({'aliases': symbols[1:]} if symbols[1:] else {}), 'member': member, 'rlib': rlib.name, 'dependency': dep,
                          'start': va, 'end': va + n, 'target_body_sha256': sha(target),
                          'source_offset': len(blob), 'source_body_sha256': sha(body),
                          'raw_equal': target == body,
                          'relocations': [{'offset': o, 'kind': t, 'width': 4, 'addend': a} for o, t, a in rel]}
                claimed[va] = record
                records.append(record)
                blob += body
    records = [r for r in records if not r.pop('ambiguous_sources', False)]
    # Rebuild the blob so only retained records remain, preserving their order.
    final = bytearray()
    for r in records:
        body = bytes(blob[r['source_offset']:r['source_offset'] + r['end'] - r['start']])
        r['source_offset'] = len(final)
        final += body
    (HERE / 'bodies.bin').write_bytes(final)
    summary = {}
    for r in records:
        s = summary.setdefault(r['dependency'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        s['windows'] += 1
        s['bytes'] += r['end'] - r['start']
        s['raw_equal_windows'] += r['raw_equal']
    out = {'schema_version': 1, 'task': 'RE-002',
           'target': {'path': TARGET, 'sha256': sha(data)},
           'toolchain': {'rustc': '1.95.0 (59807616e 2026-04-14)', 'target_triple': 'x86_64-unknown-linux-gnu',
                         'basis': 'node115 .comment rustc version string'},
           'inputs': inputs, 'bodies': {'path': 'bodies.bin', 'bytes': len(final), 'sha256': sha(final)},
           'method': __doc__.split('\n\n')[1].replace('\n', ' '),
           'minimum_bytes': MIN_BYTES, 'summary': summary, 'records': records,
           'limits': ['Only std functions emitted out-of-line in the published rlibs; generic/inlined std code '
                      'instantiated in node crates is not covered.',
                      'Relocation fields are masked, not resolved; GOTPCRELX relaxation would surface as a '
                      'non-relocation difference and is therefore excluded rather than normalized.',
                      'Ambiguous bodies (several node115 FDEs or several std symbols) are dropped.',
                      'No first-party component credit, gate or behavior claim.']}
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
