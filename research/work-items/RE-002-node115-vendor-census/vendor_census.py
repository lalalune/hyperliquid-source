"""Match third-party crate rlibs built with rustc 1.95.0 against node115 FDEs.

Same admission rule as RE-002-node115-std-census/census.py: a function section
is kept only when its relocation-masked bytes match exactly one complete node115
.text FDE and no different body claims that FDE. Bodies already registered by
the std census, and bodies that also match a std rlib, are excluded.

Usage (repository root):
  python3 research/work-items/RE-002-node115-vendor-census/vendor_census.py \
      <deps-dir> <Cargo.lock> [<deps-dir> <Cargo.lock> ...]
Each <deps-dir> is target/x86_64-unknown-linux-gnu/release/deps of one build
described in README.md, paired with that build's lockfile. Earlier builds win a
shared FDE. Writes census.json and bodies.bin beside this script.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'research/work-items/RE-002-node115-std-census'))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402
from census import MIN_BYTES, ar_members, object_functions  # noqa: E402

HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lock_versions(lock):
    text = Path(lock).read_text()
    out = {}
    for block in text.split('[[package]]')[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M).group(1)
        version = re.search(r'^version = "([^"]+)"', block, re.M).group(1)
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([^"]+)"', block, re.M)
        out.setdefault(name.replace('-', '_'), []).append(
            {'crate': name, 'version': version, 'source': source and source.group(1),
             'checksum': checksum and checksum.group(1)})
    return out


def main():
    builds = [(Path(a), b) for a, b in zip(sys.argv[1::2], sys.argv[2::2])]
    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s['name'] == '.text')
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
    std = json.loads((ROOT / 'research/work-items/RE-002-node115-std-census/census.json').read_text())
    std_vas = {r['start'] for r in std['records']}
    registry = json.loads((ROOT / 'research/byte-windows.json').read_text())
    taken = [(w['start'], w['end']) for w in registry['windows'] if w['target'] == 'node115'
             and not w['id'].startswith('node115-vendor-')]
    claimed, records, inputs, locks = {}, [], [], []
    for deps, lock in builds:
      versions = lock_versions(lock)
      locks.append(sha(Path(lock).read_bytes()))
      for rlib in sorted(deps.glob('lib*.rlib')):
          stem = rlib.name[3:rlib.name.rindex('-')]
          candidates = versions.get(stem)
          if not candidates:
              continue  # the empty build-root crate or a crate absent from the lockfile
          raw = rlib.read_bytes()
          inputs.append({'file': rlib.name, 'bytes': len(raw), 'sha256': sha(raw)})
          for member, obj in ar_members(raw):
              if not member.endswith('.o') or obj[:4] != b'\x7fELF':
                  continue
              for symbols, body, rel in object_functions(obj):
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
                  if va in std_vas or any(not (va + n <= a or va >= b) for a, b in taken):
                      continue
                  if va in claimed:
                      prior = claimed[va]
                      if prior['source_body_sha256'] != sha(body):
                          prior['ambiguous_sources'] = True
                      elif prior['rlib'] != rlib.name:
                          prior.setdefault('identical_sources', []).append({'symbol': symbols[0], 'rlib': rlib.name})
                      continue
                  record = {'symbol': symbols[0], 'member': member, 'rlib': rlib.name,
                            'crate': candidates[0]['crate'], 'versions': candidates,
                            'start': va, 'end': va + n, 'target_body_sha256': sha(target),
                            'source_body': body, 'source_body_sha256': sha(body), 'raw_equal': target == body,
                            'relocations': [{'offset': o, 'kind': t, 'width': 4, 'addend': a} for o, t, a in rel]}
                  claimed[va] = record
                  records.append(record)
    # A body shared by two different crates is not attributable to one of them, and a
    # generic instantiation emitted in this crate's codegen unit for another crate's
    # item (e.g. core::ptr::drop_in_place<Option<Waker>>) is not this crate's code.
    def own(r):
        ident = r['crate'].replace('-', '_')
        symbol = r['symbol']
        # Length-prefixed path segment (legacy and v0) or a legacy `<crate::Type as Trait>` impl.
        return f'{len(ident)}{ident}' in symbol or f'$LT${ident}..' in symbol
    records = [r for r in records if not r.pop('ambiguous_sources', False)
               and all(s['rlib'] == r['rlib'] for s in r.get('identical_sources', [])) and own(r)]
    blob = bytearray()
    for r in records:
        body = r.pop('source_body')
        r['source_offset'] = len(blob)
        blob += body
    (HERE / 'bodies.bin').write_bytes(blob)
    summary = {}
    for r in records:
        s = summary.setdefault(r['crate'], {'windows': 0, 'bytes': 0, 'raw_equal_windows': 0})
        s['windows'] += 1
        s['bytes'] += r['end'] - r['start']
        s['raw_equal_windows'] += r['raw_equal']
    out = {'schema_version': 1, 'task': 'RE-002',
           'target': {'path': TARGET, 'sha256': sha(data)},
           'toolchain': {'rustc': '1.95.0 (59807616e 2026-04-14)', 'target_triple': 'x86_64-unknown-linux-gnu',
                         'profile': 'cargo release defaults (opt-level 3, 16 codegen units, no LTO, unwind)'},
           'lockfile_sha256': locks,
           'inputs': inputs, 'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
           'minimum_bytes': MIN_BYTES,
           'summary': dict(sorted(summary.items(), key=lambda kv: -kv[1]['bytes'])), 'records': records,
           'limits': ['Only symbols whose mangled path names the producing crate are kept; generic code '
                      'instantiated for other crates is excluded rather than attributed.',
                      'A match identifies the crate and confirms the candidate version reproduces that body; it '
                      'does not prove the whole crate version, features or the node build profile.',
                      'Generic code monomorphized inside node crates, and crates that did not build here '
                      '(alloy, revm, reth, rocksdb and other native dependencies), are not covered.',
                      'Relocation fields are masked, not resolved. No first-party component credit.']}
    (HERE / 'census.json').write_text(json.dumps(out, indent=1) + '\n')
    total = sum(s['bytes'] for s in summary.values())
    print(len(records), 'windows', total, 'bytes across', len(summary), 'crates')
    print(json.dumps(dict(list(out['summary'].items())[:25]), indent=0))


if __name__ == '__main__':
    main()
