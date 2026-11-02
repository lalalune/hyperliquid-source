"""Match third-party crate rlibs built with rustc 1.95.0 against node115 FDEs.

Same admission rule as RE-002-node115-std-census/census.py: a function section
is kept only when its relocation-masked bytes match exactly one complete node115
.text FDE and no different body claims that FDE. Bodies already registered by
the std census, and bodies byte-identical to any function section of the rustc
1.95.0 sysroot rlibs (std ships private copies of crates such as memchr), are
excluded. Third-party bodies must be at least 32 bytes with at least 16
unmasked bytes: an adversarial review found a 16-byte glibc pthread_atfork stub
matching a blst function, and tiny bodies are where such coincidences live.

Usage (repository root):
  python3 research/work-items/RE-002-node115-vendor-census/vendor_census.py \
      <sysroot-lib-dir> <deps-dir> <Cargo.lock> [<deps-dir> <Cargo.lock> ...]
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
from census import ar_members, object_functions  # noqa: E402
from byte_progress import RELAXATIONS, relaxation_bytes  # noqa: E402

HERE = Path(__file__).resolve().parent
TARGET = 'artifacts/node/115/hl-node'
MIN_BYTES = 32
MIN_UNMASKED = 16
# Version evidence beyond the lockfile, recorded with the affected records.
VERSION_NOTES = {
    'libz-sys': 'node115 embeds ZLIB_VERSION "1.3.1"; these bodies are identical in the zlib 1.3.2 bundled '
                'by libz-sys 1.1.31, so the zlib release is not pinned by these windows.',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def relaxed_match(src, tgt, rel, mask):
    """Return {offset: relaxation} if src equals tgt outside masks up to exact relaxations, else None.

    The rewrite rules are tools/byte_progress.py's, so the census admits exactly what
    the comparator accepts; relaxation bytes may not overlap any other masked byte.
    """
    allowed, applied = set(mask), {}
    for o, kind, _ in rel:
        for name in RELAXATIONS:
            rewritten = relaxation_bytes(src, tgt, o, kind, name)
            if rewritten is not None:
                if rewritten & allowed:
                    return None
                applied[o] = name
                allowed |= rewritten
                break
    if not applied or any(src[i] != tgt[i] for i in range(len(src)) if i not in allowed):
        return None
    return applied


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
    sysroot = Path(sys.argv[1])
    builds = [(Path(a), b) for a, b in zip(sys.argv[2::2], sys.argv[3::2])]
    sysroot_bodies = set()
    for rlib in sorted(sysroot.glob('*.rlib')):
        for member, obj in ar_members(rlib.read_bytes()):
            if member.endswith('.o') and obj[:4] == b'\x7fELF':
                sysroot_bodies.update(sha(body) for _, body, _ in object_functions(obj))
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
    archives = []
    for deps, lock in builds:
        versions = lock_versions(lock)
        locks.append(sha(Path(lock).read_bytes()))
        for rlib in sorted(deps.glob('lib*.rlib')):
            candidates = [c for c in versions.get(rlib.name[3:rlib.name.rindex('-')], []) if c['source']]
            if candidates:  # only registry/git dependencies; never a build's own workspace crates
                archives.append((rlib, rlib.name, candidates, False))
        # Native static libraries built by -sys crate build scripts (C has no
        # cross-crate generic instantiation, so the building crate owns them).
        for archive in sorted((deps.parent / 'build').glob('*/out/**/*.a')):
            package = archive.relative_to(deps.parent / 'build').parts[0]
            candidates = [c for c in versions.get(package[:package.rindex('-')].replace('-', '_'), []) if c['source']]
            if candidates:
                archives.append((archive, f'{package}/{archive.name}', candidates, True))
    for path, name, candidates, native in archives:
        raw = path.read_bytes()
        inputs.append({'file': name, 'bytes': len(raw), 'sha256': sha(raw)})
        for member, obj in ar_members(raw):
            if not member.endswith('.o') or obj[:4] != b'\x7fELF':
                continue
            # rustc codegen units are *.rcgu.o; any other object, including a -sys
            # crate's static library that rustc bundles into its rlib, is native code.
            native_object = native or not member.endswith('.rcgu.o')
            for symbols, body, rel in object_functions(obj):
                n = len(body)
                if n < MIN_BYTES or n not in by_len:
                    continue
                mask = set()
                for o, _, _ in rel:
                    mask.update(range(o, o + 4))
                if len(mask) * 2 > n or n - len(mask) < MIN_UNMASKED:
                    continue
                if sha(body) in sysroot_bodies:
                    continue
                keep = [i for i in range(n) if i not in mask]
                probe = bytes(body[i] for i in keep)
                hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
                relaxed = {}
                if not hits and any(k in (41, 42) for _, k, _ in rel):
                    # The linker relaxed GOTPCRELX sites: accept only the exact psABI rewrites.
                    candidates_relaxed = [(va, t, r) for va, t in by_len[n]
                                          for r in [relaxed_match(body, t, rel, mask)] if r]
                    if len(candidates_relaxed) == 1:
                        va, t, relaxed = candidates_relaxed[0]
                        hits = [(va, t)]
                if len(hits) != 1:
                    continue
                va, target = hits[0]
                if va in std_vas or any(not (va + n <= a or va >= b) for a, b in taken):
                    continue
                if va in claimed:
                    prior = claimed[va]
                    # Another body of the same crate (e.g. a neighbouring version whose
                    # relocation addends differ) also matches outside its own masked fields:
                    # a further candidate, not ambiguity. A different crate is ambiguous.
                    if prior['source_body_sha256'] != sha(body) and prior['crate'] != candidates[0]['crate']:
                        prior['ambiguous_sources'] = True
                    elif prior['rlib'] != name or prior['symbol'] != symbols[0]:
                        prior.setdefault('identical_sources', []).append(
                            {'symbol': symbols[0], 'rlib': name, 'crate': candidates[0]['crate'],
                             'versions': [c['version'] for c in candidates]})
                    continue
                record = {'symbol': symbols[0], 'member': member, 'rlib': name, 'native': native_object,
                          'crate': candidates[0]['crate'], 'versions': candidates,
                          'start': va, 'end': va + n, 'target_body_sha256': sha(target),
                          'source_body': body, 'source_body_sha256': sha(body), 'raw_equal': target == body,
                          'relocations': [{'offset': o, 'kind': t, 'width': 4, 'addend': a,
                                           **({'relaxation': relaxed[o]} if o in relaxed else {})}
                                          for o, t, a in rel]}
                claimed[va] = record
                records.append(record)
    # A body shared by two different crates is not attributable to one of them, and a
    # generic instantiation emitted in this crate's codegen unit for another crate's
    # item (e.g. core::ptr::drop_in_place<Option<Waker>>) is not this crate's code.
    def own(r):
        if r['native']:
            return True
        ident = r['crate'].replace('-', '_')
        symbol = r['symbol']
        # Length-prefixed path segment (legacy and v0) or a legacy `<crate::Type as Trait>` impl.
        return f'{len(ident)}{ident}' in symbol or f'$LT${ident}..' in symbol
    records = [r for r in records if not r.pop('ambiguous_sources', False)
               and all(s['crate'] == r['crate'] for s in r.get('identical_sources', [])) and own(r)]
    for r in records:
        # An identical body from another version of the same crate leaves the version open.
        versions = {v['version'] for v in r['versions']}
        for other in r.get('identical_sources', []):
            versions.update(other['versions'])
        r['candidate_versions'] = sorted(versions)
        # Identical bodies under other symbols leave the symbol name open; keep them all.
        r['candidate_symbols'] = sorted({r['symbol'], *(o['symbol'] for o in r.get('identical_sources', []))})
        if r['crate'] in VERSION_NOTES:
            r['version_note'] = VERSION_NOTES[r['crate']]
    # Keep records compact: lockfile identities once per crate version, and a count
    # of identical copies (C++ COMDAT bodies recur in many translation units).
    lock_packages = {}
    for r in records:
        for v in r.pop('versions'):
            lock_packages[f"{v['crate']} {v['version']}"] = {'source': v['source'], 'checksum': v['checksum']}
        r['identical_source_count'] = len(r.pop('identical_sources', []))
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
           'lockfile_sha256': locks, 'lock_packages': dict(sorted(lock_packages.items())),
           'inputs': inputs, 'bodies': {'path': 'bodies.bin', 'bytes': len(blob), 'sha256': sha(blob)},
           'minimum_bytes': MIN_BYTES, 'minimum_unmasked_bytes': MIN_UNMASKED,
           'summary': dict(sorted(summary.items(), key=lambda kv: -kv[1]['bytes'])), 'records': records,
           'limits': ['Rust symbols are kept only when their mangled path names the producing crate (this '
                      'includes core/alloc generics instantiated over that crate\'s own types). Native objects '
                      'are attributed to the -sys crate whose build produced them, including C++ template and '
                      'COMDAT code (e.g. libstdc++ containers) compiled in RocksDB translation units.',
                      'symbol is one representative name; candidate_symbols lists every identical-body name '
                      'and candidate_versions every version that builds the same body.',
                      'A match identifies the crate and confirms the candidate version reproduces that body; it '
                      'does not prove the whole crate version, features or the node build profile.',
                      'Generic code monomorphized inside node crates, private forks and crates that did not '
                      'build at the candidate versions are not covered.',
                      'Relocation fields are masked, not resolved. No first-party component credit.']}
    # Compact separators: about 57k relocation rows make an indented record several MB larger.
    (HERE / 'census.json').write_text(json.dumps(out, separators=(',', ':')) + '\n')
    total = sum(s['bytes'] for s in summary.values())
    print(len(records), 'windows', total, 'bytes across', len(summary), 'crates')
    print(json.dumps(dict(list(out['summary'].items())[:25]), indent=0))


if __name__ == '__main__':
    main()
