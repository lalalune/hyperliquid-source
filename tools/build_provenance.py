#!/usr/bin/env python3
"""Derive build-provenance facts from captured ELF bytes without executing them.

Each fact is labelled exact (bytes read at a stated section/offset), inferred
(reasoning stated) or unknown (what evidence would resolve it).
"""
import argparse
import collections
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import check
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'research/work-items/RE-002-build-provenance'
TARGETS = {'94': 'artifacts/node/94/hl-node', '115': 'artifacts/node/115/hl-node',
           'visor': 'artifacts/visor/captured/hl-visor'}
VERSION = rb'(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?(?:\+[A-Za-z0-9.]+)?)'
CRATE = rb'([A-Za-z0-9_][A-Za-z0-9_.-]*?)'


class Facts:
    def __init__(self, data, secs):
        self.data, self.secs, self.items = data, secs, []

    def where(self, offset):
        for s in self.secs:
            if s['type'] != 8 and s['size'] and s['offset'] <= offset < s['offset'] + s['size']:
                return s['name']
        return None

    def exact(self, key, value, offset=None, count=None, note=None):
        ev = {}
        if offset is not None:
            ev = {'file_offset': hex(offset), 'section': self.where(offset)}
        if count is not None:
            ev['occurrences'] = count
        if note:
            ev['note'] = note
        self.items.append({'key': key, 'label': 'exact', 'value': value, 'evidence': ev})

    def inferred(self, key, value, reasoning):
        self.items.append({'key': key, 'label': 'inferred', 'value': value, 'evidence': {'reasoning': reasoning}})

    def unknown(self, key, resolve):
        self.items.append({'key': key, 'label': 'unknown', 'value': None, 'evidence': {'would_resolve': resolve}})


def grouped(data, pattern):
    """Map each distinct match tuple to (first file offset, occurrence count)."""
    seen = {}
    for m in re.finditer(pattern, data):
        key = tuple(g.decode() for g in m.groups())
        first, n = seen.get(key, (m.start(), 0))
        seen[key] = (first, n + 1)
    return dict(sorted(seen.items()))


def section_bytes(data, sec):
    if sec['type'] == 8:
        raise ValueError('Cannot derive file-backed facts from NOBITS section: ' + sec['name'])
    return data[sec['offset']:sec['offset'] + sec['size']]


def program_headers(data):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    entsize, count = struct.unpack_from('<HH', data, 54)
    return [struct.unpack_from('<IIQQQQQQ', data, phoff + i * entsize) for i in range(count)]


def dynamic(data, by_name):
    dyn, dstr = by_name['.dynamic'], section_bytes(data, by_name['.dynstr'])
    raw = section_bytes(data, dyn)
    tags = []
    for i in range(0, len(raw) - 15, 16):
        tag = struct.unpack_from('<qQ', raw, i)
        if tag[0] == 0:  # DT_NULL ends the dynamic array; later slots are not entries
            break
        tags.append(tag)
    name = lambda v: dstr[v:dstr.index(b'\0', v)].decode()
    return tags, name


def derive(data):
    secs = sections(data)
    by_name = {s['name']: s for s in secs}
    f = Facts(data, secs)

    f.exact('elf.type', {2: 'EXEC', 3: 'DYN'}.get(struct.unpack_from('<H', data, 16)[0]), 16)
    f.exact('elf.machine', {0x3E: 'x86-64'}.get(struct.unpack_from('<H', data, 18)[0]), 18)
    f.exact('elf.has_symtab', '.symtab' in by_name, note='section table lookup')
    f.exact('elf.debug_sections', sorted(n for n in by_name if n.startswith(('.debug', '.zdebug'))),
            note='section table lookup')
    f.exact('elf.has_gnu_property_note', '.note.gnu.property' in by_name,
            note='absent note means no IBT/SHSTK property was recorded by the linker')

    comment = by_name.get('.comment')
    if comment:
        pos = comment['offset']
        for chunk in section_bytes(data, comment).split(b'\0'):
            if chunk:
                f.exact('comment', chunk.decode(), data.index(chunk, pos))
            pos += len(chunk) + 1

    interp = by_name.get('.interp')
    if interp:
        f.exact('interp', section_bytes(data, interp).rstrip(b'\0').decode(), interp['offset'])

    phdrs = program_headers(data)
    kinds = {0x6474E552: 'GNU_RELRO', 0x6474E551: 'GNU_STACK', 0x6474E550: 'GNU_EH_FRAME'}
    for p_type, p_flags, *_ in phdrs:
        if p_type in kinds:
            perms = ''.join(c for bit, c in ((4, 'R'), (2, 'W'), (1, 'X')) if p_flags & bit)
            f.exact(f'segment.{kinds[p_type]}', perms, note='program header')

    if '.dynamic' in by_name:
        tags, name = dynamic(data, by_name)
        f.exact('dynamic.needed', [name(v) for t, v in tags if t == 1], by_name['.dynamic']['offset'])
        flags = [v for t, v in tags if t == 30]
        flags1 = [v for t, v in tags if t == 0x6FFFFFFB]
        f.exact('dynamic.bind_now', any(t == 24 for t, _ in tags)  # DT_BIND_NOW
                or bool(flags and flags[0] & 8) or bool(flags1 and flags1[0] & 1),
                by_name['.dynamic']['offset'])
        f.exact('dynamic.pie_flag', bool(flags1 and flags1[0] & 0x08000000), by_name['.dynamic']['offset'])
        f.exact('dynamic.runpath', [name(v) for t, v in tags if t in (15, 29)], by_name['.dynamic']['offset'])
        names = section_bytes(data, by_name['.dynstr']).decode('ascii', 'replace').split('\0')
        f.exact('dynamic.hardening_imports', sorted({n for n in names if re.fullmatch(r'__stack_chk_fail|__[a-z]+_chk', n)}),
                by_name['.dynstr']['offset'])
        versions = collections.defaultdict(list)
        for lib, ver in (m.groups() for n in names if (m := re.fullmatch(r'(GLIBC|GLIBCXX|CXXABI|GCC|OPENSSL)_([0-9.]+)', n))):
            versions[lib].append(ver)
        f.exact('dynamic.max_symbol_versions', {k: max(v, key=lambda s: tuple(map(int, s.split('.'))))
                for k, v in sorted(versions.items())}, by_name['.dynstr']['offset'])

    for (commit,), (off, n) in grouped(data, rb'/rustc/([0-9a-f]{40})/').items():
        f.exact('rustc.commit_path', commit, off, n)
    for (root,), (off, n) in grouped(data, rb'(/home/[\w.-]+/hl/code_\w+)/').items():
        f.exact('source_root', root, off, n)
    for (index,), (off, n) in grouped(data, rb'\.cargo/registry/src/([^/\0]+)/').items():
        f.exact('cargo.registry_index_dir', index, off, n)
    for (name, ver), (off, n) in grouped(data, rb'\.cargo/registry/src/[^/\0]+/' + CRATE + b'-' + VERSION + b'/').items():
        f.exact('crate.registry', {'name': name, 'version': ver}, off, n)
    for (repo, rev), (off, n) in grouped(data, rb'\.cargo/git/checkouts/([A-Za-z0-9_.-]+)/([0-9a-f]{7,40})/').items():
        f.exact('crate.git_checkout', {'checkout': repo, 'short_rev': rev}, off, n)
    for (path,), (off, n) in grouped(data, rb'(/home/[\w.-]+/hl/[A-Za-z0-9_-]+-fork)/').items():
        f.exact('crate.local_fork_path', path, off, n)
    for (name,), (off, n) in grouped(data, rb'z_forks/([A-Za-z0-9_.-]+)/').items():
        f.exact('crate.z_forks_dir', name, off, n)
    for (name,), (off, n) in grouped(data, rb'z_vendor/([A-Za-z0-9_.-]+)/').items():
        m = re.fullmatch(r'(.+?)-(\d+\.\d+\.\d+.*)', name)
        value = {'dir': name, 'version_in_path': m.group(2) if m else None}
        f.exact('crate.z_vendor_dir', value, off, n)
    for (name, ver), (off, n) in grouped(data, rb'/rust/deps/' + CRATE + b'-' + VERSION + b'/').items():
        f.exact('crate.std_dep', {'name': name, 'version': ver}, off, n)
    for (ver,), (off, n) in grouped(data, rb'\0(\d+\.\d+\.\d+-\d+-g[0-9a-f]{40})\0').items():
        f.exact('jemalloc.version_string', ver, off, n)
    for (msg,), (off, n) in grouped(data, rb'(attempt to (?:add|subtract|multiply) with overflow)').items():
        f.exact('string.overflow_panic', msg, off, n)
    ub = data.find(b'unsafe precondition(s) violated')
    f.exact('string.ub_checks_message_present', ub >= 0, ub if ub >= 0 else None)
    for (triple,), (off, n) in grouped(data, rb'(x86_64-unknown-linux-(?:gnu|musl))').items():
        f.exact('string.target_triple', triple, off, n)
    if '.gcc_except_table' in by_name:
        f.exact('section.gcc_except_table_size', by_name['.gcc_except_table']['size'],
                by_name['.gcc_except_table']['offset'])
    return f.items


def interpret(items):
    """Inferences and unknowns that follow from the exact facts, with reasons."""
    f = Facts(b'', [])
    get = lambda key: [i['value'] for i in items if i['key'] == key]
    comments = get('comment')
    rust = [c for c in comments if c.startswith('rustc version')]
    lld = [c for c in comments if c.startswith('Linker: LLD')]
    if rust and lld and '/checkout/src/llvm-project' in lld[0]:
        f.inferred('linker', 'rust-lld bundled with the stamped rustc',
                   'LLD path /checkout/src/llvm-project is the rust-lang CI build root, and stable '
                   'x86_64-unknown-linux-gnu has linked with self-contained rust-lld by default since 1.90; '
                   'confirm by matching `rustc -vV` LLVM version for the stamped release')
    gcc = [c for c in comments if c.startswith('GCC:')]
    glibc = (get('dynamic.max_symbol_versions') or [{}])[0].get('GLIBC')
    if gcc and 'ubuntu2~24.04' in gcc[0] and glibc == '2.39':
        f.inferred('build_host', 'Ubuntu 24.04 (glibc 2.39, GCC 13.3.0 C runtime objects)',
                   'GCC .comment stamp names the 24.04 package and the newest GLIBC symbol version '
                   'required is 2.39, the 24.04 release glibc; host kernel and image digest are not recorded')
    if get('elf.machine') == ['x86-64'] and get('interp') == ['/lib64/ld-linux-x86-64.so.2']:
        f.inferred('target_triple', 'x86_64-unknown-linux-gnu',
                   'x86-64 ELF using the glibc dynamic loader; no triple string is required to be embedded')
    jem = get('jemalloc.version_string')
    if jem:
        f.inferred('global_allocator', f'jemalloc {jem[0]}',
                   'bundled jemalloc version string present; crate (likely tikv-jemalloc-sys) version '
                   'is not visible unless a registry/vendor path names it')
    except_size = (get('section.gcc_except_table_size') or [0])[0]
    if except_size > 1_000_000:
        f.inferred('panic_strategy', 'unwind',
                   f'.gcc_except_table is {except_size} bytes; panic=abort emits no Rust cleanup landing '
                   'pads, though linked C++ code also contributes; confirm by checking LSDA owners')
    else:
        f.unknown('panic_strategy', 'map LSDA owners to Rust functions; the except table is too small to decide')
    if get('string.ub_checks_message_present') == [False]:
        f.inferred('debug_assertions', 'off (release-like profile)',
                   'std ub_checks precondition message is absent; it is emitted when debug assertions '
                   'are enabled in the calling crate. Weak: absence can also mean no checked API was used')
    f.inferred('stripped', 'symbols and debuginfo removed' if get('elf.has_symtab') == [False] else 'not stripped',
               'no .symtab or .debug* sections; this could be Cargo strip= or a post-link strip')
    f.unknown('overflow_checks', 'overflow panic strings exist, but only callers into core panic_const '
              'helpers from first-party code would show the profile; needs xref analysis (RE-001)')
    for key, resolve in [
        ('opt_level', 'compare instruction patterns of a rebuilt known function at each opt-level'),
        ('lto', 'cross-crate inlining evidence or a matched rebuild; not stored in the ELF'),
        ('codegen_units', 'function ordering/partitioning in a matched rebuild'),
        ('target_cpu_features', 'unconditional AVX/BMI use outside runtime-dispatched paths'),
        ('frame_pointers', 'prologue survey (push rbp; mov rbp,rsp) across FDE-bounded functions'),
        ('rustflags', 'not embedded; needs the original build config or a matched rebuild'),
        ('cargo_lock', 'not embedded; registry/vendor paths give versions only where visible'),
        ('first_party_crate_versions', 'first-party paths carry no versions'),
    ]:
        f.unknown(key, resolve)
    return f.items


def record(release):
    manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
    rel = TARGETS[release]
    item = next(x for x in manifest['files'] if x['path'] == rel)
    check(ROOT / rel, item)
    facts = derive((ROOT / rel).read_bytes())
    return {'target': rel, 'sha256': item['sha256'], 'size': item['size'],
            'tool': 'tools/build_provenance.py', 'facts': facts + interpret(facts)}


def diff(old, new):
    """Facts whose (key, label, value) appear in only one record; evidence offsets are ignored."""
    def keyed(rec):
        return {(i['key'], i['label'], json.dumps(i['value'], sort_keys=True)) for i in rec['facts']}
    a, b = keyed(old), keyed(new)
    return sorted(a - b), sorted(b - a)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='compare with committed records')
    parser.add_argument('--diff', nargs=2, metavar=('OLD', 'NEW'), help='print facts that differ between two releases')
    parser.add_argument('releases', nargs='*', default=list(TARGETS))
    args = parser.parse_args()
    if args.diff:
        removed, added = diff(*(record(r) for r in args.diff))
        for sign, rows in (('-', removed), ('+', added)):
            for key, label, value in rows:
                print(sign, key, label, value)
        return
    stale = []
    for release in args.releases:
        path = OUT / f'provenance-{release}.json'
        text = json.dumps(record(release), indent=1, sort_keys=True) + '\n'
        if args.check:
            if not path.exists() or path.read_text() != text:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            print('wrote', path.relative_to(ROOT))
    if stale:
        raise SystemExit('Stale provenance records: ' + ', '.join(stale) + '; run make provenance')
    if args.check:
        print('Provenance records match the verified targets.')


if __name__ == '__main__':
    main()
