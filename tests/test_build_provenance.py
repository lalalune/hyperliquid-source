import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_provenance import OUT, TARGETS, derive, diff, interpret, record


def elf(comment, rodata):
    names = b'\0.shstrtab\0.comment\0.rodata\0'
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    blobs = [names, comment, rodata]
    offsets = []
    for blob in blobs:
        offsets.append(len(body))
        body += blob
    shoff = len(body)
    struct.pack_into('<Q', body, 40, shoff)
    struct.pack_into('<HHH', body, 58, 64, 4, 1)
    rows = [(0, 0, 0, 0, 0, 0)]
    for name, blob, off in zip((b'.shstrtab', b'.comment', b'.rodata'), blobs, offsets):
        rows.append((names.index(name + b'\0'), 3 if name == b'.shstrtab' else 1, 0, 0, off, len(blob)))
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row, 0, 0, 1, 0)
    return bytes(body), offsets


def stripping_elf(*, symbols, debug):
    """Section-table fixture with a valid minimal DWARF 4 compile unit."""
    entries = [(b'.shstrtab', 3, b'', 0, 0, 0)]
    if symbols:
        entries += [(b'.strtab', 3, b'\0', 0, 0, 0),
                    (b'.symtab', 2, bytes(24), 2, 1, 24)]
    if debug:
        # Unit length 8: version 4, abbrev offset 0, pointer size 8, root DIE 1.
        entries += [(b'.debug_info', 1, struct.pack('<IHI', 8, 4, 0) + b'\x08\x01', 0, 0, 0),
                    (b'.debug_abbrev', 1, b'\x01\x11\x00\x00\x00\x00', 0, 0, 0)]
    names = b'\0' + b''.join(name + b'\0' for name, *_ in entries)
    entries[0] = (b'.shstrtab', 3, names, 0, 0, 0)
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    rows = [bytes(64)]
    for name, kind, data, link, info, entsize in entries:
        rows.append(struct.pack('<IIQQQQIIQQ', names.index(name + b'\0'), kind,
                                0, 0, len(body), len(data), link, info, 1, entsize))
        body += data
    struct.pack_into('<Q', body, 40, len(body))
    struct.pack_into('<HHH', body, 58, 64, len(rows), 1)
    body += b''.join(rows)
    return bytes(body)


def dynamic_elf(tags):
    names = b'\0.shstrtab\0.dynstr\0.dynamic\0'
    dynstr = b'\0libfixture.so\0'
    blob = b''.join(struct.pack('<qQ', *tag) for tag in tags)
    body = bytearray(64)
    body[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH', body, 16, 3, 0x3E)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, kind, data, link, entsize in ((b'.shstrtab', 3, names, 0, 0), (b'.dynstr', 3, dynstr, 0, 0),
                                             (b'.dynamic', 6, blob, 2, 16)):
        body += b'\0' * (-len(body) % 8)
        rows.append((names.index(name + b'\0'), kind, 0, 0, len(body), len(data), link, 0, 8, entsize))
        body += data
    body += b'\0' * (-len(body) % 8)
    struct.pack_into('<Q', body, 40, len(body))
    struct.pack_into('<HHH', body, 58, 64, len(rows), 1)
    for row in rows:
        body += struct.pack('<IIQQQQIIQQ', *row)
    return bytes(body)


def dynamic_facts(tags):
    return {i['key']: i['value'] for i in derive(dynamic_elf(tags))}


def by_key(items, key):
    return [i for i in items if i['key'] == key]


class DeriveTests(unittest.TestCase):
    def setUp(self):
        comment = b'rustc version 1.94.1 (e408947bf 2026-03-25)\0Linker: LLD 21.1.8 (/checkout/src/llvm-project/llvm x)\0'
        rodata = (b'\0/rustc/' + b'a' * 40 + b'/library/core/src/x.rs\0'
                  b'/home/u/.cargo/registry/src/index.crates.io-0123/tokio-1.44.2/src/lib.rs\0'
                  b'/home/u/.cargo/git/checkouts/reth-e231042ee7db3fb7/3212af2/crates/a.rs\0'
                  b'/home/u/hl/code_Mainnet/z_vendor/axum/src/lib.rs\0'
                  b'/home/u/hl/code_Mainnet/z_vendor/ark-ff-0.5.0/src/lib.rs\0')
        self.data, self.offsets = elf(comment, rodata)
        self.items = derive(self.data)

    def test_comment_stamps_are_exact_with_their_offsets(self):
        stamps = by_key(self.items, 'comment')
        self.assertEqual([s['value'] for s in stamps][0], 'rustc version 1.94.1 (e408947bf 2026-03-25)')
        self.assertEqual(stamps[0]['evidence'], {'file_offset': hex(self.offsets[1]), 'section': '.comment'})

    def test_dependency_paths_keep_versions_only_where_present(self):
        self.assertEqual(by_key(self.items, 'crate.registry')[0]['value'], {'name': 'tokio', 'version': '1.44.2'})
        self.assertEqual(by_key(self.items, 'crate.git_checkout')[0]['value'],
                         {'checkout': 'reth-e231042ee7db3fb7', 'short_rev': '3212af2'})
        vendored = {v['value']['dir']: v['value']['version_in_path'] for v in by_key(self.items, 'crate.z_vendor_dir')}
        self.assertEqual(vendored, {'axum': None, 'ark-ff-0.5.0': '0.5.0'})

    def test_unrecorded_settings_stay_unknown(self):
        facts = interpret(self.items)
        for key in ('opt_level', 'lto', 'codegen_units', 'cargo_lock', 'panic_strategy'):
            self.assertEqual([(i['label'], i['value']) for i in by_key(facts, key)], [('unknown', None)], key)
        self.assertEqual(by_key(facts, 'linker')[0]['label'], 'inferred')

    def test_diff_ignores_offsets_and_reports_changed_values(self):
        old = {'facts': [{'key': 'k', 'label': 'exact', 'value': 1, 'evidence': {'file_offset': '0x1'}},
                         {'key': 'same', 'label': 'exact', 'value': 2, 'evidence': {'file_offset': '0x2'}}]}
        new = {'facts': [{'key': 'k', 'label': 'exact', 'value': 3, 'evidence': {}},
                         {'key': 'same', 'label': 'exact', 'value': 2, 'evidence': {'file_offset': '0x9'}}]}
        self.assertEqual(diff(old, new), ([('k', 'exact', '1')], [('k', 'exact', '3')]))

    def test_dynamic_entries_after_dt_null_are_ignored(self):
        facts = dynamic_facts([(1, 1), (0, 0), (30, 8), (1, 1), (15, 1)])
        self.assertEqual(facts['dynamic.needed'], ['libfixture.so'])
        self.assertIs(facts['dynamic.bind_now'], False)
        self.assertEqual(facts['dynamic.runpath'], [])

    def test_bind_now_accepts_every_abi_encoding(self):
        self.assertIs(dynamic_facts([(0, 0)])['dynamic.bind_now'], False)
        for tags in ([(30, 8), (0, 0)], [(0x6FFFFFFB, 1), (0, 0)], [(24, 0), (0, 0)]):
            self.assertIs(dynamic_facts(tags)['dynamic.bind_now'], True, tags)

    def test_stripping_inference_preserves_retained_debug_sections(self):
        for symbols, debug, expected in (
                (False, True, 'static symbols absent; debug sections retained'),
                (False, False, 'symbols and debuginfo removed'),
                (True, True, 'not stripped'), (True, False, 'not stripped')):
            with self.subTest(symbols=symbols, debug=debug):
                exact = derive(stripping_elf(symbols=symbols, debug=debug))
                self.assertIs(by_key(exact, 'elf.has_symtab')[0]['value'], symbols)
                self.assertEqual(bool(by_key(exact, 'elf.debug_sections')[0]['value']), debug)
                self.assertEqual(by_key(interpret(exact), 'stripped')[0]['value'], expected)

    def test_unstripped_reasoning_matches_the_present_symbol_table(self):
        exact = derive(stripping_elf(symbols=True, debug=True))
        reasoning = by_key(interpret(exact), 'stripped')[0]['evidence']['reasoning']
        self.assertIn('.symtab is present', reasoning)
        self.assertNotIn('no .symtab', reasoning)

    def test_non_elf_input_is_rejected(self):
        with self.assertRaises(ValueError):
            derive(b'not an elf' * 10)


def captured(release):
    path = ROOT / TARGETS[release]
    return path.is_file() and path.stat().st_size > 1_000_000


@unittest.skipUnless(all(captured(r) for r in TARGETS), 'captured binaries not materialized (git lfs pull)')
class CapturedTargetTests(unittest.TestCase):
    def test_committed_records_reproduce_from_verified_targets(self):
        for release in TARGETS:
            committed = json.loads((OUT / f'provenance-{release}.json').read_text())
            self.assertEqual(committed, json.loads(json.dumps(record(release))), release)

    def test_node_94_and_115_toolchains_differ(self):
        def commits(release):
            return {i['value'] for i in record(release)['facts'] if i['key'] == 'rustc.commit_path'}
        self.assertEqual(commits('94'), {'e408947bfd200af42db322daf0fadfe7e26d3bd1'})
        self.assertEqual(commits('115'), {'59807616e1fa2540724bfbac14d7976d7e4a3860'})


if __name__ == '__main__':
    unittest.main()
