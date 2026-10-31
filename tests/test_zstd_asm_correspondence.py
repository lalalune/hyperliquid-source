"""Real licensed-assembly builds and raw correspondence controls (RE-002).

Only newly assembled ET_REL objects are inspected. No object or captured code
is linked or executed. The complete text, NOTYPE/zero-size labels and actual
adjacent preprocessing limits remain separate from function/version claims.
"""
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import zstd_asm_correspondence as subject

SOURCE_ROOT = ROOT / 'research/work-items/RE-002-zstd-asm-correspondence/third_party'
X1 = 'HUF_decompress4X1_usingDTable_internal_fast_asm_loop'
X2 = 'HUF_decompress4X2_usingDTable_internal_fast_asm_loop'
POSITIVE_SHA = 'd19bc4c3bc1cac1aa31c2260c8bb2e2066c66ca435e06e52a9b9074be18d8554'
NEGATIVE_SHA = 'b3b5a35d5a478bdb104c02c4e508569631971f8b95b97ec847f993456e3b395e'
TEXT_SHA = '6d6fa64d8848a212cedad6ad4092b2477924c53da6dec111f87d3b3c3c81b72a'
EFFECTIVE_SHA = '2ed4575150c42442e039fbbf86f3dd1251fc3cacc78b78db2f6e5ed898b662e1'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def elf_sections(raw):
    """Independent standard ELF offsets, used only to make negative fixtures."""
    start = struct.unpack_from('<Q', raw, 40)[0]
    width, count, names_index = struct.unpack_from('<HHH', raw, 58)
    rows = [struct.unpack_from('<IIQQQQIIQQ', raw, start + width * i) for i in range(count)]
    names = raw[rows[names_index][4]:rows[names_index][4] + rows[names_index][5]]
    result = []
    for index, row in enumerate(rows):
        result.append({'index': index, 'header': start + width * index,
                       'name': names[row[0]:names.index(b'\0', row[0])].decode(),
                       'name_offset': row[0], 'type': row[1], 'flags': row[2],
                       'offset': row[4], 'size': row[5], 'link': row[6], 'info': row[7],
                       'entry_size': row[9]})
    return result


def elf_symbols(raw):
    sections = elf_sections(raw)
    table = next(row for row in sections if row['type'] == 2)
    strings = sections[table['link']]
    result = []
    for position in range(table['offset'], table['offset'] + table['size'], table['entry_size']):
        name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', raw, position)
        name_at = strings['offset'] + name
        result.append({'name': raw[name_at:raw.index(b'\0', name_at)].decode(),
                       'entry': position, 'name_at': name_at, 'binding': info >> 4,
                       'type': info & 15, 'visibility': other & 3, 'section': section,
                       'value': value, 'size': size})
    return result


def replace_field(raw, offset, fmt, value):
    changed = bytearray(raw)
    struct.pack_into(fmt, changed, offset, value)
    return bytes(changed)


def text_relocation(raw):
    """Add an actual RELA record by repurposing an empty own-object section.

    The positive code bytes are unchanged. The negative fixture declares one
    PLT32 relocation in .text, so unchanged raw bytes cannot imply a final body.
    No captured target, licensed source or original object is modified.
    """
    sections = elf_sections(raw)
    text = next(row for row in sections if row['name'] == '.text')
    empty = next(row for row in sections if row['name'] == '.data' and row['size'] == 0)
    symbols = next(row for row in sections if row['type'] == 2)
    changed = bytearray(raw)
    struct.pack_into('<I', changed, empty['header'] + 4, 4)  # SHT_RELA.
    struct.pack_into('<Q', changed, empty['header'] + 24, len(raw))
    struct.pack_into('<Q', changed, empty['header'] + 32, 24)
    struct.pack_into('<IIQQ', changed, empty['header'] + 40, symbols['index'], text['index'], 8, 24)
    changed += struct.pack('<QQq', 0, (1 << 32) | 4, -4)  # R_X86_64_PLT32.
    return bytes(changed)


class ZstdAssemblyCorrespondenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Unsupported hosts are explicit skips, never component qualification.
        # Once admitted, any actual build/control failure is a test failure.
        try:
            subject.toolchain()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest('Pinned native recipe unavailable; no component qualification: ' + str(error))
        cls.temporary = tempfile.TemporaryDirectory(prefix='zasm-controls-')
        cls.output = Path(cls.temporary.name) / 'actual-collection'
        cls.refs = subject.read_targets()
        cls.report = subject.collect(cls.output)
        cls.positive = (cls.output / 'positive-1/object.o').read_bytes()
        cls.second = (cls.output / 'positive-2/object.o').read_bytes()
        cls.negative = (cls.output / 'cet-none/object.o').read_bytes()
        cls.meta, cls.text = subject.parse_object(cls.positive)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_two_build_objects_and_entire_text_are_equal(self):
        self.assertEqual(self.positive, self.second)
        self.assertEqual((len(self.positive), digest(self.positive)), (3408, POSITIVE_SHA))
        self.assertEqual((len(self.text), digest(self.text)), (2418, TEXT_SHA))
        summary = self.report['summary']
        self.assertTrue(summary['positive_match'])
        self.assertTrue(summary['positive_object_reproducible'])
        for name in ('positive-1', 'positive-2'):
            self.assertEqual((self.output / name / 'text.bin').read_bytes(), self.text)
            self.assertTrue(self.report['cases'][name]['analysis']['matches'])

    def test_report_retains_licensed_and_analysis_source_bindings_separately(self):
        bindings = self.report['source_bindings']
        self.assertEqual(set(bindings), {'1.5.6', '1.5.7'})
        files = {'source': 'lib/decompress/huf_decompress_amd64.S',
                 'header': 'lib/common/portability_macros.h', 'license': 'LICENSE'}
        for version, records in bindings.items():
            self.assertEqual(set(records), set(files))
            for key, relative in files.items():
                raw = (SOURCE_ROOT / ('zstd-' + version) / relative).read_bytes()
                self.assertEqual(records[key], {'path': relative, 'bytes': len(raw), 'sha256': digest(raw)})
        helpers = self.report['analysis_source_bindings']
        self.assertEqual(set(helpers), {'tools/zstd_asm_correspondence.py', 'tools/elf_index.py'})
        for relative, recorded in helpers.items():
            self.assertEqual(recorded, digest((ROOT / relative).read_bytes()))
        for record in self.report['toolchain']['tools'].values():
            raw = Path(record['path']).read_bytes()
            self.assertEqual((record['bytes'], record['sha256']), (len(raw), digest(raw)))

    def test_actual_labels_are_notype_zero_sized_aliases_not_functions(self):
        self.assertEqual((self.meta['x1Offset'], self.meta['x2Offset']), (0, 1149))
        self.assertFalse(self.meta['hasEhFrame'])
        self.assertEqual(self.meta['codeRelocations'], [])
        symbols = {row['name']: row for row in self.meta['selectedSymbols']}
        independent = {row['name']: row for row in elf_symbols(self.positive) if row['name']}
        self.assertEqual(set(symbols), {X1, X2, '_' + X1, '_' + X2})
        for name, offset in ((X1, 0), ('_' + X1, 0), (X2, 1149), ('_' + X2, 1149)):
            row = symbols[name]
            self.assertEqual((row['value'], row['size'], row['type'], row['binding'], row['visibility']),
                             (offset, 0, 0, 1, 2))
            self.assertEqual(row['value'], independent[name]['value'])
            self.assertEqual(row['size'], independent[name]['size'])

    def test_full_span_raw_comparisons_cover_both_captured_roles(self):
        compared = subject.validate_positive(self.positive, self.refs)
        self.assertTrue(compared['matches'])
        self.assertEqual(set(compared['comparisons']), {'94-A', '94-B', '115-A', '115-B'})
        for release in ('94', '115'):
            for label, offset, length in (('A', 0, 1149), ('B', 1149, 1269)):
                ref = self.refs[release]['candidates'][label]['raw']
                self.assertEqual(self.text[offset:offset + length], ref)
                row = compared['comparisons'][release + '-' + label]
                self.assertEqual((row['emittedBytes'], row['capturedBytes']), (length, length))
                self.assertTrue(row['equal'])
                self.assertEqual((row['rawMismatchCount'], row['rawMismatches']), (0, []))

        # A byte-position comparison is repeated for each captured role/build;
        # it is not another unique source/text byte or a function denominator.
        comparison = self.report['comparison']
        matrices = [self.report['cases'][name]['analysis']['comparisons']
                    for name in ('positive-1', 'positive-2')]
        per_target = [sum(row['capturedBytes'] for key, row in matrix.items()
                          if key.startswith(release + '-'))
                      for matrix in matrices for release in ('94', '115')]
        per_build = [sum(row['capturedBytes'] for row in matrix.values()) for matrix in matrices]
        body_checks = sum(len(matrix) for matrix in matrices)
        self.assertEqual(len(self.text), 2418)
        self.assertEqual(per_target, [2418] * 4)
        self.assertEqual(per_build, [4836, 4836])
        self.assertEqual(sum(per_build), 9672)
        self.assertEqual(body_checks, 8)
        self.assertEqual(comparison['selected_text_bytes_per_object'], len(self.text))
        self.assertEqual(comparison['code_byte_pairs_per_target_per_positive_build'], per_target[0])
        self.assertEqual(comparison['code_byte_pairs_per_positive_build'], per_build[0])
        self.assertEqual(comparison['code_byte_pairs_across_two_positive_builds'], sum(per_build))
        self.assertEqual(comparison['positive_body_checks'], body_checks)
        self.assertNotIn('code_byte_pairs_per_build', comparison)

    def test_same_length_cet_negative_has_all_557_raw_differences(self):
        meta, negative = subject.parse_object(self.negative)
        self.assertEqual((len(self.negative), digest(self.negative)), (3296, NEGATIVE_SHA))
        self.assertEqual(len(negative), len(self.text))
        self.assertEqual((meta['x1Offset'], meta['x2Offset']), (0, 1149))
        report = subject.compare_object(self.negative, self.refs)
        self.assertFalse(report['matches'])
        self.assertTrue(self.report['summary']['negative_rejected'])
        for release in ('94', '115'):
            total = 0
            for label, offset, length, count in (('A', 0, 1149, 281), ('B', 1149, 1269, 276)):
                emitted = negative[offset:offset + length]
                captured = self.refs[release]['candidates'][label]['raw']
                expected = [{'offset': i, 'emitted': a, 'captured': b}
                            for i, (a, b) in enumerate(zip(emitted, captured)) if a != b]
                row = report['comparisons'][release + '-' + label]
                self.assertEqual(row['rawMismatches'], expected)
                self.assertEqual(row['rawMismatchCount'], count)
                self.assertEqual((row['emittedBytes'], row['capturedBytes']), (length, length))
                total += count
            self.assertEqual(total, 557)
        with self.assertRaises(ValueError):
            subject.validate_positive(self.negative, self.refs)

    def test_adjacent_release_identity_is_preprocessing_only(self):
        self.assertTrue(self.report['summary']['adjacent_effective_equal'])
        self.assertEqual(self.report['summary']['adjacent_object_count'], 0)
        # Two real -E -P payloads, not just a recorded equality boolean.
        effective = [p for p in self.output.rglob('*') if p.is_file()
                     and p.stat().st_size == 13374 and digest(p.read_bytes()) == EFFECTIVE_SHA]
        self.assertGreaterEqual(len(effective), 2)
        self.assertTrue(any('157' in str(p.relative_to(self.output))
                            or '1.5.7' in str(p.relative_to(self.output)) for p in effective))
        objects = {p.relative_to(self.output).as_posix() for p in self.output.rglob('*.o')}
        self.assertEqual(objects, {'positive-1/object.o', 'positive-2/object.o', 'cet-none/object.o'})

    def test_wrong_elf_machine_type_class_endian_and_table_are_rejected(self):
        changes = [('machine', 18, '<H', 3), ('type', 16, '<H', 3),
                   ('class', 4, '<B', 1), ('endianness', 5, '<B', 2),
                   ('section-table', 40, '<Q', len(self.positive) + 64)]
        for name, offset, fmt, value in changes:
            with self.subTest(field=name):
                changed = replace_field(self.positive, offset, fmt, value)
                with self.assertRaises(ValueError):
                    subject.parse_object(changed)

    def test_text_file_mapping_and_executable_section_ownership(self):
        text = next(row for row in elf_sections(self.positive) if row['name'] == '.text')
        changes = [('non-file-backed', text['header'] + 4, '<I', 8),
                   ('non-executable', text['header'] + 8, '<Q', text['flags'] & ~4),
                   ('past-file', text['header'] + 24, '<Q', len(self.positive) - 1),
                   ('missing-final-byte', text['header'] + 32, '<Q', 2417)]
        for name, offset, fmt, value in changes:
            with self.subTest(field=name):
                changed = replace_field(self.positive, offset, fmt, value)
                with self.assertRaises(ValueError):
                    subject.validate_positive(changed, self.refs)

    def test_label_name_alias_value_and_prefix_cannot_be_reassigned(self):
        symbols = {row['name']: row for row in elf_symbols(self.positive)}
        mutations = [replace_field(self.positive, symbols[X1]['name_at'], '<B', ord('Q')),
                     replace_field(self.positive, symbols['_' + X2]['entry'] + 8, '<Q', 1148),
                     replace_field(replace_field(self.positive, symbols[X1]['entry'] + 8, '<Q', 1),
                                   symbols['_' + X1]['entry'] + 8, '<Q', 1),
                     replace_field(replace_field(self.positive, symbols[X2]['entry'] + 8, '<Q', 1148),
                                   symbols['_' + X2]['entry'] + 8, '<Q', 1148),
                     replace_field(self.positive, symbols[X1]['entry'] + 4, '<B', 0x12),
                     replace_field(self.positive, symbols[X1]['entry'] + 16, '<Q', 1149)]
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(ValueError):
                    subject.validate_positive(changed, self.refs)

    def test_actual_text_relocation_blocks_raw_body_claim(self):
        changed = text_relocation(self.positive)
        meta, text = subject.parse_object(changed)
        self.assertEqual(text, self.text)
        self.assertTrue(meta['codeRelocations'])
        with self.assertRaises(ValueError):
            subject.validate_positive(changed, self.refs)

    def test_single_instruction_and_final_byte_differences_are_unmasked(self):
        text = next(row for row in elf_sections(self.positive) if row['name'] == '.text')
        for position in (0, 1148, 1149, 2417):
            with self.subTest(text_offset=position):
                changed = bytearray(self.positive)
                changed[text['offset'] + position] ^= 1
                compared = subject.compare_object(bytes(changed), self.refs)
                self.assertFalse(compared['matches'])
                label, offset = ('A', position) if position < 1149 else ('B', position - 1149)
                other = 'B' if label == 'A' else 'A'
                for release in ('94', '115'):
                    row = compared['comparisons'][release + '-' + label]
                    self.assertEqual(row['rawMismatchCount'], 1)
                    self.assertEqual(row['rawMismatches'][0]['offset'], offset)
                    self.assertTrue(compared['comparisons'][release + '-' + other]['equal'])
                with self.assertRaises(ValueError):
                    subject.validate_positive(bytes(changed), self.refs)

    def test_native_listing_requires_actual_bytes_and_complete_coordinates(self):
        listing = (self.output / 'positive-1/objdump.txt').read_text()
        rows = subject.check_native_listing(self.text, listing)
        self.assertEqual(len(rows), 609)
        match = re.search(r'(?m)^(\s*)(0):(\s*)(f3)(\s+0f\s+1e\s+fa)', listing)
        self.assertIsNotNone(match)
        changed_byte = listing[:match.start(4)] + 'f2' + listing[match.end(4):]
        changed_coordinate = listing[:match.start(2)] + '1' + listing[match.end(2):]
        for name, changed in (('byte', changed_byte), ('coordinate', changed_coordinate)):
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    subject.check_native_listing(self.text, changed)

    def test_licensed_source_header_and_license_hashes_precede_collection(self):
        for version in ('1.5.6', '1.5.7'):
            for relative in ('lib/decompress/huf_decompress_amd64.S', 'lib/common/portability_macros.h', 'LICENSE'):
                with self.subTest(version=version, source=relative), tempfile.TemporaryDirectory(prefix='zasm-source-') as temporary:
                    private = Path(temporary) / 'third_party'
                    shutil.copytree(SOURCE_ROOT, private)
                    path = private / ('zstd-' + version) / relative
                    original = path.read_bytes()
                    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                    with self.assertRaises(ValueError):
                        subject.admit_sources(private)
                    output = Path(temporary) / 'uncreated'
                    with self.assertRaises(ValueError):
                        subject.collect(output, source_root=private)
                    self.assertFalse(output.exists())
                    self.assertEqual(path.read_bytes()[0], original[0] ^ 1)

    def test_wrong_captured_input_does_not_create_output(self):
        with tempfile.TemporaryDirectory(prefix='zasm-admit-') as temporary:
            root = Path(temporary)
            wrong = root / 'not-node'; wrong.write_bytes(b'\x7fELF' + bytes(60))
            paths = {'94': wrong, '115': ROOT / 'artifacts/node/115/hl-node'}
            output = root / 'uncreated'
            with self.assertRaises(ValueError):
                subject.collect(output, target_paths=paths)
            self.assertFalse(output.exists())
            self.assertEqual(wrong.read_bytes(), b'\x7fELF' + bytes(60))

    def test_existing_output_is_preserved_before_any_work(self):
        with tempfile.TemporaryDirectory(prefix='zasm-preserve-') as temporary:
            output = Path(temporary) / 'existing'; output.mkdir()
            marker = output / 'original-result'; marker.write_bytes(b'preserve prior evidence\n')
            with self.assertRaises(FileExistsError):
                subject.collect(output, source_root=Path(temporary) / 'deliberately-absent')
            self.assertEqual(marker.read_bytes(), b'preserve prior evidence\n')
            self.assertEqual({p.name for p in output.iterdir()}, {'original-result'})

    def test_private_provider_size_or_bytes_cannot_satisfy_admission(self):
        provider = Path(self.report['toolchain']['tools']['cc']['path']).resolve()
        raw = provider.read_bytes()
        with tempfile.TemporaryDirectory(prefix='zasm-provider-') as temporary:
            path = Path(temporary) / 'private-provider'
            path.write_bytes(raw)
            self.assertEqual(subject.admit_file(path, len(raw), digest(raw)), raw)
            changed = bytearray(raw); changed[-1] ^= 1; path.write_bytes(changed)
            with self.assertRaises(ValueError):
                subject.admit_file(path, len(raw), digest(raw))
            path.write_bytes(raw[:-1])
            with self.assertRaises(ValueError):
                subject.admit_file(path, len(raw), digest(raw))
            self.assertFalse(path.stat().st_mode & 0o111)


if __name__ == '__main__':
    unittest.main()
