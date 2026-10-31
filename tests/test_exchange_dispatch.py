"""RE-010 tests: pinned output, tamper controls, boundaries, determinism, binutils cross-check."""
import bisect
import hashlib
import json
import os
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
import exchange_dispatch as ed  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-010-exchange-handlers'
PATH_INSNS = 760
SLOT_CALLS = 3
OFF_BY_ONE_SAME = 0
OUTPUT_SHA256 = 'bf82df7744abc508bd73bc8337d5b21af0a17eab9c64b6849137a4f58dfa5cb1'
_CACHE = {}


def data():
    if 'data' not in _CACHE:
        _CACHE['data'] = ed.TARGET.read_bytes()
    return _CACHE['data']


def result():
    if 'result' not in _CACHE:
        _CACHE['result'] = ed.build(data())
    return _CACHE['result']


def elf():
    if 'elf' not in _CACHE:
        _CACHE['elf'] = ed.Elf(data())
    return _CACHE['elf']


def mutate(va, new):
    buf = bytearray(data())
    o = elf().off(va)
    buf[o:o + len(new)] = new
    return bytes(buf)


def build_mut(buf, rs=ed.SOURCE):
    return ed.build(buf, rs, expected_sha256=hashlib.sha256(buf).hexdigest())


def objdump_lines():
    if 'od' not in _CACHE:
        out = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
                              f'--start-address={ed.DISPATCHER:#x}', '--stop-address=0x275a376',
                              str(ed.TARGET)], check=True, capture_output=True, text=True).stdout
        rows = {}
        for line in out.splitlines():
            m = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)$', line)
            if m:
                rows[int(m.group(1), 16)] = (m.group(2), m.group(3))
        _CACHE['od'] = rows
    return _CACHE['od']


def case(i):
    return result()['cases'][i]


class Pinned(unittest.TestCase):
    def test_output_hash(self):
        self.assertEqual(hashlib.sha256(ed.render(result())).hexdigest(), OUTPUT_SHA256)

    def test_committed_json(self):
        self.assertEqual((PACKET / 'exchange-dispatch.json').read_bytes(), ed.render(result()))

    def test_exact_summary(self):
        r = result()
        self.assertEqual((r['dispatcher']['start'], r['dispatcher']['end']), (0x2759240, 0x275a376))
        self.assertEqual(r['jump_table'], 0x3ede28)
        self.assertEqual(r['table_entries'], 88)
        self.assertEqual(r['reconstruction_claims'], 76)
        self.assertEqual(r['fde_count'], 121299)
        self.assertEqual(r['status_counts'], {'inline_claim_no_call': 1, 'real_first_call': 74,
                                              'real_first_call_on_branch': 1})
        self.assertEqual(r['address_survey_counts'], {'at_fde_start': 206, 'inside_fde': 3})

    def test_exact_rows(self):
        self.assertEqual(case(0)['arm'], 0x2759452)
        self.assertIsNone(case(0)['first_call'])
        self.assertEqual(case(0)['arm_path_end'], {'kind': 'jmp', 'site': 0x2759457, 'target': 0x275a186})
        self.assertEqual(case(1)['first_call']['target'], 0x1e5f770)
        s, e = ed.fde_index(elf())
        self.assertEqual(case(1)['first_call']['target_fde_end'], e[bisect.bisect_left(s, 0x1e5f770)])
        self.assertEqual(case(16)['first_call']['kind'], 'rip_slot')
        self.assertEqual((case(16)['first_call']['slot'], case(16)['first_call']['target']), (0x5773160, 0x3367800))
        self.assertIsNone(case(63)['first_call'])
        self.assertEqual([(b['site'], b['target']) for b in case(63)['entry_branches']], [(0x2759a83, 0x275a318)])
        self.assertEqual(case(63)['entry_branches'][0]['path_end']['target'], 0x3996230)
        self.assertEqual([(c['index'], b['site']) for c in result()['cases'] for b in c['entry_branches']],
                         [(61, 0x2759bcf), (63, 0x2759a83), (66, 0x275942d), (76, 0x2759b68)])
        self.assertEqual(sum(c['arm_path_insns'] for c in result()['cases']), PATH_INSNS)
        inside = [(r['file'], r['va']) for r in result()['address_survey'] if r['kind'] != 'at_fde_start']
        self.assertEqual(inside, [('handlers/01_approve_agent3.rs', 0x1bf18b0),
                                  ('handlers/05_claim_rewards.rs', 0x2759c55),
                                  ('handlers/05_claim_rewards.rs', 0x2759c9e)])

    def test_unclaimed_extension_arms(self):
        self.assertEqual([c['index'] for c in result()['cases'] if 'reconstruction' not in c],
                         list(range(76, 88)))


class Determinism(unittest.TestCase):
    def test_hashseed_independent(self):
        outs = set()
        for seed in ('0', '1', '4242'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outs.add(subprocess.run([sys.executable, '-B', str(ROOT / 'tools/exchange_dispatch.py')],
                                    check=True, capture_output=True, env=env).stdout)
        self.assertEqual(len(outs), 1)
        self.assertEqual(hashlib.sha256(outs.pop()).hexdigest(), OUTPUT_SHA256)


class Tamper(unittest.TestCase):
    def test_wrong_sha_rejected(self):
        with self.assertRaises(ed.EvidenceError):
            ed.build(data()[:-1] + bytes([data()[-1] ^ 1]))

    def test_tag_bias_mutation_rejected(self):
        with self.assertRaises(ed.EvidenceError):
            build_mut(mutate(0x27592a3, b'\x75'))  # cmp rax,0x74 -> 0x75

    def test_jump_idiom_mutation_rejected(self):
        with self.assertRaises(ed.EvidenceError):
            build_mut(mutate(0x27592bb, b'\xff\xe1'))  # jmp rax -> jmp rcx

    def test_truncated_table_rejects_claims(self):
        buf = mutate(0x3ede28 + 4 * 50, struct.pack('<i', 0x7fffffff))
        with self.assertRaises(ed.EvidenceError):
            build_mut(buf)

    def test_truncated_after_claims(self):
        buf = mutate(0x3ede28 + 4 * 80, struct.pack('<i', 0x7fffffff))
        self.assertEqual(build_mut(buf)['table_entries'], 80)

    def test_call_retarget_changes_status(self):
        site = case(3)['first_call']['site']
        rel = struct.unpack_from('<i', elf().read(site + 1, 4))[0]
        with self.assertRaises(ed.EvidenceError):  # off-by-one target is not an FDE start
            build_mut(mutate(site + 1, struct.pack('<i', rel + 1)))
        # Retarget to case 4's handler (a real FDE start): status must flip.
        other = case(4)['first_call']['target']
        r = build_mut(mutate(site + 1, struct.pack('<i', rel + other - (rel + site + 5))))
        self.assertEqual(r['cases'][3]['first_call']['target'], other)
        self.assertEqual(r['cases'][3]['reconstruction']['status'], 'fde_start_not_called_from_arm')
        self.assertEqual(r['status_counts']['real_first_call'], 73)

    def test_source_claim_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'exchange'
            shutil.copytree(ed.SOURCE.parent, src)
            rs = src / ed.SOURCE.name
            text = rs.read_text(encoding='utf-8')
            rs.write_text(text.replace('0x21DF_D90', '0x21DF_D91'), encoding='utf-8')
            r = ed.build(data(), rs)
            self.assertEqual(r['cases'][2]['reconstruction']['status'], 'claimed_not_fde_start')
            rs.write_text(text.replace('0x21DF_D90', '0x22BE_610'), encoding='utf-8')
            r = ed.build(data(), rs)
            self.assertEqual(r['cases'][2]['reconstruction']['status'], 'fde_start_not_called_from_arm')
            rs.write_text(text.replace('HandlerRef::new(2,', 'HandlerRef::new(1,'), encoding='utf-8')
            with self.assertRaises(ed.EvidenceError):
                ed.build(data(), rs)
            rs.write_text(text.replace('HandlerRef::new(75,', 'HandlerRef::new(95,'), encoding='utf-8')
            with self.assertRaises(ed.EvidenceError):
                ed.build(data(), rs)


class Boundaries(unittest.TestCase):
    def test_fde_end_exclusive(self):
        s, e = ed.fde_index(elf())
        self.assertEqual(ed.containing(s, e, 0x275a375), (0x2759240, 0x275a376))
        self.assertNotEqual(ed.containing(s, e, 0x275a376), (0x2759240, 0x275a376))
        self.assertNotEqual(ed.containing(s, e, 0x275923f), (0x2759240, 0x275a376))

    def test_off_by_one_handler_starts(self):
        s, _e = ed.fde_index(elf())
        for c in result()['cases']:
            if c['first_call']:
                t = c['first_call']['target']
                self.assertTrue(ed.is_fde_start(s, t))
                self.assertFalse(ed.is_fde_start(s, t + 1))
                self.assertFalse(ed.is_fde_start(s, t - 1))

    def test_off_by_one_arm_entry_rejected_or_differs(self):
        # Starting one byte late must not reproduce the real arm path.
        s, _e = ed.fde_index(elf())
        relocs = ed.relative_relocs(elf())
        same = 0
        for c in result()['cases']:
            real = ed.walk(elf(), c['arm'], relocs, s)
            try:
                late = ed.walk(elf(), c['arm'] + 1, relocs, s)
            except ed.EvidenceError:
                continue
            if late[0] == real[0][1:] and late[2] == real[2]:
                same += 1
        self.assertEqual(same, OFF_BY_ONE_SAME)

    def test_unknown_opcode_rejected(self):
        with self.assertRaises(ed.EvidenceError):
            ed.decode_one(b'\xf4' + b'\0' * 15, 0, 0x1000)  # hlt not in subset


class Binutils(unittest.TestCase):
    def test_arms_are_instruction_starts(self):
        od = objdump_lines()
        self.assertEqual([c['arm'] for c in result()['cases'] if c['arm'] not in od], [])

    def test_paths_match_objdump(self):
        od = objdump_lines()
        addrs = sorted(od)
        s, _e = ed.fde_index(elf())
        relocs = ed.relative_relocs(elf())
        starts = [c['arm'] for c in result()['cases']]
        starts += [b['target'] for c in result()['cases'] for b in c['entry_branches']]
        for va in starts:
            path, jccs, term = ed.walk(elf(), va, relocs, s)
            k = addrs.index(path[0])
            self.assertEqual(addrs[k:k + len(path)], path, hex(va))
            mn = [od[a][0] for a in path]
            self.assertEqual([a for a, m in zip(path, mn) if m.startswith('j') and m != 'jmp'],
                             [j['site'] for j in jccs], hex(va))
            self.assertEqual([m for m in mn[:-1] if m == 'call' or m == 'jmp'], [], hex(va))
            mnem, ops = od[term['site']]
            if term['kind'] == 'jmp':
                self.assertEqual((mnem, int(ops.split()[0], 16)), ('jmp', term['target']))
            elif term['kind'] == 'rel32':
                self.assertEqual((mnem, int(ops.split()[0], 16)), ('call', term['target']))
            else:
                self.assertEqual((mnem, int(ops.split('#')[1].split()[0], 16)), ('call', term['slot']))
            for j in jccs:
                self.assertEqual(int(od[j['site']][1].split()[0], 16), j['target'])

    def test_slot_targets_match_readelf(self):
        out = subprocess.run(['readelf', '-rW', str(ed.TARGET)], check=True, capture_output=True,
                             text=True).stdout
        rel = {}
        for line in out.splitlines():
            p = line.split()
            if len(p) == 4 and p[2] == 'R_X86_64_RELATIVE':
                rel[int(p[0], 16)] = int(p[3], 16)
        ends = [c['first_call'] for c in result()['cases'] if c['first_call']]
        ends += [b['path_end'] for c in result()['cases'] for b in c['entry_branches']]
        slots = [e for e in ends if e['kind'] == 'rip_slot']
        self.assertEqual(len(slots), SLOT_CALLS)
        for call in slots:
            self.assertEqual(rel[call['slot']], call['target'])

    def test_fde_bounds_match_readelf(self):
        out = subprocess.run(['readelf', '-wf', str(ed.TARGET)], check=True, capture_output=True,
                             text=True).stdout
        fdes = {}
        for m in re.finditer(r' FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)', out):
            fdes[int(m.group(1), 16)] = int(m.group(2), 16)
        self.assertEqual(len(fdes), 121299)
        self.assertEqual(fdes[0x2759240], 0x275a376)
        for c in result()['cases']:
            if c['first_call']:
                self.assertEqual(fdes[c['first_call']['target']], c['first_call']['target_fde_end'])
        for r in result()['address_survey']:
            self.assertEqual(fdes[r['fde_start']], r['fde_end'])


class ElfShstrtabTypeTests(unittest.TestCase):
    """A NOBITS section name table occupies no file bytes, so names read
    from its offset are phantom names, not a string table."""

    NAMES = b'\0.text\0.shstrtab\0'

    def build(self, shstrtab_type):
        data = bytearray(0x2000)
        data[0:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<QQ', data, 0x20, 0, 64)  # phoff, shoff
        struct.pack_into('<HHHHH', data, 0x36, 0, 0, 64, 3, 2)

        def section(index, name, typ, flags, addr, off, size):
            struct.pack_into('<IIQQQQIIQQ', data, 64 + index * 64,
                             name, typ, flags, addr, off, size, 0, 0, 1, 0)

        section(0, 0, 0, 0, 0, 0, 0)
        section(1, 1, 1, 0x6, 0x400000, 0x1000, 0x10)  # .text
        section(2, 7, shstrtab_type, 0, 0, 0x1000, len(self.NAMES))
        data[0x1000:0x1000 + len(self.NAMES)] = self.NAMES
        return bytes(data)

    def test_nobits_shstrtab_rejected(self):
        with self.assertRaises(ed.EvidenceError):
            ed.Elf(self.build(8))

    def test_strtab_shstrtab_accepted(self):
        self.assertEqual(sorted(ed.Elf(self.build(3)).sections),
                         ['', '.shstrtab', '.text'])


if __name__ == '__main__':
    unittest.main()
