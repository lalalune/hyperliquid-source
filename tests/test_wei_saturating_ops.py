"""Tests for tools/wei_saturating_ops.py: the Wei add and sub recorder sites of node #94."""

import filecmp
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import wei_saturating_ops as tool  # noqa: E402

BINARY = ROOT / tool.BINARY
PACKET = ROOT / 'research/work-items/RE-004-wei-saturating-ops-94'
ADD_SITE = 0x28d5493
SUB_SITE = 0x372d89c
CMP_SITE = 0x4460065
SHARED_SUM_SITE = 0x2752b74
CHAIN_SITE = 0x2752b48
REGISTER_CALL_SITE = 0x4cb068d
SHARED_XOR_SITE = 0x26b1957
XMM_SITE = 0x272ef61
BRANCH_ONLY_SITE = 0x3c017cd
STATE = {}


def setUpModule():
    STATE['blob'] = tool.load_binary(BINARY)
    STATE['table'] = tool.fde_table(STATE['blob'])
    STATE['starts'] = [item[0] for item in STATE['table']]
    STATE['relocs'] = tool.relocations(STATE['blob'])
    STATE['result'] = tool.analyse(BINARY)


def rows_at(va):
    return tool.disassemble(BINARY, *tool.enclosing(STATE['table'], STATE['starts'], va))


def facts_for(lea):
    return [item for item in STATE['result'][1] if item['lea'] == lea]


def replaced(rows, old, new, after):
    """Replace the first row at or after VA after whose text contains old."""
    changed = list(rows)
    for k, row in enumerate(changed):
        if row[0] >= after and old in row[1]:
            changed[k] = (row[0], row[1].replace(old, new), row[2])
            return changed
    raise AssertionError(f'{old!r} not found after {after:#x}')


def machine_for(*bodies):
    rows = [(0x1000 + 4 * k, body, 0) for k, body in enumerate(bodies)]
    return tool.Machine(rows, {row[0]: k for k, row in enumerate(rows)}, set(), 1)


def run_all(machine):
    position = 0
    while position < len(machine.rows):
        position = machine.step(position)
    return machine


class Anchor(unittest.TestCase):
    def test_location_record(self):
        name, line, column = tool.read_location(STATE['blob'], STATE['relocs'], tool.LOCATION)
        self.assertTrue(name.endswith(tool.LOCATION_SUFFIX))
        self.assertEqual((line, column), (6, 1))

    def test_counts(self):
        evidence = STATE['result'][0]
        self.assertEqual(evidence['location_references'], 117)
        self.assertEqual(evidence['location_data_references'], 0)
        self.assertEqual(evidence['location_function_count'], 81)
        self.assertEqual(evidence['functions'], 71)
        self.assertEqual(evidence['sites_analysed'], 107)
        self.assertEqual(evidence['sites_by_kind'], {'add': 42, 'sub': 65})
        self.assertEqual(evidence['guards'], 118)
        self.assertEqual(evidence['sites_calling_through_a_register'], 2)

    def test_excluded_functions_hold_one_site_each(self):
        excluded = STATE['result'][0]['excluded_functions']
        self.assertEqual(len(excluded), 10)
        self.assertEqual(sorted(int(key, 16) for key in excluded), sorted(tool.EXCLUDED_FUNCTIONS))
        analysed = {item['function'] for item in STATE['result'][1]}
        self.assertFalse(analysed & set(tool.EXCLUDED_FUNCTIONS))

    def test_tampered_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'hl-node'
            path.write_bytes(b'not the node')
            with self.assertRaises(tool.EvidenceError):
                tool.load_binary(path)

    def test_address_outside_every_fde(self):
        with self.assertRaises(tool.EvidenceError):
            tool.enclosing(STATE['table'], STATE['starts'], 0x10)

    def test_missing_relocation(self):
        with self.assertRaises(tool.EvidenceError):
            tool.read_location(STATE['blob'], {}, tool.LOCATION)

    def test_reference_messages_are_absent_and_the_count_can_hit(self):
        self.assertEqual(set(STATE['result'][0]['reference_messages_in_binary'].values()), {0})
        self.assertGreater(STATE['blob'].count(b'assertion failed: idx < CAPACITY'), 0)

    def test_only_the_recorder_and_the_clear_use_the_map(self):
        facts = STATE['result'][0]['recorder']
        self.assertEqual(facts['functions_using_globals'], [f'{tool.RECORDER_CLEAR:#x}', f'{tool.RECORDER:#x}'])
        self.assertEqual(facts['relocations_into_globals'], 0)

    def test_rip_scan_finds_a_known_operand_and_nothing_in_a_gap(self):
        hits = tool.rip_references(STATE['blob'], tool.RECORDER_SLOT, tool.RECORDER_SLOT + 8)
        self.assertIn(0x1e63278 + 2, hits)
        self.assertEqual(tool.rip_references(STATE['blob'], 0x10, 0x20), [])

    def test_recorder_facts_reject_another_clear_count(self):
        with mock.patch.object(tool, 'RECORDER_CLEAR_REFERENCES', 2):
            with self.assertRaises(tool.EvidenceError):
                tool.recorder_facts(BINARY, STATE['blob'], STATE['relocs'], STATE['table'], STATE['starts'])

    def test_recorder_facts_reject_another_map_insert(self):
        with mock.patch.object(tool, 'RECORDER_INNER', 0x3396d00):
            with self.assertRaises(tool.EvidenceError):
                tool.recorder_facts(BINARY, STATE['blob'], STATE['relocs'], STATE['table'], STATE['starts'])


class Classification(unittest.TestCase):
    def test_add_site(self):
        self.assertEqual({(item['kind'], item['form']) for item in facts_for(ADD_SITE)}, {('add', 'add-carry')})

    def test_sub_site(self):
        self.assertEqual({(item['kind'], item['form']) for item in facts_for(SUB_SITE)}, {('sub', 'sub-borrow')})

    def test_cmp_site(self):
        self.assertEqual({(item['kind'], item['form']) for item in facts_for(CMP_SITE)}, {('sub', 'cmp-borrow')})

    def test_shared_sum_site_reads_as_add(self):
        self.assertEqual({(item['kind'], item['form']) for item in facts_for(SHARED_SUM_SITE)},
                         {('add', 'cmp-shared-sum')})

    def test_no_site_has_both_kinds(self):
        self.assertEqual(STATE['result'][0]['sites_with_both_kinds'], [])

    def guard(self, setter, branch, taken=True):
        rows = [(0x10, setter, 0), (0x14, branch, 0), (0x18, 'lea rsi,[rip+0x0]', tool.LOCATION)]
        return tool.classify(rows, 0, 1, taken, 2)

    def test_swapped_compare_swaps_operands(self):
        self.assertEqual(self.guard('cmp rax,rcx', 'ja 40')[:4], ('sub', 'cmp-swapped', 'rcx', 'rax'))

    def test_fall_through_negates_the_branch(self):
        self.assertEqual(self.guard('sub rax,rcx', 'jae 40', taken=False)[:2], ('sub', 'sub-borrow'))

    def test_add_that_goes_to_the_site_without_carry_is_rejected(self):
        with self.assertRaises(tool.EvidenceError):
            self.guard('add rax,rcx', 'jae 40')

    def test_immediate_is_rejected(self):
        with self.assertRaises(tool.EvidenceError):
            self.guard('cmp rax,0x10', 'jb 40')

    def test_signed_overflow_branch_is_rejected(self):
        with self.assertRaises(tool.EvidenceError):
            self.guard('add rax,rcx', 'jo 40')

    def test_label_between_setter_and_branch_is_rejected(self):
        rows = [(0x10, 'add rax,rcx', 0), (0x14, 'mov rdx,rax', 0), (0x18, 'jb 40', 0)]
        with self.assertRaises(tool.EvidenceError):
            tool.flag_setter(rows, {0x14: [9]}, 2)

    def test_other_flag_writer_is_rejected(self):
        rows = [(0x10, 'add rax,rcx', 0), (0x14, 'test rax,rax', 0), (0x18, 'jb 40', 0)]
        with self.assertRaises(tool.EvidenceError):
            tool.flag_setter(rows, {}, 2)

    def test_unconditional_edge_needs_a_conditional_branch(self):
        rows = [(0x10, 'mov rax,rcx', 0), (0x14, 'jmp 20', 0), (0x18, 'nop', 0), (0x20, 'lea rsi,[rip+0x0]', tool.LOCATION)]
        with self.assertRaises(tool.EvidenceError):
            tool.find_guards(rows, tool.branch_targets(rows), 3)

    def test_guard_behind_a_jmp(self):
        rows = [(0x10, 'cmp rax,rcx', 0), (0x14, 'jae 30', 0), (0x18, 'jmp 20', 0), (0x20, 'lea rsi,[rip+0x0]', tool.LOCATION),
                (0x30, 'nop', 0)]
        self.assertEqual(tool.find_guards(rows, tool.branch_targets(rows), 3), [(1, False)])

    def test_recorder_register_needs_the_slot_load(self):
        rows = [(0x10, 'mov rbx,QWORD PTR [rip+0x0]', tool.RECORDER_SLOT), (0x14, 'call rbx', 0)]
        self.assertEqual(tool.recorder_registers(rows), {0x14})
        rows[0] = (0x10, 'mov rbx,QWORD PTR [rip+0x0]', 0x1234)
        self.assertEqual(tool.recorder_registers(rows), set())


class MachineSemantics(unittest.TestCase):
    def test_add_carry_boundary(self):
        machine = machine_for('add rax,rcx')
        machine.regs.update(rax=tool.MASK, rcx=0)
        run_all(machine)
        self.assertFalse(machine.flags['c'])
        machine = machine_for('add rax,rcx')
        machine.regs.update(rax=tool.MASK, rcx=1)
        run_all(machine)
        self.assertTrue(machine.flags['c'])
        self.assertEqual(machine.regs['rax'], 0)

    def test_sub_borrow_boundary(self):
        machine = machine_for('sub rax,rcx')
        machine.regs.update(rax=5, rcx=5)
        run_all(machine)
        self.assertFalse(machine.flags['c'])
        self.assertTrue(machine.flags['z'])
        machine = machine_for('cmp rax,rcx')
        machine.regs.update(rax=4, rcx=5)
        run_all(machine)
        self.assertTrue(machine.flags['c'])
        self.assertEqual(machine.regs['rax'], 4)

    def test_cmov_reads_carry(self):
        machine = machine_for('add rax,rcx', 'mov rdx,0x7', 'cmovb rax,rdx')
        machine.regs.update(rax=tool.MASK, rcx=1)
        self.assertEqual(run_all(machine).regs['rax'], 7)

    def test_unknown_flags_halt(self):
        machine = machine_for('cmovb rax,rcx')
        with self.assertRaises(tool.Halt):
            run_all(machine)

    def test_unknown_call_halts(self):
        with self.assertRaises(tool.Halt):
            run_all(machine_for('call 2000'))

    def recorder_machine(self, location, first):
        rows = [(0x1000, 'call QWORD PTR [rip+0x10]', tool.RECORDER_SLOT)]
        machine = tool.Machine(rows, {0x1000: 0}, set(), 1)
        machine.regs.update(rsi=location, rdi=first)
        return machine

    def test_recorder_counts_and_clobbers_caller_saved(self):
        machine = self.recorder_machine(tool.LOCATION, 0)
        kept = machine.regs['r12']
        run_all(machine)
        self.assertEqual(machine.records, 1)
        self.assertEqual(machine.regs['r12'], kept)
        self.assertNotEqual(machine.regs['rsi'], tool.LOCATION)

    def test_recorder_with_another_location_halts(self):
        with self.assertRaises(tool.Halt):
            run_all(self.recorder_machine(tool.LOCATION + 0x18, 0))

    def test_recorder_with_another_byte_halts(self):
        with self.assertRaises(tool.Halt):
            run_all(self.recorder_machine(tool.LOCATION, 1))

    def test_rip_memory_halts(self):
        with self.assertRaises(tool.Halt):
            run_all(machine_for('mov rax,QWORD PTR [rip+0x10]'))

    def test_scaled_address(self):
        machine = machine_for('mov rax,QWORD PTR [rcx+rdx*8+0x10]')
        machine.regs.update(rcx=0x100, rdx=2)
        machine.ram[0x120] = 99
        self.assertEqual(run_all(machine).regs['rax'], 99)

    def test_integer_to_double(self):
        machine = machine_for('cvtsi2sd xmm2,rax')
        machine.regs['rax'] = 1
        self.assertEqual(run_all(machine).xmm['xmm2'], 0x3ff0000000000000)

    def test_unmodelled_instruction_leaves_a_mark_and_no_flags(self):
        machine = machine_for('cmp rax,rax', 'popcnt rax,rcx')
        before = machine.regs['rax']
        run_all(machine)
        self.assertNotEqual(machine.regs['rax'], before)
        self.assertIsNone(machine.flags)

    def test_marks_repeat_for_one_seed_only(self):
        self.assertEqual(tool.mark(1, 'x'), tool.mark(1, 'x'))
        self.assertNotEqual(tool.mark(1, 'x'), tool.mark(2, 'x'))


class Vectors(unittest.TestCase):
    def test_every_vector_overflows(self):
        self.assertTrue(all(tool.overflows('add', *pair) for pair in tool.OVER_ADD))
        self.assertTrue(all(tool.overflows('sub', *pair) for pair in tool.OVER_SUB))

    def test_boundaries_do_not_overflow(self):
        self.assertFalse(tool.overflows('add', tool.MASK, 0))
        self.assertFalse(tool.overflows('add', tool.SIGN, tool.SIGN - 1))
        self.assertTrue(tool.overflows('add', tool.SIGN, tool.SIGN))
        self.assertFalse(tool.overflows('sub', 7, 7))
        self.assertTrue(tool.overflows('sub', 6, 7))

    def test_saturated_values(self):
        self.assertEqual(tool.saturate('add', tool.MASK, 2), tool.MASK)
        self.assertEqual(tool.saturate('sub', 1, 2), 0)
        self.assertEqual(tool.saturate('add', 2, 3), 5)
        self.assertEqual(tool.saturate('sub', 3, 2), 1)

    def test_partners_keep_the_result_and_never_overflow(self):
        for kind, pairs in (('add', tool.OVER_ADD), ('sub', tool.OVER_SUB)):
            for left, right in pairs:
                for keep in ('smaller', 'left', 'right'):
                    same, others = tool.partners(kind, left, right, keep)
                    self.assertFalse(tool.overflows(kind, *same))
                    self.assertEqual(tool.saturate(kind, *same), tool.saturate(kind, left, right))
                    for pair, wanted in others:
                        self.assertFalse(tool.overflows(kind, *pair))
                        self.assertEqual(tool.saturate(kind, *pair), wanted)
                        self.assertNotEqual(wanted, tool.saturate(kind, left, right))

    def test_partners_keep_the_named_input(self):
        self.assertEqual(tool.partners('sub', 1, 2, 'left')[0], (1, 1))
        self.assertEqual(tool.partners('sub', 1, 2, 'right')[0], (2, 2))
        self.assertEqual(tool.partners('add', tool.MASK, 1, 'right')[0], (tool.MASK - 1, 1))
        self.assertEqual(tool.partners('add', 1, tool.MASK, 'left')[0], (1, tool.MASK - 1))


class Hundred(unittest.TestCase):
    def test_bound_holds_and_neighbours_fail(self):
        self.assertTrue(tool.hundred_proof()['proved'])
        self.assertEqual(tool.hundred_proof()['delta'], 11)
        self.assertFalse(tool.hundred_proof(tool.HUNDRED_MAGIC - 1)['proved'])
        self.assertFalse(tool.hundred_proof(tool.HUNDRED_MAGIC + 1)['proved'])

    def test_formula_on_edges(self):
        for x in (0, 99, 100, 101, 199, 200, tool.MASK, tool.MASK - 15, 10 ** 19):
            self.assertEqual((((x >> 2) * tool.HUNDRED_MAGIC) >> tool.HUNDRED_SHIFT), x // 100)

    def test_wrong_magic_gives_a_wrong_quotient(self):
        x = tool.MASK - tool.MASK % 100 - 1
        self.assertNotEqual((((x >> 2) * (tool.HUNDRED_MAGIC + 1)) >> tool.HUNDRED_SHIFT), x // 100)

    def test_seven_guards_divide_their_result(self):
        forms = STATE['result'][0]['guards_by_result_form']
        self.assertEqual((forms['value'], forms['floor-100'], forms['derived'], forms['branch']), (107, 7, 1, 3))

    def test_changed_divisor_is_no_longer_floor_100(self):
        rows = rows_at(XMM_SITE)
        changed = replaced(rows, 'shr rdx,0x2', 'shr rdx,0x3', XMM_SITE)
        self.assertEqual({item['result_form'] for item in tool.analyse_site(tool.make_listing(changed), XMM_SITE)},
                         {'derived'})


class Mutations(unittest.TestCase):
    def assert_fails(self, rows, lea):
        self.assertTrue(tool.fails(rows, lea))

    def test_unchanged_listing_passes(self):
        for lea in (ADD_SITE, SUB_SITE, CMP_SITE, CHAIN_SITE):
            self.assertFalse(tool.fails(rows_at(lea), lea))

    def test_every_control_is_caught(self):
        controls = STATE['result'][2]
        self.assertEqual(len(controls), 214)
        self.assertFalse([item for item in controls if item['caught'] is False])
        self.assertEqual([item['lea'] for item in controls if item['caught'] is None], [BRANCH_ONLY_SITE])

    def test_flipped_saturating_cmov(self):
        self.assert_fails(replaced(rows_at(ADD_SITE), 'cmovb', 'cmovae', ADD_SITE), ADD_SITE)

    def test_add_without_its_saturation(self):
        self.assert_fails(replaced(rows_at(ADD_SITE), 'cmovb r14,rax', 'nop', ADD_SITE), ADD_SITE)

    def test_sub_keeps_the_wrapped_value(self):
        self.assert_fails(replaced(rows_at(SUB_SITE), 'xor ebx,ebx', 'nop', SUB_SITE), SUB_SITE)

    def test_flipped_guard(self):
        rows = rows_at(SUB_SITE)
        fact = facts_for(SUB_SITE)[0]
        self.assert_fails(replaced(rows, 'jae', 'jb', fact['branch_va']), SUB_SITE)

    def test_site_passing_another_location(self):
        rows = rows_at(SUB_SITE)
        changed = [(row[0], row[1], row[2] + 0x18) if row[0] == SUB_SITE else row for row in rows]
        self.assert_fails(changed, SUB_SITE)

    def test_site_passing_a_nonzero_byte(self):
        rows = rows_at(SUB_SITE)
        self.assert_fails(replaced(rows, 'xor edi,edi', 'mov edi,0x1', SUB_SITE), SUB_SITE)

    def test_register_call_needs_the_recorder_slot(self):
        self.assertFalse(tool.fails(rows_at(REGISTER_CALL_SITE), REGISTER_CALL_SITE))
        rows = rows_at(REGISTER_CALL_SITE)
        load = max(k for k, row in enumerate(rows) if row[0] < REGISTER_CALL_SITE and row[1].startswith('mov rbx,'))
        rows[load] = (rows[load][0], rows[load][1], 0x1234)
        self.assert_fails(rows, REGISTER_CALL_SITE)

    def test_shared_xor_outside_the_cold_block(self):
        point = tool.mutation_point(rows_at(SHARED_XOR_SITE), tool.make_listing(rows_at(SHARED_XOR_SITE)),
                                    tool.make_listing(rows_at(SHARED_XOR_SITE))['index'][SHARED_XOR_SITE], 'sub')
        self.assertIsNotNone(point)
        rows = rows_at(SHARED_XOR_SITE)
        self.assert_fails(replaced(rows, 'xor eax,eax', 'mov eax,0x5', 0x26b1750), SHARED_XOR_SITE)

    def test_value_that_only_reaches_a_later_add(self):
        rows = rows_at(CHAIN_SITE)
        self.assert_fails(replaced(rows, 'mov rbx,0xffffffffffffffff', 'mov rbx,0x5', CHAIN_SITE), CHAIN_SITE)

    def test_double_result(self):
        self.assertEqual({item['result_form'] for item in facts_for(XMM_SITE)}, {'floor-100'})
        self.assertEqual(facts_for(XMM_SITE)[0]['locations'], ['xmm2'])
        self.assert_fails(replaced(rows_at(XMM_SITE), 'xorpd xmm2,xmm2', 'nop', XMM_SITE), XMM_SITE)

    def test_branch_only_site(self):
        self.assertEqual({item['result_form'] for item in facts_for(BRANCH_ONLY_SITE)}, {'branch'})
        rows = rows_at(BRANCH_ONLY_SITE)
        listing = tool.make_listing(rows)
        self.assertIsNone(tool.mutation_point(rows, listing, listing['index'][BRANCH_ONLY_SITE], 'sub'))
        self.assert_fails(replaced(rows, 'jmp 3c017eb', 'jmp 3c017e2', BRANCH_ONLY_SITE), BRANCH_ONLY_SITE)

    def test_overflow_run_alone_compares_another_value(self):
        rows = rows_at(0x371a769)
        self.assert_fails(replaced(rows, 'xor r14d,r14d', 'mov r14d,0x5', 0x371a766), 0x371a769)


class Outputs(unittest.TestCase):
    def test_rows_and_order(self):
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, *STATE['result'])
            lines = (Path(folder) / 'wei-sites.tsv').read_text().splitlines()
            self.assertEqual(len(lines), 119)
            sites = [line.split('\t')[2] for line in lines[1:]]
            self.assertEqual(sites, sorted(sites, key=lambda text: int(text, 16)))
            self.assertEqual(len((Path(folder) / 'mutation-controls.tsv').read_text().splitlines()), 215)
            self.assertEqual(json.loads((Path(folder) / 'evidence.json').read_text())['target_sha256'], tool.SHA256)

    def test_generated_files_match_the_packet(self):
        names = ['evidence.json', 'mutation-controls.tsv', 'wei-sites.tsv']
        with tempfile.TemporaryDirectory() as folder:
            tool.write_outputs(folder, *STATE['result'])
            match, mismatch, errors = filecmp.cmpfiles(folder, PACKET, names, shallow=False)
        self.assertEqual((sorted(match), mismatch, errors), (names, [], []))

    def test_manifest_lists_every_other_file(self):
        listed = {}
        for line in (PACKET / 'MANIFEST.sha256').read_text().splitlines():
            digest, name = line.split('  ', 1)
            listed[name] = digest
        present = {path.name for path in PACKET.iterdir() if path.name != 'MANIFEST.sha256'}
        self.assertEqual(set(listed), present)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((PACKET / name).read_bytes()).hexdigest(), digest)


if __name__ == '__main__':
    unittest.main()
