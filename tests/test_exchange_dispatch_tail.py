"""RE-010 cases 76..87 / shared tail: pinned output, negative control, tamper controls,
determinism, independent verifier, GNU binutils cross-checks (SKIP without GNU)."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import exchange_dispatch as ed  # noqa: E402
import exchange_dispatch_tail as edt  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-010-dispatch-cases-76-87'
BASE_PACKET = ROOT / 'research/work-items/RE-010-exchange-handlers'
OUTPUT_SHA256 = '7a914e3ae82e149c8b78a29a12c5386a2e8dfe123ca988662de4cfdc6f502844'
ROWS = {  # case: (arm, first-call site, target, idiom, reaches)
    76: (0x2759B60, 0x2759B7E, 0x2729060, 'result_word_check', 0x275A182),
    77: (0x275938D, 0x275939F, 0x1E611A0, 'join', 0x275A186),
    78: (0x275A2CF, 0x275A2E1, 0x1E60F90, 'join', 0x275A186),
    79: (0x2759333, 0x2759356, 0x1E61110, 'join', 0x275A186),
    80: (0x275945C, 0x275946E, 0x204C4E0, 'join', 0x275A186),
    81: (0x2759865, 0x2759888, 0x1E60BB0, 'join', 0x275A186),
    82: (0x2759821, 0x2759831, 0x27288C0, 'result_word_check', 0x275A182),
    83: (0x2759306, 0x2759329, 0x1E641E0, 'join', 0x275A186),
    84: (0x27592EA, 0x27592FC, 0x1E646C0, 'join', 0x275A186),
    85: (0x2759E54, 0x2759E77, 0x27E3750, 'join', 0x275A186),
    86: (0x2759E9D, 0x2759EAF, 0x1E648C0, 'join', 0x275A186),
    87: (0x275A259, 0x275A27C, 0x1E5F010, 'join', 0x275A186),
}
NAMES_76_87 = ['sendToEvmWithData', 'userPortfolioMargin', 'userSetAbstraction', 'agentSetAbstraction',
               'userOutcome', 'gossipPriorityBid', 'agentSendAsset', 'hip3LiquidatorTransfer',
               'l1ValidatorVoteBridgeDeposit', 'authorizeAqav2Role', 'stakingLinkDisableTradingUser',
               'voteL1Hash']
_CACHE = {}


def data():
    if 'data' not in _CACHE:
        _CACHE['data'] = ed.TARGET.read_bytes()
    return _CACHE['data']


def result():
    if 'result' not in _CACHE:
        _CACHE['result'] = edt.build(data())
    return _CACHE['result']


def mutate(va, new):
    buf = bytearray(data())
    o = ed.Elf(data()).off(va)
    buf[o:o + len(new)] = new
    return bytes(buf)


def build_mut(buf):
    return edt.build(buf, expected_sha256=hashlib.sha256(buf).hexdigest(), check_base=False)


def gnu_objdump():
    exe = shutil.which('objdump')
    if not exe:
        return None
    try:
        v = subprocess.run([exe, '--version'], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return exe if v.startswith('GNU objdump') else None


def requires_gnu(fn):
    return unittest.skipUnless(gnu_objdump(), 'requires GNU objdump (LLVM or none found)')(fn)


def objdump(lo, hi):
    out = subprocess.run([gnu_objdump(), '-d', '-M', 'intel', '--no-show-raw-insn',
                          f'--start-address={lo:#x}', f'--stop-address={hi:#x}', str(ed.TARGET)],
                         check=True, capture_output=True, text=True).stdout
    rows = {}
    for line in out.splitlines():
        m = re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(\S*)', line)
        if m:
            rows[int(m.group(1), 16)] = (m.group(2), m.group(3))
    return rows


class TestPinned(unittest.TestCase):
    def test_output_hash(self):
        self.assertEqual(hashlib.sha256(edt.render(result())).hexdigest(), OUTPUT_SHA256)

    def test_committed_json(self):
        self.assertEqual(edt.render(result()), (PACKET / 'dispatch-tail.json').read_bytes())

    def test_negative_control_cases_0_75(self):
        text = ed.render(ed.build(data()))
        self.assertEqual(hashlib.sha256(text).hexdigest(), edt.BASE_JSON_SHA256)
        self.assertEqual(text, (BASE_PACKET / 'exchange-dispatch.json').read_bytes())

    def test_exact_counts(self):
        r = result()
        self.assertEqual(r['name_agreement_counts'], {'action_suffix': 13, 'different': 1, 'exact': 51,
                                                      'first_letter_case': 6,
                                                      'first_letter_case_and_action_suffix': 5})
        self.assertEqual(len(r['name_agreement_non_exact']), 25)
        self.assertEqual(r['unclaimed_join_counts'], {0x275A182: 2, 0x275A186: 10})
        self.assertEqual(r['tail_branch_source_counts'],
                         {0x275A136: 8, 0x275A180: 2, 0x275A182: 9, 0x275A186: 78})
        self.assertEqual([t['va'] for t in r['variant_tables']], [0x56C46E0, 0x56E8BD0, 0x5733130])
        self.assertEqual(len(r['variant_names']), 88)
        self.assertEqual([len(c['callee_lea_anchors']) for c in r['unclaimed_cases']],
                         [3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0])

    def test_exact_rows(self):
        cases = result()['unclaimed_cases']
        self.assertEqual([c['index'] for c in cases], list(range(76, 88)))
        self.assertEqual([c['serde_name'] for c in cases], NAMES_76_87)
        for c in cases:
            arm, site, tgt, idiom, reach = ROWS[c['index']]
            k = c['continuation']
            self.assertEqual((c['arm'], c['first_call']['site'], c['first_call']['target'], k['idiom'],
                              k.get('trampoline', k)['to']), (arm, site, tgt, idiom, reach), c['index'])
            self.assertEqual(c['discriminant'], 0x74 + c['index'])

    def test_case76_gate_and_location(self):
        c = result()['unclaimed_cases'][0]
        g = c['entry_gate']
        self.assertEqual((g['field_offset'], g['compare_imm'], g['taken_to'], g['error_code_word'], g['then_jmp']),
                         (0x3AC9, 0, 0x275A34F, 0x8E, 0x275A180))
        locs = [a for a in c['callee_lea_anchors'] if a['kind'] == 'location']
        self.assertEqual([(a['target'], a['file'].rsplit('/', 3)[-3:], a['line'], a['col']) for a in locs],
                         [(0x56BE068, ['alloc', 'src', 'string.rs'], 2918, 14)])
        self.assertEqual(sum(c['entry_gate'] is not None for c in result()['unclaimed_cases']), 1)

    def test_tail_facts(self):
        t = result()['tail']
        self.assertEqual(t['bytes_sha256'], '51b254e20ebec8b2c341feef9f1f902898b4fd6d54d48e788e75bf194f494122')
        self.assertEqual([x['target'] for x in t['join_entry']['calls']], [0x4EE3800, 0x4EE3730])
        self.assertEqual((t['copy_block']['movups'], t['join_entry']['result_copy_bytes'],
                          t['join_entry']['skip_if_ebp_eq']), (6, 0x68, 1000000000))

    def test_hashseed_independent(self):
        outs = set()
        for seed in ('0', '7', '99'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/exchange_dispatch_tail.py')],
                               cwd=ROOT, env=env, check=True, capture_output=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    def test_verify_scripts_modes(self):
        for flags in (['-I', '-B'], ['-O', '-B']):
            for script, word in (('verify.py', 'OK'), ('independent_verify.py', 'PASS')):
                p = subprocess.run([sys.executable, *flags, str(PACKET / script)], cwd=ROOT,
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, (flags, script, p.stderr))
                self.assertIn(word, p.stdout)


class TestTamper(unittest.TestCase):
    def test_mutated_binary_rejected_by_default(self):
        with self.assertRaises(ed.EvidenceError):
            edt.build(mutate(0x275A180, b'\xb0\x0f'))

    def test_tail_al_byte(self):
        with self.assertRaises(ed.EvidenceError):
            build_mut(mutate(0x275A180, b'\xb0\x0f'))

    def test_tail_sentinel(self):
        with self.assertRaises(ed.EvidenceError):
            build_mut(mutate(0x275A188, b'\x01\xca\x9a\x3b'))

    def test_continuation_idiom(self):
        with self.assertRaises(ed.EvidenceError):
            build_mut(mutate(0x27593A4, b'\x90'))

    def test_gate_target_idiom(self):
        with self.assertRaises(ed.EvidenceError):
            build_mut(mutate(0x275A34F, b'\x90\x90'))

    def test_variant_count_message(self):
        buf = bytearray(data())
        hits = [m.start() for m in re.finditer(rb'variant index 0 <= i < 88', data())]
        self.assertEqual(len(hits), len(set(hits)))
        for o in hits:
            buf[o + 23:o + 25] = b'87'
        with self.assertRaises(ed.EvidenceError):
            build_mut(bytes(buf))

    def test_variant_tables_disagree(self):
        elf = ed.Elf(data())
        rel = ed.relative_relocs(elf)
        slot = 0x56E8BD0 + 16 * 80 + 8   # length of entry 80 in the second table
        if slot - 8 not in rel:
            self.fail('expected RELATIVE slot')
        buf = mutate(slot, (4).to_bytes(8, 'little'))
        with self.assertRaises(ed.EvidenceError):
            build_mut(buf)

    def test_first_call_retarget_changes_row(self):
        site = ROWS[77][1]
        rel = (ROWS[78][2] - (site + 5)) & 0xFFFFFFFF
        r = build_mut(mutate(site + 1, rel.to_bytes(4, 'little')))
        self.assertEqual(r['unclaimed_cases'][1]['first_call']['target'], ROWS[78][2])
        self.assertNotEqual(hashlib.sha256(edt.render(r)).hexdigest(), OUTPUT_SHA256)

    def test_independent_verifier_fail_and_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            pk = Path(td) / 'research/work-items/X'
            pk.mkdir(parents=True)
            shutil.copy(PACKET / 'independent_verify.py', pk)
            js = json.loads((PACKET / 'dispatch-tail.json').read_text())
            (pk / 'dispatch-tail.json').write_text(json.dumps(js))
            run = lambda: subprocess.run([sys.executable, '-I', '-B', str(pk / 'independent_verify.py')],
                                         capture_output=True, text=True)
            p = run()
            self.assertEqual((p.returncode, 'INCONCLUSIVE' in p.stdout), (2, True), p.stdout)
            (Path(td) / 'artifacts/node/94').mkdir(parents=True)
            os.symlink(ed.TARGET, Path(td) / 'artifacts/node/94/hl-node')
            self.assertEqual(run().returncode, 0)
            for mut in (lambda j: j['unclaimed_cases'][3].__setitem__('serde_name', 'x'),
                        lambda j: j['tail_branch_source_counts'].__setitem__('0x275a186', 77),
                        lambda j: j['unclaimed_cases'][0]['first_call'].__setitem__('target', '0x2729061'),
                        lambda j: j['tail'].__setitem__('bytes_sha256', '0' * 64)):
                j = json.loads(json.dumps(js))
                mut(j)
                (pk / 'dispatch-tail.json').write_text(json.dumps(j))
                p = run()
                self.assertEqual((p.returncode, 'FAIL' in p.stdout), (1, True), p.stdout)


class TestGnu(unittest.TestCase):
    @requires_gnu
    def test_arm_sites_are_instructions(self):
        od = objdump(0x2759240, 0x275A376)
        for c in result()['unclaimed_cases']:
            self.assertIn(c['arm'], od)
            self.assertEqual(od[c['first_call']['site']], ('call', f"{c['first_call']['target']:x}"))
            k = c['continuation']
            self.assertEqual(od[k['jmp_site']], ('jmp', f"{k['to']:x}"))
            if 'trampoline' in k:
                self.assertEqual(od[k['trampoline']['at'] + 2], ('jmp', f"{k['trampoline']['to']:x}"))

    @requires_gnu
    def test_tail_sources_match_objdump(self):
        od = objdump(0x2759240, 0x275A376)
        want = {}
        for va, (mn, arg) in od.items():
            if mn.startswith('j') and arg:
                t = int(arg, 16) if re.fullmatch('[0-9a-f]+', arg) else None
                if t in edt.TAIL_ENTRIES:
                    want.setdefault(t, []).append({'site': va, 'kind': 'jmp' if mn == 'jmp' else 'jcc'})
        self.assertEqual(result()['tail_branch_sources'], want)

    @requires_gnu
    def test_callee_lea_sites_are_instructions(self):
        for c in result()['unclaimed_cases']:
            fc = c['first_call']
            od = objdump(fc['target'], fc['target_fde_end'])
            for a in c['callee_lea_anchors']:
                self.assertEqual(od.get(a['site'], ('?',))[0], 'lea', hex(a['site']))
            leas = [va for va, (mn, _a) in od.items() if mn == 'lea']
            self.assertGreaterEqual(len(leas), len(c['callee_lea_anchors']))


if __name__ == '__main__':
    unittest.main()
