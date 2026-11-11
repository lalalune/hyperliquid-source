import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import action_router_115 as ar  # noqa: E402


class ActionRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = ar.load()

    def run_case(self, case, image=None):
        real, _ = ar.run_real(image or self.image, *case)
        return real, ar.model(*case)

    def test_every_arm_matches_model(self):
        for i in range(92):
            case = (0x86 + i, i & 1, ar.NOWS[i % len(ar.NOWS)], ar.PTRS[i % len(ar.PTRS)])
            real, mod = self.run_case(case)
            self.assertTrue(ar.compare(real, mod), i)
            self.assertEqual([t[1] for t in real[0] if t[0] == 'handler'], [ar.HANDLERS[i]])

    def test_tags_below_base_take_the_niche_arm(self):
        for tag in (0, 1, 0x40, 0x85):
            real, mod = self.run_case((tag, 1, ar.NOWS[0], ar.PTRS[0]))
            self.assertTrue(ar.compare(real, mod))
            handler = [t for t in real[0] if t[0] == 'handler'][0]
            self.assertEqual(handler[1], ar.HANDLERS[20])
            self.assertEqual(handler[5], ar.PTRS[0][3])

    def test_flag_gate_only_for_trading_indices(self):
        gated = {0, 2, 3, 4, 12, 14}
        for i in range(92):
            real, _ = self.run_case((0x86 + i, 0, ar.NOWS[0], ar.PTRS[0]))
            calls = [t[0] for t in real[0]]
            self.assertEqual('flag' in calls, i in gated, i)
            # flag false: gated arms run untimed, the others always time.
            self.assertEqual('now' in calls, i not in gated, i)

    def test_flag_true_times_gated_arms(self):
        real, mod = self.run_case((0x86 + 14, 1, ar.NOWS[2], ar.PTRS[1]))
        self.assertEqual([t[0] for t in real[0]], ['flag', 'now', 'handler', 'now', 'record'])
        self.assertEqual(real[0][0][1], 50)
        self.assertTrue(ar.compare(real, mod))

    def test_record_receives_end_then_start(self):
        real, _ = self.run_case((0x86 + 1, 1, ar.NOWS[2], ar.PTRS[0]))
        rec = real[0][-1]
        self.assertEqual(rec, ('record', (1794169131, 123456790), (1794169131, 123456789)))

    def test_result_is_copied_and_callee_saved_registers_restored(self):
        real, mod = self.run_case((0x86 + 7, 1, ar.NOWS[3], ar.PTRS[2]))
        self.assertTrue(real[2])
        self.assertEqual(real[1], mod[1])
        self.assertEqual(len(real[1]), 128)

    def test_table_slot_count_and_handlers_are_distinct(self):
        self.assertEqual(len(ar.HANDLERS), 92)
        self.assertEqual(len(set(ar.HANDLERS)), 92)
        self.assertEqual(len(ar.NO_EXTRA), 11)

    def test_arm_bytes_match_table(self):
        ar.verify_arms(self.image)
        arm, handler, shape, join = ar.decode_arm(self.image, 19)
        self.assertEqual((handler, shape, join), (0x2c08600, 'tag_pointer_plus_8', ar.JOIN))
        self.assertEqual(ar.decode_arm(self.image, 20)[2], 'tag_pointer')
        self.assertEqual(ar.decode_arm(self.image, 0)[2], 'none')

    def test_arm_decoder_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            ar.decode_arm(self.image, 92)
        with self.assertRaises(ValueError):
            ar.decode_arm(self.image, -1)
        self.image.patches[ar.decode_arm(self.image, 3)[0] + 4] = 0x90
        try:
            with self.assertRaises(ValueError):
                ar.decode_arm(self.image, 3)
            with self.assertRaises((ValueError, SystemExit)):
                ar.verify_arms(self.image)
        finally:
            self.image.patches.clear()

    def test_model_mutants_are_all_detected(self):
        detect = list(ar.case_inputs(8))
        reals = [ar.run_real(self.image, *c)[0] for c in detect]
        for name, params in ar.model_mutants():
            hit = any(not ar.compare(r, ar.model(*c, params=params)) for r, c in zip(reals, detect))
            self.assertTrue(hit, name)

    def test_byte_damage_is_detected(self):
        detect = list(ar.case_inputs(2))
        for name, va, old, new in ar.byte_damage():
            self.assertEqual(self.image.byte(va), old, name)
            self.image.patches[va] = new
            try:
                hit = False
                for c in detect:
                    try:
                        real, _ = ar.run_real(self.image, *c)
                    except (ar.EmuError, ValueError, IndexError):
                        hit = True
                        break
                    if not ar.compare(real, ar.model(*c)):
                        hit = True
                        break
                self.assertTrue(hit, name)
            finally:
                self.image.patches.clear()

    def test_out_of_domain_inputs_rejected(self):
        self.assertFalse(ar.accepts(0x86 + 92, ar.NOWS[0]))
        self.assertFalse(ar.accepts(1 << 40, ar.NOWS[0]))
        self.assertFalse(ar.accepts(0x86, ((1, 1000000000), (2, 0))))
        self.assertTrue(ar.accepts(0x86 + 91, ar.NOWS[0]))
        self.assertTrue(ar.accepts(3, ar.NOWS[0]))

    def test_wrong_digest_refuses(self):
        with mock.patch.object(ar, 'DIGEST', '0' * 64):
            with self.assertRaises(SystemExit):
                ar.load()

    def test_emulator_rejects_unknown_call_target(self):
        emu = ar.Emu(self.image, 0x86, 1, ar.NOWS[0], ar.PTRS[0])
        with self.assertRaises(ar.EmuError):
            emu.call(0x1234, 0)

    def test_regeneration_matches_measure(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sys, 'argv', ['x', '--out', tmp]):
                ar.main()
            measure = json.loads((Path(tmp) / 'measure.json').read_text())
            self.assertEqual(measure['cases'], 10396)
            self.assertEqual(measure['negative_detected'], measure['negative_controls'])
            self.assertGreaterEqual(measure['negative_controls'], 30)
            committed = ROOT / 'research/work-items/action-dispatch-router-115'
            if committed.exists():
                for name in ('arms.tsv', 'controls.tsv', 'coverage.tsv', 'summary.json', 'measure.json', 'cases-sample.tsv'):
                    self.assertEqual((Path(tmp) / name).read_bytes(), (committed / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
