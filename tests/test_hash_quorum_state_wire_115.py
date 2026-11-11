"""Tests for tools/hash_quorum_state_wire_115.py (node #115 six-field quorum record serializers)."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import hash_quorum_state_wire_115 as tool  # noqa: E402

FOLDER = ROOT / 'research/work-items/serialization-hash-quorum-state-wire-115'
_CACHE = {}


def data():
    if 'data' not in _CACHE:
        _CACHE['data'] = tool.TARGET.read_bytes()
    return _CACHE['data']


def image():
    if 'image' not in _CACHE:
        _CACHE['image'] = tool.PImage(data())
        _, recs, _ = tool.fde_extents.fde_extents(data())
        _CACHE['by_start'] = {r['start']: r for r in recs}
    return _CACHE['image']


def by_start():
    image()
    return _CACHE['by_start']


def result():
    if 'result' not in _CACHE:
        _CACHE['result'] = tool.build(data())
    return _CACHE['result']


class TestInput(unittest.TestCase):
    def test_binary_is_node_115(self):
        self.assertEqual(hashlib.sha256(data()).hexdigest(), tool.SHA115)

    def test_digest_check_refuses_other_bytes(self):
        with self.assertRaises(tool.Reject):
            tool.check_digest(data()[:-1])

    def test_every_entry_is_an_fde_start(self):
        for body in tool.BODIES:
            self.assertIn(body['entry'], by_start())

    def test_entry_inside_a_body_is_refused(self):
        with self.assertRaises(tool.Reject):
            tool.body_rows(image(), by_start(), dict(entry=tool.RMP[0]['entry'] + 1))


class TestStatic(unittest.TestCase):
    def test_every_body_decodes_to_its_fde_end(self):
        for body in tool.BODIES:
            rows = tool.body_rows(image(), by_start(), body)
            self.assertEqual(rows[-1].va + rows[-1].length, by_start()[body['entry']]['end'], body['name'])

    def test_keys_and_counts_come_from_the_bytes(self):
        for body in tool.BODIES:
            rows = tool.body_rows(image(), by_start(), body)
            keys = tool.static_checks(image(), body, rows)
            want = list(tool.ADDITIONAL_FIELD_KEYS)
            self.assertEqual(keys, want[:4] if body['style'] == 'json' else want, body['name'])

    def test_role_table_mismatch_is_refused(self):
        body = dict(tool.RMP[0])
        body['roles'] = dict(body['roles'], tracker=body['roles']['tracker'] + 0x10)
        rows = tool.body_rows(image(), by_start(), body)
        with self.assertRaises(tool.Reject):
            tool.static_checks(image(), body, rows)

    def test_sixth_field_key_is_one_byte(self):
        for role, entry, want in tool.HELPER_KEYS:
            _, _, key = tool.first_key(image(), by_start(), entry)
            self.assertEqual(key, want, role)

    def test_first_key_refuses_a_non_fde_address(self):
        with self.assertRaises(tool.Reject):
            tool.first_key(image(), by_start(), 0x10)

    def test_header_calls_carry_field_count_six(self):
        for body in tool.RMP:
            rows = tool.body_rows(image(), by_start(), body)
            sixes = [r for k, r in enumerate(rows) if r.op == 'movimm' and r.reg == 2 and r.imm == 6
                     and rows[k + 1].op == 'call']
            self.assertEqual(len(sixes), 2, body['name'])


class TestRmpBodies(unittest.TestCase):
    def test_all_bodies_match_the_model(self):
        for body in tool.RMP:
            for flag, fail_at, seed in tool.rmp_inputs(4):
                got = tool.run_rmp(image(), body, flag, fail_at, seed)
                self.assertEqual(got, tool.recon_rmp(body, flag, fail_at, seed), (body['name'], flag, fail_at))

    def test_flag_zero_uses_the_array_header_and_no_keys(self):
        log, res = tool.recon_rmp(tool.RMP[0], 0, None, 0)
        self.assertEqual(log[0][1], 'hdr_arr')
        self.assertFalse([e for e in log if e[1] == 'str'])
        self.assertEqual(res, (tool.OK_WORD, tool.PATTERN, tool.PATTERN))

    def test_flag_one_writes_five_keys_and_flag_two_none(self):
        one = [e for e in tool.recon_rmp(tool.RMP[0], 1, None, 0)[0] if e[1] == 'str']
        two = [e for e in tool.recon_rmp(tool.RMP[0], 2, None, 0)[0] if e[1] == 'str']
        self.assertEqual(len(one), 5)
        self.assertEqual(two, [])

    def test_header_failure_returns_before_any_field(self):
        log, res = tool.recon_rmp(tool.RMP[0], 1, 0, 3)
        self.assertEqual(len(log), 1)
        self.assertEqual(res[0], tool.NICHE)

    def test_f64_error_shape_differs_between_forms(self):
        ret = tool.recon_rmp(tool.RMP[0], 0, 5, 1)[1]
        out = tool.recon_rmp(tool.RMP[2], 0, 5, 1)[1]
        self.assertEqual(ret[0], tool.NICHE)
        self.assertNotEqual(out[0], tool.NICHE)


class TestJsonBodies(unittest.TestCase):
    def test_all_bodies_match_the_model(self):
        for body in tool.JSON:
            for i, (depth, cap, length, fail_at, mode) in enumerate(tool.json_inputs()):
                if i % 3:
                    continue
                got = tool.run_json(image(), body, depth, cap, length, fail_at, mode)
                self.assertEqual(got, tool.recon_json(body, depth, cap, length, fail_at, mode), (body['name'], i))

    def test_depth_overflow_panics_before_any_write(self):
        tag, log, appended, end, depth, flag = tool.recon_json(tool.JSON[0], tool.MASK, 8, 0, None, 'rax')
        self.assertEqual(tag, ('panic', tool.SLOT_OVERFLOW))
        self.assertEqual((log, appended, end, depth, flag), ([], b'', 0, tool.MASK, tool.FLAG_INIT))

    def test_open_brace_and_separator_bytes(self):
        tag, log, appended, end, depth, flag = tool.recon_json(tool.JSON[0], 0, 64, 0, None, 'rax')
        self.assertEqual(appended, b'{: ')
        self.assertEqual((tag, depth, flag), (('ok', 0), 1, 1))

    def test_state_byte_after_htm_is_not_checked(self):
        tag = tool.recon_json(tool.JSON[0], 0, 64, 0, 4, 'state')[0]
        self.assertEqual(tag, ('ok', 0))
        tag = tool.recon_json(tool.JSON[0], 0, 64, 0, 3, 'state')[0]
        self.assertEqual(tag, ('rax', 'errctor'))

    def test_first_key_state_one_is_a_format_panic(self):
        tag = tool.recon_json(tool.JSON[0], 0, 64, 0, 0, 'state')[0]
        self.assertEqual(tag, ('panic', tool.SLOT_FMT))

    def test_reserve_grows_when_two_bytes_do_not_fit(self):
        grows = [e for e in tool.recon_json(tool.JSON[0], 0, 2, 0, None, 'rax')[1] if e[0] == 'grow']
        self.assertEqual(grows, [('grow', 1, 2)])
        grows = [e for e in tool.recon_json(tool.JSON[0], 0, 3, 0, None, 'rax')[1] if e[0] == 'grow']
        self.assertEqual(grows, [])


class TestThirdFamilyJson(unittest.TestCase):
    def test_body_matches_the_model(self):
        body = tool.JSONC[0]
        for i, (depth, cap, length, fail_at, mode) in enumerate(tool.json_inputs('jsonc')):
            if i % 2:
                continue
            got = tool.run_json(image(), body, depth, cap, length, fail_at, mode)
            self.assertEqual(got, tool.recon_jsonc(body, depth, cap, length, fail_at, mode), (i, fail_at, mode))

    def test_end_helper_is_conditional_on_the_state_bytes(self):
        body = tool.JSONC[0]
        ok = tool.recon_jsonc(body, 0, 64, 0, None, 'rax')[1]
        closed = tool.recon_jsonc(body, 0, 64, 0, 6, 'closed')[1]
        state = tool.recon_jsonc(body, 0, 64, 0, 6, 'state')[1]
        self.assertEqual(ok[-1], ('call', 'end', ('ser+8', 'vec')))
        self.assertEqual(closed[-1][1], 'tail')
        self.assertEqual(state[-1][1], 'tail')

    def test_adu_key_is_written_by_the_body(self):
        rows = tool.body_rows(image(), by_start(), tool.JSONC[0])
        keys = [r[5] for r in tool.key_rows(image(), tool.JSONC[0], rows)]
        self.assertEqual(keys[-1], 'adu')

    def test_state_byte_after_adu_is_not_read(self):
        a = tool.recon_jsonc(tool.JSONC[0], 0, 64, 0, 5, 'state')
        b = tool.recon_jsonc(tool.JSONC[0], 0, 64, 0, None, 'rax')
        self.assertEqual(a, b)

    def test_depth_overflow_panics_first(self):
        tag, log, appended, end, depth, flag = tool.recon_jsonc(tool.JSONC[0], tool.MASK, 8, 0, None, 'rax')
        self.assertEqual((tag, log, appended, end), (('panic', tool.SLOT_OVERFLOW), [], b'', 0))


class TestNegativeControls(unittest.TestCase):
    def test_every_wrong_rmp_model_differs_somewhere(self):
        for name, variant in tool.WRONG_RMP.items():
            differs = any(tool.recon_rmp(b, f, k, s) != tool.recon_rmp(b, f, k, s, variant)
                          for b in tool.RMP for f, k, s in tool.rmp_inputs(2))
            self.assertTrue(differs, name)

    def test_every_wrong_json_model_differs_somewhere(self):
        for name, variant in tool.WRONG_JSON.items():
            differs = any(tool.recon_json(b, *x) != tool.recon_json(b, *x, variant)
                          for b in tool.JSON for x in tool.json_inputs())
            self.assertTrue(differs, name)

    def test_every_wrong_third_family_model_differs_somewhere(self):
        for name, variant in tool.WRONG_JSONC.items():
            differs = any(tool.recon_jsonc(tool.JSONC[0], *x) != tool.recon_jsonc(tool.JSONC[0], *x, variant)
                          for x in tool.json_inputs('jsonc'))
            self.assertTrue(differs, name)

    def test_wrong_model_does_not_match_the_machine_code(self):
        body = tool.RMP[0]
        wrong = tool.WRONG_RMP['field_count_five']
        got = tool.run_rmp(image(), body, 1, None, 0)
        self.assertNotEqual(got, tool.recon_rmp(body, 1, None, 0, wrong))

    def test_corrupted_bytes_are_detected(self):
        for body in (tool.RMP[1], tool.RMP[3], tool.JSON[1], tool.JSONC[0]):
            rows = tool.body_rows(image(), by_start(), body)
            sites = tool.pick_sites(rows, body['style'])
            self.assertGreaterEqual(len(sites), 6)
            for site in sites:
                self.assertTrue(tool.corrupted_detected(data(), body, site), (body['name'], site))

    def test_a_no_op_overlay_is_not_detected(self):
        body = tool.RMP[0]
        site = ('same-byte', body['entry'] + 0x21, 0, image().read(body['entry'] + 0x21, 1)[0])
        self.assertFalse(tool.corrupted_detected(data(), body, site))

    def test_range_controls_all_refused(self):
        rows = tool.range_controls(data(), image(), by_start())
        self.assertGreaterEqual(len(rows), 10)
        self.assertTrue(all(ok for _, ok in rows), rows)


class TestEvidence(unittest.TestCase):
    def test_build_numbers(self):
        s = result()['summary']
        self.assertEqual(s['mismatches'], 0)
        self.assertGreaterEqual(s['cases'], 10000)
        self.assertGreaterEqual(s['negative_controls'], 30)
        self.assertEqual(s['negative_detected'], s['negative_controls'])
        self.assertEqual((s['msgpack_bodies'], s['json_bodies']), (5, 3))

    def test_every_case_row_listed_as_mismatch_is_absent(self):
        self.assertFalse([r for r in result()['cases'] if r[-1] != 'match'])

    def test_committed_files_equal_a_fresh_build(self):
        files = tool.render(result())
        for name, text in files.items():
            self.assertEqual((FOLDER / name).read_text(encoding='utf-8'), text, name)

    def test_measure_json_matches_summary(self):
        s = result()['summary']
        m = json.loads((FOLDER / 'measure.json').read_text(encoding='utf-8'))
        self.assertEqual((m['cases'], m['negative_controls'], m['negative_detected']),
                         (s['cases'], s['negative_controls'], s['negative_detected']))

    def test_manifest_lists_every_file(self):
        lines = (FOLDER / 'MANIFEST.sha256').read_text(encoding='utf-8').splitlines()
        listed = {l.split('  ', 1)[1]: l.split('  ', 1)[0] for l in lines}
        on_disk = sorted(p.name for p in FOLDER.iterdir() if p.name != 'MANIFEST.sha256')
        self.assertEqual(sorted(listed), on_disk)
        for name, digest in listed.items():
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
