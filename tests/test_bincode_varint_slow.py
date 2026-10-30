"""RE-005 slow/widths: pinned output, negative control, tamper, determinism,
independent verifier, GNU binutils cross-checks (SKIP without GNU)."""
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
import bincode_varint as bv  # noqa: E402
import bincode_varint_decode as dv  # noqa: E402
import bincode_varint_slow as sv  # noqa: E402

PACKET = ROOT / 'research/work-items/RE-005-bincode-slow-widths'
FAST_PACKET = ROOT / 'research/work-items/RE-005-bincode-varint'
OUTPUT_SHA256 = '2a997306317bd14b243d1f780501514707f3b4a5d75726555a0156608867df14'
_CACHE = {}


def data():
    if 'data' not in _CACHE:
        _CACHE['data'] = bv.TARGET.read_bytes()
    return _CACHE['data']


def result():
    if 'result' not in _CACHE:
        _CACHE['result'] = sv.scan(data())
    return _CACHE['result']


def mutate(va, new):
    buf = bytearray(data())
    o = bv.va_to_off(bv.sections(data()), va)
    buf[o:o + len(new)] = new
    return bytes(buf)


def scan_mut(buf):
    return sv.scan(buf, expected_sha256=hashlib.sha256(buf).hexdigest(), check_fast_path=False)


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


def objdump_starts(lo, hi):
    out = subprocess.run([gnu_objdump(), '-d', '-M', 'intel', '--no-show-raw-insn',
                          f'--start-address={lo:#x}', f'--stop-address={hi:#x}', str(bv.TARGET)],
                         check=True, capture_output=True, text=True).stdout
    starts = set()
    for line in out.splitlines():
        m = re.match(r'\s+([0-9a-f]+):', line)
        if m:
            starts.add(int(m.group(1), 16))
    return starts


class TestPinned(unittest.TestCase):
    def test_output_hash(self):
        self.assertEqual(hashlib.sha256(sv.render(result())).hexdigest(), OUTPUT_SHA256)

    def test_committed_json(self):
        self.assertEqual(sv.render(result()), (PACKET / 'slow-sites.json').read_bytes())

    def test_negative_control_fast_path(self):
        text = bv.render(dv.scan(data()))
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), sv.FAST_PATH_JSON_SHA256)
        self.assertEqual(text, (FAST_PACKET / 'decode-sites.json').read_text())

    def test_exact_counts(self):
        r = result()
        self.assertEqual(r['reader_call_counts'], {'0x466d850': 2, '0x466d980': 12})
        self.assertEqual(len(r['readers']), 2)
        self.assertEqual(len(r['decode_vectors']), 22)
        self.assertEqual([x['name'] for x in r['readers']],
                         ['varint_decode_u32_reader', 'varint_decode_u64_reader'])

    def test_exact_tables_and_gots(self):
        r = result()
        self.assertEqual(r['readers'][0]['jump_targets_by_tag'],
                         {'0xfb': '0x466d8b7', '0xfc': '0x466d8c4', '0xfd': '0x466d945', '0xfe': '0x466d92d'})
        self.assertEqual(r['readers'][1]['jump_targets_by_tag'],
                         {'0xfb': '0x466d9e7', '0xfc': '0x466da01', '0xfd': '0x466d9f4', '0xfe': '0x466da8c'})
        self.assertEqual(r['u32_slice_decoder']['jump_targets_by_tag'],
                         {'0xfb': '0x466bc79', '0xfc': '0x466bc85', '0xfd': '0x466bcd3', '0xfe': '0x466bcbb'})
        self.assertEqual(r['u32_slice_decoder']['slow_path'],
                         {'got_slot': '0x5775138', 'reader': '0x466d850',
                          'gate': 'cmp rax,4 ; jbe', 'gate_va': '0x466bc3d'})
        self.assertEqual(r['u64_slice_slow_branch']['slow_path'],
                         {'got_slot': '0x57745e0', 'reader': '0x466d980',
                          'gate': 'cmp rax,8 ; jbe', 'gate_va': '0x466bd3d'})
        self.assertEqual(r['readers'][0]['expected_type_code_on_0xfe'], 2)
        self.assertEqual(r['readers'][1]['expected_type_code_on_0xfe'], 3)

    def test_decode_vectors_markers(self):
        by = {(v['reader'], v['input_hex']): v for v in result()['decode_vectors']}
        self.assertEqual(by[('varint_decode_u32_reader', 'fe')]['found_code'], 4)
        self.assertEqual(by[('varint_decode_u32_reader', 'ff')]['found_code'], 0xc)
        self.assertEqual(by[('varint_decode_u64_reader', 'fe')]['expected_code'], 3)
        self.assertEqual(by[('varint_decode_u64_reader', 'fb3412')]['value'], 0x1234)
        self.assertEqual(by[('varint_decode_u64_reader', 'fdefcdab9078563412')]['value'],
                         0x1234567890abcdef)

    def test_hashseed_independent(self):
        outs = set()
        for seed in ('0', '7', '99'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            p = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/bincode_varint_slow.py')],
                               cwd=ROOT, env=env, check=True, capture_output=True)
            outs.add(hashlib.sha256(p.stdout).hexdigest())
        self.assertEqual(outs, {OUTPUT_SHA256})

    def test_verify_modes(self):
        for opt in ('-I', '-O'):
            p = subprocess.run([sys.executable, opt, '-B', str(PACKET / 'verify.py')],
                               cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(OUTPUT_SHA256, p.stdout)


class TestTamper(unittest.TestCase):
    def test_flip_u32_reader_jump_table(self):
        # Flip the 0xfe slot of the u32 Reader table (last of 4 int32s).
        buf = mutate(0x6f6ec8 + 12, b'\x00\x00\x00\x00')
        with self.assertRaises(bv.EvidenceError):
            scan_mut(buf)

    def test_flip_u64_reader_width_marker_cmp(self):
        # Corrupt cmp r8,0xfb at the u64 Reader tag check.
        buf = mutate(0x466d9a0, b'\x90' * 7)
        with self.assertRaises(bv.EvidenceError):
            scan_mut(buf)

    def test_flip_slow_branch_jbe(self):
        buf = mutate(0x466bd41, b'\x90\x90')  # nop the jbe
        with self.assertRaises(bv.EvidenceError):
            scan_mut(buf)

    def test_flip_error_builder_tag(self):
        buf = mutate(0x466dac3, b'\xc6\x07\x00')  # tag 0 instead of 0x3
        with self.assertRaises(bv.EvidenceError):
            scan_mut(buf)

    def test_scan_removed_hit_rejected(self):
        buf = mutate(0x134690d, b'\x48\x83\xf9\x03')  # cmp rcx,3: hit disappears
        with self.assertRaisesRegex(bv.EvidenceError, 'length-2-adjacent hits'):
            scan_mut(buf)

    def test_scan_site_bytes_rejected(self):
        buf = mutate(0x3959c68 + 3, b'\xfc')  # cmp rcx,0xfc at a pinned 0xfb site
        with self.assertRaises(bv.EvidenceError):
            scan_mut(buf)

    def test_wrong_digest_rejected(self):
        buf = bytearray(data()); buf[0x100] ^= 1
        with self.assertRaisesRegex(bv.EvidenceError, 'SHA-256'):
            sv.scan(bytes(buf))


class TestIndependent(unittest.TestCase):
    def test_independent_pass(self):
        p = subprocess.run([sys.executable, '-I', '-B', str(PACKET / 'independent_verify.py')],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertIn('PASS', p.stdout)

    def test_independent_in_temp_with_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'artifacts/node/94').mkdir(parents=True)
            (td / 'artifacts/node/94/hl-node').symlink_to(bv.TARGET.resolve())
            pkt = td / 'research/work-items/RE-005-bincode-slow-widths'
            pkt.mkdir(parents=True)
            for name in ('slow-sites.json', 'independent_verify.py'):
                (pkt / name).write_bytes((PACKET / name).read_bytes())
            p = subprocess.run([sys.executable, '-I', '-B', str(pkt / 'independent_verify.py')],
                               cwd=td, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
            self.assertIn('PASS', p.stdout)

    def test_independent_tampered_json_fails(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'artifacts/node/94').mkdir(parents=True)
            (td / 'artifacts/node/94/hl-node').symlink_to(bv.TARGET.resolve())
            pkt = td / 'research/work-items/RE-005-bincode-slow-widths'
            pkt.mkdir(parents=True)
            js = json.loads((PACKET / 'slow-sites.json').read_text())
            js['reader_call_counts']['0x466d980'] = 99
            (pkt / 'slow-sites.json').write_text(json.dumps(js))
            (pkt / 'independent_verify.py').write_bytes((PACKET / 'independent_verify.py').read_bytes())
            p = subprocess.run([sys.executable, '-I', '-B', str(pkt / 'independent_verify.py')],
                               cwd=td, capture_output=True, text=True)
            self.assertEqual(p.returncode, 1)
            self.assertIn('FAIL', p.stdout)


class TestGnu(unittest.TestCase):
    @requires_gnu
    def test_anchor_vas_are_instruction_starts(self):
        ranges = [
            (0x466bc10, 0x466bd03, result()['u32_slice_decoder']['anchors']),
            (0x466bd10, 0x466bdf5, result()['u64_slice_slow_branch']['anchors']),
            (0x466d850, 0x466d975, result()['readers'][0]['anchors']),
            (0x466d980, 0x466dabc, result()['readers'][1]['anchors']),
            (0x466dac0, 0x466dace, result()['error_builder']['anchors']),
        ]
        misses = []
        for lo, hi, anchors in ranges:
            starts = objdump_starts(lo, hi)
            for a in anchors:
                va = int(a['va'], 16)
                if va not in starts:
                    misses.append(va)
        self.assertEqual(misses, [])

    @requires_gnu
    def test_cmp_fb_sites_equal_full_text_disassembly(self):
        secs = bv.sections(data())
        tx = secs['.text']
        out = subprocess.run([gnu_objdump(), '-d', '-M', 'intel', '--no-show-raw-insn',
                              f'--start-address={tx["addr"]:#x}',
                              f'--stop-address={tx["addr"] + tx["size"]:#x}', str(bv.TARGET)],
                             check=True, capture_output=True, text=True).stdout
        got = [int(m.group(1), 16) for m in
               re.finditer(r'^\s+([0-9a-f]+):\tcmp +[^,]+,0xfb$', out, re.M)]
        self.assertEqual(len(got), 35)
        self.assertEqual(got, [va for va, _ in sv.CMP_FB_SITES])
        c2 = {int(m.group(1), 16) for m in
              re.finditer(r'^\s+([0-9a-f]+):\tcmp +[^,]+,0x2$', out, re.M)}
        rows = result()['u16_marker_scan']['sites']
        for row in rows:
            self.assertTrue({int(x, 16) for x in row['cmp2_sites_in_window']} <= c2, row['va'])

    @requires_gnu
    def test_chain_id_fn_reads_no_buffer(self):
        out = subprocess.run([gnu_objdump(), '-d', '-M', 'intel', '--no-show-raw-insn',
                              '--start-address=0x1346860', '--stop-address=0x1346daf', str(bv.TARGET)],
                             check=True, capture_output=True, text=True).stdout
        insns = [l.split('\t', 1)[1] for l in out.splitlines() if re.match(r'\s+[0-9a-f]+:\t', l)]
        mem = [i for i in insns if '[' in i and 'rip' not in i
               and 'rdx+rcx*4' not in i and not i.startswith('lea ')]
        self.assertEqual(mem, [])
        starts = objdump_starts(0x1346860, 0x1346daf)
        for a in result()['u16_marker_scan']['hit_characterisation']['anchors']:
            self.assertIn(int(a['va'], 16), starts)

    @requires_gnu
    def test_off_by_one_rejected(self):
        # Control: an anchor VA + 1 is not an instruction start.
        starts = objdump_starts(0x466d980, 0x466dabc)
        self.assertIn(0x466d9a0, starts)
        self.assertNotIn(0x466d9a1, starts)


if __name__ == '__main__':
    unittest.main()
