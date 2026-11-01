"""RE-014 follow-on: static target binding and synthetic trace checks only.

The captured programs are read as inert bytes. No node code is executed or emulated.
"""

import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from node115_field_adapter_drift import Image, selected_frame  # noqa: E402

VECTORS = ROOT / 'research/work-items/RE-014-node115-padadapter-semantic-comparison/VECTORS.json'
TARGETS = {
    94: (91774280, '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
         0x157d000, 622, 'd62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4',
         0x20a058),
    115: (105896032, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301',
          0x1686bd0, 630, 'fc968173616031f08d0a0e77dedca4e6cc4b81ddd1f7cb57e74b10cfae20cb2d',
          0x45a128),
}

# Complete individual instructions/operands at the control and data sites used
# by the packet. This is a below-identity check; full body SHA binds the rest.
SITES = {
    94: {0x157d025: '48bb0001010101010101', 0x157d0e6: '4883f90f',
         0x157d100: '803c300a', 0x157d120: '4c8d5807',
         0x157d124: '4983e3f8', 0x157d128: '4929c3',
         0x157d140: '4e8b441ff8', 0x157d154: '4e8b041f',
         0x157d16a: '4d39ea', 0x157d16d: '7541',
         0x157d16f: '4983c310',
         0x157d1c0: '803c300a',
         0x157d1d0: '4e8d243e', 0x157d069: '4a8d3407',
         0x157d074: '8801', 0x157d076: '488b7db8',
         0x157d07a: '4c89ea',
         0x157d07d: '488b45c0', 0x157d081: 'ff5018', 0x157d087: '84c0',
         0x157d09a: '8b45cc', 0x157d09d: '0f85ba010000',
         0x157d21d: '803800', 0x157d222: 'ba04000000',
         0x157d22b: '488d3526cec8fe', 0x157d232: '488b45c0',
         0x157d23a: 'ff5018',
         0x157d245: '84c07514'},
    115: {0x1686cfb: '49bd0001010101010101', 0x1686cb6: '4883f90f',
          0x1686cd0: '803c300a', 0x1686cf0: '4c8d5807',
          0x1686cf4: '4983e3f8', 0x1686cf8: '4929c3',
          0x1686d20: '4e8b441ff8', 0x1686d34: '4e8b041f',
          0x1686d4a: '4939da', 0x1686d4d: '7541',
          0x1686d4f: '4983c310',
          0x1686da0: '803c300a',
          0x1686db0: '4e8d2c36', 0x1686c3b: '4901ff',
          0x1686c42: '8801', 0x1686c44: '488b7db8',
          0x1686c48: '4c89fe', 0x1686c4b: '4889da',
          0x1686c4e: '488b45c0', 0x1686c52: 'ff5018',
          0x1686c58: '84c0',
          0x1686c6b: '8b45cc', 0x1686c6e: '0f85c1010000',
          0x1686dfd: '803800', 0x1686e02: 'ba04000000',
          0x1686e0b: '488d351633ddfe', 0x1686e12: '488b45c0',
          0x1686e16: 'ff5018',
          0x1686e1d: '84c07514'},
}


def site_matches(body, start, sites):
    return all(body[va - start:va - start + len(bytes.fromhex(encoded))]
               == bytes.fromhex(encoded) for va, encoded in sites.items())


def abstract_first_lf(data, cursor, pointer_mod_8):
    """Scan semantic partitions, not the captured machine instructions."""
    remaining = len(data) - cursor
    if remaining <= 15:
        return data.find(b'\n', cursor)
    prefix = (-(pointer_mod_8 + cursor)) & 7
    end = min(len(data), cursor + prefix)
    found = data.find(b'\n', cursor, end)
    if found >= 0:
        return found
    position = end
    while position + 16 <= len(data):
        found = data.find(b'\n', position, position + 16)
        if found >= 0:
            return found
        position += 16
    return data.find(b'\n', position)


def abstract_trace(data, initial, fail_at, pointer_mod_8, mutations):
    """Check the documented callback contract, independent of machine execution."""
    cursor, state, calls, entry_flags = 0, initial, [], []
    while cursor < len(data):
        found = abstract_first_lf(data, cursor, pointer_mod_8)
        end = len(data) if found < 0 else found + 1
        if state:
            calls.append('indent')
            entry_flags.append(state)
            state = mutations.get(str(len(calls) - 1), state)
            if fail_at == len(calls) - 1:
                return calls, state, 1, entry_flags
        state = int(data[end - 1] == 10)
        calls.append(f'payload:{cursor}:{end}')
        entry_flags.append(state)
        state = mutations.get(str(len(calls) - 1), state)
        if fail_at == len(calls) - 1:
            return calls, state, 1, entry_flags
        cursor = end
    return calls, state, 0, entry_flags


class PadAdapterSemanticComparison(unittest.TestCase):
    def test_full_identity_selected_unwind_and_sites(self):
        for number, (size, digest, start, length, body_digest, literal) in TARGETS.items():
            with self.subTest(number=number):
                data = (ROOT / f'artifacts/node/{number}/hl-node').read_bytes()
                self.assertEqual(len(data), size)
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                image = Image(data, 3)
                frame = selected_frame(image, start, length)
                self.assertEqual(frame['body_sha256'], body_digest)
                self.assertEqual(frame['end'], start + length)
                self.assertEqual(image.virtual(literal, 4)[0], b'    ')
                body = image.virtual(start, length, code=True)[0]
                self.assertTrue(site_matches(body, start, SITES[number]))

    def test_changed_semantic_sites_reject_below_full_identity(self):
        for number, (_, _, start, length, _, _) in TARGETS.items():
            data = (ROOT / f'artifacts/node/{number}/hl-node').read_bytes()
            body = Image(data, 3).virtual(start, length, code=True)[0]
            for site in SITES[number]:
                with self.subTest(number=number, site=hex(site)):
                    changed = bytearray(body)
                    changed[site - start] ^= 1
                    self.assertFalse(site_matches(changed, start, SITES[number]))

    def test_frozen_synthetic_callback_traces(self):
        vectors = json.loads(VECTORS.read_text())
        for case in vectors['cases']:
            data = bytearray(b'a' * case['length'])
            for index in case['lf']:
                data[index] = 10
            for index in case.get('high', []):
                data[index] = 0x80 if index % 2 else 0xff
            expected = (case['calls'], case['final'], case['return'])
            for alignment in vectors['alignments']:
                with self.subTest(case=case['name'], pointer_mod_8=alignment):
                    # Alignment labels bind the documented scan-boundary matrix;
                    # the abstract scan partitions do vary with alignment.
                    actual = abstract_trace(bytes(data), case['initial'], case['fail_at'],
                                            alignment, case.get('mutations', {}))
                    self.assertEqual(actual[:3], expected)
                    if 'entry_flags' in case:
                        self.assertEqual(actual[3], case['entry_flags'])


if __name__ == '__main__':
    unittest.main()
