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
TARGETS = {115: (105896032, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301', 23620560, 630, 'fc968173616031f08d0a0e77dedca4e6cc4b81ddd1f7cb57e74b10cfae20cb2d', 4563240)}

# Complete individual instructions/operands at the control and data sites used
# by the packet. This is a below-identity check; full body SHA binds the rest.
SITES = {115: {23620859: '49bd0001010101010101', 23620790: '4883f90f', 23620816: '803c300a', 23620848: '4c8d5807', 23620852: '4983e3f8', 23620856: '4929c3', 23620896: '4e8b441ff8', 23620916: '4e8b041f', 23620938: '4939da', 23620941: '7541', 23620943: '4983c310', 23621024: '803c300a', 23621040: '4e8d2c36', 23620667: '4901ff', 23620674: '8801', 23620676: '488b7db8', 23620680: '4c89fe', 23620683: '4889da', 23620686: '488b45c0', 23620690: 'ff5018', 23620696: '84c0', 23620715: '8b45cc', 23620718: '0f85c1010000', 23621117: '803800', 23621122: 'ba04000000', 23621131: '488d351633ddfe', 23621138: '488b45c0', 23621142: 'ff5018', 23621149: '84c07514'}}


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
