"""Actual Node115 byte/RELA corruption controls; no captured execution."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import node115_cli_command_factory as factory
from elf_index import sections

class Node115FactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.blob = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
        cls.spec = json.loads((factory.PACKET / 'spec.json').read_text())
        cls.secs = sections(cls.blob)
        if hashlib.sha256(cls.blob).hexdigest() != factory.TARGET:
            raise ValueError('Actual115 required, no synthetic substitute or skip')

    def offset(self, va):
        s = next(s for s in self.secs if s['type'] != 8 and s['address'] <= va < s['address'] + s['size'])
        return s['offset'] + va - s['address']

    def changed(self, va, mask=1):
        value = bytearray(self.blob)
        value[self.offset(va)] ^= mask
        return value

    def test_actual_producer_and_non_global_required_names(self):
        record = factory.collect(self.blob, self.spec)
        self.assertEqual((len(record['commands']), len(record['arguments'])), (14, 24))
        self.assertEqual(sum(d['requiredNameAppendBit'] for d in record['arguments']), 14)
        self.assertFalse(any(d['globalBit'] for d in record['arguments']))
        profile = [d for d in record['arguments'] if d['command'] == 'change-validator-profile']
        self.assertEqual([d['argument'] for d in profile], ['abci-state-fln', 'node-ip', 'name', 'description', 'unjailed', 'disable-delegations', 'commission-bps', 'signer'])
        self.assertEqual([d['rawFlags'] for d in profile], ['0x425','0x424','0x424','0x424','0x404','0x424','0x424','0x424'])

    def test_registration_displacement_control(self):
        d = self.spec['arguments'][0]
        mutated = self.changed(int(d['registration'],16)+2)
        with self.assertRaisesRegex(ValueError, 'registration slot'):
            factory.derive_declarations(mutated, self.secs, self.spec)

    def test_literal_pointer_control(self):
        d = self.spec['arguments'][0]
        mutated = self.changed(int(d['pointerDefinition'],16)+3)
        with self.assertRaisesRegex(ValueError, 'declaration name'):
            factory.derive_declarations(mutated, self.secs, self.spec)

    def test_literal_length_control(self):
        d = self.spec['arguments'][0]
        w = self.spec['witnesses'][d['lengthStore']]
        mutated = self.changed(int(w['va'],16)+len(bytes.fromhex(w['bytes']))-4)
        with self.assertRaisesRegex(ValueError, 'declaration name'):
            factory.derive_declarations(mutated, self.secs, self.spec)

    def test_required_flag_control(self):
        d = self.spec['arguments'][0]
        w = self.spec['witnesses'][d['settings']['site']]
        mutated = self.changed(int(w['va'],16)+len(bytes.fromhex(w['bytes']))-4)
        with self.assertRaisesRegex(ValueError, 'declaration flags'):
            factory.derive_declarations(mutated, self.secs, self.spec)

    def test_vtable_header_control(self):
        v = self.spec['validators'][0]['validatorCandidates'][0]
        with self.assertRaisesRegex(ValueError, 'vtable header'):
            factory.derive_validators(self.changed(int(v['vtable'],16)), self.secs, self.spec)

    def test_actual_rela_target_control(self):
        w = self.spec['validators'][0]['validatorCandidates'][0]['writers'][0]
        value = bytearray(self.blob)
        offset = next(sec['offset'] + n for sec in self.secs if sec['type'] == 4
                      for n in range(0,sec['size'],24)
                      if struct.unpack_from('<Q',self.blob,sec['offset']+n)[0] == int(w['slot'],16))
        value[offset+16] ^= 1
        with self.assertRaisesRegex(ValueError, 'vtable RELA writer'):
            factory.derive_validators(value, self.secs, self.spec)

    def test_duplicate_actual_rela_writer_control(self):
        w = self.spec['validators'][0]['validatorCandidates'][0]['writers'][0]
        value = bytearray(self.blob)
        sec = next(s for s in self.secs if s['type'] == 4)
        struct.pack_into('<QQq',value,sec['offset'],int(w['slot'],16),8,int(w['addend'],16))
        with self.assertRaisesRegex(ValueError, 'vtable RELA writer'):
            factory.derive_validators(value, self.secs, self.spec)

    def test_actual_fde_extent_control(self):
        f = self.spec['functions'][0]
        with self.assertRaises(ValueError):
            factory.derive_functions(self.changed(int(f['fde'],16)+12), self.secs, self.spec)

    def test_actual_lsda_encoding_control(self):
        f = self.spec['functions'][1]
        table = factory.lsda_table(self.blob, self.secs, f)
        with self.assertRaisesRegex(ValueError, 'LSDA call-site encoding'):
            factory.lsda_table(self.changed(int(table['callSiteEncodingVA'],16)), self.secs, f)

    def test_validator_body_control_and_public_digest_gate(self):
        changed = self.changed(0x565454a)
        with self.assertRaisesRegex(ValueError, 'body identity'):
            factory.derive_functions(changed, self.secs, self.spec)
        with self.assertRaisesRegex(ValueError, 'target identity'):
            factory.collect(changed, self.spec)

if __name__ == '__main__':
    unittest.main()
