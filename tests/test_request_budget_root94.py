"""Static negative controls for the request-budget root packet."""
import hashlib
import itertools
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import request_budget_root94 as codec
from elf_index import sections


class RequestBudgetRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = codec.BINARY.read_bytes()
        cls.sections = sections(cls.data)
        cls.result = codec.collect(cls.data)

    def test_artifact_and_selected_functions(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),codec.DIGEST)
        self.assertEqual(len(self.result['functions']),10)
        self.assertEqual(self.result['functions'][0]['start'],'0x20296f0')
        self.assertEqual(self.result['functions'][-1]['end_exclusive'],'0x28e7a0f')
        self.assertEqual(len(self.result['calls']),25)
        self.assertEqual(len(self.result['branches']),50)

    def test_capture_closure_and_sort_binding(self):
        binding = self.result['binding']
        self.assertEqual(binding['state_offset'],0x740)
        self.assertEqual(binding['vtable'],'0x56bdc38')
        self.assertEqual(binding['closure'],'0x2819ad0')
        self.assertEqual(binding['closure_call'],'0x2819b20')
        self.assertEqual(binding['config'],'0x1000400')
        self.assertEqual(binding['extra_flag'],0)
        sort = self.result['sort']
        self.assertEqual((sort['small_count_exclusive'],sort['compare_bytes'],sort['entry_pointer_stride']), (21,20,16))
        self.assertEqual(sort['symbol']['symbol'],'memcmp')

    def test_field_layout(self):
        fields = self.result['fields']
        self.assertEqual([f['name'] for f in fields],['ln','R','C','P','t','no','f','r','a'])
        self.assertEqual([f['value_offset'] for f in fields],
                         ['0x0','0x8','0x10','0x18','0x30','0x20','0x3d','0x28','0x3c'])
        self.assertEqual([f['writer'] for f in fields],['unsigned','unsigned','signed','signed',
                         'datetime helper','unsigned','boolean','unsigned','enum'])
        self.assertEqual(self.result['epoch']['day_argument'],719163)

    def test_reader_classifier_exhaustive_and_duplicate_dispatch(self):
        fields = self.result['fields']
        single,two,rows,dispatch = codec.reader_tables(self.data,self.sections,fields)
        known = {item['name'].encode():i for i,item in enumerate(fields)}
        for x in range(256):
            key = bytes([x])
            self.assertEqual(codec.classify_field(key,single,two),known.get(key,9))
        for x in range(65536):
            key = x.to_bytes(2,'little')
            self.assertEqual(codec.classify_field(key,single,two),known.get(key,9))
        for key in (b'',b'abc',b'longer'):
            self.assertEqual(codec.classify_field(key,single,two),9)
        self.assertEqual(len(rows),256)
        self.assertEqual([row['field'] for row in dispatch[:-1]],[x['name'] for x in fields])
        self.assertTrue(all(row['duplicate_target'] != '-' for row in dispatch[:-1]))
        self.assertEqual(dispatch[-1]['field'],'<unknown>')
        self.assertEqual(dispatch[-1]['helper'],'0x19682d0')
        bad = bytearray(self.data)
        site = 0x3ecc48 + (ord('R') - 0x43) * 4
        section = next(s for s in self.sections if s['type'] != 8 and
                       s['address'] <= site < s['address']+s['size'])
        offset = section['offset']+site-section['address']
        bad[offset:offset+4] = bytes(4)
        with self.assertRaisesRegex(ValueError,'classifier jump'):
            codec.reader_tables(bad,self.sections,fields)

    def test_small_named_examples(self):
        examples = self.result['examples']
        self.assertEqual(examples['all_default_hex'],'80')
        self.assertEqual(examples['R_1_r_2_hex'],'82a15201a17202')

    def test_every_presence_mask_and_invalid_mask(self):
        names = [x['name'] for x in self.result['fields']]
        rows = self.result['masks']
        self.assertEqual(len(rows),512)
        for row in rows:
            mask = row['mask']
            expected = [name for i,name in enumerate(names) if (mask >> i) & 1]
            self.assertEqual(codec.presence(mask,names),expected)
            self.assertEqual(row['fields'],','.join(expected))
            self.assertEqual(row['count'],len(expected))
            self.assertEqual(row['named_header'],hex(0x80+len(expected)))
        self.assertEqual(rows[0]['named_header'],'0x80')
        self.assertEqual(rows[-1]['named_header'],'0x89')
        for bad in (-1,512,1.5,'1'):
            with self.assertRaises(ValueError):
                codec.presence(bad,names)

    def test_enum_targets_and_corrupt_table(self):
        self.assertEqual([e['value'] for e in self.result['enums']],['e','i','d','u','p'])
        self.assertEqual(self.result['enum_tail_jump']['target'],'0x28e7990')
        bad = bytearray(self.data)
        s = next(s for s in self.sections if s['type'] != 8 and
                 s['address'] <= 0x3f5a20 < s['address']+s['size'])
        bad[s['offset']+0x3f5a20-s['address']:s['offset']+0x3f5a20-s['address']+4] = bytes(4)
        with self.assertRaisesRegex(ValueError,'enum jump'):
            codec.enum_rows(bad,self.sections)

    def test_small_sort_permutations_and_bounds(self):
        keys = [bytes([n])+bytes(19) for n in (0,1,127,128,255)]
        for order in itertools.permutations(keys):
            self.assertEqual(codec.small_sort(order,21,20),sorted(keys))
        self.assertEqual(codec.small_sort([],21,20),[])
        edge = [bytes([n])+bytes(19) for n in reversed(range(20))]
        self.assertEqual(codec.small_sort(edge,21,20),sorted(edge))
        self.assertEqual(codec.small_sort([keys[1],keys[1],keys[0]],21,20),
                         [keys[0],keys[1],keys[1]])
        with self.assertRaises(ValueError):
            codec.small_sort([keys[0]]*21,21,20)
        with self.assertRaises(ValueError):
            codec.small_sort([b'bad'],21,20)

    def test_branches(self):
        branches = {r['label']:r for r in self.result['branches']}
        for label,target in (
            ('small_sort_limit','0x1fe88d4'),('skip_ln','0x275cfbb'),
            ('skip_R','0x275d004'),('skip_C','0x275d04d'),
            ('skip_P','0x275d09b'),('skip_t','0x275d123'),
            ('skip_no','0x275d16c'),('skip_f','0x275d1ce'),
            ('skip_r','0x275d218'),('skip_a','0x275d23f'),
            ('epoch_unavailable','0x275d35f')):
            self.assertEqual(branches[label]['target'],target)

    def test_hash_and_selected_body_corruption(self):
        bad = bytearray(self.data)
        bad[0] ^= 1
        with self.assertRaisesRegex(ValueError,'digest mismatch'):
            codec.generate(bad)
        with self.assertRaisesRegex(ValueError,'digest mismatch'):
            codec.check_digest(self.data,'0'*64)
        bad[0] ^= 1
        s = next(s for s in self.sections if s['type'] != 8 and
                 s['address'] <= 0x2029778 < s['address']+s['size'])
        offset = s['offset']+0x2029778-s['address']
        bad[offset+1] ^= 1
        with self.assertRaisesRegex(ValueError,'destination changed'):
            codec.checked_call(bad,self.sections,0x2029778,0x1e4a430)
        with self.assertRaisesRegex(ValueError,'selected body mismatch'):
            codec.collect(bad,codec.digest(bad))

    def test_file_mapping_and_bad_opcodes(self):
        fake = [{'type':8,'size':6,'address':0x1000,'offset':0}]
        with self.assertRaises(ValueError):
            codec.va_bytes(b'abcdef',fake,0x1000,1)
        fake[0]['type']=1
        for data,secs,va,size in ((b'abc',fake,0x1000,6),
                                   (b'abcdef',fake,0x1005,2),
                                   (b'abcdef',fake+fake,0x1000,1),
                                   (b'abcdef',fake,0x1000,0)):
            with self.assertRaises(ValueError):
                codec.va_bytes(data,secs,va,size)
        with self.assertRaises(ValueError):
            codec.direct_call(b'\x90'*6,fake,0x1000)
        with self.assertRaises(ValueError):
            codec.branch(b'\x90'*6,fake,0x1000)


if __name__ == '__main__':
    unittest.main()
