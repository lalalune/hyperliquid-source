"""Static corruption and boundary controls for the revision-9 call corridor."""
import hashlib
from pathlib import Path
import unittest

from tools import evm_read_precompile94 as subject


class ReadPrecompile94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.image = subject.Image(cls.data)
        cls.files = subject.generate(cls.image)
        cls.packet = subject.ROOT / 'research/work-items/RE-021-evm-read-revision9-94'
        cls.decoded = {}
        for start in subject.FUNCTIONS:
            fde, raw, rows = subject.decoded_body(cls.image, start)
            cls.decoded[start] = (fde, {r['va']: r for r in rows}, rows)

    def test_retained_evidence_regenerates_byte_for_byte(self):
        self.assertEqual(set(self.files), {p.name for p in self.packet.iterdir()
                                         if p.suffix in ('.json', '.tsv')})
        for name, actual in self.files.items():
            with self.subTest(name=name):
                self.assertEqual(actual, (self.packet / name).read_bytes())

    def test_full_target_digest_rejects_corruption(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), subject.DIGEST)
        bad = bytearray(self.data)
        bad[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):
            subject.Image(bad)

    def test_selected_fde_ranges_match_index_and_pins(self):
        self.assertEqual(len(self.decoded), 12)
        for start, (fde, _, _) in self.decoded.items():
            with self.subTest(start=hex(start)):
                self.assertEqual(self.image.index[start][0]['fde'], fde['fde'])
                size, wanted = subject.BODY_PINS[start]
                self.assertEqual(fde['end'] - start, size)
                self.assertEqual(hashlib.sha256(self.image.read(start, size)).hexdigest(), wanted)
        self.assertEqual(self.decoded[0x2789db0][0]['end'], 0x278b402)

    def test_every_semantic_window_rejects_first_and_last_byte_corruption(self):
        image = self.image
        image.data = bytearray(self.data)
        try:
            for start, end, label in subject.WINDOWS:
                owner = next(x for x in subject.FUNCTIONS if x <= start < end <= image.fdes[x][0]['end'])
                for site in (start, end-1):
                    off = image.offset(site, 1)
                    image.data[off] ^= 1
                    with self.subTest(label=label, site=hex(site)):
                        with self.assertRaisesRegex(ValueError, 'body pin'):
                            image.body(owner)
                    image.data[off] ^= 1
        finally:
            image.data = self.data

    def test_bad_fde_length_and_missing_index_are_rejected(self):
        owner = 0x2789db0
        fde = self.image.fdes[owner][0]
        end = fde['end']
        try:
            fde['end'] += 1
            with self.assertRaises(ValueError):
                self.image.body(owner)
        finally:
            fde['end'] = end
        idx = self.image.index.pop(owner)
        try:
            with self.assertRaisesRegex(ValueError, 'index'):
                self.image.body(owner)
        finally:
            self.image.index[owner] = idx

    def test_exception_table_rejects_changed_header(self):
        image = self.image
        owner = 0x2789db0
        fde, _, rows = self.decoded[owner]
        image.data = bytearray(self.data)
        try:
            at = image.offset(fde['lsda'], 1)
            self.assertEqual(image.data[at], 0xff)
            image.data[at] = 0
            with self.assertRaisesRegex(ValueError, 'landing-pad base'):
                subject.exception_sites(image, owner, rows)
        finally:
            image.data = self.data

    def test_reject_nobits_unmapped_crossing_and_ambiguous_ranges(self):
        image = self.image
        for va, size in ((-1,1), (0,0), (1<<63,1)):
            with self.subTest(va=va,size=size), self.assertRaises(ValueError):
                image.offset(va,size)
        text = image.section('.text')
        with self.assertRaises(ValueError):
            image.offset(text['address'] + text['size']-1,2)
        fake = {'name':'test_nobits', 'type':8, 'flags':2, 'address':1<<48, 'size':64, 'offset':0}
        image.secs.append(fake)
        try:
            with self.assertRaises(ValueError):
                image.offset(1<<48,1)
        finally:
            image.secs.pop()
        duplicate = dict(text)
        image.secs.append(duplicate)
        try:
            with self.assertRaises(ValueError):
                image.offset(0x2789db0, 1)
        finally:
            image.secs.pop()

    def test_revision_switch_map_and_default(self):
        fde, _, rows = self.decoded[0x2461390]
        cases = subject.cases(self.image, rows, fde['end'])
        self.assertEqual([r['canonical'] for r in cases[:20]],
                         [0,0,2,2,4,5,6,8,8,9,9,11,12,12,12,15,16,17,18,19])
        for n in (9,10):
            self.assertEqual(cases[n]['entry_va'], 0x2461a4f)
            self.assertEqual(cases[n]['constructor'], 0x2798a10)
        self.assertEqual((cases[20]['raw'],cases[20]['canonical']), ('20..255',255))

    def test_revision_table_corruption_rejected_even_for_valid_other_target(self):
        image = self.image
        image.data = bytearray(self.data)
        try:
            raw9 = image.offset(subject.TABLE_VA+9*4,4)
            raw8 = image.offset(subject.TABLE_VA+8*4,4)
            image.data[raw9:raw9+4] = image.data[raw8:raw8+4]
            fde, _, rows = self.decoded[0x2461390]
            with self.assertRaisesRegex(ValueError, 'revision table pin'):
                subject.cases(image, rows, fde['end'])
        finally:
            image.data = self.data

    def test_revision_normal_path_rejects_inserted_jump(self):
        fde, _, original = self.decoded[0x2461390]
        rows = [dict(row) for row in original]
        branch = next(row for row in rows if row['va'] == 0x2461ab7)
        branch['kind'] = 'jump'
        with self.assertRaisesRegex(ValueError, 'nonlinear revision case'):
            subject.cases(self.image, rows, fde['end'])

    def test_allocation_checks_and_corrupt_null_branches(self):
        rows = {start: [dict(row) for row in decoded[2]]
                for start, decoded in self.decoded.items()}
        checks = subject.allocation_checks(rows)
        self.assertEqual(len(checks), 21)
        self.assertEqual([sum(row[0] == hex(owner) for row in checks)
                          for owner in (0x2461390, 0x2790e20, 0x2798a10)], [6, 4, 11])
        self.assertTrue(all(row[3] == 16 for row in checks))
        selected = next(i for i, row in enumerate(rows[0x2790e20])
                        if row['va'] == 0x2790e3c)
        test = rows[0x2790e20][selected]
        test['bytes'] = '909090'
        with self.assertRaisesRegex(ValueError, 'allocation null check'):
            subject.allocation_checks(rows)
        test['bytes'] = '4885c0'
        branch = rows[0x2790e20][selected+1]
        branch['target'] = 0x2790f39
        with self.assertRaisesRegex(ValueError, 'allocation null check'):
            subject.allocation_checks(rows)

    def test_selected_call_and_vtable_bindings(self):
        sites = ((0x2446ac0,0x2446cbb,0x2461390), (0x2446ac0,0x24472c2,0x25134e0),
                 (0x2461390,0x2461aa4,0x2790e20), (0x2461390,0x2461c68,0x2798a10),
                 (0x25134e0,0x251357b,0x25b6b20), (0x276d490,0x276d4a0,0x2789db0))
        for owner, site, target in sites:
            with self.subTest(site=hex(site)):
                row = self.decoded[owner][1][site]
                self.assertEqual((row['kind'],row['target']), ('call',target))
        self.assertEqual(self.decoded[0x2798a10][1][0x2798ccc]['rip'], 0x56c1270)
        self.assertEqual(self.image.relocation(0x56c1298)[1], 0x276d490)
        self.assertEqual(self.image.relocation(0x56bece8)[1], 0x276e2d0)
        self.assertEqual(self.image.relocation(0x5774e30)[1], 0x4ea2df0)

    def test_code_hydration_hash_chunks_and_branches(self):
        rows = self.decoded[0x2788500][1]
        self.assertEqual(rows[0x2788535]['target'], 0x278869b)
        self.assertEqual(rows[0x2788547]['rip'], 0x204be0)
        self.assertEqual(rows[0x278854f]['rip'], 0x206160)
        self.assertEqual(rows[0x2788564]['target'], 0x2788603)
        self.assertEqual(rows[0x278859a]['target'], 0x37d13c0)
        self.assertEqual(rows[0x27885a3]['target'], 0x278863f)
        parts = subject.code_hash_constants(self.image)
        self.assertEqual(''.join(row[4] for row in parts), subject.CODE_HASH_HEX)
        image = self.image
        image.data = bytearray(self.data)
        try:
            for va in (0x206160, 0x204be0):
                at = image.offset(va, 1)
                image.data[at] ^= 1
                with self.subTest(va=hex(va)), self.assertRaisesRegex(ValueError, 'code hash constant'):
                    subject.code_hash_constants(image)
                image.data[at] ^= 1
        finally:
            image.data = self.data

    def test_postexecution_callbacks_and_copy_symbol_corruption(self):
        self.assertEqual(self.decoded[0x2461390][1][0x2461c3a]['rip'], 0x56a6ff8)
        self.assertEqual(self.decoded[0x2461390][1][0x2461c51]['rip'], 0x56a7028)
        self.assertEqual(self.image.relocation(0x56a7020)[1], 0x244f550)
        self.assertEqual(self.image.relocation(0x56a7050)[1], 0x244f570)
        body = self.decoded[0x244f550][1]
        self.assertEqual(body[0x244f554]['bytes'], 'ba90000000')
        self.assertEqual(body[0x244f559]['bytes'], '4889ce')
        self.assertEqual(body[0x244f55c]['rip'], 0x576dfe0)
        symbol = subject.copy_symbol_relocation(self.image)
        self.assertEqual((symbol[2],symbol[3],symbol[-1]), (6,6,'memcpy'))
        image = self.image
        slot = 0x576dfe0
        original = image.relocs[slot]
        try:
            image.relocs[slot] = (original[0]+1,original[1],original[2])
            with self.assertRaisesRegex(ValueError, 'relocation type'):
                subject.copy_symbol_relocation(image)
        finally:
            image.relocs[slot] = original
        image.data = bytearray(self.data)
        try:
            image.data[int(symbol[-2],16)] ^= 1
            with self.assertRaisesRegex(ValueError, 'symbol changed'):
                subject.copy_symbol_relocation(image)
        finally:
            image.data = self.data

    def test_wrong_relocation_type_and_addend_rejected(self):
        img = self.image
        slot = 0x56c1298
        old = img.relocs[slot]
        try:
            img.relocs[slot] = (1,old[1],old[2])
            with self.assertRaisesRegex(ValueError, 'RELATIVE'):
                img.relocation(slot)
            img.relocs[slot] = (8,old[1]+1,old[2])
            with self.assertRaisesRegex(ValueError, 'relocation mismatch'):
                subject.generate(img)
            del img.relocs[slot]
            with self.assertRaisesRegex(ValueError, 'missing relocation'):
                img.relocation(slot)
        finally:
            img.relocs[slot] = old

    def test_decoder_rejects_truncated_and_unsupported_shapes(self):
        for raw in (b'\xe8\x00', b'\x0f', b'\x0f\x0a', b'\x48\x8b'):
            with self.subTest(raw=raw.hex()), self.assertRaises(ValueError):
                subject.walk(raw)

    def test_lookup_guards_match_retained_byte_shapes(self):
        body = self.decoded[0x2789db0][1]
        self.assertEqual(body[0x278a7fa]['target'], 0x278a857)
        self.assertEqual(body[0x278a844]['target'], 0x278a92f)
        self.assertEqual(body[0x278a863]['target'], 0x2789f44)
        self.assertEqual(body[0x278a94c]['rip'], 0x5774e30)
        self.assertEqual(body[0x278ade4]['rip'], 0x5774e38)

    def test_lookup_miss_or_scheme_bypass_reloads_account_code(self):
        body = self.decoded[0x2789db0][1]
        self.assertEqual(body[0x278a767]['target'], 0x2789f44)
        self.assertEqual(body[0x278a863]['target'], 0x2789f44)
        self.assertEqual(body[0x2789f79]['target'], 0x2788500)
        self.assertEqual(body[0x2789f88]['target'], 0x278a6d1)
        self.assertEqual(body[0x2789fc2]['target'], 0x278a71c)
        self.assertEqual(body[0x2789fcd]['target'], 0x26b0730)

    def test_outer_error_forwarding_and_builder_sentinel_gate(self):
        executor = self.decoded[0x25134e0][1]
        self.assertEqual(executor[0x2513730]['bytes'], '4883f804')
        self.assertEqual(executor[0x2513734]['target'], 0x251396a)
        self.assertEqual(executor[0x2513742]['target'], 0x2513959)
        self.assertEqual(executor[0x2513965]['target'], 0x251375f)
        self.assertEqual(executor[0x251375f]['bytes'], '48b80200000000000080')
        builder = self.decoded[0x2446ac0][1]
        self.assertEqual(builder[0x244736e]['bytes'], '48b80200000000000080')
        self.assertEqual(builder[0x2447380]['target'], 0x244739e)
        self.assertEqual(builder[0x2447393]['target'], 0x2447548)
        self.assertEqual(builder[0x2447399]['target'], 0x244759c)
        self.assertEqual(builder[0x24475a0]['bytes'], 'c60000')

    def test_synthetic_lookup_rejects_every_single_key_bit_change(self):
        key = bytes(19) + b'\x09'
        controls = bytearray([0xff]*64)
        controls[7] = 0x12
        seed_hash = (0x12 << 57) | 7
        self.assertEqual(subject.probe(bytes(controls), {7:key}, seed_hash, key, 1), 7)
        for bit in range(160):
            changed = bytearray(key)
            changed[bit // 8] ^= 1 << (bit % 8)
            with self.subTest(bit=bit):
                self.assertIsNone(subject.probe(bytes(controls), {7:key}, seed_hash, bytes(changed), 1))

    def test_synthetic_probe_wrap_empty_and_deleted_controls(self):
        key = bytes(19)+b'\x09'
        ctrl = bytearray([0x80]*64)
        ctrl[2] = 0x12
        ctrl[33] = 0xff
        word = (0x12 << 57) | 49
        self.assertEqual(subject.probe(bytes(ctrl), {2:key}, word, key, 1), 2)
        ctrl[49] = 0xff
        self.assertIsNone(subject.probe(bytes(ctrl), {2:key}, word, key, 1))
        self.assertIsNone(subject.probe(bytes(ctrl), {2:key}, word, key, 0))
        with self.assertRaises(ValueError):
            subject.probe(bytes([0x80]*64), {}, word, key, 1)
        with self.assertRaises(ValueError):
            subject.probe(bytes(7), {}, word, key, 1)

    def test_synthetic_hash_seed_and_width_controls(self):
        self.assertEqual(subject.mix_address(bytes(20), 1, 0, 0), 20)
        key = bytes(range(20))
        a,b,c = 0x123456789abcdef0, 0x0fedcba987654321, 0x1122334455667788
        mask = (1 << 64)-1
        words = [int.from_bytes(key[i:i+8], 'little') for i in (0,4,8,12)]
        first = (words[2]^b)*(words[3]^a)
        second = (words[0]^c)*(words[1]^a)
        mixed = ((first>>64)^(first&mask)^(second>>64)^(second&mask)^20)*a
        self.assertEqual(subject.mix_address(key,a,b,c), ((mixed>>64)^(mixed&mask))&mask)
        with self.assertRaises(ValueError):
            subject.mix_address(b'\x09',a,b,c)
        with self.assertRaises(ValueError):
            subject.mix_address(key,-1,b,c)

    def test_result_branch_boundaries_and_binary_sites(self):
        body = self.decoded[0x2789db0][1]
        self.assertEqual(body[0x278ae33]['target'], 0x278ae8b)
        self.assertEqual(body[0x278af7b]['target'], 0x278af99)
        m = (1<<64)-1
        examples = [((1,0,0,0,0),('success',2,0)),
                    ((1,0,0,m,m),('success',2,0)),
                    ((1,0,0,10,11),('rollback',0x53,None)),
                    ((0,1,0,0,0),('fatal',4,None)),
                    ((0,2,1<<63,0,0),('rollback',0x53,None)),
                    ((0,0,(1<<63)-1,0,0),('rollback',0x60,None)),
                    ((0,0,(1<<63)+1,0,0),('rollback',0x60,None))]
        for args, expected in examples:
            with self.subTest(args=args):
                self.assertEqual(subject.result_policy(*args), expected)
        with self.assertRaises(ValueError):
            subject.result_policy(0,0,0,-1,0)


if __name__ == '__main__':
    unittest.main()
