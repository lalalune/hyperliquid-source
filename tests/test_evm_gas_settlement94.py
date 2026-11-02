"""Byte, control-flow and arithmetic controls for the selected #94 path."""
import hashlib
import random
import struct
import unittest
from unittest.mock import patch

from tools import evm_gas_settlement94 as evm


def limbs(value, width):
    mask = (1 << width) - 1
    return [(value >> (i * width)) & mask for i in range(4)]


def pack(values, width):
    return sum(value << (i * width) for i, value in enumerate(values))


def add_limbs(a, b, width):
    mask = (1 << width) - 1
    aa, bb = limbs(a, width), limbs(b, width)
    out, carry = [], 0
    for x, y in zip(aa, bb):
        total = x + y + carry
        out.append(total & mask)
        carry = total >> width
    return pack(out, width), carry


def mul_limbs(price, quantity, width):
    # This is the four-partial-product shape of the selected instruction
    # windows; the returned high carry is intentionally discarded.
    mask = (1 << width) - 1
    p = limbs(price, width)
    q0, q1, q2, q3 = [x * quantity for x in p]
    v1 = (q1 & mask) + (q0 >> width)
    v2 = (q2 & mask) + (q1 >> width) + (v1 >> width)
    v3 = (q3 & mask) + (q2 >> width) + (v2 >> width)
    return pack([q0 & mask, v1 & mask, v2 & mask, v3 & mask], width)


def floor_sub_limbs(a, b, width):
    mask = (1 << width) - 1
    aa, bb = limbs(a, width), limbs(b, width)
    out, borrow = [], 0
    for x, y in zip(aa, bb):
        value = x - y - borrow
        borrow = int(value < 0)
        out.append(value & mask)
    return 0 if borrow else pack(out, width)


def quantity_sub(a, b, c):
    if a < b:
        raise OverflowError('first subtraction')
    if a - b < c:
        raise OverflowError('second subtraction')
    return a - b - c


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evm.BINARY.read_bytes()
        cls.records = evm.rows_from_image(cls.data)
        cls.image = evm.Image(cls.data)

    def test_pinned_ranges_and_complete_windows(self):
        self.assertEqual({k: len(v[1]) for k, v in self.records.items()},
                         {'functions.tsv': 4, 'unwind.tsv': 4, 'windows.tsv': 14, 'anchors.tsv': 26, 'branches.tsv': 16,
                          'calls.tsv': 4, 'indirect-calls.tsv': 4, 'adapter-slots.tsv': 15,
                          'descriptors.tsv': 15, 'locations.tsv': 4})
        for row in self.records['functions.tsv'][1]:
            self.assertEqual(len(bytes.fromhex(row[-1])), row[-3])
        for row in self.records['unwind.tsv'][1]:
            self.assertEqual(len(bytes.fromhex(row[-1])), row[-2])
        for row in self.records['windows.tsv'][1]:
            raw = bytes.fromhex(row[-1])
            self.assertEqual(len(raw), row[-3])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row[-2])

    def test_digest_negative_control(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            evm.verify_digest(b'not the selected image')

    def test_corrupted_instruction_is_rejected_even_if_input_digest_is_rebound(self):
        altered = bytearray(self.data)
        offset = self.image.offset(0x24689ac, 1)
        altered[offset] ^= 1
        with patch.object(evm, 'TARGET', hashlib.sha256(altered).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                evm.rows_from_image(altered)

    def test_semantic_anchor_corruption_is_rejected(self):
        altered = bytearray(self.data)
        offset = self.image.offset(0x24689b2, 1)
        altered[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'anchor mismatch'):
            evm.match_anchor(evm.Image(altered), 0x24689b2, '492b7e10')

    def test_changed_fde_start_is_rejected(self):
        altered = bytearray(self.data)
        fde_va = int(self.records['unwind.tsv'][1][0][2], 16)
        altered[self.image.offset(fde_va + 8, 1)] ^= 1
        with patch.object(evm, 'TARGET', hashlib.sha256(altered).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'FDE'):
                evm.rows_from_image(altered)

    def test_descriptor_prefix_corruption_is_rejected(self):
        altered = bytearray(self.data)
        offset = self.image.offset(0x56a7148 + 0x10, 1)
        altered[offset] ^= 1
        with patch.object(evm, 'TARGET', hashlib.sha256(altered).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'descriptor prefix'):
                evm.rows_from_image(altered)

    def test_relocation_type_corruption_is_rejected(self):
        altered = bytearray(self.data)
        rela = next(section for section in self.image.sections if section['name'] == '.rela.dyn')
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            if struct.unpack_from('<Q', altered, pos)[0] == 0x56a7170:
                altered[pos + 8] = 0
                break
        else:
            self.fail('selected relocation was absent')
        with patch.object(evm, 'TARGET', hashlib.sha256(altered).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'relocation census'):
                evm.rows_from_image(altered)

    def test_invalid_address_and_nobits_are_rejected(self):
        with self.assertRaises(ValueError):
            self.image.read(0xffffffffffffffff, 1)
        bss = next(s for s in self.image.sections if s['name'] == '.bss')
        self.assertEqual(bss['type'], 8)
        with self.assertRaises(ValueError):
            self.image.read(bss['address'], 1)
        with self.assertRaises(ValueError):
            self.image.read(0x2468870, 0)

    def test_selected_descriptor_method_relocations(self):
        rows = self.records['descriptors.tsv'][1]
        counts = {}
        relocations = evm.relative_relocations(self.image)
        for start, file_offset, raw_hex, slot, name, method in rows:
            counts[name] = counts.get(name, 0) + 1
            self.assertEqual(int(slot, 16), int(start, 16) + 0x28)
            self.assertEqual(bytes.fromhex(raw_hex), self.image.read(int(start, 16), 0x30))
            self.assertEqual(int(file_offset, 16), self.image.offset(int(start, 16), 0x30))
            self.assertEqual(relocations[int(slot, 16)], int(method, 16))
        self.assertEqual(counts, {'gross_adapter': 8, 'net_adapter': 7})

    def test_failure_branch_order_relative_to_flag_store(self):
        branches = {row[0]: (int(row[1], 16), int(row[3], 16))
                    for row in self.records['branches.tsv'][1]}
        anchors = {row[0]: int(row[1], 16) for row in self.records['anchors.tsv'][1]}
        for name in ('gross', 'net'):
            lookup = branches[name + '_lookup_not_5'][0]
            touch = anchors[name + '_touch']
            first_sub = anchors[name + '_first_subtract']
            first_branch, first_tail = branches[name + '_first_borrow']
            second_sub = anchors[name + '_second_subtract']
            second_branch, second_tail = branches[name + '_second_borrow']
            self.assertLess(lookup, touch)
            self.assertLess(touch, first_sub)
            self.assertLess(first_sub, first_branch)
            self.assertLess(first_branch, second_sub)
            self.assertLess(second_sub, second_branch)
            self.assertNotEqual(first_tail, second_tail)
        self.assertEqual(branches['gross_first_borrow'][1], 0x2468a94)
        self.assertEqual(branches['net_second_borrow'][1], 0x246923c)

    def test_branch_and_source_negative_controls(self):
        target, raw = evm.decoded_rel(self.image, 0x24689ac, '0f82')
        self.assertEqual(target, 0x2468a94)
        self.assertEqual(len(raw), 6)
        with self.assertRaisesRegex(ValueError, 'opcode'):
            evm.decoded_rel(self.image, 0x24689ac, '0f85')
        with self.assertRaises(ValueError):
            evm.decoded_rel(self.image, 0x24689ac, '90')
        self.assertEqual(evm.indirect_slot(self.image, 0x2468a9b)[0], 0x576e150)
        with self.assertRaisesRegex(ValueError, 'indirect call'):
            evm.indirect_slot(self.image, 0x24689ac)
        relocs = evm.relative_relocations(self.image)
        with self.assertRaisesRegex(ValueError, 'suffix'):
            evm.source_record(self.image, relocs, 0x56b6fb8, 'other.rs')
        with self.assertRaisesRegex(ValueError, 'relocation'):
            evm.source_record(self.image, {}, 0x56b6fb8, 'other.rs')


class ArithmeticTests(unittest.TestCase):
    def test_reduced_width_exhaustive_add_and_floor(self):
        # Every pair of four-limb values at widths 1 and 2 exercises all
        # carry and borrow positions, including top carry and exact equality.
        for width in (1, 2):
            modulus = 1 << (4 * width)
            maximum = modulus - 1
            for a in range(modulus):
                for b in range(modulus):
                    wrapped, carry = add_limbs(a, b, width)
                    self.assertEqual(wrapped, (a + b) % modulus)
                    self.assertEqual(carry, int(a + b >= modulus))
                    self.assertEqual(maximum if carry else wrapped, min(maximum, a + b))
                    self.assertEqual(floor_sub_limbs(a, b, width), max(0, a - b))

    def test_reduced_width_exhaustive_partial_products(self):
        for width in (1, 2, 3):
            modulus = 1 << (4 * width)
            for price in range(modulus):
                for quantity in range(1 << width):
                    self.assertEqual(mul_limbs(price, quantity, width), price * quantity % modulus)

    def test_full_width_boundaries_and_seeded_vectors(self):
        rng = random.Random(94)
        maximum = (1 << 256) - 1
        values = [0, 1, (1 << 64) - 1, 1 << 64, 1 << 128,
                  1 << 192, 1 << 255, maximum - 1, maximum]
        for _ in range(1024):
            values.append(rng.getrandbits(256))
        for index, a in enumerate(values):
            b = values[-1 - index]
            q = (a ^ b) & ((1 << 64) - 1)
            wrapped, carry = add_limbs(a, b, 64)
            self.assertEqual(wrapped, (a + b) & maximum)
            self.assertEqual(maximum if carry else wrapped, min(maximum, a + b))
            self.assertEqual(floor_sub_limbs(a, b, 64), max(0, a - b))
            self.assertEqual(mul_limbs(a, q, 64), (a * q) & maximum)
        self.assertEqual(mul_limbs(1 << 255, 2, 64), 0)
        self.assertEqual(add_limbs(maximum, 1, 64), (0, 1))

    def test_quantity_boundaries_and_distinct_failures(self):
        self.assertEqual(quantity_sub(10, 3, 7), 0)
        with self.assertRaisesRegex(OverflowError, 'first'):
            quantity_sub(2, 3, 0)
        with self.assertRaisesRegex(OverflowError, 'second'):
            quantity_sub(10, 3, 8)

    def test_two_beneficiary_formulas_and_credit_boundaries(self):
        maximum = (1 << 256) - 1
        cases = [(100, 20, 10, 7), (10, 20, 10, 7),
                 (100, 0, 0, 7), (100, 20, 0, 0),
                 (maximum, maximum, maximum, 2)]
        for price, base, balance, quantity in cases:
            gross_product = mul_limbs(price, quantity, 64)
            net_product = mul_limbs(floor_sub_limbs(price, base, 64), quantity, 64)
            gross_wrapped, gross_carry = add_limbs(balance, gross_product, 64)
            net_wrapped, net_carry = add_limbs(balance, net_product, 64)
            gross = maximum if gross_carry else gross_wrapped
            net = maximum if net_carry else net_wrapped
            self.assertEqual(gross, min(maximum, balance + ((price * quantity) & maximum)))
            self.assertEqual(net, min(maximum, balance + ((max(0, price-base) * quantity) & maximum)))
            if balance + price * quantity <= maximum:
                self.assertEqual(gross - net, min(price, base) * quantity)
        self.assertEqual(quantity_sub(100, 20, 5), 75)

    def test_exhaustive_small_credit_difference(self):
        # Exhaust all 4-limb, 1-bit prices, bases and balances and both
        # 1-bit quantities; compare two formulas only on the no-wrap domain.
        width, maximum = 1, 15
        for price in range(16):
            for base in range(16):
                net_price = floor_sub_limbs(price, base, width)
                for quantity in range(2):
                    gross_product = mul_limbs(price, quantity, width)
                    net_product = mul_limbs(net_price, quantity, width)
                    for balance in range(16):
                        gross = min(maximum, balance + gross_product)
                        net = min(maximum, balance + net_product)
                        if balance + price * quantity <= maximum:
                            self.assertEqual(gross - net, min(price, base) * quantity)
        self.assertEqual(2 + 12 * 3 - (2 + max(0, 12 - 10) * 3), 30)

    def test_exhaustive_reduced_width_complete_local_path(self):
        # Exhaust a complete four-limb miniature: mode, the three price
        # inputs, all three 1-bit quantity words and every balance. This is
        # a mathematical model, not an instruction or target emulator.
        width, maximum = 1, 15
        for cap in range(16):
            for base in range(16):
                for priority in range(16):
                    selected_sum, _ = add_limbs(base, priority, width)
                    for mode in (0, 1, 2):
                        price = min(cap, selected_sum) if mode == 1 else cap
                        oracle_price = min(cap, (base + priority) & maximum) if mode == 1 else cap
                        self.assertEqual(price, oracle_price)
                        net_factor = floor_sub_limbs(price, base, width)
                        for g0 in (0, 1):
                            for g1 in (0, 1):
                                for g2 in (0, 1):
                                    if g0 < g1 or g0 - g1 < g2:
                                        with self.assertRaises(OverflowError):
                                            quantity_sub(g0, g1, g2)
                                        continue
                                    quantity = quantity_sub(g0, g1, g2)
                                    for factor, oracle_factor in ((price, oracle_price),
                                            (net_factor, max(0, oracle_price - base))):
                                        product = mul_limbs(factor, quantity, width)
                                        oracle_product = (oracle_factor * quantity) & maximum
                                        self.assertEqual(product, oracle_product)
                                        for balance in range(16):
                                            low, carry = add_limbs(balance, product, width)
                                            result = maximum if carry else low
                                            if result != min(maximum, balance + oracle_product):
                                                self.fail('complete-path mismatch')

    def test_price_selection_and_net_floor(self):
        maximum = (1 << 256) - 1
        for cap, base, priority in [(100, 10, 5), (12, 10, 5), (10, 10, 0),
                                    (maximum, maximum, 1), (5, 9, 0)]:
            wrapped, _ = add_limbs(base, priority, 64)
            selected = min(cap, wrapped)
            self.assertEqual(selected, min(cap, (base + priority) & maximum))
            self.assertEqual(floor_sub_limbs(selected, base, 64), max(0, selected - base))
        self.assertEqual(min(12, 10 + 5), 12)
        self.assertEqual(floor_sub_limbs(5, 9, 64), 0)


if __name__ == '__main__':
    unittest.main()
