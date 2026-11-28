"""Instruction-level controls for the bounded prologue predicate."""
import unittest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from survey import classify


class Entries(unittest.TestCase):
    def check(self, sequence, category, after=None):
        decoder=Cs(CS_ARCH_X86,CS_MODE_64)
        got, pc, _ = classify(decoder,bytes.fromhex(sequence),0x1000)
        self.assertEqual((got,pc),(category,None if after is None else 0x1000+after))

    def test_distinct_move_encodings(self):
        for sequence in ('55 4889e5','55 488bec'):
            self.check(sequence,'push-and-set-rbp',4)

    def test_endbr_prefix(self):
        self.check('f30f1efa 55 4889e5','push-and-set-rbp',8)

    def test_save_does_not_establish_frame(self):
        self.check('55 4889ec','push-rbp-without-immediate-set')
        self.check('55 90 4889e5','push-rbp-without-immediate-set')

    def test_fde_ends_before_move(self):
        self.check('55 4889','push-rbp-without-immediate-set')
        self.check('f30f1efa','no-decodable-entry')

    def test_setup_is_entry_anchored(self):
        self.check('90 55 4889e5','other-entry')


if __name__=='__main__':
    unittest.main(verbosity=2)
