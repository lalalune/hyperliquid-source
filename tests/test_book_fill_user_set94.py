import bisect
import hashlib
from pathlib import Path
import random
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import book_fill_user_set94 as subject
from elf_index import sections


class TargetEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = subject.TARGET.read_bytes()
        cls.secs = sections(cls.data)
        cls.funcs = subject.pinned_functions(cls.data, cls.secs)

    def test_authenticated_target(self):
        self.assertEqual(subject.checked_image(self.data), subject.SHA256)
        with self.assertRaises(ValueError):
            subject.checked_image(self.data, '0' * 64)
        changed = bytearray(self.data)
        changed[0] ^= 1
        with self.assertRaises(ValueError):
            subject.checked_image(changed)

    def test_function_hash_and_extent_corruption(self):
        for _, fde, _ in self.funcs[:2]:
            with self.subTest(start=fde['start']):
                changed = bytearray(self.data)
                changed[subject.va_offset(self.secs, fde['start'], 1)] ^= 1
                with self.assertRaisesRegex(ValueError, 'function bytes'):
                    subject.pinned_functions(changed, self.secs)
        fde = self.funcs[1][1]
        changed = bytearray(self.data)
        changed[subject.va_offset(self.secs, fde['fde'] + 12, 1)] ^= 1
        with self.assertRaisesRegex(ValueError, 'FDE extent'):
            subject.pinned_functions(changed, self.secs)

    def test_every_selected_branch_and_corruption(self):
        for name,site,op,target in subject.BRANCHES:
            with self.subTest(name=name):
                raw,_ = subject.branch(self.data,self.secs,site,op,target)
                buf=bytearray.fromhex(raw)
                sec=[dict(type=1,address=site,offset=0,size=len(buf))]
                for byte in (0,len(buf)-1):
                    changed=bytearray(buf)
                    changed[byte]^=1
                    with self.assertRaises(ValueError):
                        subject.branch(changed,sec,site,op,target)

    def test_every_selected_call_and_corruption(self):
        for name,site,kind,target in subject.CALLS:
            with self.subTest(name=name):
                raw,_=subject.call(self.data,self.secs,site,kind,target)
                buf=bytearray.fromhex(raw)
                sec=[dict(type=1,address=site,offset=0,size=len(buf))]
                for byte in (0,len(buf)-1):
                    changed=bytearray(buf)
                    changed[byte]^=1
                    with self.assertRaises(ValueError):
                        subject.call(changed,sec,site,kind,target)

    def test_entry_comparison_masks_and_targets(self):
        left,right=self.funcs[0][2],self.funcs[2][2]
        rows,digest=subject.compare_entries(left,right)
        self.assertEqual(len(rows),7)
        self.assertNotEqual(left,right)
        self.assertEqual(sum(a!=b for a,b in zip(left,right)),21)
        self.assertEqual(digest,'1b7dab88b874257ad5d2715fc68ce26e83ec487d4d79ea186c7f5f12ccf490f3')
        self.assertEqual(rows[1][-1],0x41fb1d0)
        for offset in subject.MASKS:
            changed=bytearray(left)
            changed[offset]^=1
            with self.assertRaises(ValueError):
                subject.compare_entries(changed,right)
        changed=bytearray(left)
        changed[0]^=1
        with self.assertRaisesRegex(ValueError,'unmasked'):
            subject.compare_entries(changed,right)

    def test_split_immediate_corruption(self):
        params,rows=subject.split_parameters(self.data,self.secs)
        self.assertEqual(len(rows),13)
        self.assertEqual(params['capacity'],11)
        changed=bytearray(self.data)
        changed[subject.va_offset(self.secs,0x41fb273+3,1)]^=1
        with self.assertRaisesRegex(ValueError,'split immediate'):
            subject.split_parameters(changed,self.secs)

    def test_windows(self):
        for name,start,expected in subject.WINDOWS:
            with self.subTest(name=name):
                actual=subject.verify_window(self.data,self.secs,start,expected)
                self.assertEqual(actual.hex(),expected)
                changed=bytearray(actual)
                changed[len(changed)//2]^=1
                local=[dict(type=1,address=start,offset=0,size=len(changed))]
                with self.assertRaisesRegex(ValueError,'window mismatch'):
                    subject.verify_window(changed,local,start,expected)

    def test_file_backing_and_bounds(self):
        secs=[dict(type=1,address=0x100,offset=0,size=4),dict(type=8,address=0x200,offset=4,size=8)]
        self.assertEqual(subject.read_va(b'abcd',secs,0x100,4),b'abcd')
        for va,size in ((0xff,1),(0x103,2),(0x200,1),(0x100,0),(-1,1)):
            with self.subTest(va=va,size=size), self.assertRaises(ValueError):
                subject.read_va(b'abcd',secs,va,size)
        with self.assertRaises(ValueError):
            subject.va_offset(secs+[secs[0]],0x100,1)

    def test_exception_routes_and_corruption(self):
        fde=self.funcs[1][1]
        rows=subject.exception_table(self.data,self.secs,fde)
        self.assertEqual(len(rows),10)
        failures={r[0]:r for r in subject.failure_rows(rows)}
        self.assertEqual(len(failures),12)
        self.assertEqual(failures['root_height_wrap'][4],0x41fbb3f)
        self.assertIsNone(failures['published_height_mismatch'][4])
        self.assertEqual(failures['leaf_right_count'][4],0x41fbb53)
        changed=bytearray(self.data)
        changed[subject.va_offset(self.secs,fde['lsda']+5,1)]^=1
        with self.assertRaises(ValueError):
            subject.exception_table(changed,self.secs,fde)
        outside=dict(fde,lsda=0)
        with self.assertRaises(ValueError):
            subject.exception_table(self.data,self.secs,outside)
        with self.assertRaises(ValueError):
            subject.failure_rows([])

    def test_diagnostics_and_location_corruption(self):
        locations,messages=subject.diagnostic_rows(self.data,self.secs)
        self.assertEqual(len(locations),9)
        self.assertEqual(len(messages),4)
        height=next(x for x in locations if x[0]==0x571c438)
        self.assertEqual(height[3:5],(694,9))
        changed=bytearray(self.data)
        changed[subject.va_offset(self.secs,0x571c438+16,1)]^=1
        with self.assertRaisesRegex(ValueError,'Location mismatch'):
            subject.diagnostic_rows(changed,self.secs)
        changed=bytearray(self.data)
        changed[subject.va_offset(self.secs,0x6ee259,1)]^=1
        with self.assertRaisesRegex(ValueError,'diagnostic text'):
            subject.diagnostic_rows(changed,self.secs)

    def test_dynamic_slots(self):
        rows=subject.relocation_rows(self.data,self.secs)
        by_slot={r[0]:r for r in rows}
        self.assertEqual(len(rows),9)
        self.assertEqual(by_slot[0x576e488][-1],'memcmp')
        self.assertEqual(by_slot[0x576dfe0][-1],'memcpy')
        self.assertEqual(by_slot[0x576e0e0][-1],'memmove')
        self.assertEqual(by_slot[0x576dfd8][1],8)
        bad=bytearray(self.data)
        rela=next(s for s in self.secs if s['name']=='.rela.dyn')
        for off in range(rela['offset'],rela['offset']+rela['size'],24):
            if struct.unpack_from('<Q',bad,off)[0]==0x576dfd8:
                struct.pack_into('<Q',bad,off,0)
                break
        else:
            self.fail('relocation missing')
        with self.assertRaisesRegex(ValueError,'missing relocation'):
            subject.relocation_rows(bad,self.secs)
        changed=bytearray(self.data)
        changed[off+16]^=1
        with self.assertRaisesRegex(ValueError,'relocation data'):
            subject.relocation_rows(changed,self.secs)


class SplitProjection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data=subject.TARGET.read_bytes()
        subject.checked_image(data)
        cls.params,_=subject.split_parameters(data,sections(data))

    def test_twelve_old_pivots(self):
        expected=[(4,'left',0),(4,'left',1),(4,'left',2),(4,'left',3),
                  (4,'left',4),(5,'left',5),(5,'right',0),(6,'right',0),
                  (6,'right',1),(6,'right',2),(6,'right',3),(6,'right',4)]
        self.assertEqual([subject.split_case(i,self.params) for i in range(12)],expected)
        for bad in (-1,12,40):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                subject.split_case(bad,self.params)

    def test_nonfull_full_and_duplicate_sequences(self):
        # This is an independent B-tree model, not an emulator. It checks that
        # the pinned split decisions maintain search-tree invariants.
        class Node:
            def __init__(self):
                self.keys=[]
                self.children=[]

        def insert(node,key):
            pos=bisect.bisect_left(node.keys,key)
            if pos<len(node.keys) and node.keys[pos]==key:
                return False,None
            if node.children:
                added,promotion=insert(node.children[pos],key)
                if not added:
                    return False,None
                if promotion is None:
                    return True,None
                key,right=promotion
            else:
                right=None
            if len(node.keys)<11:
                node.keys.insert(pos,key)
                if right is not None:
                    node.children.insert(pos+1,right)
                return True,None
            pivot,side,index=subject.split_case(pos,self.params)
            promoted=node.keys[pivot]
            sibling=Node()
            sibling.keys=node.keys[pivot+1:]
            node.keys=node.keys[:pivot]
            if node.children:
                sibling.children=node.children[pivot+1:]
                node.children=node.children[:pivot+1]
            target=node if side=='left' else sibling
            target.keys.insert(index,key)
            if right is not None:
                target.children.insert(index+1,right)
            return True,(promoted,sibling)

        def audit(root,expected):
            leaves=[]
            def visit(node,depth,low,high,is_root):
                self.assertEqual(node.keys,sorted(node.keys))
                self.assertEqual(len(node.keys),len(set(node.keys)))
                self.assertLessEqual(len(node.keys),11)
                if not is_root:
                    self.assertGreaterEqual(len(node.keys),5)
                for key in node.keys:
                    self.assertTrue(low<key<high)
                if not node.children:
                    leaves.append(depth)
                    return list(node.keys)
                self.assertEqual(len(node.children),len(node.keys)+1)
                boundaries=[low]+node.keys+[high]
                result=[]
                for i,child in enumerate(node.children):
                    result.extend(visit(child,depth+1,boundaries[i],boundaries[i+1],False))
                    if i<len(node.keys):
                        result.append(node.keys[i])
                return result
            self.assertEqual(visit(root,0,-1,10000,True),sorted(expected))
            self.assertEqual(len(set(leaves)),1)

        sequences=[list(range(600)),list(range(599,-1,-1))]
        shuffled=list(range(600))
        random.Random(94).shuffle(shuffled)
        sequences.append(shuffled)
        for sequence in sequences:
            root=Node()
            seen=set()
            for key in sequence+sequence[::11]:
                added,promotion=insert(root,key)
                self.assertEqual(added,key not in seen)
                seen.add(key)
                if promotion:
                    old=root
                    pivot,right=promotion
                    root=Node()
                    root.keys=[pivot]
                    root.children=[old,right]
            audit(root,seen)


if __name__=='__main__':
    unittest.main()
