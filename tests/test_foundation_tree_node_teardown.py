#!/usr/bin/env python3
"""Tests for node #94 tree-node teardown at 0x514c1c0 (RE-001).

Covers the model in tools/foundation_tree_node_teardown.py, the packet
verifier, and corruption controls that must make the verifier fail.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKET = REPO_ROOT / 'research' / 'work-items' / 'RE-001-tree-node-teardown-94'

sys.path.insert(0, str(REPO_ROOT))

from tools.foundation_tree_node_teardown import (  # noqa: E402
    destroy_list, make_node, teardown, wrapper_teardown)


def heap_node(node_id, **kw):
    kw.setdefault('heap', True)
    kw.setdefault('buffer', f'buf-{node_id}')
    kw.setdefault('capacity', 5)
    return make_node(node_id, **kw)


class TestTeardownModel(unittest.TestCase):
    def test_null_head(self):
        self.assertEqual(teardown(None, {}), [])

    def test_single_sso_leaf(self):
        nodes = {'a': make_node('a')}
        self.assertEqual(teardown('a', nodes), [('free_node', 'a', 0x48)])

    def test_single_heap_leaf_capacity_plus_one(self):
        nodes = {'a': heap_node('a', capacity=5)}
        self.assertEqual(teardown('a', nodes),
                         [('free_buffer', 'buf-a', 6),
                          ('free_node', 'a', 0x48)])

    def test_sibling_chain_order(self):
        nodes = {
            'a': make_node('a', next_id='b'),
            'b': heap_node('b', next_id='c'),
            'c': make_node('c'),
        }
        self.assertEqual(teardown('a', nodes),
                         [('free_node', 'a', 0x48),
                          ('free_buffer', 'buf-b', 6),
                          ('free_node', 'b', 0x48),
                          ('free_node', 'c', 0x48)])

    def test_post_order_parent_after_children(self):
        # P has children C1 -> C2; C1 has child G. Post-order:
        # G, C1, C2, then P itself.
        nodes = {
            'p': make_node('p', child_id='c1'),
            'c1': make_node('c1', next_id='c2', child_id='g'),
            'c2': heap_node('c2'),
            'g': make_node('g'),
        }
        self.assertEqual(teardown('p', nodes),
                         [('free_node', 'g', 0x48),
                          ('free_node', 'c1', 0x48),
                          ('free_buffer', 'buf-c2', 6),
                          ('free_node', 'c2', 0x48),
                          ('free_node', 'p', 0x48)])

    def test_deep_first_child_chain(self):
        # Depth 10 exceeds the 7-link unrolling; the model (and the
        # target's self-call) still destroys deepest-first.
        nodes = {}
        prev = None
        for i in reversed(range(10)):
            nodes[f'n{i}'] = make_node(f'n{i}', child_id=prev)
            prev = f'n{i}'
        expected = [('free_node', f'n{i}', 0x48)
                    for i in reversed(range(10))]
        self.assertEqual(teardown('n0', nodes), expected)

    def test_wrapper_matches_destroy_list(self):
        nodes = {
            'a': make_node('a', next_id='b', child_id='g'),
            'g': heap_node('g'),
            'b': make_node('b'),
        }
        self.assertEqual(wrapper_teardown('a', nodes),
                         destroy_list('a', nodes))
        self.assertEqual(wrapper_teardown('a', nodes),
                         [('free_buffer', 'buf-g', 6),
                          ('free_node', 'g', 0x48),
                          ('free_node', 'a', 0x48),
                          ('free_node', 'b', 0x48)])


class TestPacket(unittest.TestCase):
    def test_records_shape(self):
        records = json.loads((PACKET / 'records.json').read_text())
        self.assertEqual(records['function']['sha256'],
                         'b1ef129bc4668b404ab184a7f4149631948da307cb71c8585427b96e22fcd895')
        self.assertEqual(records['function']['byte_length'], 861)
        self.assertEqual(records['node_layout']['size'], '0x48')
        self.assertEqual(len(records['callers']), 2)
        self.assertEqual(records['callers'][0]['site'], '0x514c537')
        self.assertEqual(records['callers'][1]['site'], '0x5150dec')
        # No per-instruction mnemonic list: semantic records only.
        self.assertNotIn('instructions', records)
        self.assertNotIn('mnemonics', records)

    def test_packet_verification(self):
        r = subprocess.run([sys.executable, str(PACKET / 'verify.py')],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('ALL CHECKS PASSED', r.stdout)

    def test_excerpt_regeneration(self):
        r = subprocess.run([sys.executable, str(PACKET / 'export_excerpts.py')],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = subprocess.run([sys.executable, str(PACKET / 'verify.py')],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('ALL CHECKS PASSED', r.stdout)

    def test_corruption_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / 'packet'
            shutil.copytree(PACKET, copy)
            records = json.loads((copy / 'records.json').read_text())
            records['function']['sha256'] = '0' * 64
            (copy / 'records.json').write_text(json.dumps(records, indent=2))
            r = subprocess.run([sys.executable, str(copy / 'verify.py'),
                                '--packet-dir', str(copy)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            # A corrupted manifest entry must also fail verification.
            p2 = Path(tmp) / 'packet2'
            shutil.copytree(PACKET, p2)
            (p2 / 'MANIFEST.sha256').write_text('0' * 64 + '  window.objdump.txt\n')
            r = subprocess.run([sys.executable, str(p2 / 'verify.py'),
                                '--packet-dir', str(p2)],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)


if __name__ == '__main__':
    unittest.main()
