#!/usr/bin/env python3
"""Tests for the 0x514bee0 nested-teardown model (node #94, RE-001).

Stdlib only. Run from the repository root:

    python3 -m pytest tests/test_foundation_nested_teardown.py -q
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import foundation_nested_teardown as m

PACKET = os.path.join(os.path.dirname(__file__), "..", "research",
                       "work-items", "RE-001-nested-teardown-94")
BINARY = os.path.join(os.path.dirname(__file__), "..", "work",
                       "hl-node-94.bin")


def test_null_input_frees_nothing():
    assert m.teardown(None) == []


def test_single_node_no_items():
    node = m.OuterNode("N0")
    assert m.teardown(node) == [("free", "outer", "N0", 0x58)]


def test_single_node_with_items_and_child():
    # Child subtree torn down first (self-recursion on +0x18),
    # then items in order (each item's +0x18 chain via the callee
    # rule, then the item itself), then the outer node itself.
    grandchild = m.ItemNode("G0")
    item0 = m.ItemNode("I0", child=grandchild)
    item1 = m.ItemNode("I1")
    item0.next = item1
    child = m.OuterNode("C0")
    node = m.OuterNode("N0", child=child, items=item0)
    assert m.teardown(node) == [
        ("free", "outer", "C0", 0x58),
        ("free", "item", "G0", 0x30),
        ("free", "item", "I0", 0x30),
        ("free", "item", "I1", 0x30),
        ("free", "outer", "N0", 0x58),
    ]


def test_single_node_item_chain_with_nested_children():
    # The callee rule (0x514b690) walks an item's +0x10 chain,
    # tearing down each item's +0x18 subtree before deleting it.
    inner = m.ItemNode("J0")
    item0 = m.ItemNode("I0", child=inner)
    item1 = m.ItemNode("I1")
    item0.next = item1
    node = m.OuterNode("N0", items=item0)
    assert m.teardown(node) == [
        ("free", "item", "J0", 0x30),
        ("free", "item", "I0", 0x30),
        ("free", "item", "I1", 0x30),
        ("free", "outer", "N0", 0x58),
    ]


def test_two_node_chain_deletes_each_node_once():
    # The loop head is 0x514beec and the mov %rbp,%r12 at
    # 0x514bef0 sits after it, so r12 is reloaded with the
    # current node on every iteration: each node reads its OWN
    # items list and is deleted exactly once, in chain order.
    item0 = m.ItemNode("I0")
    item1 = m.ItemNode("I1")
    node1 = m.OuterNode("N1", items=item1)
    node0 = m.OuterNode("N0", next=node1, items=item0)
    assert m.teardown(node0) == [
        ("free", "item", "I0", 0x30),
        ("free", "outer", "N0", 0x58),
        ("free", "item", "I1", 0x30),
        ("free", "outer", "N1", 0x58),
    ]


def test_two_node_chain_second_child_torn_down_first():
    # The second node's +0x18 subtree is torn down on the
    # second iteration (step 1), before the second node itself
    # is deleted.
    child = m.OuterNode("C1")
    node1 = m.OuterNode("N1", child=child)
    node0 = m.OuterNode("N0", next=node1)
    assert m.teardown(node0) == [
        ("free", "outer", "N0", 0x58),
        ("free", "outer", "C1", 0x58),
        ("free", "outer", "N1", 0x58),
    ]


def test_packet_verifies_against_binary():
    if not os.path.exists(BINARY):
        raise SystemExit("work binary missing")
    assert m.check_packet(PACKET, BINARY) == []


def test_packet_manifest_and_excerpts_regenerate():
    # The shipped excerpts must be byte-identical to a fresh
    # objdump run on the digest-pinned binary. Run from the
    # repository root, as in the packet README: objdump prints
    # the binary path as given, so the regeneration uses the
    # same repo-relative path the excerpts were shipped with.
    import subprocess
    rel_binary = os.path.join("work", "hl-node-94.bin")
    for name, start, stop in (
            ("window.objdump.txt", "0x514bee0", "0x514bf60"),
            ("callee.objdump.txt", "0x514b690", "0x514b6d0")):
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%s" % start,
             "--stop-address=%s" % stop, rel_binary],
            capture_output=True, text=True)
        assert out.returncode == 0
        with open(os.path.join(PACKET, name)) as f:
            assert f.read() == out.stdout


def test_corruption_controls():
    # Mutating the packet must fail verification: a corrupted
    # excerpt byte and a corrupted manifest hash each fail.
    import json
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(PACKET, os.path.join(tmp, "packet"))
        pdir = os.path.join(tmp, "packet")
        with open(os.path.join(pdir, "window.objdump.txt")) as f:
            text = f.read()
        with open(os.path.join(pdir, "window.objdump.txt"), "w") as f:
            f.write(text.replace("48 85 ff", "48 85 fe", 1))
        assert m.check_packet(pdir, BINARY) != []
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(PACKET, os.path.join(tmp, "packet"))
        pdir = os.path.join(tmp, "packet")
        with open(os.path.join(pdir, "records.json")) as f:
            records = json.load(f)
        records["function"]["sha256"] = "0" * 64
        with open(os.path.join(pdir, "records.json"), "w") as f:
            json.dump(records, f)
        assert m.check_packet(pdir, BINARY) != []
