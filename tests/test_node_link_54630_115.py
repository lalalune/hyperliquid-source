"""Tests for tools/node_link_54630_115.py (node #115, 0x5d54630).

pytest is not installed on this VM; the packet verify.py invokes every
test_* function here directly, so each test is self-contained.
Chain slots are (slot_id, handler) pairs; the walk compares slot_id
values against the global value "G", exactly like the binary compares
each node's +0xc0 slot against the stored qword / previous slot.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from node_link_54630_115 import Holder, Node, VPTR, link_node


def _handler(tag, freed_ptr="old"):
    calls = []

    def fn(out_pair, node, aux):
        calls.append(tag)
        out_pair[0] = "produced"
        out_pair[1] = freed_ptr
        aux[0] = "aux-value"

    fn.calls = calls
    return fn


def _chain(pairs):
    head = None
    for slot_id, fn in reversed(pairs):
        head = Node(slot_id=slot_id, slot_fn=fn, next_node=head)
    return head


def _std_chain():
    """Five nodes with distinct slot ids A..E (first diverges at once)."""
    return _chain([(t, _handler(t)) for t in "ABCDE"])


def _holder(chain, flag_c98=True, slot480_same=True, flag_17b2_zero=False):
    tail = Node()
    holder = Holder(
        chain_head=chain,
        global_slot="G",
        c98_nonzero=flag_c98,
        slot480_value="S" if slot480_same else "OTHER",
        slot480_global="S",
        slot480_fn=lambda h: "slot480-result",
        flag_17b2_zero=flag_17b2_zero,
        obj68_108="via-108",
        obj68_120="via-120",
        anchor_addr=0x11E0,
        anchor_tail=tail,
    )
    return holder, tail


def _handlers_of(chain):
    out = []
    node = chain
    while node is not None:
        out.append(node.slot_fn)
        node = node.next
    return out


def test_divergent_first_node_calls_its_slot():
    chain = _std_chain()
    ha = chain.slot_fn
    holder, tail = _holder(chain)
    node = link_node(holder, 0x41, 1)
    assert node is not None
    assert ha.calls == ["A"]
    assert holder.freed == ["old"]
    assert node.vptr == VPTR
    assert node.f10 == 1
    assert node.f30 == "aux-value"
    assert node.f38 == -1
    assert node.f40 == 0x41
    assert node.f08 == "via-108"
    assert holder.count == 1
    assert holder.mutex_calls == [("acquire_606ca40", 0x700),
                                  ("release_60d52f0", 0x700)]


def test_full_match_calls_fifth_node_unconditionally():
    chain = _chain([("G", _handler(t)) for t in "ABCDE"])
    hs = _handlers_of(chain)
    holder, tail = _holder(chain)
    node = link_node(holder, 0x07, 1)
    assert node is not None
    assert [h.calls for h in hs] == [[], [], [], [], ["E"]]
    assert node.f08 == "via-108"


def test_divergent_third_node_calls_only_its_slot():
    chain = _chain([("G", _handler("A")), ("G", _handler("B")),
                    ("X", _handler("C")), ("Y", _handler("D")),
                    ("Z", _handler("E"))])
    hs = _handlers_of(chain)
    holder, tail = _holder(chain)
    node = link_node(holder, 0x00, 0)
    assert node is not None
    assert hs[2].calls == ["C"]
    assert hs[0].calls == [] and hs[1].calls == []
    assert hs[3].calls == [] and hs[4].calls == []
    assert holder.mutex_calls == [("entry_60d5390", 0x700)]
    assert node.f08 == "via-108"


def test_c98_zero_flag_set_releases_then_destroys():
    holder, tail = _holder(_std_chain(), flag_c98=False)
    node = link_node(holder, 0x00, 1)
    assert node is None
    assert holder.count == 0
    assert holder.mutex_calls == [("acquire_606ca40", 0x700),
                                  ("release_60d52f0", 0x700)]
    assert len(holder.destroyed) == 1


def test_c98_zero_flag_clear_destroys_without_release():
    holder, tail = _holder(_std_chain(), flag_c98=False)
    node = link_node(holder, 0x00, 0)
    assert node is None
    assert holder.count == 0
    assert holder.mutex_calls == [("entry_60d5390", 0x700)]
    assert len(holder.destroyed) == 1


def test_slot480_divergent_overrides_field_08():
    holder, tail = _holder(_std_chain(), slot480_same=False)
    node = link_node(holder, 0x00, 1)
    assert node.f08 == "slot480-result"


def test_field_08_selects_120_when_17b2_zero():
    holder, tail = _holder(_std_chain(), flag_17b2_zero=True)
    node = link_node(holder, 0x00, 1)
    assert node.f08 == "via-120"


def test_splice_writes_and_count():
    holder, tail = _holder(_std_chain())
    node = link_node(holder, 0x00, 1)
    assert node.f18 == 0x11E0
    assert node.f20 is tail
    assert node.f28 == 0x11E0
    assert tail.f20 is node
    assert tail.f18 is node
    assert holder.count == 1


def test_null_out_pair_second_element_frees_nothing():
    def fn(out_pair, node, aux):
        out_pair[0] = "produced"
        out_pair[1] = None
        aux[0] = "aux-value"

    chain = _chain([("A", fn), ("B", _handler("B")),
                    ("C", _handler("C")), ("D", _handler("D")),
                    ("E", _handler("E"))])
    holder, tail = _holder(chain)
    node = link_node(holder, 0x00, 1)
    assert node is not None
    assert holder.freed == []
