"""Tests for the node #115 list append/erase model
(tools/list_append_erase_54b50_115.py).

Runnable with pytest, or by invoking each test_* function directly.
"""

from tools.list_append_erase_54b50_115 import (
    CELL_SIZE,
    NODE_SIZE,
    Holder,
    Slot,
    append,
    erase,
    install_handle,
)


def test_append_to_empty_returns_node_and_links():
    holder = Holder("v1")
    node = append(holder)
    assert holder.size == 1
    assert holder.values() == ["v1"]
    assert holder.sentinel.prev is node
    assert holder.sentinel.next is node
    assert node.prev is holder.sentinel
    assert node.next is holder.sentinel
    holder.check_links()


def test_append_twice_preserves_order_at_back():
    holder = Holder("a")
    first = append(holder)
    holder.source_value = "b"
    second = append(holder)
    assert holder.values() == ["a", "b"]
    assert holder.size == 2
    assert holder.sentinel.prev is second
    assert first.next is second
    assert second.prev is first
    holder.check_links()


def test_append_copies_source_value_by_value():
    holder = Holder("x")
    node = append(holder)
    holder.source_value = "y"
    assert node.value == "x"
    assert holder.values() == ["x"]


def test_erase_null_slot_is_noop():
    holder = Holder("a")
    append(holder)
    slot = Slot()
    assert erase(holder, slot) == []
    assert holder.size == 1
    assert holder.values() == ["a"]
    holder.check_links()


def test_erase_middle_node_relinks_and_frees():
    holder = Holder("a")
    n1 = append(holder)
    holder.source_value = "b"
    n2 = append(holder)
    holder.source_value = "c"
    n3 = append(holder)
    slot = Slot()
    install_handle(slot, n2)
    frees = erase(holder, slot)
    assert frees == [("node", NODE_SIZE), ("cell", CELL_SIZE)]
    assert holder.size == 2
    assert holder.values() == ["a", "c"]
    assert n1.next is n3
    assert n3.prev is n1
    assert n2.freed
    assert slot.cell is None
    holder.check_links()


def test_erase_only_node_empties_list():
    holder = Holder("solo")
    node = append(holder)
    slot = Slot()
    install_handle(slot, node)
    assert erase(holder, slot) == [("node", 0x18), ("cell", 8)]
    assert holder.size == 0
    assert holder.values() == []
    assert holder.sentinel.next is holder.sentinel
    assert holder.sentinel.prev is holder.sentinel
    holder.check_links()


def test_append_erase_append_cycle():
    holder = Holder("a")
    node = append(holder)
    slot = Slot()
    install_handle(slot, node)
    erase(holder, slot)
    holder.source_value = "b"
    node2 = append(holder)
    assert holder.values() == ["b"]
    assert holder.size == 1
    assert node2 is not node
    holder.check_links()


def test_install_handle_replaces_and_frees_old_cell():
    holder = Holder("a")
    n1 = append(holder)
    holder.source_value = "b"
    n2 = append(holder)
    slot = Slot()
    assert install_handle(slot, n1) == []
    old = slot.cell
    assert install_handle(slot, n2) == [("cell", CELL_SIZE)]
    assert old.freed
    assert slot.cell.node is n2


def test_node_and_cell_sizes():
    assert NODE_SIZE == 0x18
    assert CELL_SIZE == 8


def test_erase_leaves_other_values_untouched():
    holder = Holder(10)
    append(holder)
    holder.source_value = 20
    n2 = append(holder)
    holder.source_value = 30
    append(holder)
    slot = Slot()
    install_handle(slot, n2)
    erase(holder, slot)
    assert holder.values() == [10, 30]
    holder.check_links()
