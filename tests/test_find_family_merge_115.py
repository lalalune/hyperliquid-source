"""Tests for the node #115 Find-family hosts model.

Run under plain python3 (pytest is not installed on this VM):
    python3 tests/test_find_family_hosts_115.py

The four hosts (0x6080b10, 0x60818f0, 0x6098ad0, 0x609bcb0)
and their helpers are pinned against the node #115 binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301);
the tests pin the branch behaviour the disassembly dictates.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from find_family_merge_115 import (  # noqa: E402
    BLOCK_CTOR_BSS, BLOCK_CTOR_VTABLES, BLOCK_DEFAULTS_TEMPLATE,
    BLOCK_DEFAULTS_TEMPLATE_VALUES, CSTR_CTOR, FIND_BLOCK_TABLE,
    FIND_BY_ELEMENT_SCAN, FIND_PLAIN_TABLE, MAP_ERASE_NEXT,
    MAP_FIND_NAME, MAP_INSERT, NAME_SET_NODE_SIZE,
    OPTIONS_LIST_NODE_SIZE, OPTIONS_RECORD_GLOBAL,
    PLAIN_CONTROL_COUNTS, PLAIN_CONTROL_VTABLE, PLAIN_OBJECT_SIZE,
    PLAIN_VTABLE, RESOLVE_ALL_ELEMENTS, ConfigNode, MapNode,
    NameObject, NameSet, NameSetNode, NameTable, NodeObj,
    OptionsListNode, OptionsMap, SharedControl, SharedHolder,
    Slot10Target, Status, TableEntry, TableNode, TableOptions,
    Value, block_creator, block_default_options,
    clear_string, counted_release, cstr_ctor, cstr_dup,
    destroy_block_defaults, element_scan, find_block_table,
    find_by_element_scan, find_e70, find_plain_table,
    hash_bytes, map_erase_next, map_find_name, map_insert, matcher,
    name_lookup, options_list_destroy, options_record_append,
    plain_creator, plain_default_options, resolve_all_elements,
    shared_release,
    # Find-family merge additions.
    BOOL_PARSER, CODE_DESERIALIZE_NOT_SUPPORTED, CODE_NOT_FOUND,
    CODE_PARSE_ERROR, ENUM_LOOKUP_U32, ENUM_LOOKUP_U8_A,
    ENUM_LOOKUP_U8_F, ESCAPE_ASSIGN, ESCAPE_DECODER, HEXVAL,
    HEX_DECODE, HOST_A, HOST_B, HOST_B_KIND_TABLE, I32_PARSER,
    MERGE_DRIVER, MSG_COULD_NOT_FIND_CONFIGURABLE,
    MSG_COULD_NOT_FIND_OPTION, MSG_DESERIALIZING_OPTION,
    MSG_EQUALS, MSG_ERROR_PARSING_COLON,
    MSG_ERROR_PARSING_SPACE, MSG_IS_NOT_SUPPORTED,
    MSG_SEMICOLON_SPACE, NODE_CLONE, RANGE_CTOR, REHASH,
    STOD_PARSER, STOULL_ALIAS, STOULL_PARSER, STOULL_SUFFIX_TABLE,
    STOLL_PARSER, STOLL_SUFFIX_TABLE, STOI_PARSER, U8_PARSER,
    U32_PARSER, WORKER, WORKER_WRAPPER, EnumMap, FindDesc,
    InvalidArgument, OutOfRange, ParseError, ValueSlot,
    WorkerElement, bool_parse, clone_options_map,
    escape_assign, escape_decoder, enum_lookup_u32,
    enum_lookup_u8, hex_decode, hexval, host_a, host_b,
    i32_via_stoll_parse, merge_driver, node_clone, range_ctor,
    rehash_map, stod_parse, stoi_parse, stoull_alias_parse,
    stoull_parse, stoll_parse, u32_parse, u8_parse, value_byte02,
    worker, worker_wrapper)


# --- small helpers -----------------------------------------------------


def test_cstr_ctor_values():
    assert cstr_ctor("") == ""
    assert cstr_ctor("x") == "x"
    assert cstr_ctor("PlainTableOptions") == "PlainTableOptions"
    assert cstr_ctor("block_based_table_factory") == \
        "block_based_table_factory"


def test_cstr_ctor_null_raises():
    try:
        cstr_ctor(None)
    except ValueError as exc:
        assert "logic_error" in str(exc)
    else:
        raise AssertionError("null cstr did not raise")


def test_cstr_dup_and_clear_string():
    holder = [None]
    assert cstr_dup(holder, "abc") == "abc"
    assert holder[0] == "abc"
    assert clear_string(holder, "def") == "def"
    assert holder[0] == "def"


def test_counted_release_fast_path():
    control = SharedControl(object())
    assert control.counts == PLAIN_CONTROL_COUNTS
    counted_release(control)
    assert control.use_count == 0
    assert control.weak_count == 0
    assert control.disposed
    assert control.destroyed


def test_counted_release_decrements():
    control = SharedControl(object())
    control.acquire()
    control.acquire()
    assert control.counts == 0x100000003
    counted_release(control)
    assert control.use_count == 2
    assert not control.disposed
    assert not control.destroyed
    counted_release(control)
    assert control.use_count == 1
    assert not control.disposed


def test_counted_release_last_use_disposes():
    control = SharedControl(object())
    control.acquire()
    counted_release(control)  # use 2 -> 1, no dispose
    assert not control.disposed
    counted_release(control)  # was 1 -> the 0x5d35070 tail
    assert control.use_count == 0
    assert control.weak_count == 0
    assert control.disposed
    assert control.destroyed


def test_shared_release_weak_count():
    control = SharedControl(object())
    control.weak_count = 2
    shared_release(control)
    assert control.disposed
    assert control.weak_count == 1
    assert not control.destroyed
    shared_release(control)
    assert control.weak_count == 0
    assert control.destroyed


def test_release_none_is_noop():
    counted_release(None)
    shared_release(None)


def test_options_record_append():
    obj = TableOptions(PLAIN_OBJECT_SIZE, PLAIN_VTABLE)
    assert options_record_append(obj, "PlainTableOptions",
                                  {"x": 1}, OPTIONS_RECORD_GLOBAL) == 1
    assert options_record_append(obj, "n2", {"y": 2}, 0x6507540) == 2
    assert obj.records[0] == ("PlainTableOptions", {"x": 1},
                              OPTIONS_RECORD_GLOBAL)
    assert obj.records[1][2] == 0x6507540


def test_plain_ctor_and_creator():
    options = plain_default_options()
    obj = plain_creator(options)
    assert obj.size == PLAIN_OBJECT_SIZE
    assert obj.vtable == PLAIN_VTABLE
    assert obj.options is options
    assert obj.records == [("PlainTableOptions", options,
                            OPTIONS_RECORD_GLOBAL)]
    assert options == {0x04: 0x0A, 0x0E: 0x103FE8}


def test_block_ctor_boundary():
    options = block_default_options()
    obj = block_creator(options)
    assert obj.size == 0x260
    assert obj.options is options
    # The record name is the options struct's leading string
    # ("" for the zeroed defaults); the global is 0x6507540.
    assert obj.records[0][0] == ""
    assert obj.records[0][2] == BLOCK_CTOR_BSS
    assert obj.boundary_calls[0] == 0x60DB1E0
    assert obj.boundary_vtables == BLOCK_CTOR_VTABLES
    # The pinned defaults fields.
    assert options[0x59] == 0xA00000000000010
    assert options[0x64] == 0x0000000100000010
    assert options[0x71] == 0x0200000000000010
    assert options[0x2E] == 0x43FE8
    assert options[0xD0] == 5
    assert options[0xD8] == 0x40000
    assert options[0xE8] == BLOCK_DEFAULTS_TEMPLATE_VALUES
    assert BLOCK_DEFAULTS_TEMPLATE == 0x4506C0


def test_options_list_destroy_order():
    # Chain n1 -> n2 -> n3, n2 has a child c2, n3 has a child
    # c3: the tail is destroyed first, each node followed by
    # its child subtree.
    c2 = OptionsListNode()
    c3 = OptionsListNode()
    n3 = OptionsListNode(child=c3)
    n2 = OptionsListNode(child=c2, next=n3)
    n1 = OptionsListNode(next=n2)
    freed = options_list_destroy(n1)
    assert freed == [n3, c3, n2, c2, n1]
    assert all(n.freed for n in (n1, n2, n3, c2, c3))


def test_options_list_destroy_none_and_single():
    assert options_list_destroy(None) == []
    single = OptionsListNode()
    assert options_list_destroy(single) == [single]
    assert single.freed


def test_name_set_linear_and_hash_paths():
    local = NameSet(1)
    assert local.find_name("a") is None
    for key in ("a", "b", "c"):
        h = hash_bytes(key)
        map_insert(local, h % local.bucket_count, h,
                   NameSetNode(key))
    assert local.find_name("a").key == "a"
    assert local.find_name("missing") is None
    # Past 20 elements the hash-bucket walk runs.
    for i in range(30):
        key = "k%02d" % i
        h = hash_bytes(key)
        map_insert(local, h % local.bucket_count, h,
                   NameSetNode(key))
    assert local.element_count == 33
    assert local.find_name("k17").key == "k17"
    assert local.find_name("k99") is None


def test_map_find_name_and_erase_next():
    table = OptionsMap()
    table.index("one").set("1")
    table.index("two").set("2")
    node = map_find_name(table, "two")
    assert node is not None and node.key == "two"
    assert map_find_name(table, "three") is None
    nxt = map_erase_next(table, node)
    assert table.element_count == 1
    assert map_find_name(table, "two") is None
    assert map_find_name(table, "one") is not None
    assert nxt is None or nxt.key == "one"


# --- plain host --------------------------------------------------------


def _plain_delegate(resolved=None, slot_0x50=None):
    calls = []

    def slot_0x38(name):
        calls.append(name)
        return resolved

    return ConfigNode(slot_0x38=slot_0x38, slot_0x50=slot_0x50), calls


def test_plain_null_delegate_nonfactory():
    holder = SharedHolder(obj=None)
    status = find_plain_table(Value(), "other", "", holder)
    assert status.code == 1
    assert status.msg == "Mismatched table option: : other"
    assert holder.obj is None


def test_plain_null_delegate_factory_builds_defaults():
    holder = SharedHolder(obj=None)
    created = []

    def creator(options):
        obj = plain_creator(options)
        created.append(obj)
        return obj

    status = find_plain_table(Value(), "plain_table_factory",
                              "", holder, creator=creator)
    assert status.is_ok()
    assert len(created) == 1
    assert created[0].options == plain_default_options()
    assert holder.obj is created[0]
    assert holder.control is not None
    assert holder.control.counts == PLAIN_CONTROL_COUNTS
    assert holder.control.vtable == PLAIN_CONTROL_VTABLE


def test_plain_factory_resolved_uses_resolved():
    resolved = {"resolved": True}
    delegate, calls = _plain_delegate(resolved=resolved)
    holder = SharedHolder(obj=delegate)
    seen = []

    def creator(options):
        seen.append(options)
        return plain_creator(options)

    status = find_plain_table(Value(), "plain_table_factory",
                              "", holder, creator=creator)
    assert status.is_ok()
    assert seen == [resolved]
    assert calls == ["PlainTableOptions"]
    assert holder.obj is not None


def test_plain_factory_resolved_null_uses_defaults():
    delegate, _ = _plain_delegate(resolved=None)
    holder = SharedHolder(obj=delegate)
    seen = []

    def creator(options):
        seen.append(options)
        return plain_creator(options)

    status = find_plain_table(Value(), "plain_table_factory",
                              "", holder, creator=creator)
    assert status.is_ok()
    assert seen == [plain_default_options()]


def test_plain_nonfactory_resolved_null_is_error():
    delegate, _ = _plain_delegate(resolved=None)
    holder = SharedHolder(obj=delegate)
    status = find_plain_table(Value(), "something_else", "",
                              holder)
    assert status.code == 1
    assert status.msg == "Mismatched table option: : something_else"


def test_plain_nonfactory_resolved_runs_no_equals():
    calls = []

    def slot_0x50(out, node, value, found, str_b, arg7, extra):
        calls.append((found.name, str_b, arg7))
        return Status(0, 0, None, 0)

    delegate, _ = _plain_delegate(resolved={"r": 1},
                                  slot_0x50=slot_0x50)
    delegate.elements = [TableEntry("something_else",
                                    NameTable([TableNode(
                                        "something_else")]))]

    def slot_0x68(node, key6):
        return key6

    delegate.slot_0x68 = slot_0x68
    holder = SharedHolder(obj=delegate)
    status = find_plain_table(Value(), "something_else", "",
                              holder)
    assert status.is_ok()
    assert len(calls) == 1
    assert calls[0][0] == "something_else"


def test_plain_find_e70_failure_calls_slot08_no_install():
    delegate, _ = _plain_delegate(resolved={"r": 1})
    holder = SharedHolder(obj=delegate)
    slot08_calls = []

    def creator(options):
        obj = plain_creator(options)
        obj.slot_0x40 = lambda node, value: Status(7, 0, "bad", 0)
        obj.slot_0x08 = lambda o: slot08_calls.append(o)
        return obj

    # A non-empty arg7 without ';' or '=' reaches the
    # slot-0x40 path of find_e70.
    status = find_plain_table(Value(), "plain_table_factory",
                              "plain", holder, creator=creator)
    assert status.code == 7
    assert status.msg == "bad"
    assert holder.obj is delegate  # not installed
    assert holder.control is None
    assert len(slot08_calls) == 1


def test_plain_install_releases_old_control():
    old = SharedControl(object())
    delegate, _ = _plain_delegate(resolved={"r": 1})
    holder = SharedHolder(obj=delegate, control=old)
    status = find_plain_table(Value(), "plain_table_factory",
                              "", holder)
    assert status.is_ok()
    assert holder.obj is not delegate
    assert holder.control is not old
    assert old.disposed and old.destroyed


def test_plain_find_e70_with_equals_arg7():
    delegate, _ = _plain_delegate(resolved={"r": 1})
    holder = SharedHolder(obj=delegate)
    status = find_plain_table(Value(), "plain_table_factory",
                              "k=v", holder)
    assert status.is_ok()
    assert holder.obj is not delegate


# --- block host --------------------------------------------------------


def test_block_factory_defaults_install():
    delegate, _ = _plain_delegate(resolved=None)
    holder = SharedHolder(obj=delegate)
    seen = []

    def creator(options):
        seen.append(options)
        return block_creator(options)

    status = find_block_table(Value(), "block_based_table_factory",
                              "", holder, creator=creator)
    assert status.is_ok()
    assert seen[0][0x59] == 0xA00000000000010
    assert seen[0][0xE8] == BLOCK_DEFAULTS_TEMPLATE_VALUES
    assert holder.obj is not None
    assert holder.obj.size == 0x260


def test_block_nonfactory_branches():
    delegate, _ = _plain_delegate(resolved=None)
    holder = SharedHolder(obj=delegate)
    status = find_block_table(Value(), "other", "", holder)
    assert status.code == 1
    assert status.msg == "Mismatched table option: : other"


def test_block_destroy_defaults_noop_and_active():
    # The pinned defaults carry no owned sub-objects.
    destroy_block_defaults(block_default_options())
    control = SharedControl(object())
    head = OptionsListNode()
    destroy_block_defaults({"a": control, "options_list": head})
    assert control.disposed and control.destroyed
    assert head.freed


# --- element-scan host -------------------------------------------------


def _scan_table(entries):
    """Build the element vector for find_by_element_scan:
    ``entries`` is a list of (name, kind, obj, flag_byte,
    slot_0x10_target)."""
    elements = []
    for name, kind, obj, flag_byte, target in entries:
        node = TableNode(name, kind=kind, obj=obj,
                         flag_byte=flag_byte,
                         slot_0x10_target=target)
        elements.append(TableEntry(name, NameTable([node]),
                                   field20=0))
    return elements


def _recording_serializer(calls):
    def serializer(obj, kind, value_out):
        calls.append(kind)
        value_out[0] = "ser"
        return True

    return serializer


def test_scan_miss():
    table = _scan_table([("opt", 0x13, None, 0, None)])
    arg5 = [""]
    status = find_by_element_scan(Value(), table, "nope", arg5)
    assert status.code == 1
    assert status.msg == "Cannot find option: : nope"
    assert arg5[0] == ""


def test_scan_exact_match_runs_matcher():
    table = _scan_table([("opt", 0x10, None, 0, None)])
    calls = []
    arg5 = [""]
    status = find_by_element_scan(
        Value(), table, "opt", arg5,
        serializer=_recording_serializer(calls))
    assert status.is_ok()
    assert calls == [0x10]
    assert arg5[0] == "ser"


def test_scan_kind_0x13_matcher_on_dotted_key():
    table = _scan_table([("a", 0x13, None, 0, None)])
    calls = []
    arg5 = [""]
    status = find_by_element_scan(
        Value(), table, "a.b", arg5,
        serializer=_recording_serializer(calls))
    assert status.is_ok()
    assert calls == [0x13]


def test_scan_kind_0x15_exact_match_resolver_path():
    name_obj = NameObject(slot_0x60="x=y")
    node_obj = NodeObj(name_object=name_obj)
    table = _scan_table([("opt", 0x15, node_obj, 0, None)])
    arg5 = [""]
    status = find_by_element_scan(Value(), table, "opt", arg5)
    assert status.is_ok()
    assert arg5[0] == "{x}"


def test_scan_kind_0x15_slot10_path():
    calls = []

    def slot_0x10(obj, copy, out3_holder, arg5_holder):
        calls.append((copy.name, out3_holder[0]))
        arg5_holder[0] = "v10"
        return Status.ok()

    target = Slot10Target(slot_0x10=slot_0x10)
    table = _scan_table([("a", 0x15, None, 0, target)])
    arg5 = [""]
    status = find_by_element_scan(Value(), table, "a.b", arg5)
    assert status.is_ok()
    assert calls == [(";", "b")]
    assert arg5[0] == "v10"


def test_scan_kind_0x16_slot10_deref_and_no_deref():
    calls = []

    def slot_0x10(obj, copy, out3_holder, arg5_holder):
        calls.append(obj)
        return Status.ok()

    inner = Slot10Target(slot_0x10=slot_0x10)
    outer = Slot10Target(slot_0x10=slot_0x10, deref=inner)
    # Flag byte 0x08 set -> the object is dereferenced once.
    table = _scan_table([("a", 0x16, None, 0x08, outer)])
    assert find_by_element_scan(Value(), table, "a.b",
                                [""]).is_ok()
    assert calls == [inner]
    # Flag byte clear -> the target itself is used.
    calls.clear()
    table = _scan_table([("a", 0x16, None, 0x00, outer)])
    assert find_by_element_scan(Value(), table, "a.b",
                                [""]).is_ok()
    assert calls == [outer]


def test_scan_kind_0x16_slot10_null_target_is_error():
    table = _scan_table([("a", 0x16, None, 0, None)])
    status = find_by_element_scan(Value(), table, "a.b", [""])
    assert status.code == 1
    assert status.msg == "Cannot find option: : a.b"


def test_scan_other_kind_is_error():
    table = _scan_table([("a", 0x10, None, 0, None)])
    status = find_by_element_scan(Value(), table, "a.b", [""])
    assert status.code == 1
    assert status.msg == "Cannot find option: : a.b"


def test_scan_matcher_serialize_flag_is_code3():
    table = _scan_table([("opt", 0x10, None, 0, None)])
    table[0].table.nodes[0].flags = 0x2000
    status = find_by_element_scan(Value(), table, "opt", [""])
    assert status.code == 3
    # The binary passes msg1 = the name, msg2 = the literal,
    # so the name comes first (the sibling model's pin).
    assert status.msg == "opt: Cannot serialize option: "


def test_scan_value_copy_control_released():
    control = SharedControl(object())
    value = Value(shared=control)
    table = _scan_table([("opt", 0x13, None, 0, None)])
    status = find_by_element_scan(value, table, "opt", [""])
    assert status.is_ok()
    # The copy's acquire is balanced by the exit release.
    assert control.use_count == 1
    assert not control.disposed


# --- registry walker ---------------------------------------------------


def _walker_node(codes, calls):
    """A ConfigNode whose slot-0x68 returns the element key
    and whose slot-0x50 returns the per-name code from
    ``codes`` (recording each call in ``calls``)."""

    def slot_0x68(node, key6):
        return key6

    def slot_0x50(out, node, value, found, str_b, arg7, extra):
        calls.append(found.name)
        code = codes[found.name]
        return Status(code, 0, "msg-" + found.name, 0)

    return ConfigNode(slot_0x68=slot_0x68, slot_0x50=slot_0x50)


def _walker_state(names, codes):
    """A registry map with one element per name, a name
    table with the matching nodes, and the walker node."""
    registry = OptionsMap()
    nodes = []
    for name in names:
        registry.index(name).set("v-" + name)
        nodes.append(TableNode(name, kind=0x13))
    table = NameTable(nodes)
    calls = []
    node = _walker_node(codes, calls)
    return registry, table, node, calls


def test_walker_empty_map():
    registry = OptionsMap()
    table = NameTable([])
    node = _walker_node({}, [])
    assert resolve_all_elements(Value(), node, table,
                                registry, None).is_ok()
    assert registry.element_count == 0


def test_walker_code1_advances_without_erase():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 1})
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.is_ok()
    assert calls == ["a"]
    assert registry.element_count == 1
    assert map_find_name(registry, "a") is not None


def test_walker_code0_erases():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 0})
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.is_ok()
    assert calls == ["a"]
    assert registry.element_count == 0


def test_walker_code3_accumulates_and_sweeps():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 3})
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.code == 3
    assert status.msg == "msg-a"
    # The code-3 path does not erase during the walk, but
    # the sweep phase erases the name from the registry map.
    assert registry.element_count == 0


def test_walker_code2_accumulates_status_a():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 2})
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.code == 2
    assert status.msg == "msg-a"
    assert registry.element_count == 0


def test_walker_value_byte0_wins_over_status_a():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 2})
    value = Value(code=0x01)
    status = resolve_all_elements(value, node, table,
                                  registry, None)
    assert status.is_ok()


def test_walker_value_byte1_blocks_status_b():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 3})
    value = Value(code=0x100)
    status = resolve_all_elements(value, node, table,
                                  registry, None)
    assert status.is_ok()
    # The sweep still ran.
    assert registry.element_count == 0


def test_walker_value_byte1_keeps_status_a():
    registry, table, node, calls = _walker_state(
        ["a"], {"a": 2})
    value = Value(code=0x100)
    status = resolve_all_elements(value, node, table,
                                  registry, None)
    assert status.code == 2
    assert status.msg == "msg-a"


def test_walker_outer_loop_repeats_on_erase():
    registry, table, node, calls = _walker_state(
        ["a", "b"], {"a": 0, "b": 1})
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.is_ok()
    # "a" was erased in the first pass; "b" (code 1) was
    # visited once per outer iteration, so twice in total.
    assert calls.count("a") == 1
    assert calls.count("b") == 2
    assert registry.element_count == 1
    assert map_find_name(registry, "b") is not None


def test_walker_lookup_miss_advances():
    registry = OptionsMap()
    registry.index("ghost").set("v-ghost")
    table = NameTable([])
    calls = []
    node = _walker_node({}, calls)
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.is_ok()
    assert calls == []
    assert registry.element_count == 1


def test_walker_status_b_cleared_when_list_empty():
    # A map whose count is non-zero but whose list head is
    # null: the StatusB code and sub-bytes are zeroed (the
    # message is kept) and the sweep phase runs.
    registry = OptionsMap()
    registry.element_count = 1
    registry.first = None
    table = NameTable([])
    node = _walker_node({}, [])
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.is_ok()


def test_walker_phase2_sweep_erases_by_name():
    # Two code-3 elements: both names land in the local set
    # and both are swept out of the registry map.
    registry, table, node, calls = _walker_state(
        ["a", "b"], {"a": 3, "b": 3})
    status = resolve_all_elements(Value(), node, table,
                                  registry, None)
    assert status.code == 3
    assert registry.element_count == 0


def test_addresses_pinned():
    assert FIND_PLAIN_TABLE == 0x6080B10
    assert FIND_BLOCK_TABLE == 0x60818F0
    assert FIND_BY_ELEMENT_SCAN == 0x6098AD0
    assert RESOLVE_ALL_ELEMENTS == 0x609BCB0
    assert CSTR_CTOR == 0x607D9F0
    assert MAP_FIND_NAME == 0x609A1B0
    assert MAP_ERASE_NEXT == 0x609A2F0
    assert MAP_INSERT == 0x609BAD0
    assert NAME_SET_NODE_SIZE == 0x30
    assert OPTIONS_LIST_NODE_SIZE == 0x28


# --- Find-family merge additions ---------------------------------------


def _raises(exc_type, fn, *args):
    try:
        fn(*args)
    except exc_type as exc:
        return exc
    raise AssertionError("%s did not raise %s" % (fn.__name__,
                                                   exc_type.__name__))


def test_stoull_suffixes():
    assert stoull_parse("12") == 12
    assert stoull_parse("5K") == 5120
    assert stoull_parse("5k") == 5120
    assert stoull_parse("5M") == 5 << 20
    assert stoull_parse("5G") == 5 << 30
    assert stoull_parse("5T") == 5 << 40
    assert stoull_parse("5t") == 5 << 40
    assert stoull_parse("5KB") == 5120
    assert stoull_parse("5x") == 5
    assert stoull_parse(" 42 ") == 42
    assert stoull_parse("-5") == (1 << 64) - 5
    assert stoull_parse("+7") == 7
    assert stoull_parse("1.5") == 1


def test_stoull_errors():
    exc = _raises(InvalidArgument, stoull_parse, "")
    assert exc.message == "stoull"
    exc = _raises(InvalidArgument, stoull_parse, "abc")
    assert exc.message == "stoull"
    exc = _raises(OutOfRange, stoull_parse,
                  "18446744073709551616")
    assert exc.message == "stoull"
    assert stoull_parse("18446744073709551615") == (1 << 64) - 1


def test_stoll_suffixes_and_range():
    assert stoll_parse("5T") == 5 << 40
    assert stoll_parse("-5") == -5
    assert stoll_parse("9223372036854775807") == (1 << 63) - 1
    assert stoll_parse("-9223372036854775808") == -(1 << 63)
    exc = _raises(OutOfRange, stoll_parse,
                  "9223372036854775808")
    assert exc.message == "stoll"
    exc = _raises(InvalidArgument, stoll_parse, "xx")
    assert exc.message == "stoll"


def test_stoi_t_no_shift_and_wrap():
    assert stoi_parse("5T") == 5
    assert stoi_parse("5t") == 5
    assert stoi_parse("5K") == 5120
    # "5G" wraps at 32 bits: (5 << 30) & 0xffffffff.
    assert stoi_parse("5G") == 1073741824
    assert stoi_parse("2147483647") == 2147483647
    # The range check runs BEFORE the shift: 0x7fffffff
    # passes it, then << 10 wraps to a negative i32.
    assert stoi_parse("2147483647K") == -1024
    exc = _raises(OutOfRange, stoi_parse, "2147483648")
    assert exc.message == "stoi"
    exc = _raises(InvalidArgument, stoi_parse, "")
    assert exc.message == "stoi"


def test_u8_u32_i32_range_throws_carry_input():
    assert u8_parse("255") == 255
    exc = _raises(OutOfRange, u8_parse, "256")
    assert exc.message == "256"
    assert u32_parse("4294967295") == 4294967295
    exc = _raises(OutOfRange, u32_parse, "4294967296")
    assert exc.message == "4294967296"
    assert i32_via_stoll_parse("2147483647") == 2147483647
    assert i32_via_stoll_parse("-2147483648") == -2147483648
    exc = _raises(OutOfRange, i32_via_stoll_parse,
                  "2147483648")
    assert exc.message == "2147483648"
    assert stoull_alias_parse("3M") == 3 << 20
    assert stoull_alias_parse("9") == 9


def test_bool_parser():
    assert bool_parse("true") == 1
    assert bool_parse("false") == 0
    assert bool_parse("1") == 1
    assert bool_parse("0") == 0
    exc = _raises(InvalidArgument, bool_parse, "True")
    assert exc.message == ""
    exc = _raises(InvalidArgument, bool_parse, "yes")
    assert exc.message == ""
    exc = _raises(InvalidArgument, bool_parse, "true ")
    assert exc.message == ""


def test_stod_parser():
    assert stod_parse("3.14") == 3.14
    assert stod_parse("-2.5e3") == -2500.0
    assert stod_parse("42") == 42.0
    assert stod_parse("12px") == 12.0
    exc = _raises(InvalidArgument, stod_parse, "abc")
    assert exc.message == "stod"
    exc = _raises(OutOfRange, stod_parse, "1e999")
    assert exc.message == "stod"


def test_embedded_nul_truncates_parsers():
    assert stoull_parse("12\x00junk") == 12
    assert bool_parse("true\x00x") == 1
    assert escape_assign("a\x00b") == "a"


def test_hexval_and_decode():
    assert hexval("0") == 0
    assert hexval("9") == 9
    assert hexval("a") == 10
    assert hexval("F") == 15
    assert hexval("g") == -1
    assert hexval(" ") == -1
    assert hex_decode("deadbeef") == (True, b"\xde\xad\xbe\xef")
    assert hex_decode("") == (True, b"")
    assert hex_decode("abc") == (False, b"")
    assert hex_decode("zz") == (False, b"")
    # A bad digit leaves the output PARTIALLY filled.
    assert hex_decode("dezz") == (False, b"\xde")


def test_escape_assign():
    assert escape_assign("a\\nb") == "a\nb"
    assert escape_assign("a\\rb") == "a\rb"
    assert escape_assign("a\\\\b") == "a\\b"
    assert escape_assign("a\\qb") == "aqb"
    # A trailing lone backslash is dropped.
    assert escape_assign("a\\") == "a"
    assert escape_assign("plain") == "plain"
    assert escape_decoder("r") == "\r"
    assert escape_decoder("n") == "\n"
    assert escape_decoder("x") == "x"


def test_enum_lookup_linear_and_hash_paths():
    small = EnumMap(4)
    small.insert("red", 3)
    small.insert("blue", 7)
    assert enum_lookup_u8(small, "red") == (True, 3)
    assert enum_lookup_u8(small, "blue") == (True, 7)
    assert enum_lookup_u8(small, "green") == (False, None)
    # u8 width masks; u32 keeps the full word.
    wide = EnumMap(4)
    wide.insert("big", 0x1234)
    assert enum_lookup_u8(wide, "big") == (True, 0x34)
    assert enum_lookup_u32(wide, "big") == (True, 0x1234)
    # Above 20 entries the hash walk runs.
    big = EnumMap(8)
    for i in range(25):
        big.insert("k%02d" % i, i)
    assert enum_lookup_u8(big, "k00") == (True, 0)
    assert enum_lookup_u8(big, "k24") == (True, 24)
    assert enum_lookup_u8(big, "k25") == (False, None)
    # An empty name matches only a zero-length key.
    empty = EnumMap(2)
    empty.insert("", 9)
    assert enum_lookup_u8(empty, "") == (True, 9)
    assert enum_lookup_u8(empty, "x") == (False, None)


def test_node_clone_and_rehash():
    src = OptionsMap(4)
    src.index("a").set("1")
    src.index("b").set("2")
    node = map_find_name(src, "a")
    clone = node_clone(node)
    assert clone.key == "a"
    assert clone.value == "1"
    assert clone.next is None
    # The clone does NOT carry the hash; the caller writes it.
    assert clone.hash is None
    clone.hash = node.hash
    assert clone.hash == node.hash
    # Rehash to 8 buckets keeps every key findable.
    rehash_map(src, 8)
    assert src.bucket_count == 8
    assert map_find_name(src, "a").value == "1"
    assert map_find_name(src, "b").value == "2"
    assert src.element_count == 2
    exc = _raises(ValueError, rehash_map, src, 1 << 61)
    assert "bad_array_new_length" in str(exc)


def test_clone_options_map_first_wins():
    src = OptionsMap(1)
    src.index("a").set("1")
    src.index("b").set("2")
    # One bucket: only the FIRST clone in list order
    # survives (the map prepends, so that is "b").
    cloned = clone_options_map(src)
    assert cloned.element_count == 1
    assert cloned.first.key == "b"
    assert map_find_name(cloned, "a") is None
    assert map_find_name(cloned, "b").value == "2"
    src2 = OptionsMap(16)
    for name in ("a", "d", "f"):
        src2.index(name).set("v-" + name)
    cloned2 = clone_options_map(src2)
    assert cloned2.element_count == 3
    assert [n.key for n in cloned2._nodes()] == ["f", "d", "a"]
    assert cloned2.bucket_count == 16


def _stub_walker(calls, status):
    def walker(value, desc, table, registry, extra):
        calls.append((table, extra))
        return status
    return walker


def _driver_desc(entries):
    return FindDesc(entries=entries)


def test_merge_driver_clone_first_wins_and_no_arg7_report():
    src = OptionsMap(1)
    src.index("a").set("1")
    src.index("b").set("2")
    desc = _driver_desc([TableEntry("e", NameTable([]), 0)])
    calls = []
    status = merge_driver(Value(), desc, src, None,
                          walker=_stub_walker(calls, Status.ok()))
    # The walker ran once; the clone kept only "b" (one
    # bucket, first-wins in list order); value code byte 0
    # and no walker error -> code 1. The builder renders
    # msg1 (which already ends ": ") + ": " + the key, so
    # the message carries a doubled ": ".
    assert len(calls) == 1
    assert status.code == 1
    assert status.msg == "Could not find option: : b"


def test_merge_driver_arg7_merge_fixes_error():
    src = OptionsMap(16)
    src.index("a").set("1")
    src.index("b").set("2")
    arg7 = OptionsMap(16)
    desc = _driver_desc([TableEntry("e", NameTable([]), 0)])
    calls = []
    err = Status.build(4, 0, "Error parsing:", "a")
    status = merge_driver(Value(code=1), desc, src, arg7,
                          walker=_stub_walker(calls, err))
    # Walker error + arg7: the clones merge into arg7 and
    # the value code byte (1) zeroes the status out.
    assert status.is_ok()
    assert map_find_name(arg7, "a").value == "1"
    assert map_find_name(arg7, "b").value == "2"


def test_merge_driver_arg7_null_zeroes_on_value_code():
    src = OptionsMap(16)
    src.index("a").set("1")
    desc = _driver_desc([TableEntry("e", NameTable([]), 0)])
    err = Status.build(4, 0, "Error parsing:", "a")
    status = merge_driver(Value(code=1), desc, src, None,
                          walker=_stub_walker([], err))
    assert status.is_ok()
    status = merge_driver(Value(code=0), desc, src, None,
                          walker=_stub_walker([], err))
    # Value code byte 0 keeps the walker error.
    assert status.code == 4


def test_merge_driver_skips_null_table_entries():
    src = OptionsMap(16)
    desc = _driver_desc([TableEntry("e", None, 0),
                         TableEntry("f", NameTable([]), 7)])
    calls = []
    status = merge_driver(Value(), desc, src, None,
                          walker=_stub_walker(calls, Status.ok()))
    assert len(calls) == 1
    assert calls[0][1] == 7
    assert status.is_ok()


def _find_desc(**kwargs):
    return FindDesc(**kwargs)


def test_host_a_empty_map_slot28():
    desc = _find_desc(
        slot_0x28=lambda node, value: Status.build(3, 0, "x", ""))
    # value+0x03 == 0 returns the zeroed out.
    assert host_a(desc, Value(code=0), OptionsMap(),
                  None).is_ok()
    # value+0x03 set takes the slot-0x28 path.
    status = host_a(desc, Value(code=0x01000000), OptionsMap(),
                    None)
    assert status.code == 3
    assert status.msg == "x"


def _red_serializer(obj, kind, value_out):
    """A harness serializer that writes "red" into the
    value-out and reports serialized."""
    value_out[0] = "red"
    return True


def test_host_a_semicolon_worker_driver_and_tail():
    tail_calls = []

    def slot48(out, node, value, ctx_map, flag):
        tail_calls.append(value.code)
        return Status.build(9, 0, "tail", "")

    node = TableNode("color", kind=0x09, obj=NodeObj(
        name_object=NameObject(slot_0x60="red")))
    desc = _find_desc(slot_0x48=slot48, elements=[
        WorkerElement("pfx", [node])], entries=[
        TableEntry("e", NameTable([]), 0)])
    src = OptionsMap(16)
    src.index("opt").set("v")
    # Code low byte 0 runs the ";" worker path (the worker
    # writes "color=red" into the accumulator), the driver
    # reports code 1, and the non-empty accumulator runs
    # the find_e70 tail -- whose code-9 status is DISCARDED.
    status = host_a(desc, Value(code=0x01000000, name="orig"),
                    src, None,
                    serializer=_red_serializer,
                    walker=_stub_walker([], Status.ok()))
    assert status.code == 1
    assert status.msg == "Could not find option: : opt"
    assert tail_calls == [0x01000101]


def test_host_a_tail_skipped_when_accumulator_empty():
    calls = []

    def slot28(node, value):
        calls.append(value.code)
        return Status.build(9, 0, "tail", "")

    desc = _find_desc(slot_0x28=slot28, entries=[
        TableEntry("e", NameTable([]), 0)])
    src = OptionsMap(16)
    src.index("opt").set("v")
    # A walker error keeps out non-ok, but the accumulator
    # stayed empty, so neither the slot-0x28 path nor the
    # find_e70 tail runs.
    err = Status.build(4, 0, "Error parsing:", "a")
    status = host_a(desc, Value(code=0x01000000), src, None,
                    walker=_stub_walker([], err))
    assert status.code == 4
    assert calls == []


def test_host_b_kind_arms():
    slot = ValueSlot()
    desc = _find_desc(kind=0x01)
    assert host_b(desc, Value(), "n", "42", 100,
                  slot=slot).is_ok()
    assert (slot.kind, slot.value) == (0x01, 42)
    slot = ValueSlot()
    desc = _find_desc(kind=0x05)
    assert host_b(desc, Value(), "n", "200", 100,
                  slot=slot).is_ok()
    assert slot.value == 200
    slot = ValueSlot()
    desc = _find_desc(kind=0x07)
    assert host_b(desc, Value(), "n", "7K", 100,
                  slot=slot).is_ok()
    assert slot.value == 7 << 10
    slot = ValueSlot()
    desc = _find_desc(kind=0x09)
    assert host_b(desc, Value(), "n", "hello", 100,
                  slot=slot).is_ok()
    assert slot.value == "hello"
    slot = ValueSlot()
    desc = _find_desc(kind=0x0A)
    assert host_b(desc, Value(), "n", "1.5", 100,
                  slot=slot).is_ok()
    assert slot.value == 1.5
    slot = ValueSlot()
    desc = _find_desc(kind=0x00)
    assert host_b(desc, Value(), "n", "true", 100,
                  slot=slot).is_ok()
    assert slot.value == 1


def test_host_b_enum_and_hex_arms():
    enums = EnumMap(4)
    enums.insert("fast", 2)
    enums.insert("slow", 5)
    slot = ValueSlot()
    desc = _find_desc(kind=0x0B)
    assert host_b(desc, Value(), "n", "fast", 100,
                  enum_maps={0x0B: enums}, slot=slot).is_ok()
    assert slot.value == 2
    # A missed enum lookup leaves the slot untouched and
    # still reports success.
    slot = ValueSlot()
    assert host_b(desc, Value(), "n", "missing", 100,
                  enum_maps={0x0B: enums}, slot=slot).is_ok()
    assert slot.value is None
    # Kind 0x17: the hex return is IGNORED -- a failed
    # decode still reports success with the partial bytes.
    slot = ValueSlot()
    desc = _find_desc(kind=0x17)
    assert host_b(desc, Value(), "n", "dezz", 100,
                  slot=slot).is_ok()
    assert slot.value == b"\xde"
    slot = ValueSlot()
    assert host_b(desc, Value(), "n", "beef", 100,
                  slot=slot).is_ok()
    assert slot.value == b"\xbe\xef"


def test_host_b_code3_code4_and_catch():
    slot = ValueSlot()
    desc = _find_desc(kind=0x11, ac=2)
    status = host_b(desc, Value(), "opt", "x", 100, slot=slot)
    assert status.code == 3
    assert status.msg == \
        "Deserializing the option opt is not supported"
    desc = _find_desc(kind=0x11, ac=0)
    status = host_b(desc, Value(), "opt", "x", 100, slot=slot)
    assert status.code == 4
    # msg1 "Error parsing:" + the builder's ": " + the name.
    assert status.msg == "Error parsing:: opt"
    # A parser throw is caught as code 4
    # "Error parsing <name>:<what>".
    desc = _find_desc(kind=0x01)
    status = host_b(desc, Value(), "opt", "abc", 100, slot=slot)
    assert status.code == 4
    assert status.msg == "Error parsing opt:stoi"
    desc = _find_desc(kind=0x05)
    status = host_b(desc, Value(), "opt", "300", 100, slot=slot)
    assert status.code == 4
    assert status.msg == "Error parsing opt:300"


def test_host_b_selector4_and_escape_gate():
    desc = _find_desc(kind=0x01, ac=4)
    assert host_b(desc, Value(), "n", "42", 100).is_ok()
    # value+0x02 set unescapes the options; a null base
    # then reports code 1 "Could not find option: <name>".
    desc = _find_desc(kind=0x01)
    status = host_b(desc, Value(code=0x10000), "n", "a\\nb",
                    0)
    assert status.code == 1
    assert status.msg == "Could not find option: n"
    # The same value with a base parses the unescaped text.
    slot = ValueSlot()
    assert host_b(desc, Value(code=0x10000), "n", "42", 100,
                  slot=slot).is_ok()
    assert slot.value == 42


def test_host_b_delegate_path():
    calls = []

    def slot20(desc, value, name, options, value_ptr):
        calls.append((name, options, value_ptr))
        return Status.build(7, 0, "delegated", "")

    desc = _find_desc(kind=0x01, delegate_present=True,
                      slot_0x20=slot20, offset=16)
    status = host_b(desc, Value(), "n", "x", 100)
    assert status.code == 7
    assert calls == [("n", "x", 116)]


def test_worker_wrapper_and_worker():
    # A node whose matcher serializes "red" into the
    # accumulator as name=value, with no ';' separator
    # between pairs.
    node = TableNode("color", kind=0x09, obj=NodeObj(
        name_object=NameObject(slot_0x60="red")))
    node2 = TableNode("size", kind=0x09, obj=NodeObj(
        name_object=NameObject(slot_0x60="red")))
    delegate = _find_desc(elements=[
        WorkerElement("pfx", [node, node2])])
    status, acc = worker_wrapper(delegate, Value(),
                                 serializer=_red_serializer)
    assert status.is_ok()
    assert acc == "color=redsize=red"


def test_host_addresses_pinned():
    assert HOST_A == 0x609D0E0
    assert HOST_B == 0x60BEDC0
    assert MERGE_DRIVER == 0x609C8C0
    assert WORKER_WRAPPER == 0x6098510
    assert WORKER == 0x6097630
    assert RANGE_CTOR == 0x60B7CD0
    assert NODE_CLONE == 0x6095B80
    assert REHASH == 0x5D38260
    assert ESCAPE_ASSIGN == 0x61D10A0
    assert ESCAPE_DECODER == 0x61D0EE0
    assert BOOL_PARSER == 0x61D1480
    assert STOULL_PARSER == 0x61D1540
    assert STOULL_ALIAS == 0x61D1EF0
    assert U8_PARSER == 0x61D17D0
    assert U32_PARSER == 0x61D1840
    assert STOLL_PARSER == 0x61D18A0
    assert I32_PARSER == 0x61D1B30
    assert STOI_PARSER == 0x61D1B90
    assert STOD_PARSER == 0x61D1E30
    assert HEX_DECODE == 0x61C7FC0
    assert HEXVAL == 0x61C7DC0
    assert ENUM_LOOKUP_U8_A == 0x60BE160
    assert ENUM_LOOKUP_U32 == 0x60BE7F0
    assert ENUM_LOOKUP_U8_F == 0x60BE940
    assert STOULL_SUFFIX_TABLE == 0x97E998
    assert STOLL_SUFFIX_TABLE == 0x97EA50
    assert HOST_B_KIND_TABLE == 0x9786B4
    assert MSG_SEMICOLON_SPACE == "; "
    assert MSG_COULD_NOT_FIND_OPTION == "Could not find option"
    assert MSG_COULD_NOT_FIND_CONFIGURABLE == \
        "Could not find configurable: "
    assert MSG_ERROR_PARSING_COLON == "Error parsing:"
    assert MSG_ERROR_PARSING_SPACE == "Error parsing "
    assert MSG_DESERIALIZING_OPTION == "Deserializing the option "
    assert MSG_IS_NOT_SUPPORTED == " is not supported"
    assert MSG_EQUALS == "="

def _run_all():
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    for name, fn in fns:
        fn()
        print("ok", name)
    print("all %d tests passed" % len(fns))


if __name__ == "__main__":
    _run_all()
