"""Tests for the node #115 ObjectLibrary registry model (RE-001).

End-to-end: Default -> register MockEnv/CompositeEnv -> default-init
TimeEmulatedSystemClock -> count (keys=2, total=3) -> find-or-insert
hit/miss + rehash -> vector-insert growth -> PatternEntry match
modes -> dispose/destroy order. Boundary and corruption controls
cover the matcher edges the binary pins.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from objectlibrary_registry_115 import (
    ObjectLibrary, PatternEntry, SubPattern, UnorderedMap,
    vector_insert, _elem_match, _str_match,
    REGISTRY_NAME, ENVIRONMENT_KEY, SYSTEMCLOCK_KEY,
    MOCK_ENV_PATTERN, COMPOSITE_ENV_PATTERN, TIME_EMULATED_PATTERN,
    FRESH_COUNTS, HASH_SEED, CONTROL_BLOCK_SIZE, MAP_NODE_SIZE,
    PATTERN_ENTRY_SIZE, FACTORY_NODE_SIZE,
)


def _fresh_registry():
    reg = ObjectLibrary.default()
    assert reg.name == REGISTRY_NAME
    assert reg.map.bucket_count == 1
    assert reg.map.element_count == 0
    return reg


def test_default_is_empty_single_bucket():
    reg = _fresh_registry()
    keys, total = reg.count()
    assert (keys, total) == (0, 0)


def test_register_two_env_entries_under_environment():
    reg = _fresh_registry()
    reg.register()
    keys, total = reg.count()
    assert (keys, total) == (1, 2)
    vec = reg.map.find(ENVIRONMENT_KEY)
    assert vec is not None and len(vec) == 2
    assert [n.entry.pattern for n in vec] == [
        MOCK_ENV_PATTERN, COMPOSITE_ENV_PATTERN]
    assert [n.kind for n in vec] == ["Env", "Env"]
    # The map rehashed out of its single bucket on the first key.
    assert reg.map.bucket_count >= 2
    assert reg.map.element_count == 1


def test_register_is_once_only():
    reg = _fresh_registry()
    reg.register()
    reg.register()
    keys, total = reg.count()
    assert (keys, total) == (1, 2)


def test_default_init_uses_systemclock_key():
    reg = _fresh_registry()
    reg.default_init()
    keys, total = reg.count()
    assert (keys, total) == (1, 1)
    vec = reg.map.find(SYSTEMCLOCK_KEY)
    assert vec is not None and len(vec) == 1
    assert vec[0].entry.pattern == TIME_EMULATED_PATTERN
    assert vec[0].kind == "SystemClock"
    assert reg.map.find(ENVIRONMENT_KEY) is None


def test_full_sequence_counts_two_keys_three_entries():
    reg = _fresh_registry()
    reg.register()
    reg.default_init()
    # Second calls are pthread_once no-ops: no duplicates.
    reg.register()
    reg.default_init()
    keys, total = reg.count()
    assert (keys, total) == (2, 3)
    assert reg.map.element_count == 2


def test_find_or_insert_hit_returns_same_vector():
    m = UnorderedMap()
    v1 = m.find_or_insert("Environment")
    v1.append("x")
    v2 = m.find_or_insert("Environment")
    assert v2 is v1
    assert v2 == ["x"]
    assert m.element_count == 1


def test_find_or_insert_miss_and_rehash_keeps_keys():
    m = UnorderedMap()
    keys = ["Environment", "SystemClock", "SliceTransform", "FileSystem",
            "RandomAccessFile", "WritableFile", "Logger", "Comparator"]
    for k in keys:
        m.find_or_insert(k).append(k)
    assert m.element_count == len(keys)
    assert m.bucket_count > 1
    for k in keys:
        assert m.find(k) == [k]
    assert m.find("NoSuchKey") is None


def test_vector_insert_order_and_growth():
    vec = ["a", "b", "c"]
    vector_insert(vec, 1, "X")
    assert vec == ["a", "X", "b", "c"]
    vector_insert(vec, 4, "Y")
    assert vec == ["a", "X", "b", "c", "Y"]
    vector_insert(vec, 0, "Z")
    assert vec == ["Z", "a", "X", "b", "c", "Y"]
    # The binary moves the value out of the source slot, zeroing
    # it; the caller-side slot is cleared after the move.
    slot = ["node"]
    vector_insert(vec, 0, slot[0])
    slot[0] = None
    assert vec[0] == "node"
    assert slot[0] is None


def test_vector_insert_out_of_range():
    vec = ["a"]
    try:
        vector_insert(vec, 5, "X")
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")


def test_pattern_exact_match_and_flag():
    e = PatternEntry("MockEnv")
    assert e.matches("MockEnv") is True
    assert e.matches("MockEn") is False
    assert e.matches("MockEnvX") is False
    assert e.matches("") is False
    # Flag off blocks the equal-length path when a sub-pattern
    # vector is present.
    e.elements.append(SubPattern("x", 2))
    e.flag = 0
    assert e.matches("MockEnv") is False
    e.flag = 1
    assert e.matches("MockEnv") is True


def test_pattern_subpattern_strings():
    e = PatternEntry("MockEnv")
    e.subpatterns.append("OtherEnv")
    assert e.matches("OtherEnv") is True
    assert e.matches("MockEnv") is True
    assert e.matches("Neither") is False


def test_pattern_empty_vector_is_exact_only():
    e = PatternEntry("ab")
    assert e.matches("ab") is True
    # No sub-patterns: a longer query cannot match by prefix.
    assert e.matches("abc") is False
    assert e.matches("a") is False


def test_matcher_mode2_prefix_then_end():
    e = PatternEntry("ab")
    # Sub-pattern "cd" with mode 2: must occur at pos 2, and the
    # tail (governed by that element's mode, 2) requires the end.
    e.elements.append(SubPattern("cd", 2))
    assert e.matches("abcd") is True
    assert e.matches("abcde") is False
    assert e.matches("abce") is False
    # Exact pattern match short-circuits: the elements only gate
    # the prefix path, so "ab" matches without consulting them.
    assert e.matches("ab") is True
    # A query that starts with the pattern but cannot fit the
    # sub-pattern fails.
    assert e.matches("abx") is False


def test_matcher_mode_lag():
    # The mode governing element i+1 lives in element i's +0x20
    # field; element 0 is governed by the initial mode 2. Here
    # element 0 ("cd", mode 3) is matched in mode 2 (at pos), and
    # its mode 3 governs the tail: the remainder must be digits.
    e = PatternEntry("ab")
    e.elements.append(SubPattern("cd", 3))
    assert e.matches("abcd123") is True
    assert e.matches("abcd") is False  # mode 3 tail needs digits
    assert e.matches("abcd12x") is False


def test_matcher_mode3_gap_digits():
    e = PatternEntry("ab")
    # Mode 3 for element 1 lives in element 0's +0x20 field:
    # element 0 ("xy") is matched in the initial mode 2, element
    # 1 ("zz") is matched in mode 3: find "zz" after pos+1, the
    # gap (after an optional '-') must be all digits.
    e.elements.append(SubPattern("xy", 3))
    e.elements.append(SubPattern("zz", 2))
    assert e.matches("abxy123zz") is True
    assert e.matches("abxy-123zz") is True
    assert e.matches("abxy12azz") is False
    assert e.matches("abxyzz") is False


def test_matcher_mode4_gap_dotted_digits():
    e = PatternEntry("ab")
    e.elements.append(SubPattern("xy", 4))
    e.elements.append(SubPattern("zz", 2))
    assert e.matches("abxy1.5zz") is True
    assert e.matches("abxy1.5.2zz") is False  # two dots
    assert e.matches("abxy1azz") is False
    assert e.matches("abxy.zz") is False  # no digit in the gap


def test_matcher_mode0_search_anywhere():
    e = PatternEntry("ab")
    # Element 0's mode 0 governs element 1 ("zz"): find "zz"
    # anywhere after pos+1. Element 1's mode 0 governs the tail,
    # which accepts any remainder.
    e.elements.append(SubPattern("cd", 0))
    e.elements.append(SubPattern("zz", 0))
    assert e.matches("abcd--zz--") is True
    assert e.matches("abcd") is False  # "zz" never found


def test_elem_match_modes_directly():
    e = PatternEntry("ab")
    assert _elem_match(e, 0, "abcd", 2, SubPattern("ab", 2)) == 2
    assert _elem_match(e, 0, "abce", 2, SubPattern("ab", 2)) == 2
    assert _elem_match(e, 1, "xabcd", 2, SubPattern("ab", 2)) == 3
    assert _elem_match(e, 0, "xabcd", 2, SubPattern("ab", 2)) == -1
    assert _elem_match(e, 1, "xacbd", 2, SubPattern("ab", 2)) == -1
    assert _elem_match(e, 0, "xxab", 0, SubPattern("ab", 0)) == 4
    assert _elem_match(e, 0, "xxab", 1, SubPattern("ab", 1)) == 4
    assert _elem_match(e, 0, "ab", 0, SubPattern("", 0)) == 1
    assert _elem_match(e, 0, "ab", 2, SubPattern("", 2)) == 0
    assert _elem_match(e, 0, "a", 2, SubPattern("ab", 2)) == -1


def test_str_match_boundaries():
    e = PatternEntry("ab")
    assert _str_match(e, "ab", "ab") is True
    assert _str_match(e, "ab", "") is False
    assert _str_match(e, "", "ab") is False
    assert _str_match(e, "", "") is True
    # offset (+0x50) raises the lower bound on the query length:
    # qlen must reach offset + plen = 2 + 2 = 4.
    e.offset = 2
    e.elements.append(SubPattern("cd", 2))
    assert _str_match(e, "ab", "abc") is False  # 3 < 4
    assert _str_match(e, "ab", "abcd") is True  # 4 == 4
    assert _str_match(e, "ab", "abcdef") is False  # tail: 4 != 6
    e.offset = 0


def test_dispose_destroys_map_and_entries():
    reg = _fresh_registry()
    reg.register()
    reg.default_init()
    nodes = []
    for head in reg.map.buckets:
        node = head
        while node is not None:
            nodes.extend(node.values)
            node = node.next
    assert len(nodes) == 3
    reg.dispose()
    assert reg.destroyed is True
    assert reg.name == ""
    assert reg.map.destroyed is True
    assert reg.map.element_count == 0
    assert all(n.destroyed for n in nodes)
    assert all(n.entry.destroyed for n in nodes)
    keys, total = reg.count()
    assert (keys, total) == (0, 0)


def test_get_deleter_tag_only():
    reg = _fresh_registry()
    assert reg.get_deleter("St19_Sp_make_shared_tag") is reg
    assert reg.get_deleter("St23_Sp_counted_ptr_inplaceIN7rocksdb13ObjectLibraryESaIvELN9__gnu_cxx12_Lock_policyE2EE") is None
    assert reg.get_deleter("*St19_Sp_make_shared_tag") is None


def test_pinned_constants():
    assert FRESH_COUNTS == 0x100000001
    assert HASH_SEED == 0xC70F6907
    assert CONTROL_BLOCK_SIZE == 0x90
    assert MAP_NODE_SIZE == 0x48
    assert PATTERN_ENTRY_SIZE == 0x70
    assert FACTORY_NODE_SIZE == 0x30
    assert ENVIRONMENT_KEY == "Environment"
    assert SYSTEMCLOCK_KEY == "SystemClock"


def test_node_forwarders():
    reg = _fresh_registry()
    reg.register()
    vec = reg.map.find(ENVIRONMENT_KEY)
    node = vec[0]
    assert node.matches("MockEnv") is True
    assert node.matches("CompositeEnv") is False
    assert node.pattern() == MOCK_ENV_PATTERN
