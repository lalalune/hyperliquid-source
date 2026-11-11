"""Tests for the CompositeEnvWrapper option maps (node #115).

Grounding: research/work-items/RE-001-composite-env-maps-115/ (records.json,
maps.tsv, whole-function excerpts of the static initializer 0x5fe0760 and
the insert helper 0x5d405b0). Resolves merged PR #3950's open unknown about
the three maps' contents.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from composite_env_maps_115 import (  # noqa: E402
    CALLBACK_PAIRS,
    DIGEST,
    INSERT_HELPER,
    MAPS,
    MAP_DESTRUCTOR,
    REGISTRATIONS_3950,
    all_keys,
    decode_pack,
    lookup,
    option_type,
    verification,
)


def test_digest_is_full_64_char_sha256():
    assert len(DIGEST) == 64
    assert DIGEST == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def test_three_maps_one_entry_each():
    assert len(MAPS) == 3
    assert sorted(all_keys()) == ["clock", "file_system", "target"]


def test_target_entry():
    e = MAPS[0x6504C60]
    assert e["key"] == "target"
    assert e["key_literal"] == 0x44A390
    assert e["insert_site"] == 0x5FE0B4A
    assert e["atexit_site"] == 0x5FE0BEE
    assert e["group_base"] == "object+0x48 (Env*)"


def test_file_system_entry():
    e = MAPS[0x6504C20]
    assert e["key"] == "file_system"
    assert e["key_literal"] == 0x44B349
    assert e["insert_site"] == 0x5FE0D4B
    assert e["atexit_site"] == 0x5FE0D7F


def test_clock_entry():
    e = MAPS[0x6504BE0]
    assert e["key"] == "clock"
    assert e["key_literal"] == 0x4496D9
    assert e["insert_site"] == 0x5FE0ED1
    assert e["atexit_site"] == 0x5FE0F1A


def test_pack_decodes():
    assert decode_pack(0x10000001A) == (26, 1)
    assert decode_pack(0x100000016) == (22, 1)
    assert option_type(0x6504C60) == 26
    assert verification(0x6504C60) == 1
    assert option_type(0x6504C20) == 22
    assert option_type(0x6504BE0) == 22
    assert verification(0x6504C20) == 1
    assert verification(0x6504BE0) == 1


def test_flags_differ_by_entry():
    assert MAPS[0x6504C60]["flags"] == 0x2000  # target
    assert MAPS[0x6504C20]["flags"] == 0x400   # file_system
    assert MAPS[0x6504BE0]["flags"] == 0x400   # clock


def test_lookup_hit_and_miss():
    assert lookup(0x6504C60, "target")["key_literal"] == 0x44A390
    assert lookup(0x6504C20, "file_system") is not None
    assert lookup(0x6504BE0, "clock") is not None
    assert lookup(0x6504C60, "file_system") is None  # wrong map
    assert lookup(0x6504C60, "env") is None          # no such key
    assert lookup(0x6504C00, "target") is None       # no such map


def test_registrations_from_3950_match_maps():
    assert len(REGISTRATIONS_3950) == 3
    for reg in REGISTRATIONS_3950:
        assert reg["name"] == ""  # empty-named groups
        assert reg["map"] in MAPS
        assert MAPS[reg["map"]]["group_base"] == reg["base"]


def test_insert_helper_and_destructor():
    assert INSERT_HELPER == 0x5D405B0
    assert MAP_DESTRUCTOR == 0x5D3F820


def test_callback_pairs_resolve_to_named_invokes():
    assert len(CALLBACK_PAIRS) == 2
    assert CALLBACK_PAIRS[0]["resolved"] == (0x5FCC660, 0x5FD4C30)
    assert CALLBACK_PAIRS[1]["resolved"] == (0x5FD5460, 0x5FD7470)
    # The second element of each pair is the vendor-census-named
    # AsCustomSharedPtr _M_invoke function.
    assert CALLBACK_PAIRS[0]["resolved"][1] == 0x5FD4C30
    assert CALLBACK_PAIRS[1]["resolved"][1] == 0x5FD7470


def test_insert_sites_are_inside_initializer_in_order():
    sites = sorted(m["insert_site"] for m in MAPS.values())
    assert sites == [0x5FE0B4A, 0x5FE0D4B, 0x5FE0ED1]
    assert all(0x5FE0760 <= s < 0x5FE0FBC for s in sites)


def test_keys_are_distinct_and_maps_distinct():
    assert len({m["key"] for m in MAPS.values()}) == 3
    assert len({m["key_literal"] for m in MAPS.values()}) == 3
    assert len({m["insert_site"] for m in MAPS.values()}) == 3
