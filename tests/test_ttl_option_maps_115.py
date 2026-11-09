import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from ttl_option_maps_115 import (EMPTY_MAP, INITIALIZER, INSERT_HELPER,
                                 MAP_ENTRIES, entry_for, lookup,
                                 pack_source, ttl_has_own_pack_and_flags)


def test_four_maps_each_hold_one_entry():
    assert len(MAP_ENTRIES) == 4
    for addr in (0x6509480, 0x6509440, 0x6509400, 0x65093C0):
        assert entry_for(addr) is not None


def test_keys_are_the_initializer_keys():
    assert entry_for(0x6509480)["key"] == "user_operator"
    assert entry_for(0x6509440)["key"] == "ttl"
    assert entry_for(0x6509400)["key"] == "user_filter_factory"
    assert entry_for(0x65093C0)["key"] == "user_filter"


def test_three_entries_carry_type_22_and_ttl_carries_type_2():
    for addr in (0x6509480, 0x6509400, 0x65093C0):
        entry = entry_for(addr)
        assert entry["type"] == 22
    ttl = entry_for(0x6509440)
    assert ttl["type"] == 2
    assert ttl["pack"] == 0x2
    assert ttl["verification"] == 0


def test_only_user_filter_factory_carries_verification_3():
    for addr, entry in ((a, entry_for(a)) for a in MAP_ENTRIES):
        if addr == 0x6509400:
            assert entry["verification"] == 3
            assert entry["pack"] == 0x300000016
        elif addr == 0x6509440:
            assert entry["verification"] == 0
        else:
            assert entry["verification"] == 1
            assert entry["pack"] == 0x100000016


def test_only_user_filter_carries_flags_0x1200_and_ttl_carries_zero():
    for addr in MAP_ENTRIES:
        entry = entry_for(addr)
        if addr == 0x65093C0:
            assert entry["flags"] == 0x1200
        elif addr == 0x6509440:
            assert entry["flags"] == 0x0
        else:
            assert entry["flags"] == 0x400


def test_insert_sites_are_the_initializer_inserts():
    assert entry_for(0x6509480)["insert_site"] == 0x62070C2
    assert entry_for(0x6509440)["insert_site"] == 0x620726B
    assert entry_for(0x6509400)["insert_site"] == 0x620740B
    assert entry_for(0x65093C0)["insert_site"] == 0x6207575


def test_pack_sources():
    assert pack_source(0x6509480) == "got:0x458f68"
    assert pack_source(0x6509440) == "immediate"
    assert pack_source(0x6509400) == "got:0x4594e8"
    assert pack_source(0x65093C0) == "got:0x458f68"


def test_ttl_carries_its_own_pack_and_flags():
    assert ttl_has_own_pack_and_flags()


def test_lookup_matches_only_the_inserted_key():
    assert lookup(0x6509440, "ttl")
    assert not lookup(0x6509440, "user_filter")
    assert lookup(0x65093C0, "user_filter")
    assert not lookup(0x65093C0, "ttl")
    assert not lookup(EMPTY_MAP, "ttl")


def test_initializer_and_insert_helper_addresses():
    assert INITIALIZER == 0x6206EF0
    assert INSERT_HELPER == 0x5D405B0
    assert entry_for(EMPTY_MAP) is None
