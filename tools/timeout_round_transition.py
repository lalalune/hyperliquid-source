#!/usr/bin/env python3
"""RE-008: node #94 timeout admission and bounded round-transition evidence.

This is a static, fail-closed collector.  It does not execute the captured
node.  It verifies the target digest, FDE bounds, relocation-backed calls,
rel32 call targets, complete bytes for bounded CFG blocks, and the exact
instructions supporting the reported state-offset observations.

The earlier ``consensus_wire`` packet owns verifier discovery and the shared
quorum predicate.  This collector starts at the newly located state-machine
callers and follows only the bounded path into one round update.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"
EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

_SPEC = importlib.util.spec_from_file_location("consensus_wire", ROOT / "tools/consensus_wire.py")
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError("cannot load tools/consensus_wire.py")
_CW = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CW)
Elf = _CW.Elf
EvidenceError = _CW.EvidenceError
containing = _CW.containing
fde_index = _CW.fde_index
relative_relocs = _CW.relative_relocs

# FDE ends are exclusive.  Names are evidence labels, not recovered symbols.
FUNCTIONS = {
    "state_dispatch": (0x44ADFA0, 0x44B303A),
    "round_transition": (0x44B6670, 0x44B7E10),
    "verify_signed_timeout": (0x454AA10, 0x454AD45),
    "verify_timeout_certificate": (0x47594F0, 0x4759963),
    "post_tc_helper_unknown": (0x47593A0, 0x47594E3),
    "validator_snapshot_by_round": (0x4B31D40, 0x4B31E61),
    "total_stake": (0x4B33770, 0x4B33988),
    "signed_key_stake_intersection": (0x4B33990, 0x4B33EA9),
    "tc_key_collection_helper": (0x4451690, 0x445189C),
    "remaining_timeout_verifier_unknown": (0x4768F80, 0x47694D3),
}

# Every byte in each interval is retained in the JSON.  The intervals are
# deliberately small and end at verified instruction boundaries.  Edges are
# exhaustive for each interval's final direct branch; calls are listed below.
BLOCKS = (
    ("tc_round_guard", 0x44AF4FD, 0x44AF52C, "406499e5ef8e38e09c930831acc173c8be31a2da67e6ba51e4528a2846c8b514"),
    ("tc_verify_result", 0x44AF52C, 0x44AF560, "687b2059364e6cd4cd6ea42657e5df840a423022d81ffd3516bc2a3b929b51ee"),
    ("tc_post_verify_result", 0x44AF560, 0x44AF58D, "4b34622b32c6c577183a8e3f15cdfeab0665211bb623b3116ecb321c1d1e858e"),
    ("tc_register_and_dispatch", 0x44AF58D, 0x44AF5F5, "cdf2f2cf3761d2861ddfa89d301222ddb9d0f14c3f16bb066311672d2f5d0103"),
    ("tc_round_call", 0x44B1797, 0x44B17D8, "f66802e75d4f57efb13275e26caccac80cb4ec05191d034a0a6498bf4c18c2c0"),
    ("tc_round_false", 0x44B17D8, 0x44B17DA, "43a3e11864f597c6c6d1eb099da74062bbfe5a29140e46ab0edc3190a36332f4"),
    ("timeout_round_guard", 0x44B0356, 0x44B036E, "df17ced8c6a861af4f5184737c2c38388b97286be99744af2f8511d904c7bd54"),
    ("timeout_duplicate_guard", 0x44B036E, 0x44B0391, "24ed4dc64edc55d30d18ada597e9346f8d32baed22548d356e2249fd4aad80aa"),
    ("timeout_verify_result", 0x44B1548, 0x44B1583, "917b70f96131e302558ea6db0eed2843d2db9cd12903afeb66d52195343658d1"),
    ("timeout_seen_round_update", 0x44B1583, 0x44B15D7, "11e4f82c438beebe509fe870fdd075e1880a21ed7ea8ed355267b38eb137cd1d"),
    ("timeout_snapshot_result", 0x44B15D7, 0x44B1613, "fdb46530329d65ba535a85a99ecef38d8642a0f33aaf632b048b1d04a82db0db"),
    ("timeout_insert_result", 0x44B1613, 0x44B1677, "e0f30fa7f84f5a2881669129b44f6e55541a33737b4315dc2fc5a80707945922"),
    ("stake_inputs_cleanup_guard", 0x44B24BA, 0x44B24D9, "72ed7ce192fd2913e4183ede5a52330717fc870b5467e2fdbd54067dc6181695"),
    ("stake_inputs_cleanup", 0x44B24D9, 0x44B24F1, "e9da1abf4ca9bd84ee2bd30871a3276929fd7a4a01364f8968834babae428bdf"),
    ("stake_calculation", 0x44B24F1, 0x44B2524, "ec241fb1bfe0172de946841818909926419080252e7b33f7a338ad6831fd1e9f"),
    ("pre_quorum_overflow", 0x44B2524, 0x44B2535, "e2b420991014d3d6c299037d6f42877a73010af636572b4bef7ad3b01012dac3"),
    ("pre_quorum_compare", 0x44B2535, 0x44B253A, "d9f0e58365eafbe68b8cf3fbde0e0879fcc8fa495c001ca167114c3479cfdead"),
    ("pre_quorum_callback", 0x44B253A, 0x44B2544, "65a15be71bbc4ac0f9d480a5a26aa7e75d05a48fed22c9017cb31fcb313118cd"),
    ("strict_quorum", 0x44B2544, 0x44B2565, "886517fef019a656fce90896d39ecf158d93cd6818bb2bc23d5008e52fe363c4"),
    ("accepted_move_guard", 0x44B2565, 0x44B2592, "8226c6d178b00d95f4bd8f52da28a92dd32cc26a62a5632e400eb5963044b6e5"),
    ("accepted_move_tail", 0x44B2592, 0x44B2599, "d8eceb47eeca3d65009a0e2dd4cbe4c1895ede3d6e29978f74cd099a3e2c8c88"),
    ("accepted_build_and_dispatch", 0x44B2599, 0x44B2636, "bff51b88d44d28c499f03ccdf2eb97d24deb8513afc9ca5f790bbb82673a5e2e"),
    ("accepted_notify", 0x44B2636, 0x44B2646, "a5a394c46f22223180b5f31fd5d9b934c52306efdff5bea2b3301b2215ea30aa"),
    ("round_entry_guard", 0x44B6670, 0x44B66A7, "6139037d7ea6baaae54a988327df5bf3b62da25645745c13f08e22e557ad1b81"),
    ("round_update_payload_guard", 0x44B66A7, 0x44B66DA, "bf84800b74feccfbfa8c3b3ac9fdd24e91062c7c9d2ab43559c51dda686e4e0a"),
    ("round_update_jump", 0x44B66DA, 0x44B66E6, "ab7fd75b05b6293718d2ed365edd4a2d56d42842469c7db1c1b2215cea2dc01a"),
    ("round_stale_cleanup_guard", 0x44B66E6, 0x44B66F6, "bb393ea9c617b147c634d92298180517a99834d7553d99b809840be5818e2676"),
    ("tc_verifier_round_guard", 0x47594F0, 0x475951F, "c6e20fdbadb434b79201bffd53ac0117074366be168e638d64ba18a76ac10bd8"),
    ("tc_verifier_snapshot_result", 0x475959D, 0x47595B2, "5cda870bf5d8bdafc3d413c7596d76dc32960cfd2a80c2d3afb4966546650e66"),
    ("tc_verifier_nonempty", 0x47595E1, 0x47595EE, "72ef6abdae694cebedfb2ea406e38888ce3b49b60dd99234ee4e801e783c5000"),
    ("tc_verifier_record_round", 0x4759600, 0x475960A, "52b0d8171a9e00ae1d490b5b7c8128db6f3cbf2b6c4269d2f5439707139e2eef"),
    ("tc_verifier_loop", 0x475960A, 0x4759615, "5117dc578384ecbdbbddb52579feb056a41c207c8148a3d0b097cbc7e26a4378"),
    ("tc_verifier_first_signature_result", 0x475971F, 0x475975E, "8d5e8e99acbcbe1ebba2830a9b6e8d29b9fb11f42b30e4daad3499b27b5e3da5"),
    ("tc_verifier_remaining_result", 0x47597F4, 0x4759845, "ca22ff405b1033274a50250eab03ff9becb2740347b75c5c0024822c9c59c844"),
    ("tc_verifier_quorum", 0x4759845, 0x4759881, "6b48a6321861ae04c08001859f6ba3355357b83584dc4695a5c954b2dbf0f748"),
    ("tc_verifier_quorum_result", 0x4759920, 0x475993F, "cc707c2995e1f0eb13fd6a933bd49a0f6c7ef21e2a715a933770557bcea7dc46"),
    ("tc_verifier_quorum_reject", 0x475993F, 0x4759948, "c2cdf1d4e96b27ffe1d411b4afe39afa9f48d34f4ddc913e2779437e8cc524e8"),
    ("stake_key_compare", 0x4B33BE0, 0x4B33C16, "ec83c3923748e8b2b0527d0d06d2f39aac25b0f5b5bc8484885c0bc1742cf9f9"),
    ("stake_match_add", 0x4B33C60, 0x4B33C75, "94622a1cc95f7b4fc4a39bdf8e049aa11fe08bbfef8f773a55028f7b08af77d9"),
)

# Direct terminators for the bounded blocks.  All fallthroughs are equal to
# the block end.  Blocks omitted here have a single fallthrough edge.
TERMINATORS = {
    "tc_round_guard": (0x44AF526, "conditional", 0x44B13DE),
    "tc_verify_result": (0x44AF55A, "conditional", 0x44B13D1),
    "tc_post_verify_result": (0x44AF587, "conditional", 0x44B178A),
    "tc_register_and_dispatch": (0x44AF5F0, "jump", 0x44B1797),
    "tc_round_call": (0x44B17D6, "conditional", 0x44B1811),
    "tc_round_false": (0x44B17D8, "jump", 0x44B181C),
    "timeout_round_guard": (0x44B0368, "conditional", 0x44B0A4D),
    "timeout_duplicate_guard": (0x44B038B, "conditional", 0x44B1548),
    "timeout_verify_result": (0x44B157D, "conditional", 0x44B2313),
    "timeout_snapshot_result": (0x44B160D, "conditional", 0x44B23AB),
    "timeout_insert_result": (0x44B1675, "conditional", 0x44B1694),
    "stake_inputs_cleanup_guard": (0x44B24D7, "conditional", 0x44B24F1),
    "pre_quorum_overflow": (0x44B252F, "conditional", 0x44B28A7),
    "pre_quorum_compare": (0x44B2538, "conditional", 0x44B2544),
    "strict_quorum": (0x44B255F, "conditional", 0x44B181C),
    "accepted_move_guard": (0x44B2590, "conditional", 0x44B2599),
    "accepted_build_and_dispatch": (0x44B2630, "conditional", 0x44B181C),
    "accepted_notify": (0x44B2641, "jump", 0x44B181C),
    "round_entry_guard": (0x44B66A5, "conditional", 0x44B66E6),
    "round_update_payload_guard": (0x44B66D8, "conditional", 0x44B674D),
    "round_update_jump": (0x44B66E1, "jump", 0x44B6853),
    "round_stale_cleanup_guard": (0x44B66F0, "conditional", 0x44B7AE2),
    "tc_verifier_round_guard": (0x4759519, "conditional", 0x47595A1),
    "tc_verifier_snapshot_result": (0x47595AC, "conditional", 0x4759655),
    "tc_verifier_nonempty": (0x47595E8, "conditional", 0x4759673),
    "tc_verifier_record_round": (0x4759608, "conditional", 0x475967F),
    "tc_verifier_loop": (0x4759613, "conditional", 0x4759600),
    "tc_verifier_first_signature_result": (0x475975C, "conditional", 0x47597BD),
    "tc_verifier_remaining_result": (0x4759843, "conditional", 0x47598B8),
    "tc_verifier_quorum": (0x475987F, "conditional", 0x47598F9),
    "tc_verifier_quorum_result": (0x4759939, "conditional", 0x4759677),
    "tc_verifier_quorum_reject": (0x4759943, "jump", 0x4759677),
    "stake_key_compare": (0x4B33C14, "conditional", 0x4B33C60),
    "stake_match_add": (0x4B33C6F, "conditional", 0x4B33E9A),
}

CALLS = (
    ("direct_tc_verify", 0x44AF543, "rel32", None, 0x47594F0),
    ("post_tc_helper_unknown", 0x44AF570, "rel32", None, 0x47593A0),
    ("register_client_state_unknown", 0x44AF5EB, "rel32", None, 0x44AB560),
    ("direct_tc_round_transition", 0x44B17CF, "rel32", None, 0x44B6670),
    ("timeout_verify", 0x44B1560, "rel32", None, 0x454AA10),
    ("validator_snapshot_by_round", 0x44B15EA, "slot", 0x57769E8, 0x4B31D40),
    ("timeout_map_insert", 0x44B1657, "rel32", None, 0x493D940),
    ("signed_key_stake_intersection", 0x44B24F9, "rel32", None, 0x4B33990),
    ("total_stake", 0x44B250E, "rel32", None, 0x4B33770),
    ("build_tc_like_payload", 0x44B260C, "rel32", None, 0x47BE700),
    ("quorum_round_transition", 0x44B2629, "rel32", None, 0x44B6670),
    ("tc_verify_first_timeout", 0x475974F, "rel32", None, 0x454AA10),
    ("tc_verify_remaining_unknown", 0x475982B, "rel32", None, 0x4768F80),
    ("tc_collect_20_byte_keys", 0x4759855, "rel32", None, 0x4451690),
    ("tc_quorum_predicate", 0x4759865, "slot", 0x5776AE8, 0x4AD90D0),
    ("round_history_lookup_current", 0x44B6765, "slot", 0x5773628, 0x4B31E70),
    ("round_history_lookup_next", 0x44B6784, "slot", 0x5773628, 0x4B31E70),
    ("round_queue_push", 0x44B68A7, "slot", 0x5773648, 0x4758390),
)

SITES = (
    ("direct_tc_stale_compare", 0x44AF51F, "4d3bae180900000f82b21e0000", "+0x918 read; unsigned-below rejects incoming certificate round"),
    ("timeout_round_equality", 0x44B035E, "498b87180900004939c60f85df060000", "+0x918 read; any unequal timeout round exits"),
    ("timeout_map_lookup", 0x44B0376, "4d8dafb80900004c89ef4889eee8287547004885c00f84b7110000", "+0x9b8 lookup; null result reaches verification, present result does not"),
    ("seen_round_map", 0x44B15A1, "488db0680a0000", "+0xa68 container address"),
    ("seen_round_max", 0x44B15CA, "488b084939ce490f47ce488908", "store max(existing, timeout_round)"),
    ("strict_quorum_compare", 0x44B2544, "4889d948c1e93f4801dbba030000004c89f048f7e24839c34819d10f83b7f2ffff", "transition only when 2*total < 3*signed_weight"),
    ("move_timeout_map_head", 0x44B256A, "488b9e18090000488b86b8090000488b8ec009000048c786b809000000000000", "read +0x918/+0x9b8/+0x9c0, clear +0x9b8"),
    ("move_timeout_map_tail", 0x44B2592, "488b96c809000048c786c809000000000000", "read then clear +0x9c8"),
    ("round_load", 0x44B668E, "4c8ba718090000", "read current round at +0x918"),
    ("round_saturating_store", 0x44B66A7, "4c89f048ffc049c7c5ffffffff4c0f45e84c89af18090000", "store incoming+1, or u64::MAX on overflow, at +0x918"),
    ("round_queue_address", 0x44B6853, "498d9fe8040000", "address state+0x4e8 before 0x98-byte record push"),
    ("round_lock_pointer", 0x44B68B5, "498b9f10090000", "read pointer at +0x910 before lock/wake operations"),
    ("round_clear_flag_b01", 0x44B690D, "41c687010b000000", "clear byte +0xb01"),
    ("round_clear_timeout_map", 0x44B6915, "498b8fb8090000498b97c009000049c787b809000000000000498b87c809000049c787c809000000000000", "move +0x9b8/+0x9c0/+0x9c8 and clear +0x9b8/+0x9c8"),
    ("round_payload_replace", 0x44B6ACA, "488b442418f30f6f00f30f6f4810f30f7f4b10f30f7f03", "copy 32 payload bytes to container at +0x8a0"),
    ("round_timer_one_flag", 0x44B6B49, "41c687d808000001", "set byte +0x8d8 after timer call using +0x8c0/+0x8c8/+0x8d0"),
    ("round_clear_9b0", 0x44B6B51, "49c787b009000000000000", "clear qword +0x9b0"),
    ("round_timer_two_flag", 0x44B6C39, "41c687f808000001", "set byte +0x8f8 after timer call using +0x8e0/+0x8e8/+0x8f0"),
    ("round_clear_flag_b00", 0x44B6C55, "41c687000b000000", "clear byte +0xb00"),
    ("tc_record_round_equality", 0x4759600, "498b4c04504c39f175754805b80000004839c275eb", "every 0xb8-byte record must carry certificate round at +0x50"),
    ("stake_key_memcmp", 0x4B33BE5, "4a8d343bba140000004c89f7ff1591a8c300", "compare 20-byte vote key against stake-tree key"),
    ("stake_match_add", 0x4B33C60, "4c8b542410488b4424204c0354e8080f8225020000", "only a matching key adds its stake; overflow branches away"),
)

BRANCH_TABLE = (
    {
        "case": "direct certificate stale",
        "predicate": "incoming_round < state[+0x918] (unsigned)",
        "sites": [0x44AF51F, 0x44AF526],
        "outcome": "exit before certificate verifier and before round-transition call",
        "caller_state_write_before_outcome": False,
        "status": "observed",
    },
    {
        "case": "direct certificate verifier or post-verifier helper error",
        "predicate": "result sentinel differs from success sentinel",
        "sites": [0x44AF55A, 0x44AF587],
        "outcome": "error cleanup; no observed state-method call has occurred",
        "caller_state_write_before_outcome": False,
        "status": "observed in caller; verifier and helper transitive effects unresolved",
    },
    {
        "case": "individual timeout wrong round",
        "predicate": "timeout_round != state[+0x918]",
        "sites": [0x44B035E, 0x44B0368],
        "outcome": "exit before duplicate lookup and signature verification",
        "caller_state_write_before_outcome": False,
        "status": "observed",
    },
    {
        "case": "individual timeout duplicate",
        "predicate": "lookup in state+0x9b8 returns present",
        "sites": [0x44B0376, 0x44B038B],
        "outcome": "does not reach signature verifier or later insertion path",
        "caller_state_write_before_outcome": False,
        "status": "observed in caller; lookup-helper transitive effects unresolved",
    },
    {
        "case": "individual timeout signature rejection",
        "predicate": "verify_signed_timeout result is not success sentinel",
        "sites": [0x44B1560, 0x44B157D],
        "outcome": "error path before first observed state-container update at 0x44b15a1",
        "caller_state_write_before_outcome": False,
        "status": "observed in caller; signature algorithm and verifier transitive effects are outside this packet",
    },
    {
        "case": "validator key absent from stake tree",
        "predicate": "20-byte vote key has no equal stake-tree key",
        "sites": [0x4B33BE5, 0x4B33C60],
        "outcome": "no stake is added for that key; no separate membership rejection is shown",
        "caller_state_write_before_outcome": True,
        "status": "observed weight behavior; earlier signature/key semantics unresolved",
    },
    {
        "case": "individual timeout insufficient or exact two-thirds stake",
        "predicate": "2*total >= 3*signed_weight",
        "sites": [0x44B2544, 0x44B255F],
        "outcome": "branch away after insertion; round and timeout-map clearing path not taken",
        "caller_state_write_before_outcome": True,
        "status": "observed",
    },
    {
        "case": "individual timeout strict quorum",
        "predicate": "2*total < 3*signed_weight",
        "sites": [0x44B2544, 0x44B2565, 0x44B2629],
        "outcome": "move/clear timeout container, construct payload, call round transition",
        "caller_state_write_before_outcome": True,
        "status": "observed",
    },
    {
        "case": "round transition stale",
        "predicate": "accepted_round < state[+0x918]",
        "sites": [0x44B668E, 0x44B66A5],
        "outcome": "cleanup path without +0x918 store",
        "caller_state_write_before_outcome": False,
        "status": "observed",
    },
    {
        "case": "round transition accepted",
        "predicate": "accepted_round >= state[+0x918]",
        "sites": [0x44B66A7, 0x44B66B8],
        "outcome": "state[+0x918] := saturating_add(accepted_round, 1), then downstream queue/timer/container work",
        "caller_state_write_before_outcome": True,
        "status": "observed",
    },
)


def _direct_target(elf: Elf, site: int) -> int:
    raw = elf.read(site, 5)
    if raw[0] != 0xE8:
        raise EvidenceError(f"expected rel32 call at {site:#x}, got {raw.hex()}")
    return site + 5 + struct.unpack_from("<i", raw, 1)[0]


def _slot_target(elf: Elf, relocs: dict[int, int], site: int) -> tuple[int, int | None]:
    raw = elf.read(site, 6)
    if raw[:2] != b"\xff\x15":
        raise EvidenceError(f"expected RIP-slot call at {site:#x}, got {raw.hex()}")
    slot = site + 6 + struct.unpack_from("<i", raw, 2)[0]
    return slot, relocs.get(slot)


def _branch_target(elf: Elf, site: int) -> tuple[int, int]:
    raw = elf.read(site, 6)
    if raw[0] in range(0x70, 0x80) or raw[0] == 0xEB:
        return site + 2 + struct.unpack_from("<b", raw, 1)[0], 2
    if raw[0] == 0xE9:
        return site + 5 + struct.unpack_from("<i", raw, 1)[0], 5
    if raw[0] == 0x0F and raw[1] in range(0x80, 0x90):
        return site + 6 + struct.unpack_from("<i", raw, 2)[0], 6
    raise EvidenceError(f"unsupported direct branch at {site:#x}: {raw.hex()}")


def build(data: bytes, expected_sha256: str = EXPECTED_SHA256) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError(f"binary sha256 {digest} != {expected_sha256}")
    elf = Elf(data)
    starts, ends = fde_index(elf)
    relocs = relative_relocs(elf)

    functions = []
    for name, (start, end) in sorted(FUNCTIONS.items(), key=lambda x: x[1]):
        got = containing(starts, ends, start)
        if got != (start, end):
            raise EvidenceError(f"{name} FDE {got!r} != {(start, end)!r}")
        functions.append({"name": name, "start": start, "end": end,
                          "sha256": hashlib.sha256(elf.read(start, end - start)).hexdigest()})

    blocks = []
    for name, start, end, expected in BLOCKS:
        raw = elf.read(start, end - start)
        got = hashlib.sha256(raw).hexdigest()
        if got != expected:
            raise EvidenceError(f"block {name} sha256 {got} != {expected}")
        term = TERMINATORS.get(name)
        if term:
            site, kind, want_target = term
            target, size = _branch_target(elf, site)
            if target != want_target or site + size != end:
                raise EvidenceError(
                    f"block {name} terminator {(target, site + size)!r} != {(want_target, end)!r}")
            edges = [{"kind": "taken" if kind == "conditional" else "jump", "to": target}]
            if kind == "conditional":
                edges.append({"kind": "fallthrough", "to": end})
        else:
            edges = [{"kind": "fallthrough", "to": end}]
        blocks.append({"name": name, "start": start, "end": end,
                       "bytes": raw.hex(), "sha256": got, "edges": edges})

    calls = []
    for name, site, kind, want_slot, want_target in CALLS:
        if kind == "rel32":
            target = _direct_target(elf, site)
            slot = None
        else:
            slot, target = _slot_target(elf, relocs, site)
        if slot != want_slot or target != want_target:
            raise EvidenceError(
                f"call {name} {(slot, target)!r} != {(want_slot, want_target)!r}")
        calls.append({"name": name, "site": site, "kind": kind,
                      "slot": slot, "target": target})

    sites = []
    for name, va, expected_hex, observation in SITES:
        expected = bytes.fromhex(expected_hex)
        got = elf.read(va, len(expected))
        if got != expected:
            raise EvidenceError(f"site {name} bytes {got.hex()} != {expected_hex}")
        sites.append({"name": name, "va": va, "bytes": got.hex(),
                      "observation": observation})

    return {
        "schema": "re008-timeout-round-transition/v1",
        "binary_sha256": digest,
        "address_coordinate": "ELF virtual address; ranges end-exclusive",
        "functions": functions,
        "bounded_cfg_blocks": blocks,
        "calls": calls,
        "state_offset_sites": sites,
        "branch_table": list(BRANCH_TABLE),
        "proven_transition": {
            "precondition": "accepted_round >= current_round at state+0x918",
            "write": "state+0x918 = accepted_round.saturating_add(1)",
            "write_site": 0x44B66B8,
            "stale_branch_site": 0x44B66A5,
            "callers": [0x44B17CF, 0x44B2629],
        },
        "scope": {
            "observed": [
                "direct TC stale guard and verifier call",
                "individual timeout current-round and duplicate guards",
                "individual timeout verifier, insertion, stake intersection, strict quorum, and transition call",
                "round field update and selected downstream state offsets",
            ],
            "inferred": [
                "semantic labels for containers, timers, and notifications are based on instruction shape and reference leads",
                "the 20-byte keys compared by the stake helper are treated as validator identities",
            ],
            "unresolved": [
                "signature algorithm and the exact key-to-signature binding",
                "duplicate-key policy inside the TC key-collection helper",
                "complete semantics of 0x47593a0, 0x4768f80, 0x44ab560, queue and notification callees",
                "exact Rust types for observed state offsets",
                "persistence beyond the in-memory state writes",
            ],
        },
    }


ADDRESS_KEYS = {"start", "end", "site", "slot", "target", "to", "va",
                "write_site", "stale_branch_site", "callers", "sites"}


def _hexify(value, address=False):
    if isinstance(value, dict):
        return {k: _hexify(v, k in ADDRESS_KEYS) for k, v in value.items()}
    if isinstance(value, list):
        return [_hexify(v, address) for v in value]
    if address and isinstance(value, int) and not isinstance(value, bool):
        return f"{value:#x}"
    return value


def render(result: dict) -> bytes:
    return (json.dumps(_hexify(result), indent=1, sort_keys=True) + "\n").encode()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", type=Path, default=TARGET)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        text = render(build(args.binary.read_bytes()))
    except (EvidenceError, OSError) as exc:
        print(f"timeout_round_transition: {exc}", file=sys.stderr)
        return 2
    if args.out:
        args.out.write_bytes(text)
    else:
        sys.stdout.buffer.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
