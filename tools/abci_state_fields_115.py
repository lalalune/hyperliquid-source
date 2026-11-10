#!/usr/bin/env python3
"""Bind the node #115 Exchange field names to the abci hash slots (stage 88).

Continues the Exchange/Locus deserialiser packet (open PR #6093) and the abci
hash slot packet (open PR #6027). This tool binds:

1. the Exchange field-name pool at 0x5cb18b: 56 names stored back to back
   ("locus" .. "pmn") in .rodata;
2. the field-identifier matcher 0x54777f0 (a visit_str that compares the
   input with immediates and returns the field index in cl, 0x3b for an
   unknown field): spot pins for 10 names, including the three names that
   are not in the pool ("lhvt" = 56, "advt" = 57, "msc" = 58);
3. the hash input builder 0x4e34ce0: it forms 73 field addresses with
   `lea reg, [r15+disp32]`; the first 15 are the Locus group of slot 0
   (#6027) and the other 58 are slots 1..58 in order.

Labels (field index k <-> hash slot k, "lhvt"/"advt" as vote trackers, the
simulate-panic pair inside "msc") are inferences; the README says which
facts support them. The captured binary is not executed. objdump and
readelf are not started. Addresses are ELF virtual addresses.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import fixed, read_va, rip_target, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-state-fields-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

POOL = 0x5cb18b
POOL_NAMES = (
    'locus', 'perp_dexs', 'spot_books', 'agent_tracker', 'funding_distribute_guard',
    'funding_update_guard', 'sub_account_tracker', 'allowed_liquidators', 'bridge2',
    'staking', 'c_staking', 'funding_err_dur_guard', 'max_order_distance_from_anchor',
    'scheduled_freeze_height', 'cancel_aggressive_orders_at_open_interest_cap_guard',
    'last_hlp_cancel_time', 'post_only_until_time', 'post_only_until_height',
    'spot_twap_tracker', 'user_to_display_name', 'book_empty_user_states_pruning_guard',
    'user_to_scheduled_cancel', 'hyperliquidity', 'spot_disabled', 'prune_agent_idx',
    'max_hlp_withdraw_fraction_per_day', 'hlp_start_of_day_account_value', 'pvs',
    'register_token_gas_auction', 'perp_deploy_gas_auction', 'spot_pair_deploy_gas_auction',
    'hyper_evm', 'vtg', 'begin_block_logic_guard', 'user_to_evm_state', 'multi_sig_tracker',
    'reserve_accumulators', 'partial_liquidation_cooldown', 'evm_enabled',
    'validator_l1_vote_tracker', 'staking_link_tracker', 'action_delayer',
    'default_hip3_limits', 'hip3_stale_mark_px_guard', 'disabled_precompiles', 'lvt',
    'hip3_no_cross', 'initial_usdc_evm_system_balance', 'validator_l1_stream_tracker',
    'user_to_evm_to_l1_wei_remaining', 'dex_abstraction_enabled', 'hil', 'oh', 'pt', 'pmi',
    'pmn',
)
EXTRA_NAMES = ('lhvt', 'advt', 'msc')
MATCHER = (0x54777f0, 0x5478357)
UNKNOWN_INDEX = 0x3b
BUILDER = (0x4e34ce0, 0x4e3569b)
GROUP_COUNT = 15
SLOT_COUNT = 58

# (name, compare site va, compare bytes, return site va, index): each return
# site is `mov cl, index` (or `xor ecx, ecx` for 0) followed by
# `mov [rax+1], cl; mov byte [rax], 9`.
MATCH_PINS = (
    ('locus', 0x5477b53, 'b96c6f6375', 0x5477b69, 0),
    ('evm_enabled', 0x5477b25, '48b965766d5f656e6162', 0x5477b49, 0x26),
    ('staking', 0x5477b8a, 'b97374616b', 0x5477ba1, 9),
    ('lhvt', 0x5477edc, '813e6c687674', 0x547827b, 0x38),
    ('advt', 0x5477ee8, '813e61647674', 0x5477ef4, 0x39),
    ('msc', 0x5477c44, '81f16d730000', 0x5477c5a, 0x3a),
)
# compares that jump to a shared return block: (name, compare va, bytes, je va, block, index)
JE_PINS = (
    ('bridge2', 0x5477b73, 'b962726964', 0x5477b84, 0x5478235, 8),
    ('pvs', 0x5477bae, '81f170760000', 0x5477bbe, 0x547823f, 0x1b),
    ('vtg', 0x5477bc7, '81f176740000', 0x5477bd7, 0x54782c1, 0x20),
    ('lhvt', 0x5477edc, '813e6c687674', 0x5477ee2, 0x547827b, 0x38),
)
RETURN_TAIL = '884801c600095bc3'


def index_at(data, va):
    raw = read_va(data, va, 2)
    if raw == b'\x31\xc9':
        idx = 0
    elif raw[0] == 0xb1:
        idx = raw[1]
    else:
        raise ValueError(f'return block at {va:#x} changed')
    fixed(data, va + 2, RETURN_TAIL)
    return idx


def pool(data):
    blob = ''.join(POOL_NAMES).encode()
    if read_va(data, POOL, len(blob)) != blob:
        raise ValueError('field-name pool changed')
    starts, at = [], POOL
    for name in POOL_NAMES:
        starts.append((name, hex(at)))
        at += len(name)
    return starts


def matcher(data, fdes):
    hits = [f for f in fdes if f['start'] == MATCHER[0] and f['end'] == MATCHER[1]]
    if len(hits) != 1:
        raise ValueError('matcher extent changed')
    seen = {}
    for name, cva, cbytes, rva, idx in MATCH_PINS:
        fixed(data, cva, cbytes)
        if index_at(data, rva) != idx:
            raise ValueError(f'index for {name} changed')
        seen[name] = idx
    for name, cva, cbytes, jva, block, idx in JE_PINS:
        fixed(data, cva, cbytes)
        if rip_target(data, jva, b'\x0f\x84', 6) != block or index_at(data, block) != idx:
            raise ValueError(f'jump for {name} changed')
        seen[name] = idx
    if index_at(data, 0x5478203) != UNKNOWN_INDEX:
        raise ValueError('unknown-field index changed')
    return seen


def builder(data, fdes):
    hits = [f for f in fdes if f['start'] == BUILDER[0] and f['end'] == BUILDER[1]]
    if len(hits) != 1:
        raise ValueError('builder extent changed')
    base, code = text(data)
    body = code[BUILDER[0] - base:BUILDER[1] - base]
    disps = []
    for m in re.finditer(rb'[\x49\x4d]\x8d[\x80-\xbf]', body):
        if body[m.start() + 2] & 7 == 7:  # rm = r15 with REX.B
            disps.append(struct.unpack_from('<i', body, m.start() + 3)[0])
    if len(disps) != GROUP_COUNT + SLOT_COUNT:
        raise ValueError('builder field-address census changed')
    return disps[:GROUP_COUNT], disps[GROUP_COUNT:]


def bind(data, fdes):
    starts = pool(data)
    seen = matcher(data, fdes)
    names = list(POOL_NAMES) + list(EXTRA_NAMES)
    for name, idx in seen.items():
        if names[idx] != name:
            raise ValueError(f'{name} index {idx} does not match the pool order')
    group, slots = builder(data, fdes)
    offsets = [None] + slots
    table = []
    for k, name in enumerate(names):
        table.append({'index': k, 'name': name,
                      'hash_slot_box_offset': 'Locus group' if k == 0 else hex(offsets[k])})
    # single-byte fields: four adjacent box bytes
    bools = [(names[k], hex(offsets[k])) for k in range(1, 59) if 0x42ac <= offsets[k] <= 0x42af]
    msc = offsets[58]
    nxt = min(o for o in slots if o > msc)
    if not (msc <= 0x39a8 and 0x39b0 + 8 <= nxt):
        raise ValueError('simulate-panic pair is not inside the msc span')
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'name_pool': {'va': hex(POOL), 'names': len(starts), 'starts': starts},
        'matcher': {'fde': [hex(v) for v in MATCHER], 'pinned_indices': seen,
                    'unknown_field_index': UNKNOWN_INDEX},
        'builder': {'fde': [hex(v) for v in BUILDER], 'locus_group': [hex(v) for v in group],
                    'slot_offsets': [hex(v) for v in slots]},
        'fields': table,
        'single_byte_fields': bools,
        'msc_span': [hex(msc), hex(nxt)],
        'simulate_panic_pair': ['0x39a8', '0x39b0'],
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print('fields=%d pinned=%d msc=%s' % (len(result['fields']), len(result['matcher']['pinned_indices']),
                                         result['msc_span']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
