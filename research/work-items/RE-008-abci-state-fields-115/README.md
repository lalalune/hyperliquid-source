# RE-008: node #115 Exchange field names tied to the abci hash slots (stage 88)

- Component ID: abci. Question: open PR #6093 found the `struct Exchange with 59 elements` and `struct Locus with 16 elements` deserialisers, and open PR #6027 found that the abci hash input has 59 slots taken from box fields. Neither named the fields. This packet names the 59 Exchange fields and ties each one to a hash slot and box offset.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6027 and #6093. It does not depend on their files.
- Claim status: instruction bytes, immediates, string bytes, FDE extents and the address census are observations. "Exchange field", "field index", "Locus group", "vote tracker" and "inside msc" are inferred labels. The binary was not executed.
- Scope included: the field-name pool at `0x5cb18b`; the field-identifier matcher `0x54777f0..0x5478357` at 9 named compares and its unknown-field return; the address census of the hash input builder `0x4e34ce0`. Scope excluded: the other 47 compares in the matcher, the Locus field names, the deserialiser bodies, what each field type holds, and the writers of `+0x39a8`/`+0x39b0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_state_fields_115.py --check
python3 -m unittest tests.test_abci_state_fields_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the field-name pool

At `0x5cb18b` in `.rodata`, 56 field names are stored back to back with no separators, from `locus` to `pmn`. The tool checks that the bytes equal the joined names. The pool ends where unrelated names begin (`node_ip`, `commission_bps`, `signer` and a `struct CValidatorProfile` message).

## Evidence 2: the field-identifier matcher

`0x54777f0` compares the input string with immediates and returns the field index in `cl` (then `mov [rax+1], cl; mov byte [rax], 9; pop rbx; ret`). An unknown name returns `0x3b` (59) at `0x5478203`. The tool pins 9 names:

| Name | Compare | Index |
|---|---|---|
| `locus` | `0x5477b53` | 0 |
| `bridge2` | `0x5477b73` → `0x5478235` | 8 |
| `staking` | `0x5477b8a` | 9 |
| `pvs` | `0x5477bae` → `0x547823f` | 27 |
| `vtg` | `0x5477bc7` → `0x54782c1` | 32 |
| `evm_enabled` | `0x5477b25` | 38 |
| `lhvt` | `0x5477edc` → `0x547827b` | 56 |
| `advt` | `0x5477ee8` | 57 |
| `msc` | `0x5477c44` | 58 |

Each pinned index equals the name's position in the pool (0..55) or, for the three names not in the pool, 56..58. Reading the whole pool order as the field order is an inference from these 9 matches.

## Evidence 3: the hash slots in field order

The builder `0x4e34ce0` forms exactly 73 addresses `lea reg, [r15+disp32]`. The first 15 are the slot-0 group from #6027; the other 58 are slots 1..58 in #6027's order. Field index k ↔ slot k (inference) is supported by:

- slot 0 is a group of the base plus 15 fields; `Locus` has 16 elements (#6093), and its visitor writes `+0xb90`/`+0xb98`/`+0xb99`/`+0xb9a`, all in the group;
- slot 13 is `+0x10e8`, the layout-A freeze height (#6006, #6090), and index 13 is `scheduled_freeze_height`;
- the four single-byte slots `0x42ac`..`0x42af` are the four flag names `spot_disabled`, `evm_enabled`, `hip3_no_cross`, `dex_abstraction_enabled`;
- slots 9 and 10 (`staking` `+0x3f08`, `c_staking` `+0xd88`) are the two tables the vote handler reads (#6052);
- slots 56 and 57 (`lhvt` `+0x3d98`, `advt` `+0x3e50`) are the two digest quorum stores (#6046, #6052);
- slots 28..30 are the three `*_gas_auction` fields, at evenly spaced offsets `0x3a00`, `0x3a40`, `0x3a80`.

| Index | Field | Box offset (layout A) |
|---|---|---|
| 0 | `locus` | `Locus group` |
| 1 | `perp_dexs` | `0x3ac0` |
| 2 | `spot_books` | `0x3ad8` |
| 3 | `agent_tracker` | `0x3af0` |
| 4 | `funding_distribute_guard` | `0x4158` |
| 5 | `funding_update_guard` | `0x4168` |
| 6 | `sub_account_tracker` | `0x3c58` |
| 7 | `allowed_liquidators` | `0x41e8` |
| 8 | `bridge2` | `0xba0` |
| 9 | `staking` | `0x3f08` |
| 10 | `c_staking` | `0xd88` |
| 11 | `funding_err_dur_guard` | `0x4200` |
| 12 | `max_order_distance_from_anchor` | `0x4220` |
| 13 | `scheduled_freeze_height` | `0x10e8` |
| 14 | `cancel_aggressive_orders_at_open_interest_cap_guard` | `0x4178` |
| 15 | `last_hlp_cancel_time` | `0x4288` |
| 16 | `post_only_until_time` | `0x4294` |
| 17 | `post_only_until_height` | `0x4228` |
| 18 | `spot_twap_tracker` | `0x3ce8` |
| 19 | `user_to_display_name` | `0x3f88` |
| 20 | `book_empty_user_states_pruning_guard` | `0x4188` |
| 21 | `user_to_scheduled_cancel` | `0x3fa8` |
| 22 | `hyperliquidity` | `0x3fc8` |
| 23 | `spot_disabled` | `0x42ac` |
| 24 | `prune_agent_idx` | `0x4230` |
| 25 | `max_hlp_withdraw_fraction_per_day` | `0x4238` |
| 26 | `hlp_start_of_day_account_value` | `0x10f8` |
| 27 | `pvs` | `0x4240` |
| 28 | `register_token_gas_auction` | `0x3a00` |
| 29 | `perp_deploy_gas_auction` | `0x3a40` |
| 30 | `spot_pair_deploy_gas_auction` | `0x3a80` |
| 31 | `hyper_evm` | `0x1108` |
| 32 | `vtg` | `0x3d40` |
| 33 | `begin_block_logic_guard` | `0x4198` |
| 34 | `user_to_evm_state` | `0x3ff8` |
| 35 | `multi_sig_tracker` | `0x4018` |
| 36 | `reserve_accumulators` | `0x4038` |
| 37 | `partial_liquidation_cooldown` | `0x37e0` |
| 38 | `evm_enabled` | `0x42ad` |
| 39 | `validator_l1_vote_tracker` | `0x4058` |
| 40 | `staking_link_tracker` | `0x40a0` |
| 41 | `action_delayer` | `0x40c0` |
| 42 | `default_hip3_limits` | `0x41a8` |
| 43 | `hip3_stale_mark_px_guard` | `0x41d8` |
| 44 | `disabled_precompiles` | `0x4250` |
| 45 | `lvt` | `0x42a0` |
| 46 | `hip3_no_cross` | `0x42ae` |
| 47 | `initial_usdc_evm_system_balance` | `0x4268` |
| 48 | `validator_l1_stream_tracker` | `0x37f0` |
| 49 | `user_to_evm_to_l1_wei_remaining` | `0x4138` |
| 50 | `dex_abstraction_enabled` | `0x42af` |
| 51 | `hil` | `0x3830` |
| 52 | `oh` | `0x3d78` |
| 53 | `pt` | `0x3858` |
| 54 | `pmi` | `0x42b0` |
| 55 | `pmn` | `0x4270` |
| 56 | `lhvt` | `0x3d98` |
| 57 | `advt` | `0x3e50` |
| 58 | `msc` | `0x3908` |

## Evidence 4: the simulate-panic pair

`msc` starts at `+0x3908`; the next slot offset above it is `+0x3a00`. The simulate-panic pair from #6091 (`+0x39a8`/`+0x39b0`) lies inside that span, so it is most likely a sub-field of `msc` (inference).

## Implementation and comparison

The tool pins 9 compare sites and 10 return blocks, the 1002-byte name pool and the 73-address census, then builds the table. Tests change one byte in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: decoding all 59 compares (bounded out); reading the seq visitors' element stores (the visitor output is 0x27a8 bytes and does not use these box offsets directly).

## Results and limitations

- Result: names for all 59 Exchange fields and their layout-A box offsets.
- Limits: 47 of the 59 indices rest on pool order, not a pinned compare; the Locus field names; field types; layout-B offsets (layout A + 0xb70 above `+0x7c0`, per #6006) are not tabled; the writers of `+0x39a8`/`+0x39b0` and the meaning of the abbreviations (`pvs`, `vtg`, `lvt`, `hil`, `oh`, `pt`, `pmi`, `pmn`, `lhvt`, `advt`, `msc`) are not mapped.
