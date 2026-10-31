# bridge: daily retention of finished deposits and withdrawals in node #94

This packet finds the writer of `last_pruned_deposit_block_number` and shows how `bridge2` forgets finished rows, so a reconstruction can write the block step from the bytes: on the first block of a new date, finished deposits go by block word at or below a floor raised to the highest block of a row at least 7 days old (1 day when the chain byte is not 3), finished withdrawals go by time alone, and the vote maps are not touched.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; first task, nonce and row lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, serde names, node layouts and call sites; inference for "first block of a new date", the meaning of the 12 time bytes and the chain byte name; unresolved items are under limits
- Scope included and excluded: included are the prune `0x374f170`, its two first-edge helpers `0x2fe0c90` and `0x2fe12a0`, its two extract iterators `0x3314dd0` and `0x3314ff0`, the two B-tree removal chains under them (`path.tsv`), the 25-row gate slice in each of the three block step copies (`gate-copies.tsv`), and the three shared time helpers. The block step bodies `0x22297c0`, `0x470e9a0` and `0x47162d0` are not read beyond the slices. Their other steps, including the neighbor call through slot `0x5773a68`, are out of scope.

## Reproduce

```
python3 tools/bridge_retention_prune.py --out research/work-items/bridge-retention-prune-94
python3 -m unittest tests.test_bridge_retention_prune
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 3 minutes with four worker processes, most of it the mutation sweep.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; every function ends exactly at its FDE end. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### The path

```
block step copy (3)    previous date word < block date word, else skip
                       span = 604800 s on chain byte 3, else 86400 s
  time helper 0x151d080  cut = block time - span; date out of range panics
  slot 0x5773a60       -> prune 0x374f170 (bridge, cut)
prune 0x374f170        floor = last_pruned_deposit_block_number
                       scan every finished deposit; time <= cut raises floor to its block word
  0x2fe0c90 + 0x3314dd0   drain finished_deposits_data where block word <= floor
  0x2fe12a0 + 0x3314ff0   drain finished_withdrawal_to_time where time <= cut
                       store floor
```

`0x374f170` has no direct caller and one relocation: slot `0x5773a60`, with exactly three sites (`slots.tsv`, `call-sites.tsv`). This is the only writer found for bridge `+0x138`: the row `0x374f572` stores through the bridge pointer, which is why no state-relative displacement exists. That the scan is complete is limited as stated below.

The two maps are named by the serializer `0x22155c0`, whose key and field rows are read in `fields.tsv`: `finished_deposits_data` at bridge `+0x100`, `finished_withdrawal_to_time` at bridge `+0x118`. Each map is root, height, length. Node layouts are in `node-layouts.tsv`; a finished withdrawal is a `0x20`-byte key and a 12-byte time.

### The date gate

| Row | Copy `a` | What it does |
|---|---|---|
| `0x2229f93` | `cmp (%rbx),%eax` | date word of the previous time against the block time |
| `0x2229f95` | `jge` | signed, not later: the whole step is skipped |
| `0x2229fb5..0x2229fc1` | `cmp $3`, `cmove` | span is 604800 only for chain byte 3 |
| `0x2229fdf` | `je` | a None time panics with the text "NaiveDateTime - TimeDelta overflowed" |

Only the first word of the 12 bytes is compared, so two blocks of one date never run the step whatever their seconds (`gate_a_same_day_does_nothing`, `gate_a_same_date_later_secs`). A previous date after the block date is skipped as well (`gate_a_prev_after_now_does_nothing`). Chain bytes 0, 1, 2, 4 and 0xff all get one day (`gate_a_new_day_chain_0` through `gate_a_new_day_chain_ff`).

Copies `a` and `b` have the same offsets. Copy `c` has the chain byte at `+0x1372` and the bridge at `+0x3e18`, so it runs on a differently laid out state (`gate-copies.tsv`). All three are run with the same scenarios.

### The scan and the two drains

The scan looks at every row of `finished_deposits_data`; it does not stop at the first new row, because the map is keyed by block and not by time. A row is old when `(date, seconds, nanoseconds) <= cut`, with a signed date and unsigned other words (`0x374f3a8..0x374f3f3`; `cut_equal_is_old`, `nanos_above_is_new`, `negative_date_row_is_old`, `secs_top_bit_is_unsigned`). The floor is the unsigned maximum of the old value and the block words of old rows, so it never falls (`last_above_blocks_is_kept`, `block_top_bit_is_unsigned`).

The deposit drain tests only the block word (`0x3314e56`). A row newer than the cut goes when its block is at or below the floor (`new_row_in_lower_block_goes`, `new_row_in_same_block_goes`, `old_row_in_top_block_takes_all`). The map is ordered by that word first, so the removed rows are always a prefix in key order.

The withdrawal drain tests only the time, with the same order as the scan (`0x3315077..0x33150a1`). Any pattern of rows can go (`withdrawals_170_even_odd`, `withdrawals_170_tight_ends`). The floor does not touch it, and the deposit map does not move it (`maps_are_independent`).

Both drains are real B-tree extract loops. The fixture builds valid trees up to height 2, and after every step the harness walks the tree, checks every count, parent link, key order and length, and checks that every node freed had the right size and every live node is still reachable. A map drained to zero rows keeps its root node with count 0; the root word does not go null.

The iterators end on a niche value: the deposit loop stops on byte `+0x38` of the returned key equal to 6 (`0x374f4bb`), the withdrawal loop on a date word of 0 (`0x374f56b`). So that key byte is an enum with values below 6 on this path. The fixture uses 0 to 5.

### Reference differences

| Reference `l1/bridge2.rs` | Bytes |
|---|---|
| `prune_finished_deposits_before(block_number)` takes a block number | the input is a time; the block comes from the rows |
| keeps rows `>= block_number` | keeps rows strictly above the floor |
| also retains `eth_id_to_deposit_votes` | bridge `+0..+0x100` is unchanged in every scenario, the vote map is not read |
| sets `last_pruned_deposit_block_number = block_number` | floor is a maximum and never falls |
| no time prune for withdrawals | `finished_withdrawal_to_time` drains by time here |

### With the deposit path

The deposit core refuses a block word at or below `last_pruned_deposit_block_number` with status `0x2e` before anything else that reads the row (open packet `bridge-deposit-votes-94`). After this step no finished row has a block at or below the floor, so the two rules meet exactly: a replay of a removed deposit gets `0x2e` where it used to get `0x2d`. That is an inference over the two packets; this tool does not run them together.

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the cut, whether the prune runs, both maps row by row, the floor, and that the rest of the bridge bytes stay the same, for every operation.

## Results and limitations

- 18 functions and 3 gate slices, 3731 instruction rows. 480 named scenarios with 492 operations and 200 generated scenarios: 0 mismatches.
- 528 byte edits on reached rows, in the prune, iterators, first-edge and removal functions and gate slices: 424 killed, 104 survived (`mutations.tsv`). A survivor has a class label only and is not proved equal. Each edit runs at most 60 of the cheapest scenarios that reach it. The time helpers are shared and not edited.
- 1129 rows are not reached (`unreached.tsv`): first-edge arms for other bound kinds, internal-node removal on deposits (a prefix drain only ever removes at a leaf), panic rows, and tree heights above 2.
- The fixture does not build a tree above height 2 or a time with nanoseconds at or over 1e9 (a leap second), so that branch of `0x15206e0` is not run.
- That `0x374f572` is the only writer rests on the scan of 64-bit stores with displacement `0x138` in functions that also use the neighbor offsets; a store through a computed address would not be seen.
- What the previous time pointer of the block step holds is read only as an argument of the slice: the step reads it from its second argument at `+0x10`, and the 12-byte format is taken from the same step's rows that split it into year and ordinal.
- That chain byte 3 is mainnet is the reference's enum order, not proved here.
- Why copy `c` has another state layout is not established.
- Rows left in `eth_id_to_deposit_votes` for a removed block have no remover on this path. Whether another path removes them is not established.

Next question: what the neighbor step at slot `0x5773a68` does with state `+0x36d0` and `+0x740` at the same point of the block.
