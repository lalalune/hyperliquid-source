# bridge: deposit votes, the two vote sources and the finish step in node #94

This packet shows that a deposit is voted through one tracker by two sources, validator keys on arm 44 and listed 20-byte addresses on arm 84, and that it finishes only when stake is over 2/3 and the listed share passes the f64 `q` of the tracker, so a reconstruction can build `eth_id_to_deposit_votes`, `finished_deposits_data` and the `bal` update from the bytes: an amount below 5,000,000 still finishes and blocks later votes but does not raise `bal` and returns result 0, and the block word is refused at or below `last_pruned_deposit_block_number`.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; handler arms 44 and 84 of RE-010)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, status text, serde keys, node layouts and call sites; inference for the action name of arm 44, the word block, and that result 1 means credit; unresolved items are under limits
- Scope included and excluded: included are 18 functions run as real bytes (`path.tsv`), from the arm wrappers `0x1e5feb0` and `0x1e646c0` and the core `0x374e2e0` through the finished lookup `0x2fdd5d0`, the tracker `0x3947510`, row lookup `0x2fdd750`, quorum `0x3940ea0`, ratio `0x3bde1f0`, finished insert `0x33a0310` and row removal `0x3942480`. Excluded, and stubs here: the credit function `0x27123d0` (its status census is in #38 and #234, and #131 lists it), so the arms stop at that call and the core runs directly; the unique-validator lookup `0x33690c0` (#133, #425); the stake map builder `0x3364ed0`; the key set builders `0x3bb2dc0`, `0x3bb6560`; the keyed removal `0x33ac830`; `0x3bad4b0`; the leaf inserts, clones and drops; and the overflow recorder `0x358dcd0`. The core `0x374e2e0` appears in #234 only as a recorder site row; its body is read here. `0x3366b60`, `0x3367530`, `0x339e610` are shared with the other trackers and are not mutated here.

## Reproduce

```
python3 tools/bridge_deposit_votes.py --out research/work-items/bridge-deposit-votes-94
python3 -m unittest tests.test_bridge_deposit_votes
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 4 minutes, most of it the mutation sweep.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; every function ends exactly at its FDE end. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### The path

```
arm 44  wrapper 0x1e5feb0   voter lookup, then credit 0x27123d0 with a voter key
arm 84  wrapper 0x1e646c0   signer in the set at state +0x36a0, else 0x2b, then credit with an address
credit 0x27123d0 (stub)     reaches the core through slot 0x5774a00
core 0x374e2e0              limit, finished lookup, block test, tracker
  tracker 0x3947510         row by key, bucket by (amount, user), store; quorum 0x3940ea0
    quorum 0x3940ea0        stake test 0x3366b60 AND ratio 0x3bde1f0
  on a finish: 0x33a0310 inserts the finished row, 0x3942480 removes the vote row, bal rises
```

`eth_id_to_deposit_votes` is bridge `+0` and `finished_deposits_data` bridge `+0x100`, named by the serializer `0x22155c0`. `bal` is bridge `+0x130` and `last_pruned_deposit_block_number` bridge `+0x138`.

The tracker has named parts, read from its serializer `0x2327740` and `0x2204460` (`fields.tsv`): `name`, a string at `+0`; `hsc` at `+0x18`, holding the f64 words `q` and `i`; and `i` at `+0x28`, the row map. The withdrawal and validator set trackers keep their map at `+0x18`, so they have no `hsc`, and their quorums call only the stake test. Their first `0x18` bytes have the width of `name`; that is not read here.

### Keys and rows

The action is the amount at `+0`, a `0x40`-byte key at `+8` and the 20-byte user at `+0x48`. The key is compared in this order: word `+0`, word `+8`, byte `+0x38`, word `+0x10`, 32 bytes at `+0x18`. The last 7 bytes are never compared, so a key that differs only there is the same deposit (`core_finished_key_other_tail`). Word `+0` is the one tested against `last_pruned_deposit_block_number`.

A vote row has a `0x48`-byte value: `+0` tag (`1` none, `0` some), `+8` winner `(amount, user)`, `+0x28` inner tree, `+0x40` finished byte. The inner tree is keyed by `(amount, user)`, and each entry holds the voter set at `+0` and a second set of 20-byte addresses at `+0x18`. That second set is the one left empty and unnamed on the withdrawal and validator set paths: here it is filled by arm 84. A finished row is the key and a value of `0x28` bytes: amount, the 12-byte time, user (`0x374e482`). Node layouts are in `node-layouts.tsv`.

### Status order in the core

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`).

| Status | Text | Step |
|---|---|---|
| `0x13f` | Invalid input number | 1: `amount >= 0x0ccccccccccccccc`, payload amount |
| `0x2d` | Deposit has already been credited. | 2: the key is in `finished_deposits_data` |
| `0x2e` | Deposit is from Arbitrum block that is too old. | 3: word `+0` at or below `last_pruned_deposit_block_number` |
| `0x186` | success | 4: result byte 0, or the finish below |

A vote that no source can carry (no voter, or a voter outside the epoch, or an address outside the list) changes nothing and still returns `0x186` with result 0 (`core_no_voter_at_all`, `core_non_member`, `listed_not_in_set`). The arms refuse earlier: arm 44 with `0x97` or `0x2a` from the lookup, arm 84 with `0x2b` "User is not a voter." A validator is not a voter by being a validator (`arm_84_validator_not_listed`).

### Tracker rules

One call carries an optional voter key and an optional address. Arm 44 fills the first and arm 84 the second; `listed_both_in_one_call` drives both through the core directly.

1. A voter key must pass the member test on the current epoch. An address must be in the list. A source that fails is skipped.
2. The row and the bucket for `(amount, user)` are created if absent.
3. If the row is finished the vote is stored and nothing else happens.
4. Otherwise quorum is read before and after the store. A move from false to true writes the finished byte, the tag and the winner, and returns a clone of the sets.

Votes for two amounts or two users do not add (`core_split_amounts`, `core_split_users`).

### Quorum

`0x3940ea0` is `stake AND ratio`. `stake` is `2 * total < 3 * voted` over the validator set of the current epoch, as on the other trackers. `ratio` is `0x3bde1f0`:

- `q == 0.0`: true, with no read of the list (`ratio_zero_needs_no_listed`, `0x3bde208`).
- otherwise, `hits` is the number of addresses in the bucket's second set that are in the list, and the result is `float(hits) > q * float(list length)`, strict (`0x3bde591`).

So with `q = 0.5` and four listed addresses, two are short and three pass (`ratio_exact_is_short`, `ratio_half_of_four_needs_three`). With `q = 1.0` all four are short (`ratio_q_one_all_listed_short`), so such a tracker can never finish. A negative `q` passes at zero hits, a NaN `q` never passes (`ratio_negative_q`, `ratio_nan_q`), and a positive `q` with an empty list never passes (`ratio_empty_list`). Either test may be the last to pass (`ratio_blocks_stake_quorum`, `ratio_listed_first_then_stake`). The values `q` and `i` take on a live node are not in the binary.

### Finish

In this order:

1. `0x33a0310` inserts the key with `(winner amount, time, user)`.
2. `0x3942480` removes the vote row. Its other rows use `hsc.i` to compute a share of listed votes, but the only rows after that compare are frees, so `i` changes no state here (`ratio_i_word_not_a_gate`, `ratio_i_word_with_q`).
3. Only if `amount >= 5,000,000` does `bal` rise, with an overflow recorder call and saturation (`core_bal_saturates`, `core_bal_exact_top`).
4. Result byte `+2` is 1 for the same test (`0x374e549`).

The level is `0x4c4b40`, read as `0x4c4b3f` at `0x374e51f` and `0x4c4b40` at `0x374e542` (`constants.tsv`). An amount of 4,999,999 finishes, is in `finished_deposits_data`, and blocks every later vote with `0x2d`, but returns result 0 (`core_below_minimum_finishes_no_bal`). The caller `0x27123d0` tests that byte at `0x27124a5` and jumps past its credit rows when it is 0; those rows are read, not run, here.

### The row count step

The tracker ends with `if len >= 101`, builds a key iterator and calls `0x3bd09c0` with 100. The rows after the call are a capacity test and a free (`row-count-note.tsv`), and the map keeps every row (`no_trim_101_rows`). Rows only leave at a finish, so a row that never finishes stays.

### Reference compare

`l1/exchange/handlers/44_vote_eth_deposit.rs` and `l1/bridge2.rs` have the shape of this path. These points differ from the bytes:

| Reference | Bytes |
|---|---|
| Limit `0xCCCCCCCCCCCCCCCD` | `0x0CCCCCCCCCCCCCCC`, 16 times smaller |
| Status 45 is a failed witness check | `0x2d` is "Deposit has already been credited.", a key found in `finished_deposits_data` |
| Status 46 at or below the floor | Agrees, and the text says the word is an Arbitrum block |
| `EthEventId` is block and log index | The key is `0x40` bytes with five compared parts |
| A row is a set of signer addresses | A row is a tree keyed by `(amount, user)` with two sets |
| One vote source | Two: arm 84 is unclaimed in RE-010 and has no reference handler; it is a second caller of the same credit function |
| Finish needs one quorum | `stake AND ratio` |
| Every finalize reaches the credit | Amounts below 5,000,000 finish with no `bal` change and result 0 |
| `Bridge2` has one map at this field | A tracker with `name`, `hsc` and `i` |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the status, result byte, stub events and full tree state after every operation.

## Results and limitations

- 72 named scenarios (205 operations) and 200 generated scenarios of 14 operations: 0 mismatches.
- 400 byte edits on reached rows of 9 functions (condition, immediate; displacement on the wrappers and the core): 296 killed, 104 survived (`mutations.tsv`). Each edit runs only the named scenarios for its function, to bound the time. Survivors carry a class label per function: these are reviewed classes, not a proof that each edit is equivalent, so a survivor is a row this packet does not constrain. An unedited image must pass under the same step limit first.
- Reached rows: 832 of 3517 rows are not reached (`unreached.tsv`). They are panic tails, allocation failures, landing pads, rows for trees deeper than two levels, and the paths named below.

Limits:

- `0x27123d0` is a stub, so its limit test, its status `0x37` for a non-zero byte at action `+0x40` (key byte `+0x38`), and the user credit itself are read, not run. The core accepts that byte at any value, and a key with byte value 6 takes a niche path that is not run here.
- `0x33690c0` is a stub, so statuses `0x97` and `0x2a` are fed in.
- `0x3364ed0` is a stub, so stake values are fixture inputs.
- Who is in the set at state `+0x36a0`, and the live values of `q` and `i`, are not in the binary. The word `name` at tracker `+0` is unread on this path.
- Leaf inserts are stubs; trees have height 0 or 1. Keyed removal `0x33ac830` is a stub acting on a leaf or a one-level view.
- `0x3bad4b0` is a stub, and it only feeds rows that end in frees.
- Slot `0x576e8b8` is a stub that returns; the Once at `0x577ab98` is unresolved. The stub leaves the Once word at 3, so runs take the branch at `0x374e586`, whose compare at `0x374e5bf` has the same level; `0x374e51f` and `0x374e526` are not reached.
- Arm 44's name comes from RE-010 and the reference. Arm 84 has no name; the status text "User is not a voter." is all that names its caller.
- The two other hosts of the core, `0x4d04f80` and `0x4d055f0`, are not compared here.

No gate is requested.

Next question: the credit rows of `0x27123d0` after result 1, and who writes the set at state `+0x36a0`.
