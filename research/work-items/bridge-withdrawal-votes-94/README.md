# bridge: withdrawal row, validator signatures and finalize votes in node #94

This packet shows that a withdrawal leaves the bridge through one vote tracker with two stages and a strict `3 * voted > 2 * total` stake test, so a reconstruction can build `withdrawal_signatures`, `withdrawal_finalized_votes` and `finished_withdrawal_to_time` from the bytes: both vote handlers refuse only a row that does not exist (status `0x90`), repeat votes never fail, finalizing does not read the signature quorum, and the "keep 100 rows" step in the reference trims nothing.

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`; handler arms 40 and 46 of RE-010)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, status text, serde keys, node layouts and call sites; inference for the action names, the unit of `usd` and the meaning of the second map; unresolved items are under limits
- Scope included and excluded: included are 25 functions run as real bytes (`path.tsv`), from the row insert `0x3941fe0` through the arm `0x374ec60`, the wrapper `0x27177c0`, the core `0x374f5b0`, the two trackers, the quorum and stake test, the row removal and the finish-time insert. Excluded, and stubs here: the request builder `0x358ea60` (bridge packet), hash helper `0x37f2940`, signature recovery `0x14c6f50`, the unique-validator lookup `0x33690c0` (body bound by #133 and #425; this packet feeds its statuses in), the stake map builder `0x3364ed0` (the validator row field it reads is not pinned), the key set builders `0x3bb29c0`, `0x3bb2dc0`, the keyed removals `0x33ad8c0`, `0x33ab370`, the leaf inserts behind the vacant entries, the clones and drops, and the event sink `0x3576710`. Deposit votes (`0x3947510`) and validator set votes are not read. `0x2734200` and its nonce and amount gates are in `RE-004-withdraw-amount-gates-94`.

## Reproduce

```
python3 tools/bridge_withdrawal_votes.py --out research/work-items/bridge-withdrawal-votes-94
python3 -m unittest tests.test_bridge_withdrawal_votes
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 5 minutes, most of it the mutation sweep.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; every function ends exactly at its FDE end.

### The path

```
withdraw3 record 0x374fce0
  row_create 0x3941fe0          key (nonce, user), inner row (amount, destination), else 0x9a
action arm 40  0x374ec60        limit, hash, recover, signer, validator, row, tracker
  tracker_sign 0x3942d90        store signature; quorum 0x39415b0 -> stake test 0x3366b60
action arm 46  0x27177c0        limit, core, event
  core 0x374f5b0                validator, row, tracker
    tracker_final 0x3944860     store voter per hash; quorum 0x3940d60 -> stake test 0x3366b60
    on quorum: 0x3942240 and 0x3942880 remove both rows, 0x3399b90 writes the finish time
```

`withdrawal_signatures`, `withdrawal_finalized_votes` and `finished_withdrawal_to_time` are named by the serializer `0x22155c0`, not by the reference: each key load is followed by the `lea` of its field (`fields.tsv`). With the bridge at state `+0x3398` they sit at bridge `+0x40`, `+0x70` and `+0x118`. The two vote fields are `0x30` bytes wide, and every function here uses the tree at their `+0x18`; the first `0x18` bytes are not read on this path.

Node layouts, including the value offsets that differ between trees, are in `node-layouts.tsv`.

A signature row: key `(nonce at +0, user at +8)`, ordered by the 20-byte user first and then the nonce. Value of `0x48` bytes: `+0` tag (`1` none, `0` some), `+8` winner `(amount, destination)`, `+0x28` inner tree, `+0x40` finished byte. The inner tree is keyed by `(amount, destination)` and each entry holds a tree of 32-byte voter to `0x48`-byte signature, followed by a second tree.

A finalize row has the same key and a `0x40`-byte value: `+0` inner tree keyed by the 32-byte hash, `+0x18` tag byte, `+0x19` winning hash, `+0x39` finished byte. Each inner entry holds a voter set and a second tree.

### Status order

`limit` is `0x0ccccccccccccccc`, which is `i64::MAX / 10`, loaded by a `movabs` at three sites (`limits.tsv`). The comparison is `amount >= limit`.

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`).

| Tag | Text | Arm 40 step | Arm 46 step |
|---|---|---|---|
| `0x13f` | Invalid input number | 1, payload amount | 1 in the wrapper, and again in the core |
| `0x7a` | Unable to recover signer. | 2: hash helper error, 3: recovery error | not on this arm |
| `0x11f` | Signer does not match expected user | 4: 20-byte compare with the outer signer | not on this arm |
| `0x97` | Epoch state does not exist | 5 | 2 |
| `0x2a` | User is not a validator. | 5 | 2 |
| `0x90` | Validator cannot vote on withdrawal that does not exist | 6 | 3 |
| `0x186` | success | 7 | 4 |

Step 6 and arm 46 step 3 are the same two lookups: `0x2fdd3f0` finds the row by key, `0x2fdcfb0` finds `(amount, destination)` in its inner tree. Any miss, including an empty tree, is `0x90`. `scenarios.tsv` has the outcome of every run, including the order pairs such as `sign_order_hash_before_validator`.

The wrapper writes only the tag on success, so the core's result byte `+2` and hash `+3` stay inside the wrapper. On a finish the wrapper loads dex 0 from the vector at state `+0x5c0`; an empty vector panics through `Result::unwrap` with status `0x141` after the state has changed (`finalize_no_dex_panics`).

### Tracker rules

Both trackers follow one shape; `tracker_sign` has a second stack argument, the literal 1 from its one caller, which no row reads (`reads_of_tracker_second_stack_argument` in `evidence.json`).

1. No voter: nothing happens and the output is none.
2. `0x3367530` tests the voter against the epoch at context `+0x48`. A voter outside it leaves the state alone and the handler still returns `0x186`. Through the arms this cannot happen when the lookup and the test read the same epoch; the direct `track_*` scenarios cover it.
3. The row and then the inner entry are created if absent. Through the arms they exist already for signatures. Finalize rows are created by the first vote.
4. If the row's finished byte is set, the voter is stored and nothing else happens.
5. Otherwise quorum is read before the insert and after it. A move from false to true sets the finished byte, the tag and the winner, and returns a clone of the sets. Arm 40 drops this output without reading it.

Stored signatures are overwritten: `0x339b0d0` replaces the value of an existing voter key and reports the old one, which `tracker_sign` ignores. The voter set `0x339e610` keeps one copy. So a repeat vote is never an error (`repeat_vote_overwrites`, `finalize_repeat_voter_counts_once`).

### Stake test

`0x3366b60` finds the epoch, gets a stake map from the stubbed `0x3364ed0`, sums the stake of all validators with an overflow panic, sums the voters with saturation, skips voters not in the map, and returns `2 * total < 3 * voted` in 128 bits. Exactly two thirds is false (`exact_two_thirds_is_short`, `weighted_exact_two_thirds`). An absent epoch, an empty stake map or an empty voter set is false. The test is per entry: votes for two hashes, or two amounts, do not add (`finalize_split_hashes`, `finalize_same_voter_two_hashes`).

### Finish

When `tracker_final` reports a winner, the core removes the signature row (`0x3942240`), removes the finalize row (`0x3942880`), and writes the 12-byte time from state `+0x60` into `finished_withdrawal_to_time` through `0x3399b90`, which overwrites an older value and has its old value ignored (`create_after_finish_time_overwritten`). The wrapper then emits one record to the sink at state `+0x8f3`: head word `1 << 63`, amount as `f64 / 1e6`, nonce, `f64 / 1e6` of the word at dex 0 `+0x250`, plus a one-element user list, the time and the winning hash.

Finalize does not read the signature row's finished byte. Three of four validators can finish a row with no signatures at all (`finalize_without_signatures_then_gone`).

### The row count step

Both trackers end with `if len >= 101`, build a two-ended key iterator, and call `0x3bddbf0` or `0x3bd9680`. These collect pointers to the first 100 keys into a heap vector, and the only rows after the call are a capacity test and a free (`row-count-note.tsv`). No row is removed: with 101 rows the map still has 101 after the call, and 800 bytes are allocated and freed (`no_trim_101_rows`, `final_map_101_rows`).

### Copies

`0x374f5b0` has three callers through slot `0x5774a50`. `0x4d0f050` has the same rows as the wrapper. `0x4d0f300` has the same shape with other state offsets (`wrapper-copies.tsv`). The copies were not run.

### Reference compare

`l1/exchange/handlers/40_validator_sign_withdrawal.rs` and `46_vote_eth_finalized_withdrawal.rs` have the shape of this path. These points differ from the bytes:

| Reference | Bytes |
|---|---|
| Limits `0xCCCCCCCCCCCCCCCD` and `0xCCCCCCCCCCCCCCCC` | Both arms use `0x0CCCCCCCCCCCCCCC`, 16 times smaller. An amount of `0xCCCCCCCCCCCCCCCC` is refused, and so is `10^18` |
| Arm 40 resolves the validator before the request and recovery | Hash, recovery and signer compare come first |
| Arm 40: `144` means the same validator signed twice | `0x90` means the row does not exist; a repeat signature overwrites and returns success |
| Any signature creates the `(user, nonce)` bucket | A missing row is refused; only `0x3941fe0` creates one on these paths |
| Trackers are trimmed to at most 100 keys | No removal |
| `UserAndNonce` key values hold `Withdrawal` | The row value is a vote record; `(amount, destination)` keys its inner tree |
| Pending match is one `Withdrawal` compare | Two tree lookups |
| The event carries `bridge2.bal / 1e6` | The word is dex 0 `+0x250`; `bal` is bridge `+0x130` |
| Quorum is a trait | `2 * total < 3 * voted`, strict, per entry |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the status, payload words, stub events and the full tree state after every operation.

## Results and limitations

- 89 named scenarios (207 operations) and 150 generated scenarios of 10 operations: 0 mismatches.
- 627 byte edits on reached rows of 12 functions (condition, immediate; displacement on the three handlers): 451 killed, 176 survived (`mutations.tsv`). Each edit runs only the named scenarios for its function, to bound the time. Survivors carry a class label per function: these are reviewed classes, not a proof that each edit is equivalent, so a survivor is a row this packet does not constrain. An unedited image must pass under the same step limit first.
- Reached rows: 780 of 4223 rows are not reached (`unreached.tsv`). They are panic tails, allocation failures, landing pads, the non-empty arm of the second tree, rows for trees deeper than one level, and paths named below.

Limits:

- `0x33690c0` is a stub here, so statuses `0x97` and `0x2a` are fed in. The rule that a voter key comes from a 20-byte field of the validator value rests on the bytes of that function, read but not run.
- `0x3364ed0` is a stub, so stake values are fixture inputs. Which validator field becomes stake is not pinned.
- The leaf inserts, keyed removals, clones and drops are stubs that act on leaves. Node splits and merges are not run. Trees have height 0 or 1.
- The second tree in each inner entry stays empty in every run, and a non-empty one reaches a no-return call in `0x330fd70`. What it stores is unresolved. Its nodes keep a count at `+0x322`.
- The first `0x18` bytes of the two vote fields are unresolved.
- That `amount` is 6-decimal USD is inferred from the `1e6` divisor at `0x20ae60`. That `nonce` is the `n * 1000` of `RE-004-withdraw-amount-gates-94` is inferred from the shared key.
- Arm numbers and action names come from RE-010 and the reference. The arm entry `0x374ec60` has no direct caller; it is reached through the dispatch table.
- What the word at dex 0 `+0x250` is, and what the sink does with the record, are unresolved.
- The two copies of the wrapper were compared by rows and not run.

No gate is requested.

Next question: read the deposit tracker `0x3947510` and the validator set trackers `0x3945250`, `0x3945a20` against these rules, and name the field `0x3364ed0` turns into stake.
