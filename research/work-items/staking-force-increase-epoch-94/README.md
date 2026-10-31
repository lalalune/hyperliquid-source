# staking: forceIncreaseEpoch and the epoch roll in node #94

This packet shows how node #94 moves `active_epoch`, so a reconstruction can write `force_increase_epoch` and the `Staking` state from bytes: gate order, signed tuple, which validator field signs, the 2/3 stake compare, the epoch snapshot and the 1000 row prune. Eleven claims in the reference handler do not hold (table below).

- Component ID: staking (Staking and validator lifecycle, `l1/staking.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference file `l1/exchange/handlers/09_force_increase_epoch.rs` is a lead only. Nothing is copied from it.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are the whole functions `0x3368380`, `0x33696b0`, `0x3366b60`, `0x3369500`, `0x33676a0`, `0x3941e70` and `0x3c97a70`, the serde key rows that name their fields, and every call site of these functions. Excluded: the rows of the handler wrappers `0x21e0a00`, `0x46bbe70`, `0x46bbfe0` and of the block step functions `0x22297c0`, `0x470e9a0`, `0x47162d0`. Those functions have rows in other packets, so this packet gives only site addresses inside them. Callees are stubs with argument checks (list below).

`0x3366b60` appears in merged #98 only as the exclusive end of `0x3366580`. #98 does not read its bytes. `0x3366580` and its caller `0x3369db0` are not read here.

## Reproduce

From the repository root:

```
python3 tools/force_increase_epoch.py --out research/work-items/staking-force-increase-epoch-94
python3 -m unittest tests.test_force_increase_epoch
```

The tool takes 1 to 4 minutes, depending on server load. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `callers.tsv`, `constants.tsv`, `field-names.tsv`, `status-text.tsv`, `calendar.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. Slot targets come from `.rela.dyn` RELATIVE rows. Field names come from serde key rows (`field-names.tsv`). Status text comes from the Display table at `0x59a8d0` (`status-text.tsv`).

### State

`Staking` sits at exchange state `+0x3840` (read at the wrapper sites). `struct Staking with 6 elements` names the fields, and the serializer `0x3365130` pairs each key with its offset.

| Offset | Field | Note |
| --- | --- | --- |
| `+0` | `epoch_duration_seconds` | u64 |
| `+8` | `cur_epoch_state` | `EpochState`: `validator_states` map at `+0`, `start_time` at `+0x18` (12 bytes) |
| `+0x30` | `epoch_states` | map from u64 epoch to a 0x28 byte `EpochState` |
| `+0x48` | `active_epoch` | u64 |
| `+0x50` | `cur_epoch` | u64 |
| `+0x58` | `allowed_validators` | not read here |

`validator_states` maps a 32 byte key to a 0x40 byte `ValidatorState`: `delegations` at `+0`, `hot_user` at `+0x18`, `cold_user` at `+0x2c` (serializer `0x3365cb0`).

`ForceIncreaseEpochAction` has `validatorsAndSignatures` at `+0`, `newActiveEpoch` at `+0x18`, `nonce` at `+0x20` (serializer `0x3981d10`). The handler walks `validatorsAndSignatures` as a map: keys of 0x20 bytes at node `+0`, values of 0x48 bytes at node `+0x168`. So keys are unique and sorted.

### `0x3368380`: handler body

Result rdi, `Staking` rsi, chain byte dl, action rcx. Status `0x186` is Ok. The order below is the order of the rows. `time = start_time + f64(epoch_duration_seconds)`, from the helper in slot `0x576efb8`, is computed first.

```
0. no row for active_epoch in epoch_states:
       r = advance(chain, time, cur_epoch); status r ? 0x186 : 0x98; no signature, count or epoch is read
1. count >= 10001:                 0x143, word +0x18 = count
2. newActiveEpoch >= 0x0ccccccccccccccc:  0x13f, word +8 = value
3. newActiveEpoch < cur_epoch:     0x98
4. each (key, signature) in key order:
       h = keccak256(abi(string "forceIncreaseEpoch", uint newActiveEpoch, uint nonce))
       d = helper 0x37f2940(source byte, h, chain id 1337);  failure: 0x7a with payload
       a = recover(signature, d);                            failure: 0x7a with payload
       no validator row for key in epoch_states[active_epoch]: 0x94
       a != cold_user of that row (all 20 bytes):              0x11f
       add key to a set
5. stake_quorum(epoch_states, active_epoch, set) is false: 0x99
6. advance(chain, time, newActiveEpoch) is false: 0x98, after a call to 0x14385c0
7. active_epoch = newActiveEpoch; 0x186
```

The source byte is `0x61` when the chain byte is 3, else `0x62`. Only the low byte of the chain word is read. The hash chain is rebuilt for each row. Step 4 uses the validators of `active_epoch`, not of the new epoch. The keccak rate word is `0x88` and the delimiter word is 1, at `0x3368995` and `0x33689a1`.

### `0x3c97a70`: signed tuple

It builds a 3 element token list of 0x28 byte rows: kind 6 with the 18 byte string, kind 4 with `newActiveEpoch` as the low limb of four, kind 4 with `nonce` the same way. Then it calls slot `0x576ed20`, target `0x1592160`. The evaluator holds the row kinds, limbs and drops.

### `0x3366b60`: stake quorum

Arguments: `epoch_states` root and height, epoch, set. It has 8 call sites (`callers.tsv`), and only the one in `0x3368380` is read here.

```
no row for epoch:  false
stakes = 0x3364ed0(row)        (key -> stake)
no stake rows:     false
T = sum of stakes              (checked; overflow panics at the Location 0x56e9f88)
S = sum of stakes of the set   (saturating form; keys with no stake row add 0)
empty set:         false
return 3*S > 2*T               (128 bit compare, strict)
```

So exactly two thirds is refused. The function walks the stake map and the set in key order, and trees of height 0, 1 and 2 run in the cases.

### `0x33696b0`: advance

`advance(S, force byte, now, target)`:

```
if cur_epoch > target: return false
old = U(start_time) / epoch_duration_seconds
new = U(now)        / epoch_duration_seconds
flag = active_epoch == 0 && (force byte != 0 || len(cur_epoch_state.validator_states) == 3)
if new <= old and !flag: return false
epoch_states[target] = clone of cur_epoch_state        (keeps the old start_time)
if flag: active_epoch = cur_epoch
cur_epoch = target + 1, saturating
start_time = now                                       (all 12 bytes)
while len(epoch_states) > 1000:
    first = smallest key; stop if the map is empty or first >= active_epoch
    remove first
return true
```

`U(date, seconds)` is whole seconds from the packed chrono date, `max(days*86400 + seconds, 0)`. Sub-second bytes are not read. `calendar.tsv` pins it on 13 dates up to 9999-12-31 against the Python calendar: `floor(U/X)` is 1 and `floor(U/(X+1))` is 0 only when `U` is exactly `X`.

The prune runs before the handler writes `active_epoch` in step 7, so it uses the old value. A row is dropped only when its date word is nonzero. The root is replaced when the pop says the tree lost a level.

### Smaller functions

- `0x3369500`: `(epoch, key)` to `hot_user`. `0x97` no epoch row, `0x94` no key, else `0x186` with 20 bytes at result `+2`. Reached by two loads of slot `0x5775c88` at `0x3bd3007`, `0x3bd7b17`.
- `0x33676a0`: last key of `epoch_states`, or none when the root is null or the length is 0. Six call sites, one after each successful handler or block step.
- `0x3941e70`: map at tracker `+0x18`, u64 key. Key present gives `0x9a`, else a new row with an empty map and flag bytes `00 01`.

### Differences from the reference handler

| Reference claim | Bytes |
| --- | --- |
| signatures are a `Vec` | a map, so sorted and unique |
| `epoch > 10_000` refused | 10000 limits the signature count, status `0x143` |
| epoch row missing returns `0x97` | runs `advance` on `cur_epoch` and returns `0x186` or `0x98` |
| quorum before signatures | signatures first, then quorum |
| epoch snapshot read for `action.epoch` | `active_epoch` |
| recovered address compared with `signer` | `cold_user` (`+0x2c`) |
| signable bytes are a plain byte concat | keccak of a 3 token list, then helper `0x37f2940` |
| `requested_epoch <= wall clock bucket` refused | bucket of `start_time` against bucket of `now`, and `now` here is `start_time + duration` |
| bootstrap reads a mode word equal to 3 | length of `validator_states` equal to 3 |
| `signed*3 > total*2` over saturating totals | total is checked and panics |
| prune removes the oldest until 1000 remain | stops at the first key not below `active_epoch` |

The 1000, 2/3 and chain id 1337 values of the reference hold.

## Implementation and comparison

Rust implementation: not yet implemented. There is no compiled comparison. The comparison here is between real instruction bytes and a rule list kept apart from the evaluator.

The evaluator runs the real bytes of all seven functions. `0x33696b0`, `0x3366b60` and `0x3c97a70` run nested from `0x3368380` as well as on their own. Fixtures are real B-tree nodes with stale keys in unused slots. For every case the rule list edits a copy of the fixture and lists the expected calls. Both the 0x14800 byte fixture and the call list must match exactly.

Cases: 250 named (94 handler, 87 advance, 34 quorum, 15 lookup, 7 last key, 13 tracker) plus 600 generated. All match. `outcomes.tsv` has the status, result head, call names and a fixture digest for each named case.

Mutation: 588 edits over every reached conditional, immediate and field offset. 554 killed, 34 survived, each with its reason in `mutations.tsv`. The largest groups are the year <= 0 branch, which the `max(0)` clamp hides, and the unrolled eight level descent. An unedited image runs first under the same step limit, so a kill cannot come from that limit.

Tests: 80 pass, with negative controls for hash, a NOBITS address, a non-FDE start, changed key text, field offset, limit and string bytes, a lost call site, edited compare, limit, chain id, source byte, prune bound and store rows, and an unmodelled call. Test numbers are literals.

## Results and limitations

Stubbed callees, each with argument checks: the time helper `0x1459ca0`, keccak absorb and squeeze, the token encoder, `0x37f2940`, recover `0x14c6f50`, the stake map builder `0x3364ed0`, the map clone, insert and pop helpers, the set insert `0x33a0950` and the drops. So the keccak output, the signature recovery and the digest layout are not evaluated. The stub adds seconds to `start_time` without normalising the date.

- Inference: `0x1592160` is `ethabi::encode` and kinds 6 and 4 are `Token::String` and `Token::Uint`. The binary holds the path text `ethabi-18.0.0/src/encoder.rs`, and the kinds match that crate's enum order. The rows of the encoder are not read here.
- Inference: `0x37f2940` is the phantom agent signing hash, from the source byte and chain id. Its rows are not read here.
- Inference: chain byte 3 is Mainnet, from other packets.
- Inference: with `now = start_time + duration` and `duration > 0`, the bucket gate in step 6 passes, because `(s+d)/d = s/d + 1`. The refused cases reach that branch through stub values. Whether the real helper can give them is not shown. Rounding of a huge duration through `f64` is not read.
- Stub driven: step 0, with `advance` true, needs a state with no row for `active_epoch`. This packet does not show when that state exists.
- Read by eye, not evaluated: the three wrappers pass `Staking`, the chain byte `+0x8f2` and a copy of the action, then after Ok call `0x33676a0` and `0x3941e70` and drop a `0x9a` result. The block step functions call `advance` with `cur_epoch` and the block time `+0x60` when word `+0x28` is nonzero. So plain epoch rolls leave `active_epoch` alone once it is nonzero. This packet found no other writer of `active_epoch`, but it did not search every pointer path.
- The meaning of the 32 byte `validator_states` key is unresolved.
- `0x3369db0` is the likely reader of the snapshots for a validator set update, and it is not read here.
- `0x33a0950` is a stub, so insert order and duplicates in the set rest on the map property of the action.
- Unreached rows are listed per function in `evidence.json`: the unrolled descent for trees of height 8 or more, allocation failure, unwind pads, and panic arms for broken tree links.

Progress gate: none requested.

Next question: who writes `validator_states` of `cur_epoch_state`, and what the 32 byte key is.
