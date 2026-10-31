# RE-006: order placement path: account mode routing, the book wrapper, and the host that rests a trigger order or calls insert

This packet gives a reconstruction the path of one order on node #94 from the account mode byte to the book: which of three routes runs, the two bucket gate behind status `0x170`, the 0x48 byte request and 0x50 byte group layouts, the order type word, the first writer of field `u` of `user_states`, the rule that sends a trigger order to `u` instead of `insert`, the rows on each outcome, and the final status word. The reference has no body for any of these, so the reconstruction can now write these functions from tables instead of guessing them.

- Component ID: RE-006 (book state transitions), one path from the account mode byte to `insert` or field `u`
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are bucket gate `0x37d9ef0`, routers `0x4ca9710` and `0x4ca8eb0`, wrappers `0x4d446f0` and `0x4d472f0`, hosts `0x430be90` (perp) and `0x430abf0` (spot), user entry `0x45a3b30` and the write into `u` `0x4932c30`. Real bytes without mutants: `0x4ca8510`, `0x4ca7cb0`, `0x4d47ad0`, `0x4d476e0`, `0x4309700`, `0x4308460`, `0x45a3980`, `0x493c4b0`, shown equal to the first copies by `copies`. Stubbed at the edge: insert (`0x4311140`, `0x4314da0`, `0x4318a00`, `0x430d610`, the #47 family), record builders `0x42fe2d0` and `0x42fe970`, tick helpers `0x42c7600` and `0x4ca6b90`, settle helpers `0x4cd84f0` and `0x4470be0`, hash helper `0x3987cb0`, row flush `0x432a100` and `0x4329870`, steps `0x46ea0b0`, `0x46efb70`, `0x46ef4a0` and their second copies, tree clone `0x4995950`, node split `0x42188a0`, new user leaf `0x495a570` and `0x495a740`, count map `0x379a110` and `0x35779f0`, client id map `0x342aa50`, allocator, memcmp, memcpy. Excluded: the bodies of those stubs, and what the callers of the routers do.

## Reproduce

From the repository root:

```
python3 tools/order_place_route.py --out research/work-items/RE-006-order-place-route-94
python3 -m unittest tests.test_order_place_route
```

The tool takes about 110 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | First copy | Second copy |
| --- | --- | --- |
| Router, with the bucket gate | `0x4ca9710` | `0x4ca8510` |
| Router, no gate | `0x4ca8eb0` | `0x4ca7cb0` |
| Wrapper, status from result `+0x08` | `0x4d446f0` | `0x4d47ad0` |
| Wrapper, status from result `+0x00` | `0x4d472f0` | `0x4d476e0` |
| Perp host | `0x430be90` | `0x4309700` |
| Spot host | `0x430abf0` | `0x4308460` |
| Row flush | `0x432a100` | `0x4329870` |

Each router calls its wrapper from 3 sites. Each wrapper calls its host once. All sites are in `call_sites.tsv`, with the 20 slot sites of the bucket gate, which also shows the gate on hosts outside this path (`0x26c9cf0`, `0x26d0e50`, `0x2731870`, `0x373c9c0`, `0x4d3c640`, `0x4d3d0f0`, `0x4d3ddb0`, `0x4d401d0`). The two copies in each row are equal once call and rip displacements are masked, except rows that name a state field. `copies` lists each such row with its two displacements. The spot hosts are called from `0x4d12e80`, `0x4d15710`, `0x445f870`, `0x44612d0`, not from these wrappers.

### Names of the state fields

The Debug writer `0x4c696f0` prints struct `Context` and pins each field name to an offset (`context_fields`). The merged `RE-001-truncated-debug-94` holds this address as a callback row only. The state passed down this path starts with that struct.

| Offset | Field | Use here |
| --- | --- | --- |
| `+0x00` | `tx_index` | dword 1 means present, word at `+0x08` |
| `+0x28` | `height` | hash helper argument |
| `+0x38` | `next_oid` | read, then raised, stops at `u64::MAX` |
| `+0x58` | `maybe_operate_with_abstraction_reentrancy_counter` | raised around a wrapper run, stops at both ends |
| `+0x60` | `time` | 12 bytes: packed date, seconds, nanoseconds |

Also in the table: `initial_height`, `hardfork`, `round`, `prev_time`, `next_lid`, `next_twap_id`, `system_nonce`, `use_system_nonce`.

### Router: three routes

The mode byte is `+0x3c` of the row from `0x46f2e60` (`0x46f2fe0` in the second copies). Let `low` be bit 0 of state `+0x5b0` and `high` bit 0 of `+0x5b1`. `route_table` lists all rows.

| Mode byte | Condition | Route |
| --- | --- | --- |
| 4 or more | `low` set | direct |
| 4 or more | `low` clear | collateral |
| below 4 | `high` set | direct |
| 0, 1 | | direct |
| 2 | flag byte set and asset at least 10000 | dex |
| 2 | otherwise | direct |
| 3 | | collateral |

- Direct: the wrapper alone.
- Dex: accessor `0x3332680` gives row `+0x50`, then step `0x46ea0b0` with stack word 1 and the dex, the wrapper, then, if the flag byte is still set, a second read and step `0x46ea0b0` with the arguments turned round. A step status other than `0x186` is dropped through `0x4daf4a0`. The order still runs.
- Collateral: bucket row from `0x47d7550`, the gate in the first router, then step `0x46efb70` with a local word 2, the wrapper, then `0x46ef4a0` for mode 4 or more, else `0x46ea0b0`. A failed step status is dropped through `0x472f840`. The operation words are state `+0x1250` and bucket row `+0x30`, both saturating. A dex at or past the count panics with `Invalid perp DEX` (`0x141`).

### Bucket gate

`0x37d9ef0(row, now, window_ms, limit)`:

```
fresh = last_ms / window < now_ms / window
count = 1 if fresh else min(count + 1, u64::MAX)
last = now
return count <= limit
```

The first router calls it twice, always both, with the row at `+0x00` and `+0x18`, and with state `+0x4e8`, `+0x4f0`, then `+0x4f8`, `+0x500`. It rejects only when both return false. So one bucket under its limit lets the operation pass. The rejected call has already raised both counts and moved both times. On rejection the output is status `0x170`, text `Too many abstraction operations. Automated users should manually manage collateral.`, and the group vector is freed when the tag is below 2 and the capacity is not 0. The second router has no gate and no such status, and it raises state `+0x1250` before the row lookup.

Windows and limits are read here, not set. Their values are unresolved.

### Request and group

Layouts are in `fields`. The wrapper closure holds the 0x48 byte request, the 0x50 byte group, a pointer to the asset word at `+0x98`, and a pointer to the user at `+0xa0`.

| Group tag | Stored tag | Rows | Hash helper last argument |
| --- | --- | --- | --- |
| 0, 1 | same | pair, then 0xa on success | group `+0x48` |
| 2 | 0 | pair, then 0xa on success | 0 |
| 3 | 0 | none | not called |

The hash helper runs only when `tx_index` is present, else the 0x20 bytes are zero. With tag 3 no helper runs and the flag byte is 0.

### Host: which arm

Request byte `+0x19` picks the arm.

Kind 2 is the insert arm. The low byte of `+0x10` is the tif byte. The order type word is 9 for group tag 3, else 1 when the tif byte is 3 or more, else 0. These match the names in the #486 table: Limit, Market, Twap Slice. `insert` receives the request listed under `insert_request`.

Any other kind byte is the trigger arm. `+0x10` is the trigger price.

1. Perp only: dex past the count panics.
2. Price above `1e15` gives error word `0x8000000000000009`, text `Invalid TP/SL price.`.
3. Price not a multiple of the tick gives the same error. Perp asks `0x42c7600(dex row, asset, price)`, spot `0x4ca6b90(state + 0x90, asset, price)`. The asset comes from the book at `+0xb0`, not from the request.
4. The oid is `next_oid`, and the counter is raised.
5. `0x45a3b30` finds or creates the entry in `user_states` at book `+0xb8`.
6. `0x4932c30` writes the 0xb8 byte order into `u` at entry `+0x38`, key oid. An existing key is replaced and its vector freed. An empty map gets a new 0x850 byte leaf. Other cases go to split `0x42188a0`.
7. With client id bit set, `0x342aa50` at book `+0x48` records user, oid, client id.
8. The per-user count at state `+0x11c0` or `+0x740` goes up by 1, saturating. A new row takes date word `0xf6401a`, which decodes to 1970-01-01.
9. The result has oid at `+0x30`, flag and client id at `+0x38`, byte 1 at `+0x49`, no fills.

The stored order type word is `(3 + 2 * (kind & 1)) ^ (market & 1)`: 2 Take Profit Market, 3 Take Profit Limit, 4 Stop Market, 5 Stop Limit. Stored `+0xb0` is `(kind << 8) | market`.

### Host: after the arm

On an error word:

- Tag 3 returns the error with no row and no oid taken.
- Otherwise the oid counter moves, a record is built with that fresh oid, and two 3 rows go out: first with the stored tag, second with 4. The status byte is table `0x6f1680`, indexed by the error word with the top bit cleared, or 2 for a word with the top bit clear. `error_words` lists all 24 with their fixed texts.

On success:

- Settle (`0x4cd84f0(dex row, ...)` or `0x4470be0(state + 0x80, ...)`) gets the fills, the optional 0x20 bytes, and a byte 1 when the tag is 2 or more.
- Tag 3 stops here.
- Otherwise a record with the result oid, the same row pair with status 0, and a 0xa row with a clone of the result tree (root `+0x18`, height `+0x20`, length `+0x28`) and the request asset. Length not 0 with root 0 panics.

A resting trigger takes the same path, with no fills and an empty tree.

### Wrapper

1. Raise `+0x58`.
2. `asset / 10000` at or past the row count panics with word `0x141`. `asset % 10000` at or past the book count panics.
3. Run the host, then the flush with the rows and `asset / 10000`.
4. Result word `0x8000000000000000`: tag `0xc4`, wire asset, error word. Wire asset is the asset up to 9999, `asset + 100000` up to 99899999, else `0xffffffff`.
5. Any other word: tag `0x186` and the whole result. The dword beside the tag is stack address bytes on this arm, so it has no meaning.
6. Lower `+0x58`, stopping at 0.

Wrapper `0x4d446f0` writes a zero word first and the status from `+0x08`. Router `0x4ca9710` then drops that word. The other pair has no such word.

### Reference claims

Listed in `reference_claims`. The reference has no `untriggered_orders`, no `Too many abstraction` text, and no body for the order path by mode. `l1/order_wire.rs:62` agrees on the three trigger facts by name, and the layout is new here.

### Inferences

- Modes 2, 3, 4 are `dexAbstraction`, `unifiedAccount`, `portfolioMargin`: table `0x570d358` (`mode_name_rows`) ends with those rows, and the byte is assumed to be the variant index. `disabled` and the default name for bytes 0 and 1 are not proved.
- The routers are `maybe_operate_with_abstraction`: the counter name and the text `abstraction operations` suggest it, but no Location ties them.
- The dex and collateral steps move collateral around the order. The arguments support it. Their bodies are not read here.
- Group tag 3 is a twap slice, from order type word 9. Its first payload word then goes to insert `+0x78`.
- The 0x48 byte vector in the group is a list of child orders, from the row size and the `children` field in #486.
- The hash helper builds a transaction style hash from a state byte, the height and an index. Only its arguments are observed.

## Implementation and comparison

not yet implemented. No Rust was written. The evaluator runs real bytes against a Python specification, which is not a reconstruction.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases | 3094 |
| Mismatches | 0 |
| Instructions stepped | 736,595 |
| Stepped / total: bucket gate | 140 / 140 |
| Stepped / total: router with the bucket gate | 409 / 442 |
| Stepped / total: router without the gate | 358 / 391 |
| Stepped / total: wrapper, status at +0x08 | 163 / 200 |
| Stepped / total: wrapper, status at +0x00 | 162 / 199 |
| Stepped / total: perp host: rests a trigger or inserts | 860 / 975 |
| Stepped / total: spot host: rests a trigger or inserts | 798 / 881 |
| Stepped / total: user_states entry | 94 / 95 |
| Stepped / total: write into field u | 125 / 146 |
| Stepped / total: second router, gate | 409 / 442 |
| Stepped / total: second router, no gate | 358 / 391 |
| Stepped / total: second wrapper, +0x08 | 163 / 200 |
| Stepped / total: second wrapper, +0x00 | 162 / 199 |
| Stepped / total: second perp host | 860 / 975 |
| Stepped / total: second spot host | 798 / 881 |
| Stepped / total: spot user_states entry | 94 / 95 |
| Stepped / total: spot write into field u | 125 / 146 |
| Mutants killed / survived / unreached | 997 / 77 / 69 |

Mutants flip every conditional jump, set, cmov, immediate and non-stack field offset in the first copies. A mutant runs on at most 120 cases that reach it, plus every gate case and the cases with a rare value.

Every survivor has a reason in `mutations.tsv`, and each reason falls in one class: the arm for a date with year 0 or below, which clamps to 0 ms; the sign of the hundred quotient; the test that picks a 32 or 64 bit divide; values read only on an unwind path; an empty rows vector set up for an unwind pad; the packed `+0x1a` word, dead on the only arm that keeps it; compares with a dead equal arm; a copy size where one more byte is overwritten next; and a new leaf at index 0. Unreached rows are unwind pads, allocator failure and panic arms.

- Insert, the record builders, the steps, settle, the hash helper and the count map are stubbed, so their effects are not checked here.
- Split `0x42188a0` is stubbed. The stub checks the key slot, so a write into a full leaf is not shown.
- Second copies run all cases but have no mutants of their own.
- Stale stack bytes (group payload beyond a tag other than 1, the tail of a resting result, result `+0x20`) are left out of the compare.
- What writes state `+0x4e8` to `+0x500` is unresolved. A byte scan found only reads.
- Whether every router caller passes a user whose row exists is not read here.

Next question: what sets the bucket fields at state `+0x4e8` to `+0x500`, and what do steps `0x46efb70` and `0x46ef4a0` move for modes 3 and 4?
