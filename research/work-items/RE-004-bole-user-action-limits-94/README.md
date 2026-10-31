# RE-004: borrowLend from admission to the BOLE core: fixed window rate limits, spot room and status codes

This packet shows how a Rust rebuild must admit a `borrowLend` action: every BOLE action first passes a per-user and a global fixed-window count (status 7), a refused call still counts, class 3 users pass a second, either-window limit (tag `0x170`), a rise in the core's total must fit `total - hold` of the spot row (status 10, not an insufficient balance status), and the reference's privileged finalize branch cannot run.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has a lifted form in `l1/exchange/handlers/56_system_bole.rs` and `l1/bole/user_state.rs`, compared below.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are 15 whole functions, all with mutants: limiter `0x37d9ef0`, BOLE limit `0x373c9c0`, abstraction wrappers `0x28cc390`, `0x4592880`, `0x4592950`, record lookups `0x1f84640` with probe `0x27c4b40` and `0x47d7550`, handlers `0x2764d60`, `0x4d95a70`, `0x4d96040`, apply steps `0x2732ae0`, `0x4d44ae0`, `0x4d49ee0`, and flag and spot room step `0x232bc70`. Stubs with checked arguments stand for the user class lookups, the three pre-step and post-step helpers, `0x25a8030` and copy, `0x28d7c10`, `0x48cd030`, `0x2738e50` and copies, the hash, `memcmp`, `memcpy`, tree insert `0x33beaa0`, drops and the spot user lookup. Excluded: the core math inside `0x28d7c10` (rows in #46, #565), the outer wrappers `0x1f69020`, `0x2764b90` and copies (rows in #393), and the rate and index words (#784).

## Reproduce

From the repository root:

```
python3 tools/bole_user_action_limits.py --out research/work-items/RE-004-bole-user-action-limits-94
python3 -m unittest tests.test_bole_user_action_limits
```

The tool takes about 2 to 4 minutes on a loaded server. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `texts.tsv`, `jump-tables.tsv`, `strings.tsv`, `vote-stores.tsv`, `holders.tsv`, `class-routes.tsv`, `limiter-samples.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs. `S` is the exchange state the handlers receive, `B = S + 0x498`. Three handler copies exist. `0x4d96040` and `0x4d95a70` differ only in three fields, shifted by `0xa80` in the first (`+0x1350`, `+0x11f0`, `+0x1250` for `+0x8d0`, `+0x770`, `+0x7d0`), and `0x4d44ae0` and `0x2732ae0` differ the same way. `0x2764d60` has other stack slots and drops the post-step result through `0x277eba0`, where the other two call a form with no result.

### The limiter `0x37d9ef0`

Slot `0x5774748`. Arguments: record, time, window, limit. The record is a saturating count at `+0` and the last time at `+8` (date word, seconds, nanoseconds).

```
old = unix_ms(record time), new = unix_ms(now), both floored at 0
if old / window < new / window: count = 1
else: count = min(count + 1, u64::MAX)
record time = now
return count <= limit
```

| Fact, each with a row in `limiter-samples.tsv` or `outcomes.tsv` | Value |
| --- | --- |
| Buckets | multiples of the window from Unix 0, not a distance from the last call |
| A refused call | still stores the count and the time |
| After a reset | count 1, so limit 0 refuses every call |
| Clock moving back | counts as the same bucket and stores the earlier time |
| Window 0 | divide fault; the first divide comes before any store |

Both divides pick a 32-bit or a 64-bit `div` from `(ms | window) >> 32`, with the same result. `holders.tsv` lists its users: 0 direct, 41 through the slot, as `call *slot` or a load of the slot into a register.

### Two families of limits

| Family | Parameters | Count records | Rule | Refusal |
| --- | --- | --- | --- | --- |
| BOLE, `0x373c9c0` | user window `S+0x518`, limit `S+0x520`; global window `S+0x508`, limit `S+0x510` | user: value in the tree at `S+0x598`; global: `S+0x528` | user first; if it refuses, the global word is not touched; both must pass | status 7 `Too many operations` |
| Abstraction, `0x28cc390`, and inline in the handlers | first window `S+0x4e8`, limit `S+0x4f0`; second window `S+0x4f8`, limit `S+0x500` | hash map `S+0x770`, slots `0xe0`, record at slot `+0x18`, second at `+0x30` | both always run, either may pass | tag `0x170` |

A pass of the abstraction rule adds one to record `+0x30` and `S+0x7d0`, both saturating. A refusal adds to neither, though both window counts rise.

The user tree at `S+0x598` has 20-byte keys at `+0x218`, values of `0x30` bytes, length at `+0x2f6`, edges at `+0x2f8`. A missing user is inserted through `0x33beaa0` with count 0 and date word from `0x576e890(719163)`. Word `719163` is the day count of 1970-01-01, so the first call of a new user lands in a later bucket and sets count 1. The map record of `0x1f84640` and `0x47d7550` is made the same way, with both windows at 1970, usage 0. A failed date panics.

`vote-stores.tsv`: one store each to `+0x4f0`, `+0x500`, `+0x4f8`, `+0x510`, `+0x508`, `+0x520`, `+0x518` in each of the three vote dispatchers, 7 stores, and the string `struct variant SetBole::RateLimit with 7 elements` (`strings.tsv`). Read from the rows at `0x235c188`: the three window fields are tested non-zero, the limits by an option flag, and each is held below `0x0ccc...cccc` with tag `0x13f`. So a vote cannot set a window to 0. No store to `+0x4e8` sits in these dispatchers.

### `borrowLend` handler `0x2764d60`

The action string sits in `strings.tsv`. Arguments: output, `S`, user, action `(w0, w1, asset, op byte)`. Order:

| Step | Refusal |
| --- | --- |
| Class byte `[0x2755400]+0x3c >= 4` and `S+0x5b0` bit 0 clear | `0x173` `Manual borrow/lend not allowed with portfolio margin` |
| `0x373c9c0(B, user, S+0x60)` is not 10 | `0xe1` with that byte, so 7 |
| Asset not in the tree at `S+0x568` | `0xe1` inner 0 `Invalid token` |
| User in the tree at `S+0x8d0`: op 0 or 2, or asset not 0, or record `+0xaf` zero | `0x15` `Vault may not perform this action.` |
| Class 3 with `S+0x5b1` clear: abstraction rule | `0x170` |
| Apply step `0x2732ae0` | its result |

The limit comes before the asset check, so a call for a token that does not exist still spends the budget. `class-routes.tsv` holds the 20 pairs of class and flags as run: class 3 with `S+0x5b1` clear takes the routed form, pre-step `0x272fe00`, apply, post-step `0x272d000`, and the post-step result never reaches the output. All others apply directly.

The bytes also hold a branch for class above 3 with `S+0x5b0` clear at `0x27650e5`, and a `class == 4` finalize through `0x272f880` at `0x27651bc`. The first gate has already refused that class and flag, and the only callee between them that writes is the limit, whose stores are the count and time words. So the finalize call cannot run from this handler. In the tests it stays unreached over the whole grid, and removing the first gate reaches it. The same holds for the other two copies, whose rows at `0x4d95edc` and `0x4d964ac` stay unreached. The argument `class == 4` to the pre-step is always 0 for the same reason.

### Apply step `0x2732ae0`

Adds one to `S+0x58` (saturating) on entry and takes one off on every exit, stopping at 0. Then:

| Input or result | Output |
| --- | --- |
| `w0` low bit set and `w1 == 0` | Ok, no call |
| Core tag 3 | `0xe1` with its byte |
| Core tag 2 | `0xe2` `Insufficient balance or limits exceeded` |
| Core changed amount 0 | `0xe2`, record dropped |
| `0x2738e50` returns anything but `0x11` | `0xe1` inner 10 `Internal error` |
| Otherwise | Ok |

The word `+0` of the user's record in the tree at `S+0x8d0`, tested equal to 1, is the flag passed down. `0x25a8030` turns the op into a selector equal to the op and an amount: the arms in `jump-tables.tsv` return no amount for op 0 and 3, and for op 1 and 2 the spot row's `+0` less `+8`, with the `impl_wei.rs` recorder and 0 if that would go below 0 (read from the rows, not run).

### Flag and spot room step `0x232bc70`

Selector table `0x3dcdf8`. With `a = B+0x11b`, `b = B+0x11a`, `c = B+0x11c` (bytes `S+0x5b3`, `S+0x5b2`, `S+0x5b4`):

| Selector | Status 8 `Operation not allowed` | Status 4 `Only supplying is enabled` |
| --- | --- | --- |
| 0 | `!a` or `c` | else `b` |
| 1, 2 | `!a` | never |
| 3 | `!a` or `c` | never |

The record passed down is the user's value in the `S+0x598` tree, or the static default at `0x5786350`. After the core returns with tag other than 2 or 3 and a set byte at `+0x108`, with `x` the word at `+0x100`:

```
(total, hold) = spot row of the asset, or (0, 0) if absent
x + hold wraps, or x + hold > total: tag 3 status 10, record dropped
```

`0x25a8030` subtracts the same two row words (`+0` less `+8`) to build its amount, so this compare is the room left in that row. The row is the 24-byte value in the tree at `[0x5773170(S+0x80, user)]+0x10`.

### Status codes against the reference

From `texts.tsv`, read from table `0x5a56c4` and the arm at `0x3998418`:

| Code | Text in the binary | Reference name in `user_state.rs` |
| --- | --- | --- |
| 0 | Invalid token | none |
| 1 | Insufficient collateral for operation | `HEALTH_TIER_FAILED` |
| 2 | Insufficient balance | `ZERO_OR_UNDERFLOW` |
| 3 | Exceeded cap for asset | `ARITHMETIC` |
| 4 | Only supplying is enabled | none |
| 6 | Insufficient spot balance for operation | `CAP_EXCEEDED` |
| 7 | Too many operations | none |
| 8 | Operation not allowed | none |
| 9 | Invalid index | `ASSET_MISSING` |
| 10 | Internal error | `GENERIC_VALIDATION` |

Other reference claims this packet changes:

| Reference | Bytes |
| --- | --- |
| `normalize_user_for_bole` preflight | a rate limit that writes counts and inserts a user |
| `accept_routed_bole`, a dual set membership test | two time windows on a per-user record |
| `address_volume_limit (used, limit)`, status 5 | spot row `(total, hold)`, status 10 |
| `header_0`, `header_8`, `header_10` of the user config | limiter count and last time |
| `UserClass` `DexUser`, `PrivilegedDexUser` | class 4 is portfolio margin by tag `0x173` |
| finalize for class 4 | unreachable from this handler |

## Implementation and comparison

The bytes run in a small x86-64 evaluator inside the tool, with no objdump and no execution of the binary. Fixtures are real: B-trees with the searched key left in unused slots, and a 64-bucket hash table with twins, tombstones and wrapped groups. A rule list written apart from the evaluator predicts the whole 53 KB heap image, the stub events and the result of each run. Each stub checks its arguments.

719 named cases and 1500 vectors matched. 888 of 903 edits of reached conditions, immediates and field offsets are found, 15 survive, and each survivor has its reason in `mutations.tsv`. Rust rebuild: not yet implemented.

## Results and limitations

- Vectors and edge cases, not a proof over all inputs: the limiter's closed form is checked at 1500 points plus the bucket edges.
- `evidence.json` lists unreached rows per function: the branch for year 0 and below in `0x37d9ef0`, which only makes dates that the floor at 0 hides, the lazy default set-up in `0x232bc70`, the dead class 4 rows, landing pads, and the hash table fix-up for tables under 16 buckets.
- The stale bytes that the `0x170` exit copies behind its tag are cleared before the compare, since a payload-free tag does not read them.
- `0x25a8030` and its copy are stubs here; the op to selector reading is from the rows.
- Unresolved: what fills the eight parameters at start-up, and so whether window 0 can occur. What writes `S+0x4e8`, the one parameter that the vote does not store. What sets `S+0x5b0`, `S+0x5b1`, `S+0x5b3`, `S+0x5b4`. The vote's seven field names: the short keys in `strings.tsv` sit next to the variant, but no field table was read.

Inferences, not observations:

- Class 3 as `unifiedAccount` and the rest of the class names come from the order in `strings.tsv` and the `0x170` text. Only class 4 has a text that says so.
- Op 0 borrow, 1 supply, 2 repay, 3 withdraw follows from the status 4 text, from the spot amount on ops 1 and 2, and from lanes in the reference.
- The tree at `S+0x8d0` as vaults comes from tag `0x15` alone.
- The spot row words `+0` and `+8` as total and hold are the natural reading of the subtraction and the room compare.

Next question: what do the core's retry factors do with the amount passed from `0x232bc70`, and does the `S+0x58` word gate any reader while it is above 0.
