# vaults: node #94 vault withdraw guards: HLP daily floor inputs and the position reduction loop

This packet shows that the HLP withdrawal limit is a once-a-day snapshot of the vault's account value times one minus a fraction,
not a per-second rate, and that the loop 0x26f7280 sells or buys down the vault's positions with IOC orders in the vault's own name before
the withdraw body runs, so a reconstruction can now write both guards around the held validation and withdraw bodies with their real inputs, order and constants.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts, field names and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: snapshot 0x2702e80 and its copies 0x4cf0130, 0x4cf0330; reduction loop 0x26f7280; the fraction range test in the vote arm at 0x2357731; the host call sites at 0x2736934 to 0x2736a99
- Scope excluded: validation 0x39582c0 (open PR #630), withdraw body 0x395bdd0 (open PR #632), pre step 0x26f7ef0 (open PR #864), producer 0x37052b0 and the layout B loops 0x4cdc540, 0x4cdcd60 (open PR #197), tick 0x230b390 (open PR #948), order insert 0x26ebdc0, total equity 0x3957bc0 (companion packet `vaults-equity-views-94`)

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/vault_withdraw_guards.py --out research/work-items/vaults-withdraw-guards-94
python3 -m unittest tests.test_vault_withdraw_guards
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and `tools/fde_extents.py` for
sections and FDEs. It never runs the binary. It writes evidence.json, functions.tsv, stubs.tsv, callers.tsv, pins.tsv,
layout.tsv, locations.tsv, state-fields.tsv, cases.tsv and outcomes.tsv. All contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Extents are FDE ranges (`functions.tsv`), 4 functions and 4,703 bytes. Instruction
text in `pins.tsv` comes from the small decoder inside the tool, each of the 92 rows is compared with a frozen expected string, and an unknown
encoding raises an error. `layout.tsv` ties 29 field offsets to one decoded access each.

### Field names

The exchange serializers name the fields (`state-fields.tsv`):

| Offset | Name in .rodata | Type from the accesses |
| --- | --- | --- |
| +0x39c8 | `max_hlp_withdraw_fraction_per_day` | f64 |
| +0xbb0, +0xbb8 | `hlp_start_of_day_account_value` | tag word, then a value word |
| +0x3a98 | `last_hlp_cancel_time` | 12-byte time |

The vote arm at 0x2357731 refuses a fraction below 0 or above 1 with code 271 and otherwise stores it at +0x39c8.

### Snapshot 0x2702e80

The begin block body 0x22297c0 calls it at 0x222a112 with a pointer to the time it saved earlier. The steps:

```text
if prev.date_word >= now.date_word (signed, the whole packed word): return
if chain byte < 2: return
key = chain == 2 ? a15099a30bbf2e68942d6f4c43d70d04faeab0a0 : dfc24b077bc1425ad1dea75bcb6f8158e10df303
if key not in the vault map: return, the old value stays
clearinghouses empty: panic, unwrap of Err(321), l1/src/dex_registry/clearinghouses.rs:11:29
hlp_start_of_day_account_value = Some(max(total_equity(vault), 0))
```

The compare reads only the date word, so seconds play no part and the write happens once per UTC date. Because the word
holds the year flags too, two dates compare as packed integers. A chain byte of 1 or below never writes the field, and a day with no HLP
vault leaves yesterday's value. `cases.tsv` lists 7 named snapshot results.

The 3 copies differ only in frame offsets and the .rodata copy of the addresses.

| Copy | Called from | Vault map | Chain byte | Clearinghouses | Field |
| --- | --- | --- | --- | --- | --- |
| 0x2702e80 | 0x22297c0 | +0x8d0 | +0x8f2 | +0x5c0 | +0xbb0 |
| 0x4cf0330 | 0x470e9a0 | +0x8d0 | +0x8f2 | +0x5c0 | +0xbb0 |
| 0x4cf0130 | 0x47162d0 | +0x1350 | +0x1372 | +0x1040 | +0x1630 |

### Floor in the host

The vaultTransfer body compares the vault with the same fixed key. If the option tag is set, it calls 0x26f6050 with the value
and the fraction, which gives `trunc_sat(value as f64 * (1.0 - fraction))`, and hands the result to validation as an
optional argument. Otherwise that argument is None. This pins the wiring only, at 0x2736934, 0x273693b and 0x2736944.

### Reduction loop 0x26f7280

Called only from the vaultTransfer body at 0x2736a99 (`callers.tsv`), when the validation flag is set. Inputs: exchange, the vault address and
an f64 fraction from the validation result. The layout B body uses the loops of open PR #197 instead, and this function is the inlined layout A form that packet left unstepped.

| Step | Rule |
| --- | --- |
| Entry | no clearinghouse: panic at clearinghouses.rs:17:33 before any call |
| Rows | producer on clearinghouse 0 with the vault and the fraction. The none word returns at once |
| Context | oracle table from clearinghouse +0x60, then the 32-byte hash when the exchange flag word is 1, else 32 zero bytes |
| Row | 0x18 bytes: asset, side byte, size. Side byte 2 ends the walk |
| Index | dex = asset / 10000, local = asset % 10000. Local past the oracle table: bounds panic at oracle.rs:197:18 |
| Floor | notional = size * oracle value as a 64 x 64 product. It acts when the high word is set or the low word is above 0x7ffffffffffffffe; otherwise a low word at or below 9,999,999 skips the row |
| Book | dex past the collection panics at perp_dex.rs:30:33 and local past the books at books.rs:19:47, for acting rows only |
| Price | best keys a and b of the book. If either is 0 there is no order, and the final step still runs |
| Limit | see below |
| Order | record to 0x26ebdc0 on the book, user = the vault address, record +0x70 = 6, +0xcc = 1 |
| After | error word: free the buffer only if its capacity is positive, no post step. Success: post step 0x26f4cd0 with clearinghouse +0x68, +0x70 and the hash |
| Final | 0x24fb610 runs for each acting row on all of these paths |
| Exit | rows freed, oracle table dropped |

The limit:

```text
mid = (a & b) + ((a ^ b) >> 1)
p   = round(mid as f64 * (side & 1 ? 0.97 : 1.03)), floored at 0, saturating to u64, 0 becomes 1
q   = p / tick
sell: limit = (q + 1) * tick, saturating
buy:  limit = q * tick
0 becomes 1, product overflow gives u64::MAX
```

So a sell adds a whole tick even on an exact multiple: midpoint 2500000 at tick 100 gives 2425100. A buy below one tick gives limit 1.
The 0 to 1 step on `p` cannot fire from this path, because a midpoint of at least 1 rounds to at least 1.

### Evaluation

The tool runs each body in Python over the real instruction bytes and compares the result with a plain model: 1,800
vectors with 0 disagreements and 15 distinct outcomes (`outcomes.tsv`), plus 25 named scenarios in `cases.tsv`.
The loop model predicts the ordered call list, each order record field and each panic Location. `stubs.tsv` lists the
16 replaced calls with their FDE extents. Stubs overwrite caller-saved registers and all xmm registers.

### Inferences

- The fixed key for chain byte above 2 is the HLP vault. The field names say hlp, and the host compares the same key.
- Hand reading of validation 0x39582c0, whose bytes open PR #630 binds with no semantic claim: when the optional argument is present, `total - amount` below it returns code 272 (0x110).
  So the value acts as a floor on what stays in the vault, and the daily limit is `value * fraction`. This reading is not checked by this tool.
- Hand reading of the same body: the flag and fraction come from a shortfall test and the vault's byte +0xae (reference label `always_close_on_withdraw`), with the fraction raised to at least 0.2 on the shortfall arm.
- Record +0xcc = 1 is ImmediateOrCancel, from the reading in open PR #197.
- The rows are the vault's positions, from the same producer.

### Reference comparison

| Reference text | Bytes |
| --- | --- |
| `VoteGlobalAction::MaxHlpWithdrawPerSecond` | the stored field is `max_hlp_withdraw_fraction_per_day`, range tested to 0..1 |
| no HLP state in the vault paths | `hlp_start_of_day_account_value` taken at the first block of a date |
| `apply_vault_withdraw` has no market step | a loop places IOC orders as the vault before the withdraw body |

## Implementation and comparison

not yet implemented. No Rust was written. The formulas above are readings of the bytes, checked over the listed vectors.
They are not a claim of binary equivalence.

## Results and limitations

Passed: 92 pins, 29 layout rows, 4 state field rows, 4 functions, 16 stubs, 5 Location records, 1,800 vectors with 0
disagreements and 25 named scenarios. `tests/test_vault_withdraw_guards.py` runs 41 tests, including 8 negative controls
(wrong binary hash, address outside file-backed sections, changed pin byte, changed layout operand, changed field string, unknown encoding,
unmodelled call, non-FDE start) and 23 one-edit binary mutants, each of which the models catch.

Limits:

- Stubs are assumptions about interfaces. The insert, post step, final step, producer, tick and oracle table are not evaluated here.
- The filled list stub returns no rows, so the element free loop at 0x26f7b10 did not run with elements.
- The vote arm is pinned, not evaluated. A NaN fraction passes both compares by the flag rules, and that was not run.
- The `Once` call at 0x577ab98 was not taken in any vector.
- Why two frame layouts exist, and which one runs on a live node, is unresolved.
- Unresolved: `last_hlp_cancel_time`. By hand reading 0x27025b0 adds 30 s to it and tests against the block time, and 0x2721120 stores the block time when one of two tests passes.

Next question: what do 0x27025b0 and its writer 0x2721120 cancel for the HLP vault, and what does the 30 s test gate?
