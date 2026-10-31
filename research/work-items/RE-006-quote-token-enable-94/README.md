# RE-006: what the book must show before a spot token can become a quote token

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are the three copies of the enable function, the USDC pair check, the deployer limit, the book read and median, the price band, the status writer, pair lookup and price, and the copy of the 0xfe row. Excluded are the host dispatch before the call, the bodies of the deployer gate `0x4d76ac0` (read only, not run), `0x4d63be0` (spot registration), `0x3790b60` (f64 to decimal), `0x33690c0` (the resolver in the filter) and the three map inserts. These are stubs with checked arguments.

## Reproduce

From the repository root:

```
python3 tools/quote_token_enable.py --out research/work-items/RE-006-quote-token-enable-94
python3 -m unittest tests.test_quote_token_enable
```

The tool takes about 460 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `band.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs.

### The function and its callers

Three copies of 1979 bytes and 382 instructions: `0x4d62140`-`0x4d628fb` (second), `0x4d62900`-`0x4d630bb` (third), `0x2747390`-`0x2747b4b` (first). Each has two direct callers (`call_sites.tsv`). Arguments: `rdi` result, `rsi` state, `rdx` a 20-byte user, `rcx` the token, `r8b` a flag.

| Site | Host | Flag | User argument |
| --- | --- | --- | --- |
| `0x4ad7dd7`, `0x4ad8707`, `0x23e8237` | `0x4ad78b0`, `0x4ad81e0`, `0x23e7d10` | 0 | the host's user |
| `0x4cace52`, `0x4cb57e2`, `0x2358581` | `0x4caa870`, `0x4cb3200`, `0x2355f40` | 1 | token row `+0xd3`, after `test byte [row + 0xd2], 1` |

The flag is read from the bytes before each call in `call_flags`. At `0x4cacdf7` the second site's arm first tests a byte of the action record: zero leaves for another arm.

### Order of the checks

Observed on all three copies, with the same order on every run:

1. State `+0x80` tag zero: status `0xfb`, `Native token does not exist`. No token is read, so a token past the list returns this too.
2. Token past the list: panic at `l1/src/spot_meta.rs:113`.
3. Walk the token's spot list for the first spot with quote token 0. None: `quote token must have USDC pair`. A list entry past the spot rows panics at `spot_meta.rs:565`.
4. Collect the quote tokens of all spots with `0x3bb5f50`. Quote 0 is skipped. Ids up to `0x56e` are skipped when the network byte is 2. A quote named exactly `USDT0` is skipped. Then filter `0x4c6be50` keeps the tokens counted against the user, and the token itself is removed from the set. Anything left: `can deploy at most one quote token`.
5. Deployer gate `0x4d76ac0` with level `3 * removed + 1`, so 4 when the token was already counted, else 1. Any status but `0x186` is returned whole.
6. Book of the USDC spot. A spot past the book list panics at `l1/src/books.rs:14`. Tops from `0x4a078a0`, first the side at book `+0x80`, then `+0x98`, each `abs` of the first key, 0 for an empty side.
7. First side empty: `quote token has empty book side`.
8. `r = mid / scale - 1`, as f64. `0.2 >= r` fails, or is unordered: `quote token price too far from 1`.
9. Second side empty: `quote token has empty book side`.
10. `r >= -0.2` fails: `quote token price too far from 1`.
11. Status writer `0x375fe00`.
12. Pair creation, when the native token has no pair with this token.
13. 0xfe row copy.

Steps 8 and 9 give the two errors in an order worth noting. With an empty second side and a high median the text is the price text. With an empty second side and a low median it is the side text. The `no ask` cases show both.

### The median and the scale

`0x42fba60` has 6 direct call sites and its first-copy twin `0x26e0570` has 3, all in the enable functions and the pair price: no other code calls them.

- `0x4883410` keeps the nonzero tops, `+0x78` of the book is pushed unconditionally, and `0x471de00` sorts and takes the median.
- With 3 values, the middle one. With 2, the floored mean `(a & b) + ((a ^ b) >> 1)`. With 1, that value.
- A result of 0 falls back to `+0x78`.
- `+0x78` counts even when it is 0. With both sides present and `+0x78` 0, the mid is the lower top.

The scale is `0x375fb50`, `10^(token 0 wei - token sz)`. The exponent is `u8` with an underflow panic at `spot_meta.rs:984`. An exponent of 20 or more panics at `spot_meta.rs:1005`. An exponent of 0 returns 1.

### The band

`band.tsv` gives the lowest and highest integer mid that pass for each exponent 0 to 19, from the f64 expression of steps 8 and 10 run in Python. For exponents 0 to 15 they equal `ceil(0.8 * scale)` and `floor(1.2 * scale)`. From exponent 16 on the band is wider than that by f64 rounding: at 17 it is `79999999999999992` to `120000000000000008`. The evaluator runs the edges for exponents 0 to 8 through the real bytes.

### Status writer

`0x375fe00`, arguments `state + 0x90`, token, time pointer, flag:

1. Token wei byte `+0x49` not 8: status `0xef`, `Invalid quote token`.
2. No USDC spot in the token's list: `0xef`. Step 3 above already returned for this, so this arm is dead from these callers.
3. Row `+0xa8` nonzero: `quote token deployer trading fee is not zero`.
4. Key present in the map at metadata `+0x250` with a nonzero value byte, and flag byte 0: `quote token not allowed`. With a nonzero flag this check does not stop it.
5. `0x339d350` writes value 0 for the token. `0x33be810` gets the entry of the map at metadata `+0x208` and the 12 bytes from state `+0x60`.

### Pair and row

`0x375e430` looks through the native token's spots for one quoted in this token. If there is none:

1. `0x3760070` finds the native token's USDC spot.
2. `0x4dd5ae0` (`0x4dd5bf0`, `0x2786830`) gives `mid / 10^(quote wei - base sz)` for that spot from the table at `0x6f7470`, or 2.0 if there is no such spot.
3. `0x3790b60` turns that into a decimal. `0x4d63be0` gets it with a zero 20-byte user and the pair (native, token).

Then `0x333a520` reads the 0xfe row of the native token's USDC spot from the map at state `+0x3a00`. The row is copied only if the pair (native, token) is in the native list at this point, and `0x333a420` builds the new row:

- `+0x10` copied, with a floor of 10.0 by `maxsd`.
- `+0x30` the new spot.
- `+0x38` the amount cut to a multiple of 100. An amount of `0x68db8bac710cb` hundreds or fewer keeps its value. Above that, the row keeps the amount divided by 100, because the `* 100` step is skipped. The limit `0x28f5c28f5c28f5b` in `0x333a420` cannot trip here, since the value is at most `2^64 / 100`.
- `+0x40` copied.

Stub `0x4d63be0` does not change the spot lists, so in these runs a pair built on this call gets no row. Whether the real registration makes the list change visible in time is not shown here.

### Copies

Across `copy_diff`, the enable function second against third has 8 rows, second against first 17 rows. The pair price second against third has 2 rows, second against first 3 rows. All rows are field offsets, call targets or text addresses. No row differs in shape.

### Results

| Measure | Value |
| --- | --- |
| Cases | 340 |
| Runs across the 3 copies | 1020 |
| Mismatches, all runs | 0 |
| Instructions stepped | 1,285,594 |
| Stepped / total: enable, 3 copies | 372 / 382, 372 / 382, 372 / 382 |
| Stepped / total: mid, tops, writer | 47 / 57, 114 / 124, 139 / 145 |
| Stepped / total: pair lookup, row read, row build | 34 / 34, 93 / 103, 38 / 57 |
| Mutants killed / survived / unreached | 398 / 28 / 6 |

Outcome counts are in `evidence.json`, and `worked_example` has one full run.

### Reference comparison

`reference_claims` in `evidence.json` lists each row. `enable_quote_token` in `l1/exchange/handlers/26_spot_deploy.rs:677` has the wei and pair check, the fee check and the status check. It has no book read, no deployer limit, no pair creation and no row copy. Its fee text differs from the ELF text. The strings `quote token price too far from 1` and `quote token has empty book side` are not in the reference.

## Inferences

Kept apart from the observations:

- The side at book `+0x80` is the bid side. This follows open #292's reading of the book, and the side test here is symmetric apart from the order of the two messages.
- `scale` is a price of 1 in raw units, so the band means a USDC price within 0.8 to 1.2. The text says `too far from 1`, and the raw price has `wei - sz` decimals.
- Flag 1 sites are the vote path and flag 0 the deployer's action. The site in `0x4caa870` follows the vote dispatch, and the reference names `EnableQuoteToken` in the vote enum. A label mismatch in that table was noted in open #308, so the case number is unresolved.
- Book `+0x78` is a slow reference price. Its writer is not read here.
- Level 4 passes the deployer gate's first half: `0x4d76ac0` starts with `cmp cl, 4` and jumps past the checks with status `0x109` (`Deployer cannot have staking link`) and `0x10a` (`Deployer cannot have more than $1M volume traded`). This was read by hand, not run.
- Network byte 2 as testnet. The value comes from the same byte as in open #212.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes against a separate Python specification. Stubs check every argument. A mutant survives only with a stated reason in `mutations.tsv`.

## Results and limitations

- Only the bytes listed above are run. Stubs are named in Scope.
- The filter's resolver status is a stub input. What `0x33690c0` decides is not pinned, so the rule for a resolved user is the branch taken and not its meaning.
- Trees are built by the harness with node shapes read from the code (`node_shapes`). Live state was not read.
- `0x33be810` may keep or replace a time. Its body was not run.
- The band table beyond exponent 8 comes from the spec expression and not from a run of the bytes.
- Quote sets above 3 counted tokens are not in the list: a bulk build path in the first copy needs an opcode the evaluator lacks.
- Five surviving mutants in the two map walks of `0x375fe00` (`0x375fecb`, `0x375fef5`, `0x375ff88`, `0x375ff93`, `0x375ffb5`) are unexplained and marked so in `mutations.tsv`. The walks of those maps are not claimed beyond the listed cases.
- No Rust code, and no progress gate is requested.

Next question: what does `0x4d76ac0` read at state `+0x3a18` and `+0x37e0`, and which window does the `1e8` limit of status `0x10a` cover?
