# RE-006: where the book +0x78 word comes from: the token genesis finish

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are the three copies of the finish function `0x4d611e0`, the gates and balance merge in `0x371b950`, the sum `0x371f6b0`, the word helper `0x3c09830`, the supply map insert, the balance map entry, drain and next functions, and the write to book `+0x78`. Excluded are the hosts' checks before the call, the bodies of `0x3720a70` (holders of an existing token), `0x371d120` (balance credit), `0x3c0d6e0` (name), `0x3987cb0` (hash), the two row functions, the touch set inserts and `0x3762510` (status drop). These are stubs with checked arguments.

## Reproduce

From the repository root:

```
python3 tools/token_genesis_finish.py --out research/work-items/RE-006-token-genesis-book-word-94
python3 -m unittest tests.test_token_genesis_finish
```

The tool takes about 230 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `word.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs.

### The function and its callers

Three copies: `0x4d611e0`-`0x4d618ee` (third, 1806 bytes, 379 instructions), `0x4d618f0`-`0x4d6200b` (second, 1819 bytes, 382) and `0x2746b40`-`0x274725b` (first, 1819 bytes, 382). Arguments: `rdi` result, `rsi` state, `dl` network byte, `rcx` token, `r8`/`r9` decimal text, first stack byte a flag. Each has two direct callers (`call_sites.tsv`).

| Site | Host | Flag |
| --- | --- | --- |
| `0x4ad84ef`, `0x4ad7bbf`, `0x23e801f` | `0x4ad81e0`, `0x4ad78b0`, `0x23e7d10` | byte `+0x28` of the action |
| `0x4d6c21e`, `0x4d6c60e`, `0x274c89e` | `0x4d6bf80`, `0x4d6c370`, `0x274c600` | literal 1 |

Nested deploy table `0x70403c` entry 4 is arm `0x4ad849a`. It reads the token at action `+0x20` and the flag at `+0x28`, and the text at `+0x10`/`+0x18`. A text of 101 bytes or more gets status `0x143`, `Invalid input length`, before the call. Each `literal 1` host writes the digits of `u64::MAX` (`mov rdi, -1` before the digit writer, `digit_writer_argument`) and passes them as the text.

`0x371b950` has no direct call. Its only slot is `0x5774bf8`, and the three calls through it are in the three copies (`finish_calls`).

### Order of the steps

Observed on all three copies, with the same order on every run:

1. Parse the text as a `u64`. Empty: status `0xb7`, kind 0. A lone `+` or `-`, a `-` prefix or a non-digit: kind 1. Above `u64::MAX`: kind 2. One leading `+` is dropped. Leading zeros are fine. Up to 16 digits take a loop with no overflow test. From 17 digits a multiply overflow gives kind 2 on a digit and kind 1 on a non-digit. Status `0xb7` displays as `Failed to parse integer`. Nothing else has run at this point, so a bad text beats a bad token.
2. Token past the list: panic at `l1/src/spot_meta.rs:113`.
3. `k = wei - sz`. `wei < sz`, or `k >= 20`: panic at `spot_meta.rs:1199`.
4. `supply < min(1e8 * 10^k, u64::MAX)`: `max supply must be at least 100M lots`. The product saturates, so for `k >= 12` only `supply == u64::MAX` passes.
5. Token absent from the genesis map at state `+0x3f0`: `missing token genesis information`.
6. Sum of all user balances and all existing token amounts in the entry, by `0x371f6b0`. A carry: `genesis supply error`.
7. `supply != sum`: `genesis max supply incorrect`. A supply of 0 gives the same text, but step 4 has already refused it.
8. Read the balance of the 20-byte user `0xff..ff` (bytes at `0x599044`). With the flag set, a nonzero balance gives `Hyperliquidity balance should be 0 if no hyperliquidity is set.`, and the next check is skipped.
9. With the flag clear and the network byte nonzero: a balance below `floor(supply / 100)` gives `Hyperliquidity must be at least 1% of max supply`, unless the token's name is exactly `HYPE`. A missing row counts as 0.
10. Merge the users in key order into a new map, skipping anyone in the blocked set. Blocked balances stay in the sum of steps 6 and 7 and are credited to no one.
11. For each existing token row in key order, call `0x3720a70` with that token and amount. A status other than `0x186` is returned whole, after the new map is dropped. Its rows of `0x20` bytes (user, amount at `+0x18`) are merged with no blocked set test. A carry gives status `0xbe`, `Add result error`.
12. `word = 0x3c09830(1e12, token, supply)`.
13. `0x371d120` for each merged user in key order, with the token, a zero `ecx`, the amount and the word.
14. `0x33a19d0` sets the supply in the map at state `+0x408`, replacing an older value. `0x371b950` returns the new map and the word.
15. In the finish function: `0x3c0d6e0` gives the name. For each merged user in key order, one row (tag `0x8000000000000010`, name, amount as f64 `u64 / 10^wei`, table `0x584b08`) with the 12-byte time at `+0x60`, a hash from `0x3987cb0` only when state dword `+0x00` is 1, else 32 zero bytes, and then a touch set insert.
16. For each spot in the token's list, if its quote token is 0, write `word` to book `+0x78`. A spot past the rows panics at `spot_meta.rs:565`, a book past the list at `l1/src/books.rs:19`. Non-USDC spots skip the book bound. Both panics come after steps 13 to 15 have run.

Any refusal before step 13 changes neither the books nor the supply map (`test_nothing_changes_on_refusal`).

### The word

`0x3c09830` is the helper the merged packet `RE-004-spot-wei-scale-family-94` lists as `mul_div_floor_one`. Here `a = 1e12`, so the formula is `floor(1e12 * 10^k / supply)`, with `floor(1e12 / supply) * 10^k` when the product exceeds `u64`, and a result of 0 becomes 1.

Step 4 fixes the range. Up to `k = 7` the supply is at least `1e8 * 10^k`, so the word is at most 10000. From `k = 8` the product exceeds `u64`, the supply is at least `1e16`, `floor(1e12 / supply)` is 0, and the word is exactly 1 for every supply. So the word is always in `1..=10000`, and the two `word != 0` arms (`0x4d61716`, the zero return of the helper) are dead from here.

`word.tsv` has 40 real runs at the lowest and double-lowest supply of each `k`. Each compares the word given to the credit with the word stored in book `+0x78`. The fallback matters: with `k = 8` and supply `1e16` the exact value would be 10000, and the stored word is 1.

### Who touches book +0x78

`mov [rdx+rsi+0x78], rbp` (bytes `48896c3278`) occurs in `.text` exactly three times, once in each copy (`anchor_sites`). That is a scan of one encoding, not of all writers. The load at `0x42fbabb` (`488b5b78`) in `0x42fba60` is one reader.

### Copies

The second and first copies have the same shape, 382 instructions, and differ in 8 rows: call targets into their own monomorph group and two Location addresses (`copy_diff_second_first`). The third copy differs from those two in its frame, and it passes the row in place, where they copy `0xb0` bytes first and call `0x3576710` through slot `0x5774738` instead of `0x4855a50` through slot `0x5776ad0`. The per-copy offsets are in `copies`. The same specification passes on all three, so a wrong offset in that table fails a run.

### Results

| Measure | Value |
| --- | --- |
| Cases | 214 |
| Runs across the 3 copies | 642 |
| Mismatches, all runs | 0 |
| Instructions stepped | 1,271,653 |
| Stepped / total: finish, 3 copies | 310 / 379, 314 / 382, 314 / 382 |
| Stepped / total: gates, sum, word | 816 / 1007, 206 / 286, 80 / 105 |
| Mutants killed / survived / unreached | 533 / 39 / 143 |

Outcome counts are in `evidence.json`, and `worked_example` has one full run: `2e14` wei, 2 sz and 8 wei decimals give word 5000 on spots 0 and 3, and spot 1 (quote token 3) is left alone.

### Reference comparison

`reference_claims` in `evidence.json` lists each row. `apply_decimal_token_mutation` in `l1/exchange/handlers/26_spot_deploy.rs:279` is an abstract method, so the reference has no body for this path. None of the six refusal texts of steps 4 to 9 is in the reference's `l1` tree. It names no book field at `+0x78`.

## Inferences

Kept apart from the observations:

- The action is the token genesis finish, and the flag means no hyperliquidity. The texts say so, and the reference's field is only called `flag`.
- `0xff..ff` is the hyperliquidity user. The texts name that balance.
- The second host is the outcome token path: its format template at `0x1ec098` is the literal `o` and one argument, and it passes `u64::MAX` as the supply with flag 1. Its other calls are not read here.
- The word is a starting price. With 8 wei decimals on token 0, `supply * word` is about 10000 USDC in the raw price units of the earlier packets. The credit gets the same word, so it may be the entry price of the balance. The body of `0x371d120` is not read here.
- The network byte is nonzero outside one network. Which value is mainnet is not shown here.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes against a separate Python specification. Stubs check every argument. A mutant survives only with a stated reason in `mutations.tsv`.

## Results and limitations

- Only the bytes listed above are run. Stubs are named in Scope.
- How `0x3720a70` splits an existing token among its holders is not pinned, so the merge in step 11 is shown on scripted answers.
- The hosts' gate before the call (slot `0x5773ef8`, and `0x4d718a0`, `0x4d745f0`) is not read, so what stops a second finish of one token is not shown here.
- Trees are built by the harness with node shapes read from the code (`node_shapes`). Live state was not read.
- Other encodings of a write to book `+0x78` are not scanned.
- 2 of the mutants left are marked as not separated in `mutations.tsv`, and no claim rests on those rows. `0x371c8da` is a level climb in the walk over the new map, and `0x4d614d0` the empty name arm.
- No Rust code, and no progress gate is requested.

Next question: how does `0x3720a70` split an existing token's amount among holders, and with which rounding?
