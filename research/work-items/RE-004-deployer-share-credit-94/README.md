# RE-004: what credit does node #94 give a spot token deployer in 0x3c01bf0

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the decisions, the gate pieces, the tail pieces and the serde rows; inference for the identity of `rsi` and for the one-byte value array; unresolved items are listed under limits
- Scope included and excluded: included are function `0x3c01bf0` (FDE `0x3c01bf0..0x3c01dc6`, 103 instructions), run as real bytes with only the panic call stubbed, and the serde rows that name its fields. Excluded are its one caller and the 6 other sites that use the same two constants.

## Reproduce

```
python3 tools/deployer_share_credit.py --out research/work-items/RE-004-deployer-share-credit-94
python3 -m unittest tests.test_deployer_share_credit
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about 20 s.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`).

Function contract, as read from the rows. Arguments are `rdi` output record, `rsi` spot metadata, `rdx` token, `rcx` amount.

1. `0x3c01bf3`: `token >= [meta+0x188]` jumps to `0x3c01db9`, which panics with the Location at `0x56f21f0`, `l1/src/spot_meta.rs:113:33`.
2. `0x3c01c0e`: tests bit 0 of the record byte at `token*0xe8+0xd2`. If clear, word 0 of the output is 0 and nothing else is written. Bytes 0xfe and 0xff behave as bit 0 says.
3. `0x3c01c23`: looks up the token in the B-tree whose root is `[meta+0x250]`. A root of 0 counts as not found. The value slot is never read.
4. Found (`0x3c01c9b`): the credit is 0 for every share and amount.
5. Not found (`0x3c01d56`): share `s` is the u64 at record `+0xa8`. `f = s/100000.0`, and `f` must satisfy `1.01 >= f` (`0x3c01d8a`), else the credit is 0. Otherwise `m = f * amount as f64` and the credit is the truncation below.
6. Output: word 0 = 1, `+0x08..+0x1c` the 20 bytes at record `+0xd3`, `+0x20` the credit. Bytes `+0x1c..+0x20` stay as they were. `rax` is the output pointer.

Rows after the multiply, `0x3c01cec..0x3c01d96`: NaN and +inf give 0, negative values give 0, values above `0x43efffffffffffff` (the largest f64 below 2^64) give `u64::MAX`, others truncate. 2^64 itself clamps and gives `u64::MAX`.

Field names come from serde rows in bytes (`serde-fields.tsv`), not from the reference:

| Struct | Offset | Key | Row |
|---|---|---|---|
| spot metadata | `+0x178` | `token_infos` | `0x375a59f` |
| spot metadata | `+0x220` | `quote_token_to_aligned_quote_token_info` | `0x375a739` |
| spot metadata | `+0x250` | `quote_token_to_status` | `0x375a777` |
| token record | `+0xa8` | `deployer_trading_fee_share` | `0x375aff4` |
| token record | `+0xd2` | `deployer` | `0x375add2` |

Call census, by bytes: slot `0x5774a90` holds the function (RELATIVE record), one `call` through it at `0x271afaa`, and no direct `call` or `jmp` (`evidence.json`). The instruction pair `divsd 100000.0; movsd 1.01` occurs at 8 sites in `.text`; the 2 in this function are in `pair-sites.tsv`.

Constants are pinned by bytes in `constants.tsv`, including `1.01` at `0x20a528` (`295c8fc2f528f03f`) and `100000.0` at `0x20a9e8`.

## Implementation and comparison

Rust implementation: not yet implemented.

Comparison with `references/can1357-hl` (a clue, not a source):

- `l1/spot_clearinghouse/types.rs` and `impl_outcome.rs` return 0 unless the token's aligned-quote entry is active, so a token outside that map earns nothing. The bytes do the opposite on a different map: a token outside `quote_token_to_status` earns the share, and a token inside it earns 0. The aligned map at `+0x220` is not read.
- `reference-compare.tsv` runs both rules on the four membership states. They differ in two: not in the status map with an inactive aligned entry (real 300000000, rule 0), and in the status map with an active aligned entry (real 0, rule 300000000). The test inputs were share 30000 and amount 1e9.
- The reference formula, `1.01` limit and saturating conversion agree with the bytes once the membership test is replaced.

## Results and limitations

Results from `evidence.json`:

- 41 named cases and 2500 generated cases run from entry over real table and B-tree layouts, with 0 mismatches against a separately written specification. The output record is compared in full, and any write outside it stops the run.
- All 103 decoded rows were reached, padding aside (`unreached_rows` is empty).
- Factor gate over all u64 shares: `0..=101000` admitted, `101001..=u64::MAX` refused (`gate-pieces.tsv`, 2 pieces).
- Rows after the multiply, split over all 2^64 bit patterns: 14 pieces, each with one decision record (`tail-pieces.tsv`).
- `credit-edges.tsv`: with share 100000, amount `2^64-1025` gives `2^64-2048` and amount `2^64-1024` gives `u64::MAX`. With share 101000 the credit passes the amount: amount 1000000 gives 1010000.
- `rounding.tsv`: 20000 pairs of share and amount compare the f64 credit with integer `floor(amount*share/100000)`. Below 2^53, 162 of 16887 pairs differ. At or above 2^53, 2620 of 3113 pairs differ. The rule is f64, not integer arithmetic.
- `mutations.tsv`: 62 byte edits on reached rows, 54 killed, 8 survived. Each survivor has a reason. Seven sit in the found branch, where every path gives credit 0. One is the sign mask at `0x3c01d2d`. An unexplained survivor stops the tool.

Limits:

- The gate split relies on monotonicity: u64 to f64 and division by a constant never reverse order, so the end points of a range fix its decision. Interior points are checked only as a sample. The u64 to f64 lanes are checked by vectors, not by a proof.
- `f * amount` is not enumerated over both inputs. The split covers the rows after the multiply for every value, and the multiply itself is one `mulsd`.
- The B-tree node shape (keys at `+8`, length at `+0x62`, edges at `+0x70`) comes from this function's rows. A one-byte value array at `+0x64` is an inference from those offsets; the function never reads it.
- That `rsi` is the struct behind the serde rows is an inference from matching offsets and the `0xe8` record stride. The caller's argument was not traced.
- Other sites with the same constants are not analysed here.

The analysis ran to completion for the scope above. No progress gate is requested.

Next question: what does the caller do with the credit at `0x271afaa`, including a credit above the amount? Do the other 6 pair sites read the same map?
