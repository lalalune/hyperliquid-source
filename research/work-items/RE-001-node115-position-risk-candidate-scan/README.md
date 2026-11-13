# Position response risk-candidate scan

Target Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. This is partial HL115-099 / RE-001 research; the captured target was never executed or emulated.

The position-response producer calls `0x2f063f0` and stores its presence word and binary64 result together at response `+0x10/+0x18`. Within that helper, the selected normal continuation scans an owned array of 32-byte records in order and returns the first candidate satisfying its numerical and row bounds. This contribution reconstructs that scan after the preceding lookups and helper outputs are resolved. It does not assign a public economic name or units to the result.

## Prior work and boundary

`RE-001-node115-position-response-entry-quotient` already owns the earlier position quotient and decimal conversion in producer `0x2c7fd80`. [#3261](https://github.com/lalalune/hyperliquid-source/pull/3261) and [#2834](https://github.com/lalalune/hyperliquid-source/pull/2834) own neighboring margin range and row work. Their findings are dependencies, not new claims here. The new scope is the actual caller-to-helper-to-response handoff and the helper's ordered candidate scan, conditional on its earlier 0x2ee49a0 row construction, 0x38b54b0, 0x4716be0 and 0x3beb700 returning normally.

At `0x2c80135` the producer calls the helper when its selected flag is nonzero, then saves RAX and XMM0; `0x2c803fd..0x2c8040d` copy those to the final response. The flag-zero path supplies a zero presence word and does not call the helper. This packet does not determine all response variants, actual snapshot identity, or the upstream construction and ownership of every row.

## Selected scan

The helper first obtains a 32-byte-row array via `0x2ee49a0`; after its other calls, their signed results form a base by checked additions. The scan starts only when that setup and intervening operations return normally. Write `q` for the signed value originally read from the helper's first argument `+0x10`, `h` for incoming R9, and `base` for the already-combined signed helper result at stack `+0x20`. The exponent byte is resolved through the selected asset row at `+0x1d`. For `q != 0`, `n = f64(unsigned_abs(q)) / powers[exponent]`; for `q == 0`, the native selected path supplies `0.0`. This source limits nonzero-q exponents to 0..21, whose literal power table bytes are bound; it stops outside that documented input domain. `direction` is +1.0 if q is positive and −1.0 otherwise.

Each row is addressed in 32-byte strides. A qword tag 2 stops scanning. Other tags supply a u64 upper word at `+8`, a pointer at `+0x10` to a record whose signed word `+0x10` and byte `+0x18` are used below, and a u64 lower word at `+0x18`. A negative pointed-to signed word reaches a separate native exceptional path; the source reports a stop. With `v` as that nonnegative signed word and `d` as the byte, the selected arithmetic is:

1. `numerator = f64(saturating_sub(saturating_add(base, v), h)) / 1_000_000`.
2. `candidate = numerator / ((1 / (2*d) - direction) * n)`.
3. Skip unless the ordered comparisons admit `0 < candidate <= 1e15` and `n*candidate >= f64(lower)/1e6`.
4. If the row tag's low bit is set, also require `n*candidate <= f64(upper)/1e6`; equality passes. Otherwise no upper comparison is made.
5. Return presence 1 and that candidate for the first accepted row; exhausting the supplied array or encountering tag 2 returns absence.

Native signed overflows call a diagnostic boundary before continuation with the saturated endpoint; the source projects that normal-return continuation and does not model the diagnostic side effects. IEEE floating operations retain their native order; invalid or unordered candidates cannot satisfy the subsequent ordered lower-bound comparison. The output is conditional on valid row pointers, initialized fields, stable input, ordinary helper returns and the selected floating environment. This is not a model of every exceptional path, whole liquidation calculation, all price units, or actual on-chain reachability.

## Source and verification

`src/node115-risk-candidate-scan` uses typed already-resolved rows, raw offset names, an explicit stop for negative pointed-to words or out-of-scope exponent, and preserves scan order and bound direction. It is not a callback standing in for the preceding lookup or iterator producer. Three deterministic tests cover first match, tag-2 stop, inclusive limits, empty and zero inputs, integer saturation, minimum signed quantity, zero divisor and stop boundaries.

The verifier binds three windows, 1,948 bytes / 414 instructions, 85 facts and 79 changed-byte controls to the full original digest. It binds the caller, selected helper body, output offsets, floating constants and power table. These controls check evidence drift; the arithmetic interpretation is static analysis, not native execution.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-001-node115-position-risk-candidate-scan/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-risk-candidate-scan/Cargo.toml
```
