# exchange: token-decimals scaling helpers 0x434f660 / 0x434f790 / 0x434f910 of node #115

This packet lets a Rust port reproduce, bit for bit, the three scaling helpers of `l1/src/spot_meta.rs` that turn a token-row decimals difference (wei decimals minus size decimals) into a divisor: a u64 scaled multiply (`a * b / 10^d`, token 0 unscaled, divide-first fallback on product overflow), a u128 percent divide (`a * b / (10^d * 100)` with optional round-up and the `2^64 / 100` bound) and a signed-exponent 256-bit scaler (multiply for negative, divide for zero or positive exponents, accept only below `2^63 / 10`). All three run for real in the shared x86-64 evaluator, including the statically linked 128-bit divide `0x63efec0`, the 256-bit multiply `0x43be790` and the 5.9 KB 256-bit divide `0x144dde0` (only the imported memcpy/memset are modelled as byte moves), and 12,000 byte-derived cases agree with an independent specification; 60 negative controls (16 specification mutants, 31 single-byte patches, 13 misc) are all detected.

- Component ID: exchange (l1/src/spot_meta.rs token decimals; also reached from the Hyperliquidity seeding check, see below)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source is used
- Claim status: observation for the executed bodies and the case comparison, inference for names and meanings, unresolved for callers of the second and third body
- Scope included and excluded: included are the three bodies above and their callees `0x63efec0`, `0x43be790`, `0x144dde0` (all run for real) and the Location table; excluded are the imported memcpy and memset (modelled as byte moves), the ten callers of `0x434f660`, and any gate change (none is requested)

## Reproduce

Working directory is the repository root, platform Linux x86-64, Python 3 standard library only, no binutils, no network, the node is never executed:

```
python3 tools/artifacts.py verify
python3 -m unittest tests.test_token_decimal_scaling_115
python3 tools/token_decimal_scaling_115.py --out research/work-items/exchange-token-decimal-scaling-115
```

The tool checks the SHA-256 of the binary first, checks the FDE extent of every body, runs the cases and controls and writes every file in this folder except `README.md` and `MANIFEST.sha256`. Output is deterministic (no clock, no random source outside seeded `random.Random(str)`); peak memory is below 1 GB and one run takes about 15 s. `MANIFEST.sha256` lists every other file in `sha256sum` format.

## Evidence

All coordinates are virtual addresses of node #115 (FDE extents read from `.eh_frame`).

| body | extent | arguments | result |
| --- | --- | --- | --- |
| `0x434f660` | 297 B | rdi a, rsi token index, rdx b, rcx context | rax ok flag, rdx value |
| `0x434f790` | 369 B | rdi a, rsi token index, rdx b, cl round-up flag, r8 context | rax ok flag, rdx value |
| `0x434f910` | 453 B | sil signed exponent, rdx pointer to a u256 | rax ok flag, rdx low word, u256 updated in place by the divide path |
| `0x63efec0` | 190 B | statically linked unsigned 128-bit divide (run for real) | |
| `0x43be790` | 1127 B | checked 256-bit multiply, flag byte at +0x20 (run for real) | |
| `0x144dde0` | 5874 B | 256-bit divide in place, divisor non-zero (run for real, reciprocal table slot `0x64dfa58` seeded; uses imported memcpy slot `0x64df508` and memset slot `0x64df750`) | |

Observed rules (each is executed from bytes in every case, not read from the listing):

1. Token row lookup: the context holds the row vector pointer at +0x20 and its length at +0x28; rows are 0x158 bytes; the two decimals bytes are +0x48 and +0x49. Index >= length refuses through the Location `l1/src/spot_meta.rs:119:33` (VA `0x64768d8`). `0x434f660` skips the lookup entirely for index 0 (scale 1, works with an empty vector); `0x434f790` has no such shortcut.
2. Scale: difference = byte(+0x49) - byte(+0x48); a borrow refuses through `l1/src/spot_meta.rs:1206:57` (VA `0x6476a48`), as does any scale above u64 (`scale_by_difference.tsv`: differences 0..19 succeed, 20..39 refuse). The scale is built bit by bit (10, 100, 10^4, 10^8, then a checked multiply by 10^16 for bit 4); bits 5 and up refuse.
3. `0x434f660`: if `a * b` fits in 64 bits the result is `a * b / scale` with flag 1; otherwise the result is `(a / scale) * b` (low 64 bits) and the flag is 1 only if that second product fits (`setno`).
4. `0x434f790`: the 128-bit product `a * b` is divided by `scale * 100` through `0x63efec0`; if the low byte of the flag argument is non-zero and the remainder is non-zero the quotient is incremented (with carry into the high word); the flag is 1 only when the high word is zero and the low word is below `0x28f5c28f5c28f5c` (= `2^64 / 100`).
5. `0x434f910`: exponent 0 divides by 1 through `0x144dde0`; a negative exponent multiplies through `0x43be790` (flag byte means overflow; the input is left untouched); a positive exponent divides the input in place, so the stored quotient changes even when the final bound check refuses (the divide is the real `0x144dde0`, 808 runs in the case set, floor semantics confirmed). Magnitudes 1..19 are accepted, 20 and above (including -128) refuse. The flag is 1 only when the result is below `0x0ccccccccccccccc` (= `2^63 / 10`). On refusal rdx is not specified and is not compared.
6. Direct `call rel32` byte patterns to the three bodies (`call_sites.tsv`, found by scanning `.text`, each owner taken from the FDE table): `0x434f660` is called ten times from six bodies (`0x38bc000`, `0x38d9ee0`, `0x3bfa910` x2, `0x3c0dea0` x4, `0x3c10000`, `0x3c49220`); `0x434f790` and `0x434f910` have no direct call pattern (unresolved: tail jump, table or indirect use).

Raw files: `cases.tsv` (every 16th of 12,000 cases), `outcomes.tsv` (outcome counts of all cases), `callees.tsv` (helpers reached per harness), `locations.tsv` (decoded Location records), `scale_by_difference.tsv` (real results for differences 0..39), `scaler_by_exponent.tsv` (real results for every exponent -128..127), `call_sites.tsv`, `controls.tsv`, `measure.json`.

## Implementation and comparison

There is no Rust implementation in this packet ("not yet implemented"); `tools/token_decimal_scaling_115.py` contains the independent Python specification (`spec_muldiv`, `spec_percent`, `spec_scaler`, `scale_of`) written from the listing and the harness that executes the real bytes. Each case compares the final result and the helper-call trace (the exact operands passed to `0x63efec0`, `0x43be790`, `0x144dde0`) with the specification.

- 12,000 cases: 4,800 scaled multiply, 3,660 percent divide and 3,540 scaler cases, including directed cases exactly on the percent bound, on the signed bound and on the 256-bit multiply edge (`directed`), token bounds, every scale difference and every exponent. Mismatches: 0.
- 60 negative controls, all detected: 16 specification mutants (e.g. token 0 also bounds-checked, bound one higher, round-up always, multiply wrap), 31 single-byte patches of the real bodies (scale constants, stride 0x158, decimals offset, branch inversions, the `2^64 / 100` and `2^63 / 10` constants, `setno` -> `seto`, the zero-exponent scale, three patches inside the 256-bit divide), and 13 misc controls (flipped digest byte, wrong FDE start, extents of the six bodies, unlisted call target, non-Location address, unlisted panic site, 65-bit store, out-of-range exponent).
- One patch of the sign-fold shift (`sar 7` -> `sar 6`) was tried and removed because it is an equivalent mutant (every affected exponent still refuses).
- An early version replaced `0x144dde0` by floor division; teaching the evaluator the reciprocal-table load, an imported memcpy and an imported memset (both modelled as plain byte moves, the imports are not resolved in the binary) made the real divide run in all 808 cases with the same results. A patch of the reciprocal increment (`inc rdx` -> `dec rdx`) was not detected in 500 scaler cases and was left out.

## Results and limitations

Metrics are in `measure.json`: cases 12,000, mismatches 0, negative controls 60, detected 60. The unit tests (`tests/test_token_decimal_scaling_115.py`) cover hand-computed vectors, panic sites, bounds, the bit-built scale for every difference, every spec mutant and every byte patch, determinism of the case generator and byte equality of a regenerated folder with the committed files.

Limits: static evidence from executing the bytes in a shared model evaluator, not node execution; no Rust yet; the imported memcpy/memset are byte-move models; the meaning of the three helpers (price/size scaling, percent fee or mark-up, signed token-exponent scaling) is inference from arithmetic; callers of `0x434f790` and `0x434f910` are unresolved; no progress gate is requested.

Next question: identify the callers of `0x434f790` / `0x434f910` (look for `jmp rel32` tail calls and the vtable/table users) and then the ten call sites of `0x434f660`.
