# RE-007: node115 open-interest cap decision and formatting arguments

- Target: Linux x86-64 node115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- New independent Rust: [node115-open-interest-cap](../../../src/node115-open-interest-cap/README.md).
- Complete selected helper: ELF VA `[0x447c620,0x447c7c4)`, **420 bytes / 101 instructions**,
  body SHA-256 `fd1c8cc52b5258565d840999760c5f23038f249d62056c20febb703c9d4d654c`.
- Status: conditional local value/request reconstruction; all 92 full-scope gates remain false.

## Gap closed and prior credit

[PR2286](https://github.com/lalalune/hyperliquid-source/pull/2286) established the
caller `[0x3d987f0,0x3d98b32)` and explicitly left its call to `0x447c620` opaque.
This contribution resolves the helper's complete nonnegative-addend arithmetic,
diagnostic-request order, sentinel choice, key mapping and three format operands.
The retained 57-byte template starts with `Asset open interest exceeded cap`;
that supports the descriptive name, not a claim about live economic policy.

The base has no Rust implementation of this helper. The new source expresses
its established scalar relation without supplying invented lookup answers or
an allocator. The earlier caller packet retains ownership of its lookup and
append observations. Historical node94 [PR750](https://github.com/lalalune/hyperliquid-source/pull/750)
described analogous cap logic; it is conceptual prior credit, not #115 evidence.
No source or evaluator from that work is reused. The existing
`RE-015-node115-flag-group-format` and `RE-015-node115-flag-group-write-target`
packets retain credit for the shared formatter/dispatcher.

## Native relation

Let `x` be signed R9, `a` the signed first stack argument, `m` signed R8, `k`
unsigned RDX and `s` raw CL. Names and Rust records are new safe interfaces,
not recovered source types or an original ABI.

| Native interval | Observation and local result |
| --- | --- |
| `0x447c62e..63d` | Load `a`; a negative value reaches the unwrap boundary. The Rust API refuses this domain with `NegativeAddend`, a host admission error. |
| `0x447c64f..68a` | Add `x+a`; signed overflow computes saturation and requests selector 0 at Location `0x648ba08` before multiplication. Since `a>=0`, saturation is always toward I64_MAX. |
| `0x447c65e..698` | A negative multiplier is invalid. Otherwise the signed product is valid exactly when it fits i64; either overflow direction is invalid. |
| `0x447c69a..6c5` | Unless the product is valid and strictly less than 184467440737095517, read context+0x378. I64_MIN at that later load requests selector 1 with the caller's Location. |
| `0x447c6cb..6e3` | A valid product strictly below 1844674407370955162 writes only I64_MIN to output[0] and returns. Other output words are not initialized on this branch. |
| `0x447c6e8..77b` | Otherwise, prepare mapped key, unchanged selector byte and a binary64 amount, then request formatting. Invalid products supply positive zero. |
| `0x447c781..792` | The ordinary return forwards the output address. This does not establish the formatter's output bytes or ownership. |

The key mapping uses unsigned comparisons: keys 0..9999 are unchanged;
10000..99899999 map to key+100000; larger values map to U32_MAX. The middle
addition fits 32 bits. Every selector byte is passed through, including values
outside 0/1; this API does not impose a new enum validation rule.

Signedness and order matter. A representable negative product is below both
thresholds and returns the sentinel. Negative multipliers and overflowing
products instead select formatting with positive zero. The lower threshold
can request selector 1 while the final result is still the sentinel. Adding
I64_MAX and 1 with multiplier 0 requests selector 0 and then returns the sentinel;
the addition diagnostic cannot be erased merely because the final product is 0.

## Floating-point boundary

Valid products on the formatting branch are positive and at least the higher
threshold. `CVTSI2SD` at `0x447c717` converts the signed integer; `DIVSD` at
`0x447c71c` divides by the exact binary64 constant 1,000,000 at `0x4599a0`
(bits `0x412e848000000000`). Under nearest-even rounding this is
`RN(RN(product)/1_000_000)`, with two rounding operations.

At product 1844674407370955162, conversion rounds to 1844674407370955264.
The two-stage result has bits `0x427ad7f29abcaf49`; rounding the exact rational
product/1,000,000 just once would give `0x427ad7f29abcaf48`.
[rounding.py](rounding.py) derives 11 golden cases using exact fractions,
quotient/remainder and an even tie rule. An independent review also checked
rational midpoint inequalities. No instruction stream is interpreted by it.
The Rust integer cast's ties-to-even rule is documented in the
[Rust Reference](https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast).

Comparison with the target requires nearest-even MXCSR rounding and masked
precision exceptions, e.g. standard MXCSR`0x1f80`, preserved by preceding
callbacks. All admitted operands/results on this path are finite normal values,
so FTZ/DAZ do not change these cases. Sticky exception flags are not projected.
The capture does not establish the actual runtime floating environment.

## Caller composition and dependencies

The credited caller provides a first collection lookup word (zero on observed
miss routes) and an optional second collection's row+0x118 word. Its row index
is key%10000, with an unsigned length guard and a 288-byte stride. At
`0x3d98976..98f`, it passes those words, multiplier, original key, raw selector
and `clearinghouse.rs:544:18` to this helper.

The helper's sentinel decision can be composed with the caller's comparison
at `0x3d98998..9a0`: equality bypasses both append sequences and produces AL 1.
A formatting request is insufficient to prove the alternative append path
actually completes. The formatter, result allocation and later second append
remain dependencies. No whole clearing or settlement operation is implemented.

The context marker is loaded **after** any addition-overflow callback returns.
`observed_cap_word` therefore represents the value at that later observation;
an entry snapshot requires a preservation premise. Continuation past each
reported diagnostic requires normal return, a valid ABI/frame and preserved
saved inputs/output. Destructive aliasing between output, live stack and context
is excluded. The projection reports selector 0 before selector 1 when both occur;
it does not emit diagnostics or enforce callback behavior.

The negative-addend unwrap call has no in-body ordinary return continuation.
The safe host refusal does not reproduce panic, unwind or the original result
discriminant. Sentinel-only output does not mean zeroed padding. Formatter
return values, strings, capacity, ownership, global diagnostics and unwinding
are not inferred from call-target names or successful host tests.

## Reproduce and validation limits

The collector authenticates the complete captured file before output or native
tool invocation, checks exact FDE/CFI/byte and selected data/relocation obligations,
and exports full helper/caller evidence. GNU disassembly is static. Native
mutation controls exercise inner obligations independently of the outer digest.
The mathematical and Rust tests exercise authored relations, never captured code.

```sh
python3 research/work-items/RE-007-node115-open-interest-cap/rounding.py --check
export PATH="$(dirname "$(rustup which --toolchain 1.95.0 rustc)"):$PATH"
cargo test --offline --locked --manifest-path src/node115-open-interest-cap/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-open-interest-cap/Cargo.toml
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-open-interest-cap/Cargo.toml
```

Actual validation commands, before/after scope, outcomes, tool versions and
declared log-path projections are retained in `VALIDATION.md` and
`RUN-RECEIPTS.json`. Two independent Linux-target library builds can establish
repeatability of this authored library only. No aligned native/source-body
comparison, byte-coverage registration, hosted CI or full integrated-node build
is claimed. Full `make test` includes captured-instruction evaluators and is
outside this static-only task; the relevant authored/static tests are separate.

New source and analysis use the root MIT license; imported evidence retains
its existing rights. Next work is the real lookup-to-helper and allocated-result
integration with complete helper/ownership proof. It is not supplied by this
conditional scalar operation.
