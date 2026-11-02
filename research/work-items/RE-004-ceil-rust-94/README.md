# RE-004: reconstruct node94's binary64 ceiling scalar in Rust

- Component: `foundation`; bounded quantities/rounding dependency.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin preserved: can1357/hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. Its unlicensed implementation
  was not read or copied for this reconstruction.
- Original ELF VA: `[0x565f670, 0x565f6e7)`, 119 bytes, 30 instructions;
  file offset `0x565e670`.
- Claim: independently authored Rust scalar value reconstruction, with a
  source-level all-input argument and native host checks. No component gate.

## Before and after

[PR #1340](https://github.com/lalalune/hyperliquid-source/pull/1340) established
the complete scalar contract, FDE, constants and one caller binding, but left
Rust implementation unbuilt. The subsequent
[integration review](../RE-003-pr-integration-1335-1349/README.md) reproduced
that packet. This contribution adds the implementation in
[`src/node94-ceil`](../../../src/node94-ceil/README.md), with two actual public
functions: bit-word ceiling and the corresponding `f64` wrapper.

The implementation clears fractional bits and conditionally adds one retained
unit for positive nonintegral inputs. Its structure is independently written
from the established scalar relation. It preserves every exceptional bit
pattern and both zero signs. It does not call a host `ceil` implementation,
allocate, use unsafe code or embed captured machine instructions. The
[proof](PROOF.md) covers every source input and the absence of invalid shifts
or integer overflow.

The original target binding is reused, not counted as newly mapped code.
`verify_rust.py` first reruns its predecessor's complete static verifier,
including FDE/data/relocation and corruption checks. The result records hashes
of that proof, verifier, examples and evidence. The two original mapped
constants become authored Rust bit constants; there are no unresolved
arithmetic helper calls in the source implementation.

## Build and reproduce

With the pinned artifacts materialized and Rust 1.94.1 available, run from the
repository root:

```sh
rustup run 1.94.1 python3 -B research/work-items/RE-004-ceil-rust-94/verify_rust.py --out work/ceil-rust-check
```

The output path must not exist. No download, target execution, networking,
chain action or signing is performed. Only newly built Rust clients and unit
tests run. The library uses only `core`, so this standalone rustc build has no
third-party dependencies, Cargo manifest/lockfile, or inferred crate graph.

The verifier pins rustc 1.94.1 and explicitly selects its reported host triple,
edition 2024, one codegen unit, warnings-as-errors and overflow checks. Library
and client builds use panic abort at optimization levels 0 and 3. Unit tests
use the default unwinding test harness. Paths are remapped from the checkout
root to `/source`. Full command arrays and separate stdout/stderr are retained
in the chosen output directory. The recorded run is on macOS arm64, not a
Linux original-build reconstruction.

## Comparison and controls

The independently derived exact-rational expectations and inputs must have
the same published hashes as the predecessor's 33,066-case corpus before they
can be used. The corpus includes both signs of all 2,048 exponent fields,
fraction/mask boundaries and deterministic SHA-256 samples. The client gets
only little-endian input words on stdin, returns both API results, and cannot
read expected-output files through its code. The Python comparator checks
exact result lengths and every returned bit pattern.

Both APIs agree on all cases at both optimization levels. Two unit tests at
each level cover the 16 prior binary-grounded examples and every exact integer
from -4096 through 4096. A partial input word is rejected by each client.
Two optimized rlib builds are byte-identical on the recorded host; this is
self-build reproducibility, not comparison with the captured ELF.

Four newly compiled Rust mutations are each tested through the same input-only
client. Their mismatch counts must equal the prior independent controls:

| Incorrect implementation | Mismatching inputs / 33,066 |
| --- | ---: |
| Truncate positive fractions | 405 |
| Lose the negative-zero result | 8,226 |
| Quiet signaling NaNs | 9 |
| Return early at exponent field 1074 | 10 |

Source/build/corpus hashes and results are in `result.json`. Exact repository
check outcomes are in `VALIDATION.md`. New source and documentation use MIT;
the captured binary and predecessor disassembly retain their original rights.

## Limits

This closes the scalar value implementation under the predecessor's intact
code/data and ordinary-return premises. Original source symbol, crate/library
version, compiler recipe, upper XMM lanes, original caller ABI, caller input
domains and complete node behavior remain unresolved. The new APIs are not
claimed as drop-in ABI replacements. Host tests do not establish Linux
machine-code identity. No target byte-comparison window is registered and no
foundation or whole-node gate changes.

The next bounded question is the established caller's input-domain and
post-ceiling conversion contract; it is outside this implementation.
