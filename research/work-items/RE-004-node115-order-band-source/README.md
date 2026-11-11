# Node 115 logical spot and perpetual order-price admission

This scoped, independently authored `no_std` implementation advances #3908.
It composes the selected spot metadata admission, common numerical band, and
the actual eight-key perpetual exemption. The issue remains open and no
component gates change. Native allocation, collection memory layout, error
formatting and later order handling are outside this typed projection.

Target: node #115 ELF, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

Merged #4262 (`RE-004-order-band-gates-115`) already maps the spot gate
`0x3c0f840` and perp gate `0x4488300`, including the price-band policy and
status paths. This work credits that packet, implements their logical source
composition, and resolves the perp exemption helper `0x421a520` as eight
specific 20-byte equality checks. It does not claim discovery of the gates.

For valid unique-key metadata, spot checks the token index, the exclusion set,
then the first and second logical maps. Exclusion or a missing second-map value
returns status `0x195`. A missing first-map entry takes the numerical band;
otherwise a successful route returns `0x1a2` when `a <= 99,999,000`, and
`0x100` above it. The perp gate admits the eight observed keys directly and
uses the same band for other keys. The eight constant pairs and relocation
from the perp call slot are checked against the authenticated ELF. No account
identity or business interpretation of these constants is inferred.

The band converts unsigned `a` and `b` to binary64, computes `r = a / b - 1`,
and admits if `p > abs(r)`, or if `p < 1`, `r > 0`, and
`1 / (1 - p) - 1 >= r`. Otherwise it returns status `0x63` and `p * 100` as
the active payload. This preserves the strict lower and inclusive upper edge,
unordered comparison behavior, and the native order of binary64 operations.
The valid-key and default round-to-nearest floating environment are premises.
The owned `InvalidIndex` represents the native index panic; it is not a native
error-object or unwind ABI. Duplicate logical route keys are outside scope.

`records.json` retains all three selected FDEs (1,279 bytes and 294 decoded
instructions). The verifier authenticates the whole ELF, instruction and FDE
boundaries, selected operation/edge facts, all exemption constants and its
relocation, and semantic corruption controls. These are selected facts, not
full component coverage or runtime equivalence. The independently written
Python reference generates 10,000 synthetic binary64 cases including zeros,
infinities, NaNs and high unsigned inputs; NaN payload bits are not claimed.
Tests also mutate every byte of each exempt key. No captured instructions were
executed or emulated, and no live order path was contacted.

```sh
python3 research/work-items/RE-004-node115-order-band-source/verify.py
python3 research/work-items/RE-004-node115-order-band-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-spot-price-band/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-spot-price-band/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-spot-price-band/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-spot-price-band/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-004-node115-order-band-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

Static verification uses existing Python 3.14.7 and Capstone 5.0.7; Rust uses
the installed 1.95.0 toolchain. Full unfiltered `make test` is excluded because
discovery includes captured-instruction emulation.

Implementation and GitHub work: OpenAI `gpt-6.1-terra` / `codex-desktop`.
Independent native review: OpenAI `gpt-6-astra` / `codex-desktop`.
