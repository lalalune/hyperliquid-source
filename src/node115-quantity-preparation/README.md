# Node #115 scalar quantity preparation

This independently authored, dependency-free `no_std` Rust component implements
the established scalar preparation cut in node #115's actual FDE
`0x41c57f0..0x41c5b83`. Its evidence is the merged
[static preparation packet](../../research/work-items/RE-001-node115-wire-qty-normal-form/README.md),
not the unlicensed inferred source tree. The target's full SHA-256 is
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

```rust
pub fn prepare_quantity(input: u64) -> Result<PreparedQuantity, UnsupportedDomain>;
```

For `input < 2^63`, zero produces coefficient zero and scale zero. Otherwise
remove at most eight trailing decimal zeros: the result satisfies
`coefficient * 10^(8-scale) == input`. Scale is in `0..=8`; when positive,
the coefficient is not divisible by ten. For example, `10` produces `(1,7)`,
`100_000_000` produces `(1,0)` and `1_000_000_000` produces `(10,0)`.
No floating-point operations, allocations or formatting calls are needed.

`PreparedQuantity` is our research type, with no recovered Rust layout.
`prepared_words()` projects the four word **values** observed at native stack
offsets `+0x20,+0x24,+0x28,+0x2c`: scale shifted left by sixteen, zero, low
coefficient word and high coefficient word. This array is not an ABI, serialized
wire format or permission to call the original formatter.

Sign-bit-set words return `UnsupportedDomain` as a separate safe API policy.
The original path has a generic Result-unwrap diagnostic and an unresolved
input/niche type; it does not establish a production negative-quantity rule.
Original formatter behavior, final strings, caller reachability, units, panic,
allocation and unwind behavior remain unimplemented here.

## PDI range iterator

`pdi_range` implements the separately recovered selected relation from node115
`0x22b3160..0x22b3298`. For `count = max(end-start,0) <= 2^60-1`, each output
word is `10000*base + start + index` with checked unsigned multiply and add.
`PdiRange` is a fallible streaming iterator, not the native allocation:

```rust
pub fn new(start: u64, end: u64, base: u64) -> Result<PdiRange, PdiRangeError>;
```

The iterator yields every representable value, yields one terminal arithmetic
error, and then stops. The native function can instead leave a partially filled
allocation and unwind through a panic boundary; those effects remain excluded.
See `research/work-items/RE-004-node115-pdi-range/RUST-CONTRACT.md`.

The real build is direct `rustc 1.94.1`, edition 2021, with no external
dependencies or Cargo workspace. This is the repository's research compiler,
not an inference about the captured node's original build. To reproduce:

```sh
python3 tools/wire_qty_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
```

The runner authenticates the entire capture and accepted static records before
invoking the compiler. A host C linker driver is required; optionally select it
with `RECONSTRUCTION_LINKER`. On macOS set `SDKROOT` to an installed SDK when
needed. Compiler outputs and raw logs go only to the new output directory.

The 2,540-row fixture was committed before `lib.rs` existed. Expected values
come from the captured split-limb equations, cross-checked against an independent
decimal-string specification. The production driver receives only input words,
not expected answers. Debug and optimized builds, ordinary compiled tests,
three compiled Rust mutants and two actual captured-operand counterfactuals
are recorded in the [RE-004 packet](../../research/work-items/RE-004-node115-quantity-preparation-rust/README.md).
Finite compiled comparisons support this scalar reconstruction; they are not
original node executions, machine-code equality or a full component gate.

New code is independently authored MIT work. Imported evidence retains its
original ownership and all component gates remain unchanged.
