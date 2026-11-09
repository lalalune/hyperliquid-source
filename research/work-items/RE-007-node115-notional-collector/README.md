# Node #115 notional collector: rows, balance and iterator ownership

Partial HL115-049; target SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF virtual addresses, static inspection only. No captured execution or
emulation and no complete clearinghouse gate claim.

## Reuse and precise extension

PR #3669 reconstructs `0x44dcf80` in the standalone
`src/node115-clearinghouse-ntl-ratio/lib.rs`. The new crate imports that unchanged
implementation; it does not duplicate its floating arithmetic. #4978 identifies
an overflow diagnostic edge in the caller, while #5034/#5039 identify unrelated
edges in the surrounding owner. This contribution closes the successful flat-span
collector `0x3db8470` and its actual captured inputs at `0x4474a92`, including the
first-result versus later-result ownership split.

The helper's five words consist of a tag plus **four** data words. The collector
stores only those four data words in each 32-byte output row; it does not append
the tag as a fifth payload field.

## Actual input and captured state

The selected caller constructs tag2's two spans from a ring of 72-byte rows.
Each row's +0 supplies the full u64 key, +8 supplies a u32 discriminant, and +24
supplies a signed size/multiplier. Both collector loops skip size zero and any
nonzero discriminant before oracle access. A non2 iterator calls `0x37c5ba0`;
physical tree traversal is a separate prerequisite and is not modeled here.

The captured context is bound at `0x4474a32..0x4474a92`:

| Iterator offset | Source in caller frame | Use |
| --- | --- | --- |
| +0x48 | pointer loaded from stack+0x2a8 | oracle table descriptor |
| +0x50 | address of stack+0x230 | u64 denominator |
| +0x58 | address of stack+0x2b8 | not read by selected ratio path |
| +0x60 | address of stack+0x3f8 | signed scale |
| +0x68 | address of stack+0x1e0 | mutable signed balance cell |

In particular, denominator, scale and balance are distinct cells, not aliases.
The new source takes stable borrowed oracle input and distinct scalar/balance
arguments for this selected contract. It does not infer the original economic
identity of these caller-frame cells.

Eligible keys select oracle row `key % 10000`, with 96-byte stride and signed
field at +0x20. The full original key survives into output. Index bounds and
nonnegative/checked-product constraints precede the denominator-zero absence
branch, as in the credited helper. Zero denominator skips output without debit;
it does not bypass an earlier eligible row's invalid index/product.

## First result and subsequent rows

The first phase advances the **original borrowed iterator** until a successful
helper output. An exhausted iterator returns an empty vector. An applied helper
has already debited the balance, then returns tag1 and the four payload words.
The collector copies those 32 bytes into an initial four-row allocation.

At `0x3db85be..0x3db8614` it copies the remaining iterator and captured pointers
into local state. Later iterations advance that copy. Consequently a successful
nonempty collection leaves the original iterator positioned immediately after
its first successful result, even though the local iterator consumed the rest.
The two captured iterator representations must not be conflated.

Later rows inline the credited ratio calculation and append:

```
[key, signed_size_bits, (converted - product)_bits, product_bits]
```

Balance subtraction is committed at `0x3db881d` before reserve/growth and the
four output stores at `0x3db885e..0x3db8871`. Repeated positions therefore debit
in iterator order. The returned vector is passed to `0x3cc5d00` by the caller;
that next consumer is explicitly outside this contribution.

The prior pure model reports whether difference or balance subtraction overflowed.
The adapter checks those flags in native precedence and stops **before** the
corresponding `0x4524e40` call, preserving earlier rows/debits without committing
a hypothetical callback return. Its report of partial state is a reconstruction
observation, not a claim that native panic/unwind returns a vector. Allocation and
growth failure can also occur after a debit; successful allocation is a premise,
and allocator/unwind equivalence is not claimed.

## Validation

```
python3 research/work-items/RE-007-node115-notional-collector/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-notional-collector/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-notional-collector/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-notional-collector/Cargo.toml -- --config skip_children=true
cargo +1.95.0 clippy --manifest-path src/node115-notional-collector/Cargo.toml --all-targets -- -D warnings
```

Six new integration tests plus ten imported prior tests pass in both profiles;
formatting and Clippy pass. Tests cover two actual decoded positions with signed
results and ordered balance debits, original/local cursor divergence, skipped and
absent rows, bounds-before-zero-denominator precedence, both diagnostic stops,
and all 66 span splits of 65 full-key rows across output growth. The imported
prior tests retain the established floating and saturation frontiers.

Static verification with Python/Capstone5.0.7 authenticates target digest, FDEs,
1508 bytes, 327 instructions and 348 facts, including the inline floating literals
and producer/consumer edges. All 27 semantic mutations are rejected beyond
whole-file/window hash guards: fields, tag, modulus, captures, debit direction,
output stride/order and helper bindings. Repository checks are recorded in the PR.

Physical tree iteration, allocation/unwind, downstream balance use and full
clearinghouse behavior remain open. All gates remain false. New source/evidence
are independently authored under MIT without unlicensed inferred source.
