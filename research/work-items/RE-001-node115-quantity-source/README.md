# Node #115 quantity source before vault debit

Partial HL115-062. Original ELF SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
No captured execution or emulation; all full component gates remain false.

## Prior work and new scope

PR #3945 leaves the `0x446bdd0` quantity computation before vault debit open.
Open #5107 uses the same helper as a supplied counter reader. This contribution
replaces that opaque result with the actual logical account, position, oracle and
reserve computation. It does not assign economic units or assert that the result
is universally “available funds.”

The mode-4 dispatcher, magnitude and division are reused unchanged from merged
#4170's `src/node115-margin-range/position-modes/src/lib.rs`. Open #4403 already
uses the eight-address predicate `0x421a520`; its original constants are pinned
here as a credited dependency, not new address discoveries. Mode4 reaches capped
division, so the opaque margin-table modes in #4170 are not assumed or stubbed.

## Actual inputs

`0x446bdd0` copies the caller's 20-byte address, looks it up in owner+0x60 with
`0x4716be0`, and selects the returned 152-byte account row. The singleton compares
address bytes at row+0x80; the indexed predicate `0x3ee6740` compares the same
20 bytes and the wrapper checks the selected index. Missing accounts use the
lazy default whose initializer `0x44e9f40` supplies an empty position collection
and zero at account+0x48. Successful default initialization is a premise.

The call to `0x3beb980` supplies the selected account, flag0 (filter to tag0), mode4,
owner byte+0x509 as the cap, owner+0x148 as oracle metadata, and the same owner as
an additional context argument. In this selected mode the margin-table context
is not consumed by row computation.

The fold visits native 72-byte position rows in order: u64 key+0, u32 tag+8,
u32 divisor+12, signed size+24. It skips tag!=0 **before** any oracle access.
For tag0, key modulo10000 indexes 96-byte oracle records and loads signed value
at +0x20. A negative oracle or overflowing signed oracle*size reaches a panic
boundary before division. With nonzero min(divisor,cap), prior mode4 returns
`floor(unsigned_abs(product) / min(divisor,cap))`. INT64_MIN magnitude is 2^63,
not a saturated signed maximum.

## Ordered folds and result

Starting at signed base=account+0x48, requirement=0 and magnitude_sum=0, each
admitted position computes its product and quotient, then performs in order:

1. Checked signed base += product.
2. Checked unsigned requirement += quotient.
3. Checked unsigned magnitude_sum += unsigned_abs(product).

The fourth fold output starts at the same base field and only adds an optional
row word for active tag1. The selected filter excludes tag1, so that fourth word
remains the original base. It is not consumed by this caller. The third magnitude
sum is also not consumed, but its overflow diagnostic must still be honored.
The source stops before any diagnostic, rather than inventing its return behavior.

The caller requires requirement <= i64::MAX; otherwise it reaches an unwrap panic.
It then checked-subtracts requirement from the signed first fold word. After that,
the exact eight-address predicate decides whether to skip a reserve lookup.
Ordinary addresses use owner+0xa8 via `0x47171f0` (112-byte rows, address at +0x58),
taking reserve at row+0x48 or zero if missing. Predicate matches use reserve zero.
The returned word is `max(difference,0).saturating_sub(reserve)`.

The owned source performs real logical map lookups and arithmetic over supplied
rows. It does not accept an arbitrary counter-result callback. Physical hash-map
indices, native ring/tree traversal, allocator behavior and object lifetimes remain
valid-storage premises. Stable input state and a completed lazy initialization are
also premises; this packet does not establish locking, concurrent snapshot
coherence, native diagnostics, outer rollback, or economic units. The selected
normal path does not write account positions or reserves.

## Validation

```
python3 research/work-items/RE-001-node115-quantity-source/verify.py --target artifacts/node/115/hl-node
cargo +1.95.0 test --manifest-path src/node115-quantity-source/Cargo.toml
cargo +1.95.0 test --release --manifest-path src/node115-quantity-source/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-quantity-source/Cargo.toml -- --config skip_children=true
cargo +1.95.0 clippy --manifest-path src/node115-quantity-source/Cargo.toml --all-targets -- -D warnings
```

Nine tests pass (six new, three imported unchanged). The independent widened
oracle checks 10,496 combinations; fixtures cover exact address identity, all
eight credited special addresses, reserve saturation, missing accounts, tag
filter before invalid lookup/divisor, INT64_MIN, failure precedence and overflow
of the otherwise unused magnitude fold. The static packet checks 8 windows /
2,905 bytes / 711 instructions and rejects 30 field/branch/edge mutations.
Formatting and strict Clippy pass. The imported prior module's crate-root no_std
attribute is locally allowed when included as a submodule; its file is unchanged.
Repository checks are reported in the PR. These are source/static observations,
not executed native equivalence. Source and evidence are independently authored
under MIT except the explicitly imported existing MIT module.
