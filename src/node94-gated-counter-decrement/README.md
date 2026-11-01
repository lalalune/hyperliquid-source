# node94 gated counter decrement

Independent, dependency-free `no_std` Rust for node94's complete
`[0x50a90a0,0x50a910d)` body, with its actual five-byte
`[0x5334d60,0x5334d65)` helper closed in the proof. The helper is exactly
`endbr64; ret`; it is not an invented stub or a separate reconstructed API.

`decrement_if_equal(image, base, outer)` reads an inner pointer, compares
five qword pairs in order, and returns that pointer on the first mismatch.
If all five match, it reads an owner pointer and decrements the dword at
owner+5276 modulo `2^32`, returning the owner value sampled before the store.
Both returns preserve the entire raw RAX value. The function describes
numeric memory behavior, without assigning source-level/container meaning.

The slice represents one nonwrapping abstract u64-address interval. Field
address additions wrap modulo `2^64`; actual used ranges must fit wholly.
Only the chosen path needs mapping. The owner itself and the unused helper
argument owner+1792 need no mapping. Arbitrary data aliases and unaligned
fields are allowed, including a counter that overwrites a pointer field.
Missing ranges return `Err(Unavailable)` before any write. This safe refusal
is not a model of native fault handling.

Correspondence requires ordinary stable data memory and valid, disjoint
control stack/code. It excludes control-stack/data aliases, concurrent
changes, MMIO, faults, code modification, nonordinary returns and pointer
ABI compatibility. It does not assert native availability of every abstract
numeric mapping. Other registers/flags, indirect callers and the helper's
other users remain outside scope.

Build this standalone component with Rust 1.94.1:

```sh
cargo +1.94.1 check --offline --locked --manifest-path src/node94-gated-counter-decrement/Cargo.toml
```

The input-only standard-library client is a validation adapter, separate
from the `no_std` library. Target SHA-256, proof, frozen pre-Rust oracle,
full bytes/FDEs, native results and reproduction commands are in
[the evidence packet](../../research/work-items/RE-001-gated-counter-decrement-rust-94/README.md).
