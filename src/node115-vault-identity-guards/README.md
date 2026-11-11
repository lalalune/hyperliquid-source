# node115 vault identity prelude

This crate models only the ordered identity guards at VA `0x44ae810` in the
node #115 target, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The target-bound static packet is
`research/work-items/RE-001-node115-vault-entry-guards` (merged PR #2220).
The implementation belongs to the `vaults` component and is scoped to the
unblocked RE-001 entry-guard question.

The API keeps the native inputs raw: the context qword is called `raw_mode`,
the byte at context `+0xb5` is `policy_byte`, and identity values are opaque
20-byte arrays. It does not assign public Rust names or ownership semantics to
these values. It returns `ContinueToNextStage` only when this prelude passes;
that does not mean the later lookup or vault operation succeeds.

The target packet records two ordered mismatch reasons: raw mode `1` rejects a
20-byte identity mismatch with reason `0x16`; otherwise a zero policy byte
rejects a mismatch with reason `0x17`. A nonzero policy byte bypasses the
second comparison when raw mode is not `1`. The target writes each mismatch
reason as a 16-bit word at output `+0x10` and writes the failure head as a
64-bit value, `0x8000000000000019`, at output `+0`. Other output bytes not
assigned by the packet are not modeled.

The crate has no dependencies and never runs or emulates the captured binary.
Its tests cover the full local truth table, reason priority and mutations in all
parts of the 20-byte identity. They validate this prelude only, not a complete
vault transfer or admission decision.

Run from the repository root:

```sh
cargo test --manifest-path src/node115-vault-identity-guards/Cargo.toml
```
