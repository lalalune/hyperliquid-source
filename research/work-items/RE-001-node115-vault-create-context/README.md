# Bind the creation path to vault context identity fields

This is a bounded advance of backlog **HL115-065**: the concrete normal path
from `0x2bdd3b0` through the creation adapter/wrapper to the existing vault
identity prelude at `0x44ae810`. Target node #115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Original ELF disassembly/relocations only; no target execution or emulation.

## Prior work

[#2220](https://github.com/lalalune/hyperliquid-source/pull/2220) proves the
identity predicates, and [#4562](https://github.com/lalalune/hyperliquid-source/pull/4562)
provides their independent Rust implementation. This contribution imports that
implementation unchanged. [#5600](https://github.com/lalalune/hyperliquid-source/pull/5600)
studies the transfer core and does not supply this construction chain.
[#6587](https://github.com/lalalune/hyperliquid-source/pull/6587) owns the earlier
createVault address helper `0x46dba10` and its immediate caller limits. It
explicitly stops before modeling/pinning the `0x2bdd9ac` continuation. That
successful result is an input here; address derivation is not reimplemented.

## Closed dataflow

Let **A** be the 20-byte identity passed in RDX to `0x2bdd3b0`, and **B** the
20-byte successful result of its earlier `0x46dba10` call. These names denote
observed data origins; A is not assumed to be a cryptographically verified
signer.

1. The constructor preserves A at stack `+0x50`, copies B to `+0x130`, and
   sets stack byte `+7` to **zero** at `0x2bdd74d`.
2. Relative to the closure base at stack `+0x80`, it writes pointers to A at
   `+0x68`, B at `+0x70`, and that zero byte at `+0x88`. The pointer-bearing
   closure is passed in R8 at `0x2bdd9ac`.
3. `0x2c3c800` preserves R8 and passes it in RSI to `0x2c3d6a0` on both its
   direct and abstraction continuations. Earlier adapter checks and their
   success are premises; this packet does not reconstruct them.
4. `0x2c3d6a0` dereferences those three fields, makes distinct full-width
   copies of A and B, then calls slot `0x64e7b90 -> 0x44ae320` with RSI=B,
   RCX=A, and R8B=0. Intermediate non-identity arguments are outside scope.
5. After its own earlier checks, the wrapper constructs a context at stack
   `+0xc8` and calls slot `0x64e7bb0 -> 0x44ae810`:

| Guard input | Proven value on this path |
| --- | --- |
| context+0, qword | zero-extended R8B = **0** |
| context+0x8c, 20 bytes | **B**, the derived identity |
| context+0xa0, 20 bytes | **A**, the original argument |
| context+0xb4..+0xb7 | little-endian dword `0x100`: bytes `00 01 00 00` |
| incoming identity in RDX | **A**, the same bytes as retained context+0xa0 |

Thus policy byte `+0xb5` is **1**, supplied by construction, and raw mode is
**0** on this concrete path. The existing prelude reaches its next stage;
that does not establish successful vault creation or transfer. The identity
at `+0x8c` is separate: the original next lookup at `0x44ae909` uses B. Treating
the two identity fields as interchangeable would lose this distinction.

## Independent source and limits

`src/node115-vault-create-context` provides the successful-boundary field
projection and joins it to the existing guard implementation. Its byte-image
writer changes only the recovered fields, preserving opaque context bytes.
It accepts A and the already-derived B; it does not manufacture an accepted
address-helper result, replay earlier validation, or claim to verify a signer.

This closes a real caller's mode/policy/identity provenance, not the domain of
all callers. In particular `0x559ac10`/`0x559e900`, other mode values, signature
verification, decoded operation ownership, the address hash, adapter effects,
name/deposit checks, later lookup semantics and full transfer effects remain
outside the contribution. HL115-065 and full-scope component gates stay open.

## Validation

```sh
python3 research/work-items/RE-001-node115-vault-create-context/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-vault-create-context/Cargo.toml
cargo test --offline --release --manifest-path src/node115-vault-create-context/Cargo.toml
cargo clippy --offline --manifest-path src/node115-vault-create-context/Cargo.toml -- -D warnings
```

With Capstone 5.0.7 and pyelftools 0.32, nine digest-bound windows reproduce
1,703 bytes / 347 instructions, 70 facts and 60 in-memory corruption controls.
Controls change source/destination offsets, fixed mode/policy values, identity
halves, argument registers and the two relocation targets. Static controls are
not runtime differential validation.

Tests distinguish A and B by each of 160 individual bits, verify exact context
offsets with canaries around opaque bytes, and join the result to the existing
prelude. Counterfactual mode/policy fixtures exercise existing reasons 0x16 and
0x17 while explicitly making no claim those inputs arise on this path. The
existing guard's five tests also run.
