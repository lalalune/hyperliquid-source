# Node #94 byte and boolean decoders

This standalone, dependency-free `no_std` component implements the chosen safe
state/result/write relation of two complete node #94 native leaves:

| Inferred operation | ELF VA, end exclusive | Bytes | Native instruction rows |
| --- | --- | ---: | ---: |
| Unsigned byte | `0x466bbb0..0x466bc09` | 89 | 28 |
| Boolean byte | `0x466be00..0x466be6c` | 108 | 36 |
| Total | Two disjoint complete bodies | **197** | **64** |

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The bodies have no calls, jump tables or RIP-relative data dependencies. Names,
safe types and error variants are independently chosen; original nominal Rust
types, ABI, inactive output bytes, padding and physical pointers are not claimed.

## Contract

`read_u8(&mut &[u8], &mut Budget)` returns every byte value 0..255, including
the markers interpreted specially by the separate varint codecs.
`read_bool` accepts only 0 and 1. An invalid boolean byte is consumed before
`InvalidBooleanByte` returns, retaining the complete suffix.

Only `Budget.mode_word == 1` enables charging. Both leaves first reject
`counter == u64::MAX` without changing the counter or slice. Otherwise they
store `counter + 1` before testing the old counter against the limit. A limit
failure retains that increment and leaves the slice untouched; equality of
the increment with the limit succeeds. Other raw mode words bypass the gate.
These machine-word cases do not establish a recovered configuration enum.

Charging precedes empty-input checks. Empty input returns
`UnexpectedEnd { needed: 1 }` without consuming a byte, retaining any admitted
charge. Repeated nonoverflow limit failures continue incrementing the counter.

The target's boolean budget-error path writes raw tag 2 **and a word 1 at
output offset 8**; the u8 budget error writes only tag 2. The chosen
`BudgetExceeded { word8_write }` retains this difference as `Some(1)` versus
`None`, without interpreting that word as an active original error field.
Success corresponds to tag 18, shortage to tag 0/word 1, and invalid boolean
to tag 8/the consumed byte. This records optional writes, not reads of native
inactive bytes or a claim about native result layout.

## Build and comparison scope

`Cargo.toml` is a real standalone component manifest with no dependencies;
`Cargo.lock` was generated offline with the existing Cargo 1.89.0 and the
repository's research Rust 1.94.1. No root workspace or target compiler
provenance is inferred.

The corresponding packet is
`research/work-items/RE-005-byte-bool-rust-94/`. It retains a separately authored
complete state proof and 5,628 distinct expected input/output records sealed
before this Rust was authored. The separately linked `examples/compare.rs`
client reads only six-field input TSV from stdin. Expected JSONL is owned by
the comparison runner, not by the library or client.

Input fields: id, `u8`/`bool`, raw mode, counter, limit, lowercase input hex.
Mode is a canonical decimal u32; counter/limit are canonical decimal u64.
Output is canonical sorted-key JSONL with exactly these fields:
`byte1_written`, `consumed`, `counter_after`, `counter_written`, `id`,
`remaining`, `tag`, `tail_hex`, `word8_written`. Missing writes are null.
Unsigned integers are emitted as exact decimal integers, without floating
point. Full tail bytes and counter changes remain observable on every outcome.

The normal-state contract requires valid immutable nonwrapping slices and
suitably separated state, output and input storage under ordinary returns.
Faults, aliasing, concurrent mutation, unwind and hidden native register
effects are outside scope. No captured instruction execution or emulator is
needed for the mathematical proof or the new Rust tests. No target code-byte
identity or serialization gate is claimed.

With the recorded owned toolchain, the intended component commands are:

```sh
cargo test --offline --locked --manifest-path src/node94-byte-decoders/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node94-byte-decoders/Cargo.toml
```

Actual tool paths, flags, profile/corpus/control results and omissions belong
in the evidence packet; the commands above alone are not a claim of execution.
