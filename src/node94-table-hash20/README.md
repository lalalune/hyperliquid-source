# Node #94 fresh twenty-byte table hash

This independently authored, dependency-free `no_std` Rust component implements
the fixed-length math established by merged #1077 /
`research/work-items/RE-001-address-hash20-94`. Target node #94 SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

```rust
pub fn table_hash20(seed: [u64; 2], message: &[u8; 20]) -> u64;
```

Both seed words are explicit inputs. The function starts a fresh state, absorbs
two little-endian full words with one mix each, absorbs the four-byte tail with
length twenty in the high byte, then performs the observed three final mixes.
Additions wrap modulo `2^64`. The complete twenty-byte input is represented by
a fixed array; no generic writer, incremental state or other length is accepted.

This is the established scalar table-hash relation, not an address derivation,
signing function, password interface or recovered hasher-object ABI. The
component never retrieves runtime seeds, credentials, wallet keys or user state.
Only explicit public synthetic seed/message fixtures are used in validation.
Original caller/table ownership and general writer closure remain unqualified.

Build the real standalone research component directly with repository-pinned
Rust 1.94.1, edition 2021; no original Cargo package or root workspace is invented:

```sh
python3 tools/hash20_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
```

A host C linker is needed for the separate research driver; optionally set
`RECONSTRUCTION_LINKER`, and on macOS `SDKROOT`. Output must be a fresh directory.
The runner authenticates the capture/accepted records before compilation and
checks the complete regenerated input/answer corpus against its pre-Rust freeze.
Only a compact twelve-row smoke fixture is duplicated in Git.

The oracle and controls use the separately authorized **offline Python captured-
arithmetic interpreter**, with the existing byte-bound initializer/loop/tail
lowerings. This is not no-emulation validation, nor full interpretation of the
generic writer. A native captured node/visor or Unicorn is never launched.
The other executed programs are independently authored Rust compiler products.

The [evidence packet](../../research/work-items/RE-001-table-hash20-rust-94/README.md)
retains actual two-profile comparisons, compiled corruption controls, identities
and remaining gaps. No integrated node, complete component gate or target byte
identity is claimed. New code is MIT; imported evidence keeps its ownership.
