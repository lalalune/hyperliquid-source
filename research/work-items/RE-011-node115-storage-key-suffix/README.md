# RE-011: node 115 storage-key suffix builder

This work implements the already observed storage-key suffix relation at
node115 `0x3d47d20..0x3d47ebb` as independently authored Rust.

- Component ID: `evm-rpc`, with the RE-011 `evm` storage adapter.
- Target: Linux x86-64 node115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  size 105,896,032 bytes.
- Source evidence: existing `RE-011-storage-read-115` packet at source commit
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim status: the selected bytes, FDE extent, body hash and vector rows are
  observations; the logical API names are project-authored inferences.
- Scope included: the 52-byte suffix order and the optional concatenation with
  a caller-supplied prefix.
- Scope excluded: selector parsing, the concrete prefix, original ABI/types,
  allocator and unwind behavior, the account-read backend, JSON-RPC response
  encoding and every other storage adapter branch.

## Reproduce

From the repository root with Python 3.12 and Rust 1.95:

```sh
python3 tools/artifacts.py verify
python3 tools/re011_storage_key_suffix115.py
python3 -m unittest tests.test_re011_storage_key_suffix115
(cd src/node115-storage-key-builder && cargo test --offline --locked)
(cd src/node115-storage-key-builder && cargo test --offline --locked --release)
(cd src/node115-storage-key-builder && cargo fmt --all --check)
(cd src/node115-storage-key-builder && cargo clippy --offline --locked --all-targets -- -D warnings)
(cd src/node115-storage-key-builder && cargo build --offline --locked --release --lib)
python3 tools/catalogue.py --check
```

The Python verifier checks the complete target digest before reading a selected
window. It then checks the complete 411-byte FDE body, three instruction-aligned
windows and all 258 committed key vectors. It invokes no external program and
does not execute the captured node.

## Evidence

`0x3d47d20..0x3d47ebb` is an FDE-backed executable extent of 411 bytes, with
body SHA-256
`f0e2fe83e9d6268d41a2c15c6423e09fbfcfa6ab5441e0008d0804e992409d91`.
The complete extents and existing selected windows are retained in
`research/work-items/RE-011-storage-read-115/functions.tsv` and `windows.tsv`.
An FDE describes an unwind range, not a complete source-function inventory.

The selected normal path allocates 52 bytes. It copies 20 address bytes and
independently loads four source qwords at input offsets `+0`, `+8`, `+0x10` and
`+0x18`. Four `bswap` instructions precede stores at suffix offsets `+0x14`,
`+0x1c`, `+0x24` and `+0x2c`. The resulting relation is:

```text
prefix || address[0..20] || be(w3) || be(w2) || be(w1) || be(w0)
```

The `Es` bytes visible in the committed conditional examples are not treated as
the runtime prefix. The Rust API leaves the prefix as an input. The native
join helper at `0x3d9e820` and the storage value decoder remain outside this
bounded implementation.

## Implementation and comparison

Implementation: `src/node115-storage-key-builder`.

- `storage_key_suffix` returns the exact 52-byte suffix.
- `build_storage_key` prepends a caller-provided byte prefix.
- The crate has no dependencies, build script or external code.
- The test suite reads all 258 rows in the pre-existing `key-vectors.tsv`,
  including zero, all-ones and every single-bit slot case.

Before this change, `src/node115-storage-key-builder` did not exist and the
source evidence packet explicitly recorded the storage adapter Rust
implementation as not yet implemented. After the change, the bounded suffix
relation is independently implemented and checked against the frozen vectors.
This does not establish compiled source/target byte identity. Raw-equal,
normalized-only and unmatched compiled-window counts remain unmeasured, and no
normalization mask or helper closure is claimed.

## Results and limitations

The verifier covers one authenticated FDE body, three selected raw windows and
258 key vectors. These are explicit selected denominators, not function or
whole-node coverage. The no_std implementation excludes allocation failure,
invalid object layouts, aliasing, huge prefixes, unknown runtime prefixes and
the complete storage read/RPC flow.

No component progress gate changes. The `evm-rpc` component remains incomplete.
The next question is whether a separately authenticated caller supplies a
constant prefix on every `eth_getStorageAt` path and how the resulting key is
consumed by the selected database backend.
