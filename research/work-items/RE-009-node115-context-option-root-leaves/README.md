# RE-009 · Check Context hardfork and transaction-index leaves in node #115 raw exports

The selected restore decoder returns `hardfork.version` and `hardfork.round` at Context offsets `+0x18` and `+0x20`. The root visitor at `0x4306e30` consumes those two offsets in that order. It places version at path `[0,0,1,0]` and round at path `[0,0,1,1]`. Each leaf hashes the eight-byte little-endian word.

The Context transaction index is separate. The visitor `0x45146f0` sees a dword tag at Context `+0`. Tag 1 hashes the eight-byte index at `+8` into `[0,0,3,0]` and hashes little-endian qword 1 into `[0,0,3,1]`. Other tags take a zero-length first child slice and hash qword 0 into child 1. For a fresh destination the first child stays sentinel and the reducer omits it. This distinguishes an absent transaction index from a present index of zero.

The constructors at `0x4305cf0` and `0x45127d0` both allocate two 24-byte entries and initialize their sentinel words. Both wrappers call `0x41ae280`. It requires two entries, skips any zero-length first slice, and visits the second using the destination advanced by 24 bytes. The selected qword leaf method is `0x14199b0`, reached directly or through the round thunk. The native tree reducer hashes those leaf bytes with unkeyed BLAKE3.

The command below compares those subtrees at a known height using the already decoded Context values and one independently obtained `abci_hashes` row. It reports each subtree separately. It does not infer restored values from the row, compare the top-level raw digest, or establish how the local startup rewrite changed the provided values.

The [checkpoint read packet](../RE-017-node115-checkpoint-hardfork-pair/README.md) maps the named and positional hardfork pair into Context. [#7338](https://github.com/lalalune/hyperliquid-source/pull/7338) follows the local hardfork pair through startup into replay. The [root reducer packet](../RE-008-abci-hash-tree-115/README.md) establishes leaf hashing and sentinel omission. This packet joins the checkpoint fields to two exact root branches and supplies a reproducible leaf comparison. The fixture inputs in the log are synthetic. No actual H/H+1 checkpoint or digest is claimed.

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

Use Rust 1.95 and Python 3 from the repository root:

```sh
python3 -B research/work-items/RE-009-node115-context-option-root-leaves/verify.py
```

For a local capture:

```sh
packet=research/work-items/RE-009-node115-context-option-root-leaves
build_dir=$(mktemp -d)
rustc --edition=2024 --crate-name node115_abci_blake3 --crate-type rlib \
  src/node115-abci-blake3/src/lib.rs -o "$build_dir/libnode115_abci_blake3.rlib"
rustc --edition=2024 "$packet/project.rs" \
  --extern "node115_abci_blake3=$build_dir/libnode115_abci_blake3.rlib" -o "$build_dir/project"
python3 -B "$packet/compare.py" "$build_dir/project" EXPORT.jsonl EXPORT_SHA256 HEIGHT \
  HARDFORK_VERSION HARDFORK_ROUND TX_INDEX_OR_NONE
```

Use literal `none` for a missing transaction index. The [measured offline output](offline-log.txt) includes static binary checks, existing BLAKE3 specification-vector tests, and the two synthetic comparison controls.
