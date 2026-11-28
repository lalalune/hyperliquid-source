# RE-017: Materialize omitted #115 attachment rows from the observed tree

The omitted-owner handoff accepts a flat store or the tree representation. The earlier offline fixture reconstructs the flat branch. This evidence follows the tree discriminator, exact query, node descent, value lookup and ordered owner assembly. The fixture resolves a separately pinned Block payload against a caller-supplied tree observation. [Prior flat-branch fixture](https://github.com/lalalune/hyperliquid-source/pull/7767) · [Original owner handoff](https://github.com/lalalune/hyperliquid-source/pull/7273)

The store marker checked at `0x4fad7ff` reaches the tree branch when it selects the native sentinel. The branch reads the supplied root and depth, then scans each node's count at +0x1c2 using 32-byte comparisons. A matching slot loads the stored opaque value at +0x168. A lesser key selects the current child and a greater key advances the scan. Exhausting the local keys selects the last child. The selected descendant is read at +0x1c8 with the appropriate index while depth remains. A miss at leaf depth preserves the first missed key in the existing tag-`0x1c` result. A hit appends the unchanged 32-byte query key and the resolved value in the 40-byte owner row.

The synthetic tree has a root with two separator values and three children. The probe exercises all three child directions, a root hit, and a repeated key in original Block order. A separate probe reports a leaf miss after an earlier hit without returning a completed owner. Opaque identifiers are logical fixture values. Cache construction, pointer reclamation and processing of production data remain separate. The verifier checks 64 exact #115 instruction spans and runs the existing local Rust wire decoder and authored Python tree fixture. It reads the Linux x86-64 captured ELF as data, using SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Reproduce

From the repository root, set `packet` to this directory. Use Rust 1.95 and Python with PyCryptodome 3.23.0 for the exact existing wire-probe package.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --wire BLOCK.bin --wire-sha WIRE_SHA256 --tree STORE.json --tree-sha TREE_SHA256
```

The tree observation provides a numeric `depth` and `root`. Every node contains sorted `entries` with 32-byte lowercase `0x` keys and nonzero opaque unsigned identifiers, plus its ordered `children`. Terminal nodes have an empty children list. See the [raw offline output](offline-log.txt).
