# RE-017: compare an exported ABCI tree with its raw digest

For a locally supplied node #115 `abci_hashes` row, this offline check
rebuilds the MessagePack preimage from the exported `exchange_abci_hash`
tree and compares BLAKE3 of those bytes to `abci_digest` at the same height.
That can distinguish a coherent tree/digest pair from a mismatched or
reordered input before using the record as a replay reference.

The [line writer](../RE-008-abci-hashes-log-115/README.md) binds the same
native tree and computed digest to the record. The
[JSON tree analysis](../RE-017-node115-exchange-abci-hash-tree-json/README.md)
establishes the ordered nested pairs. The
[preimage analysis](../RE-008-abci-hash-tree-encoding-115/README.md) establishes
unsigned-integer widths, array headers and lowercase 66-byte digest strings.
The verifier rechecks all three on Linux x86-64 node #115. The local
adapter validates the export shape and uses the separately provided
MessagePack and BLAKE3 packages to rebuild the bytes. The tests freeze the
explicit expected preimages for both a root leaf and a nested tree, then
check changed order, changed digest, and unsupported shape.

The comparison establishes internal consistency of the supplied row only.
It does not authenticate the capture source or calculate a fresh checkpoint
or replay root from application state. The test inputs are synthetic.
No captured instructions run.

From the repository root, with Python and the optional analytical packages
`msgpack==1.1.2` and `blake3==1.0.8` available:

```sh
packet=research/work-items/RE-017-node115-abci-export-tree-audit
python3 -B "$packet/verify.py"
python3 -B -m unittest discover -v -s "$packet" -p test_audit.py
python3 -B "$packet/audit.py" < one-abci-hashes-row.json
```

[Raw offline output](offline-log.txt)
