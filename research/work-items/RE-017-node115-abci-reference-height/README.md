# RE-017: Read raw ABCI references from a local hash export

To check a checkpoint at H and replay at H+1, the reference must use the
same height coordinates and digest kind as the actual computation. This
helper selects exactly one raw 32-byte `abci_digest` at each requested
height from a supplied local `abci_hashes` file. It neither takes a tree
leaf from `exchange_abci_hash` nor uses the file name as a height.

The [authenticated writer evidence](../RE-008-abci-hashes-log-115/README.md)
binds the outer height and raw 32-byte digest to different record offsets,
and identifies the independent tree field. The verifier re-runs that #115
ELF check and exercises synthetic records with different raw and tree
bytes. Controls cover missing heights, duplicate records, a wrong digest
field and a short digest.

The source file is supplied by the caller. This adapter does not establish
provenance, validate checkpoint content or compare a computed state root.
No captured code runs. The output provides expected bytes for a later
offline comparison.

```sh
python3 -B research/work-items/RE-017-node115-abci-reference-height/verify.py
python3 -B research/work-items/RE-017-node115-abci-reference-height/references.py research/work-items/RE-017-node115-abci-reference-height/synthetic.jsonl 42 43
```

[Raw offline output](offline-log.txt)
