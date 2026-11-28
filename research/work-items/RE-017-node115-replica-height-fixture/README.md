# RE-017: Select a replica export row by its explicit block height

Checkpoint fixture work needs the row at H+1 from a local replica export
when one is available. The exported height, round and parent round are
separate numbers. Choosing a row by either round value can select the wrong
block even when the requested number occurs in the file.

This read-only adapter consumes the selected #115 line format. It matches
only the outer height, returns all three values, and preserves whether the
response field contains JSON null. Duplicate matches and malformed rows
produce errors. It treats the action bundles as an ordered array and prints
only the count.

The [earlier schema packet](../RE-017-node115-replica-json-schema/README.md)
provides writer field bindings. The verifier independently checks the two
writer FDEs, the selected label arguments, the null literal and the newline
write in Linux x86-64 node #115. The transcript prints its target SHA-256.
The fixture is synthetic and intentionally uses overlapping numeric values
across different coordinates. This checks row selection only. A real
artifact's capture provenance, native queue encoding, state application and
state-root validation remain outside the adapter.

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-replica-height-fixture/verify.py
python3 -B research/work-items/RE-017-node115-replica-height-fixture/replica_record.py research/work-items/RE-017-node115-replica-height-fixture/synthetic.jsonl 42
```

[Raw offline output](offline-log.txt)
