# RE-017: Stage original attachment bodies for an omitted #115 owner

A decoded Block can name attachment digests while its wire payload lacks the optional owner. The existing structural attachment check reports that the body source is missing. For an offline fixture with separately acquired original bodies, the adapter checks whole-file SHA-256 and native Keccak keys and supplies their exact byte copies in decoded header order. It records the unchanged original wire SHA-256 and its absent owner separately from the derived row files. [Attachment content check](https://github.com/lalalune/hyperliquid-source/pull/7396) · [Native owner-handoff evidence](https://github.com/lalalune/hyperliquid-source/pull/7273)

The synthetic Block names three keys in an order that differs from the independently supplied object list. Two keys repeat the same body and the remaining key identifies an empty body. The verified output preserves that exact order and both appearances of the repeated body. The controls independently detect a missing object, separately re-pinned bytes whose Keccak disagrees with the decoded key, and an original wire record with a present owner.

The output is local evidence from supplied original raw object files. The selected native empty-owner branch covers an absent owner with zero references. Other native owner reconstruction and the provenance of any production object remain independent. The adapter does not use archive JSON as an attachment body.

The verifier checks the existing attachment and owner-handoff instruction evidence against the pinned #115 Linux x86-64 ELF with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It reads the capture as data and runs reconstructed offline Rust and Python.

## Reproduce

From the repository root, set `packet` to this directory, with Rust 1.95, Python with PyCryptodome 3.23.0, and the exact pinned source snapshots available locally.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256 --output NEW_DIRECTORY
```

The external manifest contains a `wire` object with relative `path` and SHA-256, and an `objects` list in any order. Each object has relative `path`, its full-file `sha256`, and the expected lowercase `0x`-prefixed `keccak256` key. The new output directory receives the verified bodies in the order specified by the decoded header. The CLI prints a ledger of their source paths and digests. See [the actual offline run](offline-log.txt).
