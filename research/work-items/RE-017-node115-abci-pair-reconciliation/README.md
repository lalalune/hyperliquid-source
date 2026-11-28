# RE-017: Reconcile paired raw ABCI reference heights with offline observations

The authenticated [node #115 raw digest writer](../RE-008-abci-hashes-log-115/README.md)
places the explicit height and the raw digest in each `abci_hashes` line. A
comparison at a checkpoint and the first applied block needs two such reference
values and two separately measured observations. The adapter here reports the
outcome separately at H and H+1, using the row height rather than filename,
consensus round, or tree value.

This joins two captures beyond the single-input reference extraction in
[#7287](https://github.com/lalalune/hyperliquid-source/pull/7287) and the
internal export-tree check in [#7290](https://github.com/lalalune/hyperliquid-source/pull/7290).
For each supplied manifest it checks the network, authenticated target binding,
raw digest kind and SHA-256 of the named local data. A reference row has the
native exported `height`, `abci_digest` and `exchange_abci_hash` fields.
An observation row has `height`, `abci_digest` and the stage name `restored` or
`replayed`. The stage names are inputs to the offline comparison and are not
native output fields. The receipt retains both input origins and digests.

Supply each manifest as a JSON object with `network`, `target_sha256`,
`digest_kind` set to `abci_raw`, `origin`, `data` set to a JSONL basename,
and `data_sha256` set to the file's SHA-256. Source authority and whether the
supplied observations came from authentic state execution require independent
confirmation. A syntactically valid manifest or a matching receipt does not
establish either fact. Tests use synthetic digests at the motivating heights.

Run from the repository root:

```sh
packet=research/work-items/RE-017-node115-abci-pair-reconciliation
python3 -B "$packet/verify.py"
python3 -B "$packet/reconcile.py" --height 1191310000 --network mainnet \
  --reference /path/to/reference.json --observation /path/to/observation.json
```

The verifier repeats the authenticated export-writer analysis and exercises
separate result, provenance, and format controls. See the
[actual offline log](offline-log.txt). No captured binary runs.
