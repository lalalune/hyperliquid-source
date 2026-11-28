# RE-017: Compare a collected #115 response prefix with an archive row

A node #115 result capture can preserve an explicit end position and a prefix of emitted Full rows. The archive can contain additional rows for the same block. [The result collector](https://github.com/lalalune/hyperliquid-source/pull/7522) preserves source ordinals beside the emitted rows. [The existing Full comparison](https://github.com/lalalune/hyperliquid-source/pull/7345) expects complete bundle coverage. The prefix audit lets a replay investigator compare the rows that were actually collected and see which archive bundles still lack observations.

The manifest independently pins the source archive line and the result observation by SHA-256. Each declares the same explicit `H+1` height. The observation also carries Full JSON, its parallel source-ordinal sequence and the position of an explicit collector end, when present. The audit associates the ordinal with its emitted reference, joins against archive bundle keys and uses the existing Full comparator on the observed subset. The existing comparator first checks the complete archive's action geometry. It then compares every observed action result including exact numeric values. The report retains absent keys in archive order and observed keys in collection order. A row with zero actions counts as an observed row. Missing bundle coverage, differences at specific actions and a complete match have distinct report fields.

In the synthetic fixture the archive declares three bundle keys at height 43. The collector emits two groups in a different order with source ordinals 4 and 7, then encounters its explicit end. The report shows two matching observed groups, one absent group and `coverage: partial`. The verifier further distinguishes a completely absent observation, complete coverage and a changed decimal below binary64 precision. The optional Rust probe reconstructs the recorded collector output by compiling a pinned repository crate. Its observation height is deliberately supplied by the fixture. This is an offline outcome check. Production provenance, execution, and H/H+1 state-root agreement require independent evidence.

The verifier reads the approved node #115 ELF as data and rechecks the original collector branch evidence, including initial empty and later accumulated return paths. Capture SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. No captured node or network service is needed.

From the repository root, set `packet` to this directory. The verification expects the #7345 and #7522 exact commit objects in the same local Git object database. The optional compile mode uses Rust 2024 and resolves only a local path dependency offline.

```sh
python3 -B "$packet/verify.py"
python3 -B "$packet/verify.py" --compile-collector

comparator=$(mktemp)
git show e83abddbed3bb133d04f0736120dfd0a2a11c6f5:research/work-items/RE-017-node115-replica-full-response-alignment/compare.py > "$comparator"
python3 -B "$packet/audit.py" "$packet/fixture.json" "$comparator"
rm "$comparator"
```

The CLI exits nonzero for result differences or invalid evidence. For matching observed rows, consult the coverage field before treating a report as complete. See the [offline run](offline-log.txt).
