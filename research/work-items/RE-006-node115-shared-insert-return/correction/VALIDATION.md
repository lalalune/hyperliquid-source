# Correction validation

Base `05bc2de303c05525b71e7e257426e741bc66a390`; authenticated node #115
digest and complete ranges are in [PROOF.md](PROOF.md). This corrects a
research interpretation; it does not claim a production node defect.

Actual local results, macOS arm64, Python 3.14.3 and GNU binutils
2.47.20260726:

| Check | Actual result |
| --- | --- |
| Original focused tests on base | 6 tests passed; the incorrect annotation was not covered |
| New event regressions, base generator | 3 tests: 1 failure, 1 error, 1 pass |
| Reordered provenance assertion, base generator | 1 test failed on the existing erroneous quantity source |
| Regenerate corrected packet | Exit 0 |
| Complete focused suite after correction | 9 tests passed, 43.498 seconds |
| Reproduce retained inventories | Exit 0; node #115 and visor inventories reproduced |
| Catalogue check | Exit 2; pre-existing stale README progress block |

The initial provenance regression reached a missing new key; reordering its
assertion exposed the existing incorrect value directly, before correcting
the producer. Both original failures are retained. The fixed suite also
regenerates the packet and compares all six generated files byte-for-byte.
Only `records.json` changes; the four complete native exports and FDE export
remain identical to base. The evidence-only `correction/` directory is
outside that six-file generator output and is covered by the packet manifest.

The existing nine negative controls and eighteen added controls mutate bytes
in memory, below the outer whole-target hash gate. Each added control reaches
an existing exact instruction pin, covering nine source/guard/store sites
in each owner. These are static authenticity controls, **not execution of
modified instructions or empirical semantic equivalence tests**. The source
relation itself rests on the explicit address-bound proof and separate
read-only review of both owner bodies.

The catalogue helper and its relevant registry/progress/catalogue inputs
are unchanged. The same base revision already recorded this README failure
in prior validation; the correction changes no top-level work-item count,
implementation count or acceptance gates. It does not repair unrelated
generated progress drift. A failed catalogue check is not reported as a pass.

Before work, `make doctor` and `make verify` passed, including 32 imported
files, six pinned repositories and 558 packet manifests / 7,154 entries.
Final manifest verification is recorded in `final-checks.json` after all
evidence is assembled. Full `make test` and hosted CI are not run: the broad
suite includes captured-instruction evaluators beyond this static-only task.
The focused suite parses/disassembles files and tests authored static helpers.
No captured node/visor code, emulation, live service or chain operation ran.

[RUN-RECEIPTS.json](RUN-RECEIPTS.json) pins the actual source used, tool
versions and retained logs. The only log transformations replace the local
checkout root and GNU installation prefix with declared placeholders. Each
original and stored hash is retained separately; no test outcome is changed.

Reproduction (GNU `objdump` and `readelf` must be on PATH):

```sh
python3 -B tools/shared_insert_return_static.py
python3 -B -m unittest discover -s tests -p test_shared_insert_return_static.py -v
make verify
make reproduce
make catalogue-check
```

The last command retains the stated pre-existing failure until the main
catalogue is regenerated. Target initialization and exact pinned inputs are
repository prerequisites. Copy-helper implementation, source-frame stability,
consumer interpretation and runtime equivalence remain outside this result.
