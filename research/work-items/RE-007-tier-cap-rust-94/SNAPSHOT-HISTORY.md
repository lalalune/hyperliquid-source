# Historical tier-cap compiler-input boundary

The tier cap was compiled at public head709baa5d against SOURCE-FREEZE
05810b584396600904ebc2b5469ffad72e207f7c73de4b8e1c289cfce730702b.
Its archived lib.rs SHA256 is
ed8ec35b55cd5d4576b7d6935c0bf731aa86b8d3304369da2605746fef8f05b4.
The complete33-file snapshot, original input/expected streams, ten wrong-cap
relations, actual outputs and REPORT08cecadb remain immutable inside the
unchanged compiled.json.gz.b64 archive.

The next bounded RE task adds the custom-table leverage-increase decision
module and its public export. Before changing this replay boundary:

```text
python3 -B -m unittest discover -s tests -p test_tier_cap_rust.py -k actual_streams -v
exit1: current source/input src/node94-margin-risk/src/lib.rs
stderr SHA256907bc8947ea9165e8fc2cd20bff3f646b48a2bfcf490c6d5d3625dde29e8aba0
```

This failure blocks active caller reconstruction; it is not a cap mismatch.
The minimal repair keeps all archived source/input payload identities and all
actual comparison controls. Default replay still binds every other current
frozen file, including the actual tier_cap.rs, its public API test, dependencies,
input-only driver and pre-source expectations. The current shared lib export
and evolving replay auditor are current support files; their old compiled
versions remain inside the immutable archive. A separate check requires the
public tier-cap export. A new corruption test proves that altered current cap
source still rejects; another pins the original archived lib hash directly.

`--current-component` retains the optional original whole-component check.
The new caller's combined component has a separate source freeze and compiled
receipt. No historical expectation, source archive or output was refreshed, and
no gate is advanced by this boundary correction.
