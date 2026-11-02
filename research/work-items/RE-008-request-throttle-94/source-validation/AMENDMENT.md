# Additive harness admission correction before compilation

The original SOURCE-FREEZE.json (`054552ab23d80266b7ed7d6d13344d7b14cff6bb239bb8b6f6a40fc9d0b0deed`)
and build.py (`43974fae650e4ab6f33d99c1853fc443cbec52d19f615ce3ac20dd70430e7a98`)
remain byte-for-byte unchanged. All source, tests, client, proof, pre-code
oracle/corpus, mutation definitions and retained preparation remain unchanged.

Root and independent peer found a deterministic pre-compilation admission bug:
the Python mutant generator uses tuples for edit pairs, while JSON reloads
them as lists. The direct object equality is false despite identical edits and
mutant-source hashes. AMENDMENT-REPRODUCTION.json records the actual static
predicate rejection for all20 definitions and the successful canonical JSON
comparison. No original harness main/build run, source compilation or value
test occurred. This is not a failed Cargo run or a semantic mutant survivor.

The new entrypoint is `build-amended.py`. Its only change to the qualification
algorithm is comparing canonical JSON projections of the two mutant matrices.
Every edit string, name, scope and source hash still must match. The new
admit_amendment function additionally binds this script's bytes, the original
freeze and original builder, and all supporting amendment files. It checks
the caller-supplied AMENDMENT.json hash before any subprocess and again before
successful qualification is reported. The original source/harness admission
also runs at both boundaries. Required failure still stops immediately and
retains actual evidence; no successful final-admission claim follows a failure.

`build-amendment.patch` is the exact complete diff. The additional CLI argument
is `--amendment-sha`; successful result metadata identifies the amendment and
actual corrected entrypoint. The old SOURCE-FREEZE is not superseded or silently
rewritten. The planned174 subprocess commands, full streams, scoped mutant
checks, raw-retention behavior and source/test selection remain unchanged.

The amended entrypoint must receive its own exact root/peer gate before use:

```text
python3 -B source-validation/build-amended.py
  --toolchain <PINNED_1.94.1_TOOLCHAIN>
  --out <FRESH_DIRECT_CHILD_OF_CANONICAL_TMP>
  --private-map <FRESH_PRIVATE_ARTIFACT_PATH>
  --source-freeze-sha 054552ab23d80266b7ed7d6d13344d7b14cff6bb239bb8b6f6a40fc9d0b0deed
  --amendment-sha <SHA256_OF_AMENDMENT.json>
```

This amendment authorizes no compilation by itself. Source-phase chronology
and the original pre-code freeze are preserved; only the additive entrypoint
should be used after the separate source/build gate.
