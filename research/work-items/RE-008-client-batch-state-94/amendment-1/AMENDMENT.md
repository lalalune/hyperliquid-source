# Type adapter amendment after the first compilation failure

The first author and coordinator runs each stopped after 13 commands at the
first debug library build, exit 101 (`E0308`). No tests, value clients or mutants
ran. The frozen source compared a `ConnectionId` to `[u8;32]`. Its provider was
always the pinned baseline `node94-action-signable`: `keccak256` returns
`ConnectionId`; the field is private, and its public `as_bytes()` returns
`&[u8;32]` (`src/context.rs:89..112`). The five input-client uses made the same
uncompiled type assumption. This is a compile-time integration defect, not an
observed native disagreement or a changed hash formula.

`original/` preserves the first module, client, harness and source freeze.
`author-first-failure/` and `root-first-failure/` preserve both exact 13-command
receipts and all 26 stdout/stderr references each. Every raw stream was rehashed.
The first author source freeze remains
`fd33cfb20eadc9b643266dce91496196354b352b8127b4fd19cae309c2b0b4c4`.
The original 53 pre-Rust files, corpus, expectations, manual proof and tests are
unchanged. A parser-only formatting check first reported one long corrected
expression; `format-check.json` retains that result with an explicitly normalized
diagnostic path. `format-apply.json` records its subsequent line wrapping. Neither
command compiled Rust or changed an expression's meaning.

`type-edits.json` contains one exact public projection in the production module
and five in the input client. `corrected/` is the exact result, including the one
rustfmt line wrap. `type-adapter.patch` shows the complete human-readable diff.
No signature relation, source formula, fixture or expected byte is changed. The
`tx-hash-only31` mutation now targets the corrected array/slice projection;
`runner.patch` also shows the isolated original-coordinate replacement. All other
mutations remain the same behavioral faults.

The original actual crate has not been edited while this amendment is prepared.
After the amended gate and qualification, the final public source distribution
applies exactly the single module edit to the real crate; the input client remains
under `corrected/`, while original top-level driver/build files remain historical.
No original snapshot is overwritten. `SOURCE-FREEZE-2.json` binds both the original
history and the effective corrected graph and harness before compilation resumes.

`build_amended.py` admits the same original graph, manifests, baseline prerequisites
and original source freeze. It accepts the actual module only if byte-identical
to the archived original or the declared corrected module, then reconstructs the
original graph from archived module bytes and checks its exact 28-file inventory.
Each fresh build copy receives the exact pinned projection; the input-only client
is likewise derived from the original by pinned replacements. No other actual
source variant is admitted. Toolchain, environment, copied-source verification,
comparison, raw retention and same-path repeat controls are unchanged.

This route permits reproduction directly from a clean public checkout containing
the corrected actual crate, without reverting it to the failed source. Use:

```sh
python3 -B build_amended.py --toolchain <PINNED_1.94.1_ROOT> \
  --out /tmp/client-batch-amended-reproduction \
  --source-freeze-sha <SHA256_OF_SOURCE-FREEZE-2.json> \
  --private-map <FRESH_PRIVATE_PATH_OUTSIDE_PACKET>
```

The original `build.py` is a preserved first-attempt artifact, not the final
reproduction entry point. A later validation record must report actual amended
runs separately; preparing this amendment does not claim compilation or test
success. The full native/authenticator/TC and host-hermeticity limitations in
`SOURCE-PROOF.md` continue to apply.
