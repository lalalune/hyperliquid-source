# Visor clock-sample and fixed60 readiness values — pre-code phase

This additive phase extends the open [calendar contribution #1361](https://github.com/lalalune/hyperliquid-source/pull/1361). The existing packet remains unchanged and credited. It closes the current-clock canonical timestamp dependency through the actual sample wrapper, zero-reference difference, calendar producer and complete day constructor, including the19,600 borrow-correction days in a400-year cycle. The intended single outcome is a real safe Rust value component plus that proof; **this phase contains no production Rust or build success claim**.

Target: Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`. Source baseline for the main evidence is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The credited prior calendar proof is pinned to its submitted head `f82c93aa7cb20251c02185bd1fb0ff158bd643ef`; this packet rebinds all needed bytes itself and does not require that unmerged packet to be present.

Read [CONTRACT.md](CONTRACT.md) for the safe value domain/API, [PROOF.md](PROOF.md) for the conditional argument and [PROTOCOL.md](PROTOCOL.md) for the future input-only client. [VALIDATION-PLAN.md](VALIDATION-PLAN.md) separates this pre-code gate from the later real crate/build qualification. Original imported source is not copied; new material is MIT.

| Full native evidence | Bytes | Rows | Role |
| --- | ---: | ---: | --- |
| `66eb20..66ebe9`, `66ea50..66eb16` |399|106| Normal sample and difference against zero |
| `444600..444705`, `443ec0..44403a` |639|156| Numeric sample to canonical packed date/time |
| `445830..445992`, `444040..44426c` |910|232| Credited fixed60 time/date addition |
| `330360..330581`, `5b41b0..5b470d` |1918|416| Complete duration/caller context; selected path only |
| **Total** |**3866**|**910**| **No new byte-comparison or component-gate credit** |

`observed/records.json` and16 compressed GNU/LLVM exports retain all eight full FDE bodies, raw FDE/CIEs, literal/call bindings and relocation checks. Complete context retention is not a theorem for every branch. `arithmetic.json` records whole-interval quotient bounds and finite calendar certificates. `corpus/` retains60,009 separate input/expected/provenance records with opaque IDs. Native evidence is single-project provenance; independent decoders and arithmetic methods do not create independent historical sources.

From the repository root, after inspecting the scripts, replay into fresh paths:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B research/work-items/RE-013-visor-readiness-value-rust/verify.py \
  --scratch /tmp/hl-readiness-value-replay \
  --receipt /tmp/hl-readiness-value-replay.json \
  --require-source-absent
```

The source-absence option is specifically a pre-code chronology gate. After a future approved source phase, omit only that option to replay these unchanged static files/corpus; it is then a static replay, not proof that production source was absent historically. Later Rust validation requires its separate frozen build harness. `verification.json` retains actual pre-code command/result/control records; `MANIFEST.json` binds replay inputs and `PRE-RUST-FREEZE.json` binds the full chronology. Logical `<repo>`/`<scratch>` paths in receipts replace only command paths, not evidence bytes; the receipt records that mapping explicitly.

The theorem assumes normal imported success with nonnegative numeric seconds0..8210266876799, nano below1e9 and valid preserved nonaliasing frames/storage. The original source timestamp is separately required canonical. The API's invalid-input refusals are new safe policy; generic negative samples, raw packed words, extended nanos, opaque failures, original source timestamp provenance and earlier/later readiness behavior remain open. No captured executable or evaluator ran; no target clock, process, filesystem or live-network operation was performed. No whole Visor gate changes.
