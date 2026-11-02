# RE-007: supplied-summary funding residual values, node94

This pre-code packet closes one conditional value operation after the opaque
funding worker: insert/sort supplied summaries, fold saturated sums, select the
first unsigned maximum, flatten inner row prefixes, and apply the complete
residual to an existing selected user/position plus ARU and auxiliary maps.
It adds no production implementation or executable client yet.

The important state correction is that equal old/new size does **not** imply
an auxiliary no-op. For size!=MIN and a=abs(size), the native two ordered stores
produce `max(old_or_zero,MIN+a)`, and an absent key becomes present even at size0.
Existing auxiliary MIN with size1 becomes MIN+1. ARU insertion precedes debit;
zero total or no winner avoids selected state access altogether.

Read [CONTRACT.md](CONTRACT.md), [PROOF.md](PROOF.md),
[TREE-PROOF.md](TREE-PROOF.md) and [CALL-FRAMES.md](CALL-FRAMES.md) first.
Correspondence assumes valid unique tag0/1 summaries and a stable post-worker
snapshot, existing selected state, selected size!=MIN, valid finite native
storage, and successful ordinary allocation/copy/diagnostic/initialization
frames. Worker calculations/provenance, missing-state constructors, unwind,
economic interpretation and the whole host operation remain outside scope.
The separate safe-source rejection policy is explicitly labeled.

Merged [PR899](https://github.com/lalalune/hyperliquid-source/pull/899) already
established the host and sorted-summary outline. This packet credits it and
closes its stubbed user lookup, ARU insertion and auxiliary state edges. It
neither imports nor executes that packet's captured evaluator. There is one
native project/target lineage; two decoders and several reviewers do not supply
independent native sources. The generic [memcmp interface](https://man7.org/linux/man-pages/man3/memcmp.3.html)
is a stated external-call premise, not proof of the captured import.

The digest-bound capture is node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Exact baseline is56c0ec672bd8fdcfaa80f2db700a61e6240b3663.
The retained evidence covers29 full FDEs/25,803 bytes/5,832 grouped rows:
25 bounded operation/support helpers and4 explicit caller/worker/default
contexts. It binds5,750 non-NOP instruction obligations,273 calls including33
register calls,275 RIP references,53 referenced relocation slots,2 hash-constant
spans and the full80,300-entry dynamic relocation census. GNU/LLVM full raw byte
partitions agree. Context exports do not expand the admitted operation.

Actual normal and optimized Python replays passed110 rejection controls and two
identical regeneration trees each. The independent corpus has912 complete frames:
853 conditional native-corresponding and59 separately labeled safe-policy cases.
No captured code, emulator, Rust source or production test was run. See
[VALIDATION.md](VALIDATION.md), [PROTOCOL.md](PROTOCOL.md),
[SOURCE-PLAN.md](SOURCE-PLAN.md) and [CREDITS.json](CREDITS.json).

From the repository root, with the exact pinned capture already present:

```sh
python3 research/work-items/RE-007-funding-residual-values-94/verify.py --out /tmp/residual-static-check
python3 -O research/work-items/RE-007-funding-residual-values-94/verify.py --out /tmp/residual-static-check-optimized
```

Both output paths must be absent. Optional `--binary`, `--gnu` and `--llvm`
flags select existing inputs/providers. Defaults match providers.json's recorded
macOS host; native text is version-sensitive. The scripts run only reviewed
static ELF/DWARF parsing, native disassemblers, and independent mathematical
models. The compressed native/fixture bytes are ordinary Git objects by this
packet's .gitattributes; no LFS hydration is required for these exports.
