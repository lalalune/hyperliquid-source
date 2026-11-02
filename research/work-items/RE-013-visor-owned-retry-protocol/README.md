# Visor owned retry protocol, pre-code phase

This packet closes a conditional value boundary around the complete retry,
sleep and owned optional-cleanup operation. It specifies lazy first attempt,
default versus empty schedules, canonical interrupted sleep requests, creation
before error destruction, final-error construction, and cleanup that preserves
the retry result. Commands, formatting, clock effects and cleanup adapters
remain supplied opaque operations under explicit normal-return and ownership
premises. No shell, OS sleep or captured program was executed.

This is an additive extension of [PR1599](https://github.com/lalalune/hyperliquid-source/pull/1599).
The eventual real `src/visor-retry-protocol` crate will depend on the unchanged
`src/visor-duration-value` in the same PR graph. No new Rust or client exists
in this phase. Original1599 source and all336 prior publicmanifest entries
were rehashed unchanged. This is separate Visor work, not node completion,
new matching-byte credit or an additional PR count.

| Scope | Complete bodies | Bytes | GNU/LLVM rows |
|---|---:|---:|---:|
|Retry, owned caller, two terminal constructors|4|1,095|291|
|Credited duration and runner/format/GPG context|6|6,854|1,403|
|All retained evidence|10|7,949|1,694|

The target SHA256 is
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Start with [CONTRACT](CONTRACT.md), [API](API.md), the address-bound
[PROOF](PROOF.md), and [prior credit/limits](PRIOR-AND-SCOPE.md).
`observed/records.json` binds complete CIE/FDE and selected LSDA tables,
unwind-header entries,18 slots and the15,595-record relocation search.
Complete GNU/LLVM exports are compressed without normalization. Both methods
share one captured target lineage.

The independent exact-rational/total-nanosecond oracle has775 histories:
727 conditional ordinary-domain cases and48 explicitly new safe refusals.
Its6,741 events cover provided identities, liveness, full raw schedules and
creation/destruction order. Input IDs are opaque; descriptions and arbitrary
request bytes are supplied values, while identity labels are observer labels,
not native pointers. Only the input stream will reach a future client; case
names, domain provenance and expectations stay in separate files. See the
[wire protocol](PROTOCOL.md) and [validation plan](VALIDATION-PLAN.md).

Actual normal and optimized Python runs both passed206 rejection controls,
10 abstract-specification sensitivity changes, and six regeneration actions
across two fresh trees. Each tree reproduced26 files byte-for-byte. Both raw
reports are identical (SHA256
`553bc490e917fa8cdc46d5421398ed398022e4933a99b561ed5d6f4cc9144d4c`).
These are static and oracle checks, not production Rust mutant kills or
target traces. [VALIDATION.json](VALIDATION.json) retains commands, source
pins and raw streams; [DEVELOPMENT.json](DEVELOPMENT.json) records the earlier
unfrozen path-diagnostic correction without masking its original reports.

To replay before source authorship, provide the externally recorded freeze
SHA from the review/PR receipt, materialize the pinned capture, and use a
checkout containing the exact1599 dependency files. Choose a fresh report:

```sh
packet=research/work-items/RE-013-visor-owned-retry-protocol
PYTHONDONTWRITEBYTECODE=1 python3 -B "$packet/verify.py" \
  --binary artifacts/visor/captured/hl-visor \
  --dependency-root . --freeze-sha "$RETRY_PRECODE_SHA256" \
  --out work/visor-retry-precode-check.json
```

The retained native provider executables/versions are pinned in TOOL-PINS;
the author interpreter is recorded in TOOLING. The verifier deliberately
refuses when the retry crate or client exists. A later post-source replay
must use an exact isolated copy of the frozen pre-code packet, with the
capture and unchanged dependency supplied by explicit paths. It must not
edit this guard. No dynamic toolchain, production build, external callback,
unwind behavior, elapsed time, filesystem result or GPG authenticity follows
from this pre-code qualification. Independent root/peer gates and any later
source/build receipts are separate from this immutable phase.
