# RE-007: funding worker's state updates, rows and first-maximum summary

Node #94's per-user worker `0x3757610` produces the values that the earlier
distribute-funding packet took as input. This packet closes its conditional
state-update and result contract, including the actual leaf caller. Its maximum
summary compares the unsigned magnitude of the **checked metadata-word ×
position-size product**, retaining the first equal maximum. It is not merely
absolute position size. No economic unit is established.

Target: Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Research source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Task RE-007 / clearinghouses and risk. All ranges use linked ELF virtual
addresses, half-open. New code/prose is independently authored MIT research;
captured native exports retain the input artifact's provenance and rights.

Read [PROOF.md](PROOF.md) for the complete conditional argument, then the
[pre-source contract](pre-rust/CONTRACT.md) and
[independent oracle proof](pre-rust/ORACLE-PROOF.md). **Rust is not implemented
at this static/pre-source freeze.** A real dependency-free component is planned
only after independent review; no source or compiled correspondence is claimed.

| Role | Full FDE | Bytes | Instructions |
|---|---|---:|---:|
| worker | `3757610..375809a` | 2698 | 578 |
| actual leaf caller | `3766a10..3766ba4` | 404 | 103 |
| 72-byte row growth | `32d6660..32d66c4` | 100 | 27 |
| supporting 104-byte result growth | `32d5cc0..32d5d24` | 100 | 27 |
| supporting allocation bridge | `32d6740..32d682a` | 234 | 74 |
| credited host capture context | `3703f20..3704678` | 1880 | 399 |
| opaque diagnostic boundary context | `358dcd0..358de41` | 369 | 83 |

The three primary ranges total 3,202 bytes/708 instructions. All seven retained
ranges total 5,785 bytes/1,291 rows. Supporting/context bytes are not extra
whole-component completion credit. Complete structural tables have 288 blocks
and 25 separate LSDA call sites; exceptional reachability and helper effects
are distinct from normal CFG edges. `native/records.json` pins both exports,
actual FDE/CIE records, required relocations and opaque dependency identities.
GNU text stays readable; the second complete native export is losslessly
compressed. For example: `gzip -dc native/worker.llvm.txt.gz`.

The qualified behavior preserves missing/zero rate skips, unsigned asset modulo
10000, metadata bounds before size-zero, checked signed product, two binary64
roundings, raw NaN rate bits, finite-MIN rejection versus nonfinite amount zero,
raw time-word gating, ordered signed saturation and diagnostic requests, row
ownership transfer, and the caller's low32 tag2 exclusion. Empty/ineligible
results have inactive bytes that are not deterministic output values.

The value theorem explicitly assumes valid stable trees and disjoint live spans,
successful exact-prefix allocation and normal helper returns with the stated
frames. It requires RN-even, gradual underflow, DAZ/FTZ disabled and all SSE
exceptions masked; it does not establish the running node's MXCSR. Diagnostic
and allocator transitive implementations remain opaque. Failure can occur after
earlier mutation. No rollback, actual free, scheduler completion, global
settlement, native execution, instruction emulation or risk gate is claimed.

From the repository root:

```sh
python3 -O research/work-items/RE-007-funding-worker-values-94/verify.py
python3 research/work-items/RE-007-funding-worker-values-94/collect.py --out /tmp/funding-worker-native-fresh
python3 -O research/work-items/RE-007-funding-worker-values-94/pre-rust/oracle.py --out /tmp/funding-worker-oracle-fresh
```

Choose nonexistent output directories. Native tools default to the observed
Homebrew GNU objdump and macOS LLVM objdump; `--gnu`/`--llvm` accept equivalent
installed executable paths. Their exact reported versions and parser hashes
are retained; output byte equality can depend on tool version. Neither provider
executes the target. Both read one authenticated private snapshot, checked
before and after exports. Only the exact LLVM standalone LOCK-prefix printing
difference is joined when comparing instruction partitions; no target byte is
masked. The independent PT_LOAD reader also checks every selected body/literal.

Author static validation passed **989 rejecting controls**, eight actual
operand changes decoded by both native providers, and two complete fresh
regenerations under different Python optimization/hash-seed/time-zone settings.
Controls run below full-image hash admission: 818 instruction anchors, required
RELA type/symbol/addend checks, imported comparator symbol/name, literal and
FDE/CIE/LSDA/index corruption, full native bytes and independent load mapping.
An unselected prologue mutation passes the selected anchors but fails full
native comparison, making that subset's limit explicit. These checks bind a
manual proof to bytes; they do not automatically prove its semantics.

The pre-source exact-Fraction oracle freezes **10,945 supplied-state cases**:
9,081 successful accepted states, four eligibility exclusions and 1,860 safe
domain refusals. Thirteen mathematical controls cover ties, subnormal/overflow
boundaries and modulus arithmetic. Fixture expectations are not native runs.
The source plan uses a different u128-significand algorithm, and production
must pass a separate pre-build freeze and actual compiled qualification later.

The previous `RE-007-distribute-funding-94`/#899 and rate formula #860 remain
credited. Historical byte-binding #753 is closed/unmerged, not work taken over
from an active owner. `overlap.json` retains the fresh admission evidence and
limits through #1513. No existing packet, shared source, imports, catalogue or
progress file is modified by this packet. Repository-wide integration checks
remain the coordinator's responsibility; no hosted CI or full-suite result is
claimed here. Provider OpenAI; client Codex; exact model identifier is not
exposed to this worker and is not invented.
