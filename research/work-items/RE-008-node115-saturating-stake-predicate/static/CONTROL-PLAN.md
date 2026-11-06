# Draft operative controls for the fixed stake certificate

Status: authored for parent source/effects review. **The new verifier and these controls have not been imported, compiled or executed.** Counts below are planned from the literal definitions, not results. The sealed native contract/proof and its earlier raw binding run remain unchanged.

The checker uses the five complete FDEs (2,542 B / 643 rows), sealed native export rows and exact known capture. It performs static file/byte/address/relocation parsing only. It has no register-state evaluator, instruction emulator, behavioral reference, source implementation, subprocess, network call or native code loader.

## Baseline and bypass discipline

Normal verification requires the exact 105,896,032-byte target SHA before creating output, plus the exact 12-entry independent evidence freeze and binding receipt. It checks file-backed PT_LOAD mappings, full CIE/FDE bytes and decoded extents, complete native row partitions and bytes, all 16 calls / 98 branch bindings, the memcmp/failure relocations and source data, and 29 explicit instruction-span guards linked to the manual proof.

There is no user switch to admit an arbitrary changed target. `--controls` first requires a valid baseline. The unchanged original is then required to pass the internal below-identity path. Each fixed negative control changes an in-memory copy only and uses that same path. Only the universal image-digest, full-body-digest and export-to-image byte-equality layers are bypassed. File size, ELF/FDE/CIE structure, call/branch/import/data checks and every semantic guard remain active. Original evidence files are still admitted by their freeze before controls and re-admitted afterwards.

For three malformed-export controls, the internally substituted text has no new trusted file hash; it must fail the retained row parser. Those tests neither rewrite the sealed exports nor change the expected byte source for any successful semantic verification. No arbitrary JSON/guard-plan input can define commands or relaxed checks.

## Planned negative controls: 68

There are **48 semantic byte substitutions** in `SEMANTIC_CONTROLS`. Each gives an exact original instruction VA, byte offset, original/replacement bytes, and required named semantic guard. The replacement is applied to the capture's actual mapped bytes. A stale coordinate, wrong original byte, different patch width or no-op is a control-definition error, never a passing control.

| Family | Faults bound by the literal controls |
| --- | --- |
| Predicate K bridge | Root-nonnull tag polarity; K count offset; remaining-count storage; saved map-pointer field |
| Key iteration | Remaining load/decrement/empty branch; tag; leaf key count/exhaustion equality; initial child and eight-edge unroll; parent-edge offset; right-child selection; next leaf index; twenty-byte key stride and key base |
| Flat lookup | Live length/empty/head normalization; twenty-byte seam and final comparisons; seam equality and segment sign routing; both last-equal conditional moves; 32-byte row stride; second-segment logical offset |
| Selected fold | Low status bit; live bound field; head addition; row stride and weight+24; both carry clamps; final-miss saved accumulator |
| All fold | Span split, span stride, tag 2; weight+24, row advance, carry clamp; second-span start and empty comparison |
| Wide predicate | Three multiplier; high-limb shift; borrow propagation; strict versus inclusive condition |

The guard spans bind the corresponding manual argument to exact bytes; they do not prove arbitrary altered programs semantically correct or incorrect. Control mutation outcomes are **guard rejection**, not executed counterfactual native output. Some faults could violate memory/termination premises if executed, but nothing executes them.

The other **20 controls** are:

| Count | Category | Required failure |
| ---: | --- | --- |
| 2 | Direct iterator-call displacement / RBP memcmp-source slot | `call.target` / `call.register-slot` |
| 1 | Empty-iterator branch to another valid instruction start | `branch.target` |
| 2 | Wrong ELF machine / section table outside file | `elf.identity` / `elf.bounds` |
| 5 | FDE length, CIE reference, start, extent, CIE encoding | Their corresponding `fde.*` / `cie.encoding` guard |
| 2 | memcmp symbol index / failure RELATIVE addend | `import.symbol-index` / `import.failure-target` |
| 3 | Location length, Location line, source-path byte | `data.location` / `data.source-text` |
| 2 | Whole-target truncation / wrong target digest | `identity.size` / `identity.sha256`, with normal admission enabled |
| 3 | Missing first export row, duplicate row, malformed hex | `export.partition` / `export.syntax` |

Calls/branches are checked before semantic spans, so their controls must reject at their actual binding checks. Branch binding checks encoded width and destination; a same-width polarity flip retains its destination and must reach the named semantic guard. This prevents a generic body/export/branch byte-equality check from masquerading as an operative semantic check.

## Failure classes and actual-results requirements

* A normal wrong identity, malformed input or failed static check returns exit 2 with a structured rejection. No output directory exists until baseline admission and verification succeed.
* An unexpected I/O/schema/parsing exception returns exit 3 and is inconclusive, not a useful guard rejection.
* A control passes only when its actual rejection code exactly equals the predeclared code. Any other rejection, unexpected exception or admission is a failed control.
* After an admitted baseline, the deterministic result records every attempted control and its actual code. Any failed control makes the helper return exit 1. It is retained rather than hidden by a rerun.
* A stale control patch can stop the run as `control.definition`; this is an authoring failure, not detection of a semantic fault.

Parent should inspect the complete source before any run. If admitted, run normal and `-O` invocations separately with identical frozen inputs and fresh output directories, retaining actual command/stdout/stderr/exit records. Both outputs should be byte-identical because no assert-dependent checks, clocks, paths or optimization flags enter the generated result. Do not infer that outcome from this plan.

## Limits

All five bodies were already credited by prior work. This does not add measured-byte coverage, execute the capture, establish actual memcmp runtime/frame behavior, recover original constructors, validate the excluded tree-map route, or prove a safe Rust implementation. It also cannot detect every pure early-stop implementation from B/S/P values; there is no value corpus in this stage. Exact sealed byte identities protect the entire body in normal use, while the below-identity controls qualify only their specifically named operative checks.

## EXPAND

After parent source/effects approval, execute the fixed qualification once normally and once with `-O`, preserve any first failure, and return actual receipts. Independent mathematical-reference/corpus work and Rust source remain separate gates.
