# RE-017: ABCI sample handoff, callback queue and line fields in node 94

This packet maps a node #94 ABCI constructor result through a conditional save-worker handoff, three guarded sample routes, callback-queue delivery, and six-field line serialization, allowing a reconstruction to preserve the observed field layout and failure decisions.

- Component ID: `abci`, RE-017.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. Its labels are leads, not licensed implementation source.
- Claim status: static byte observations below, with conditional relationships and inferences identified explicitly. No component gate is requested.
- Scope included and excluded: 22 newly selected FDE extents and selected decisions, calls, operands, data and exception entries. Short previously inventoried caller and loop excerpts in `boundaries.tsv` are context, not newly owned functions. The original loader GOT and call site are not re-owned. Node #115 and the separate visor executable are not examined.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3 and the standard library:

```sh
python3 tools/abci_sample_path94.py --out research/work-items/RE-017-abci-sample-path-94
python3 -m unittest tests.test_abci_sample_path94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_sample_path94.py --out work/abci-sample-a
PYTHONHASHSEED=271828 TZ=Asia/Seoul python3 tools/abci_sample_path94.py --out work/abci-sample-b
diff -r work/abci-sample-a work/abci-sample-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-sample-path-94 work/abci-sample-a
```

Use initially empty output directories. The producer verifies the complete input SHA-256 before parsing or creating its output, uses the repository's shared ELF and CIE/FDE/ULEB readers, and rejects ambiguous mappings and `SHT_NOBITS` as file contents. It resolves selected fixed instruction patterns and RELATIVE relocations from ELF bytes. It does not invoke external programs or execute the node. GNU objdump 2.42 was used only for human instruction inspection; its output is not an input to the producer or tests. `MANIFEST.sha256` covers the README and every generated file in this work item.

## Evidence

Addresses are linked ELF virtual addresses; file offsets and exact bytes are in the TSVs. `functions.tsv` joins selected `.eh_frame_hdr` starts to actual FDE/CIE records and hashes complete FDE byte ranges. Those ranges are unwind extents, not proven whole-function boundaries. `windows.tsv` retains their bytes; `boundaries.tsv` separately marks prior-work integration excerpts. The remaining tables record selected decisions and edges, not an exhaustive disassembly or reachability proof.

| New FDE starts | Bounded role |
| --- | --- |
| `0x474ba90`, `0x4331a70`, `0x433a7c0`, `0x4341050` | Name and spawn the save worker, capture the shared pointer, invoke the prior loop, and drop the payload. |
| `0x4523150`, `0x46a90f0`, `0x46b9df0`, `0x47a6af0`, `0x47a5fa0` | Lock and sample directly or arrange one of two TLS-dependent callback paths. |
| `0x4e19c40`, `0x4e19e50`, `0x4e15970`, `0x47799c0` | Publish and recover a callback/context pair, invoke the recovered pointer conditionally, and notify completion. |
| `0x45b5910`, `0x48fe6b0`, `0x4972060`, `0x4a7c270`, `0x4a87800`, `0x4a10c80`, `0x4a8f530`, `0x4a9b850`, `0x4ad4100` | Build the line, serialize its six fields, and format selected values. |

### Entry and pointer handoff

The existing [state link](../RE-017-abci-state-link-94/README.md) establishes the Location-bearing loader chain; the [node inventory](../node-inventory-94/instructions.json) records the surrounding startup and loop bodies. On the selected normal constructor return, the prior constructor leaves its second returned word in `rdx`; startup saves it at stack `+0x10` and later stores it at stack `+0x1dc8`. The copied parent starts at stack `+0x1760`, making that slot parent `+0x668`. The selected parent copy has length `0x698`. On the prior non-2 outer-result arm, the parent is copied to outer object `+0xe8`; `0xe8 + 0x668 = 0x750`. These arithmetic steps are recorded as decoded operands. The connection is conditional on the intervening calls preserving the saved word and the selected copy path; the separate tag-2 arm and other paths are not characterized here.

The prior startup body loads outer `+0x750` for the established slow worker. A later load from the same field at `0x22772a0` precedes the boundary call at `0x22772b1`; its previously unbound slot `0x5773b68` has a symbol-zero RELATIVE relocation to new FDE `0x474ba90`. There is an intervening call between the two loads, so equality of their runtime values is conditional on no intervening mutation or aliasing. This packet does not re-own the earlier slow-worker call. It does not yet prove that the constructor input or the live sampled instance is byte-identical to the original loader result.

`0x474ba90` binds the 26-byte literal `node save visor_abci_state` and passes its first argument as a stack argument to `0x4331a70`. Six saved registers, the return address and the builder's `0xd8`-byte frame explain its stack argument at `+0x110`. The builder stores this word in the closure at `+0x28`; `0x433a7c0` loads that slot and passes it to the prior loop `0x432e930` via a distinct RELATIVE slot. `descriptor.tsv` binds the closure descriptor at `0x571cb48`, its size `0x30`, alignment 8, drop target `0x4341050`, and callback target `0x433a7c0`. Actual callback scheduling is not observed. The prior loop adds `0x10` to the captured pointer; call this resulting base `B`.

The existing slow-worker packet (PR #1640) establishes that its direct guarded path forms its own base plus `0x570` and passes that pointer in a context to the previously inventoried `0x4677fd0`. The latter's prior instruction transcript loads context `+0x30` and passes that word to the apply-block copy `0x42e5d40`. On the previously described selected gates, that copy calls begin-block copy `0x4cdf180`, whose saturating height update and conditional time update are characterized by the [round-clock packet](../staking-round-clock-94/README.md). Thus, **if** the two startup pointer loads are equal, the selected prior slow-worker path and this direct sampling path use the same input base `B+0x570`. The prior functions and their call sites are citations, not new ownership; the selected paths, scheduling and temporal ordering remain conditional.

### Sampling and callback delivery

The prior loop calls the prior getter, whose selected direct edge reaches `0x4523150`. Its second and third base arguments both equal `B` on that path. The guard is at `B+0x568`; define the sampled input base `E = B+0x570`. The direct route tests a TLS pointer and compares its `+0x110` word with the word at `B+0x4138`. If the pointer is null, it calls `0x46a90f0`; if nonnull and unequal, it calls `0x46b9df0`; equal takes the direct loads. The two adapters name callbacks `0x47a6af0` and `0x47a5fa0` respectively. The selected callback loads use the same `E` offsets as the direct route, as checked in `operands.tsv`.

Both adapters pass a callback pointer and a context pointer to `0x4e19c40`. That function publishes them at `segment + 24*i + 8` and `+16`, then sets bit 0 at `+24`. It derives `i` from `(ticket >> 1) & 0x3f`: index `0x3f` waits, while `0x3e` uses a newly allocated `0x5f0`-byte segment and the corresponding final-slot offsets. The selected consumer `0x4e19e50` checks the ready bit and returns a tag and the same two-word slot shape. `0x4e15970` retries returned tag 2, takes a separate zero-tag path, and on its selected nonzero path calls the first word with the second as argument at `0x4e15cdf`. The producer uses a queue at owner `+0x80`; the consumer uses its own `+0x110` owner pointer followed by the same adjustment. **Inference:** these form the delivery path if they refer to the same queue and entry. The bytes do not prove that a particular producer and consumer share an instance or that a callback runs.

The null-adapter callback calls `0x47799c0` after publishing its result. That helper attempts an atomic zero-to-one guard, takes a helper on contention, and checks a separate status byte before its notification path. Its nonzero status path reaches a diagnostic helper and `ud2` if the helper returns. Exact wakeup and scheduling semantics remain outside this packet.

### Sample and serialization layout

The direct sample copies 72 output bytes and returns two additional 8-byte timing-like values. The prior getter forwards the first 72 bytes; the prior loop may subsequently replace the lag tag and value. The offsets below are from the newly traced machine instructions and length-bound serializer names. Names are supported by the output keys, not by assumed source types.

| `E` source on selected direct/callback routes | Sample offset | Output key | Selected behavior |
| --- | --- | --- | --- |
| `+0x10` qword | `+0x20` | `initial_height` | integer formatter |
| `+0x28` qword | `+0x28` | `height` | integer formatter |
| `+0xb90` and `+0xb98` | `+0x00`, `+0x08` | `scheduled_freeze_height` | tag and value, described below |
| `+0x60` qword and `+0x68` dword | `+0x30` | `consensus_time` | delegated time formatter |
| result of the selected time helper | `+0x3c` | `wall_clock_time` | delegated time formatter |
| initially zero tag; prior loop may set tag/value | `+0x10`, `+0x18` | `reference_lag` | tag and binary64 bits, described below |

The offsets agree with the conditional state layout in the existing [round-clock packet](../staking-round-clock-94/README.md), but matching offsets alone do not prove the same runtime object or historical value. On the direct path the lag tag is explicitly zeroed; the adjacent payload is not established as initialized by that store and must not be inferred from it. The loop has a later conditional tag/value replacement.

`0x45b5910` allocates an initial `0x80`-byte buffer, writes `[`, serializes a quoted first component, writes a comma, serializes the sample object with the six keys in the table's order, writes `]` and newline, and passes the resulting bytes to existing writer `0x13d12a0`. The first component is consistent with a timestamp from the prior wrapper; its full formatting and the writer's downstream behavior are boundaries. This is a selected successful serialization path, not a claim that a file was opened, written, flushed or retained.

The freeze helper loads the qword tag and payload and tests only tag bit 0. If clear it writes the four bytes `null`; if set it sends the payload to the integer formatter. The lag helper likewise tests bit 0, and for a set tag clears the binary64 sign bit and compares the remaining bits with `0x7ff0000000000000`: finite patterns use a formatting helper, while infinity and NaN patterns use `null`. Raw tag values 2 and 3 exercise these byte predicates, but are synthetic controls, not evidence that invalid source-level representations are reachable.

The existing grouped-root packet (PR #1701) independently records a low or secondary builder capture at its own input base `+0xb90`, and its option child's selected direct path selects the value only when the pointed-to dword equals 1. If that input base and this sampler's `E` identify the same instance at the relevant times, both paths refer to the same freeze slot. The local predicates agree for canonical tags 0 and 1, but differ for synthetic raw tag 3: the selected sample writer tests its low bit, while the previously recorded root child tests dword equality. This comparison does not establish object identity, valid noncanonical tags, actual serialization, or a resulting hash.

The integer formatter `0x4a10c80` uses the 200-byte pair table at `0x704d88` and a 20-byte work area. Its four-digit grouping uses `(n * 0x346dc5d63886594b) >> 75` for unsigned division by 10000. The checked model proves the reciprocal's error bound for the full unsigned 64-bit input range and exhausts the 10000 possible four-digit pair splits; focused tests compare 20059 boundary and deterministic inputs against independently rendered decimal. The string and floating-point formatter internals remain separate boundaries.

### Selected failure and exception decisions

| Condition | Selected continuation |
| --- | --- |
| The TLS-associated reference increment at `0x474bac8` is nonpositive | Branches to `ud2` at `0x474bcf6`. |
| Name or builder allocation returns null | Separate allocation-failure helpers; the builder paths reach `ud2` if those helpers return. |
| Builder's thread result low bit is set | Its first output word is zero; the save constructor uses `failed to spawn thread` and reaches `ud2` if its error helper returns. |
| Guard word has bit 3 set, is at least `0xfffffffffffffff0`, or the compare-exchange fails | Call the slow acquisition helper; otherwise attempt `old + 0x10`. |
| After decrement by `0x10`, `(old & 0xfffffffffffffff2) == 0x12` | Call the selected release helper. The LSDA entries covering the two TLS adapter calls and selected time call land at `0x4523478`, which performs release before the unwind-resume boundary. |
| Queue index is `0x3f`, the slot ready bit is clear, or the consumer reports tag 2 | The corresponding selected path waits or retries; this does not establish a progress guarantee. |
| A checked intermediate field-writer state byte is nonzero | The selected sample-writer paths call a separate helper. At the final close check, a set low bit in the first state byte or a zero second byte returns zero without appending `}`; reachability of those raw states is not established. |
| Either line component serializer returns a nonzero word | Release the temporary buffer when its allocation field is nonzero, then call the existing error-conversion helper; the sink is not called on that selected path. |
| Line allocation is null or newline capacity is exhausted | The former goes to a failure helper, while the latter calls a growth helper before the newline store. Separate unwind records are retained. |

`decisions.tsv` preserves exact guards, condition codes, displacements and targets; `lsda.tsv` preserves selected call-site ranges, landing pads and uninterpreted action indices. The table does not claim that every condition is reachable or that all helper failures are covered.

## Implementation and comparison

Not yet implemented. There is no independent Rust component, build, normalized comparison, helper closure or whole-ELF comparison. The pure Python decimal, lock, option and queue models in the producer are narrowly scoped evaluations of byte-checked predicates; the tests provide synthetic inputs and never run target code. There is no captured node execution, networking, chain operation or fixture derived from private runtime state.

## Results and limitations

`summary.json` and the evidence tables report 22 FDE extents covering 12323 selected bytes, 17 prior-work boundary windows, 56 selected conditional decisions, 27 selected edges, four RIP-relative references, 65 decoded operands, six field rows, four descriptor words, three length-bound literals, one 200-byte decimal table and 114 LSDA call-site rows. These are selection counts, not component or node-wide coverage denominators.

The focused suite passes 24 tests with zero skips. It corrupts every selected FDE and boundary pin, each selected branch opcode and displacement, relocation type/symbol/target, descriptor size, a field name, an LSDA header, a decimal table byte and range mappings. Independent controls cover lock thresholds and CAS failure, raw tag and finite/nonfinite floating-point cases, queue index/rotation/slot offsets, constructor-copy arithmetic and 20059 deterministic integer values. Two regenerations under different hash seeds and time zones compare byte-for-byte; artifact verification and catalogue consistency are separate repository checks.

The initial loader result's complete data provenance, callback and worker instance identity, thread scheduling, all indirect helpers, I/O success, begin/action/end-block effects and state-root inputs remain unresolved. No milestone is advanced; the ABCI component remains at 0/4. Next question: bind the loader's selected returned state through the prior constructor transformations to the shared `E` instance, then trace its actual block-update and state-root inputs without re-owning established functions.
