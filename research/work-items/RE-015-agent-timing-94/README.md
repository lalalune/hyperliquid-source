# RE-015: configuration-dependent timing on the hourly record path

Node #94's selected hourly path can insert 32-byte records and conditionally mark table entries, then checks `1.0` or `5.0` against zero for only ten configuration name bytes, exposing concrete local mutation and timing decisions for reconstruction.

- Component ID: `constants`, task `RE-015`; the connected downstream record path is included to establish how the configuration byte is used.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is an unlicensed lead, not implementation or ground truth.
- Claim status: observations are authenticated bytes, relocation records, unwind ranges, decoded direct transfers, local stores and fixed comparisons. Names, source-level types, calendar meaning and the abstract models below are inferences. No captured execution, Rust equivalence or component gate is claimed.
- Scope included and excluded: eleven selected FDE extents, three related drivers, their three record builders, cutoff builder, shared record handoff, two local state-mutation routines and name-dependent timing helper. The existing directory selector, static-config parser, 76-name inventory and their bodies are not reproduced. Clock/calendar routines, record collectors and mutation callees, formatting, allocation, lazy initialization internals, #115 and visor remain boundaries.

## Reproduce

From the repository root, with the pinned artifacts and shared repository readers present:

```sh
python3 tools/config_agent_prune94.py --out research/work-items/RE-015-agent-timing-94
python3 -m unittest tests.test_config_agent_prune94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-agent-timing-94 && sha256sum -c MANIFEST.sha256)
```

For the independent regeneration, replace the placeholders with two distinct writable relative directory names:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_agent_prune94.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_agent_prune94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer first checks the whole target SHA-256, then imports `tools/elf_index.py` and `tools/fde_extents.py`; NOBITS sections never supply bytes. The independent MIT x86 encoding reader adapts the earlier RE-015 chain-bucket collector. It accepts a closed encoding subset, checks complete selected FDE partitions and rejects unsupported/truncated instructions and intra-FDE direct branches into operands. The producer and tests use Python's standard library and the shared readers only: no subprocess, disassembler, target execution, clock, randomness or network. The new collector is needed because the existing literal/xref inventory does not follow this discriminator through the timing and state-handoff decisions.

The recorded environment was Linux x86-64, Python 3.12.3 and GNU objdump 2.42 for human inspection. Objdump output is neither parsed nor retained as generated evidence. The following optional command displays the timing helper; it is not part of regeneration:

```sh
objdump -d --start-address=0x13cbdb0 --stop-address=0x13cbee3 artifacts/node/94/hl-node
```

`functions.tsv`, `instructions.tsv`, `branches.tsv`, `calls.tsv`, `contracts.tsv`, `relocations.tsv`, `selected-names.tsv`, `drivers.tsv`, `failure-literals.tsv`, `state-properties.tsv`, `comparison-cases.tsv`, `guard-cases.tsv`, `hour-cases.tsv`, `counter-cases.tsv`, `cfg-claims.tsv`, `lsda-headers.tsv`, `exception-sites.tsv` and `summary.json` are generator outputs. The README and manifest are authored metadata. File offsets are obtained from the appropriate file-backed ELF section, not a universal VA subtraction.

## Evidence

All addresses are linked ELF virtual addresses before load rebasing. FDE ends are exclusive. An FDE describes an unwind range; it does not establish a source function boundary or complete component coverage. The byte contracts are exact instruction encodings, while names assigned to routines are explanatory labels.

### From the retained configuration cell to the name decision

The existing `constants` packet resolves the `/cham` and `/static_config` format-template entries and identifies the name byte in the returned configuration; `constants-aws-name-parse-94` separates the `NvTestnet` value from failure/default control flow. This packet does not re-analyze those owned functions. Here, slot `0x576e928` has an `R_X86_64_RELATIVE` addend `0x577b288`. The selected timing helper `0x13cbdb0` reads the cell's state word at `+0x50`; the nonzero path calls the existing Once boundary and reloads byte `+0x48`. The actual runtime cell contents and initialization outcome are unknown.

The byte code tests the unsigned range `18..=25`, then individual values `31` and `10`. For those ten values only, `ucomisd` compares the incoming binary64 value with zero, and `jb` reaches the failure-text call boundary at `0x13cbeca` on a negative or unordered comparison. The failure text at `0x219f59` is the length-delimited `assertion failed: self.0 >= 0.`. Other byte values bypass that comparison and reach the clock call when the initialization boundary returns. The abstract floating-point cases assume exceptions are masked; unmasked floating-point exceptions are not modeled.

The previously established descriptor table supplies names for only the selected ten indices. The tool reads each complete 16-byte entry, its RELATIVE record, pointer, length and text directly. It also reads the separate default-context entry `0x5668488 -> 0x2180ff`, nine-byte `NvTestnet`, for index 32. The original packet associates that index with the name byte; this new descriptor check alone does not prove the runtime cell's value.

| Byte indices | Descriptor names | Timing helper's local branch |
| --- | --- | --- |
| 10 | `Ea2` | Floating comparison against zero |
| 18–25 | `SoloTestnet`, `SoloMainnet`, `LockerTestnet`, `LockerMainnet`, `RpcTestnet`, `RpcSandbox`, `RpcMainnet`, `RpcMainnet2` | Floating comparison against zero |
| 31 | `SoloSandbox` | Floating comparison against zero |
| 32 | `NvTestnet` | Bypasses that comparison |

The bound diagnostic descriptor at `0x5668778` contains the length-delimited text `variant index 0 <= i < 76`. The model tests the full possible byte range to expose arithmetic-boundary behavior; bytes outside the established name domain are controls, not claims of reachable runtime enum values. `selected-names.tsv` is a ten-entry predicate-specific subset, not a replacement 76-name table.

### Connected driver and record path

| Driver FDE | Record builder | Local counter offset | State-handoff offset | Label bytes |
| --- | --- | --- | --- | --- |
| `0x26fb750..0x26fbaa8` | `0x1f84e00` | `+0x39c0` | `+0x36d0` | `0x3efa0f` |
| `0x4ce1300..0x4ce1658` | `0x47dbf50` | `+0x4440` | `+0x4150` | `0x714e24` |
| `0x4ce1660..0x4ce19b8` | `0x47dc080` | `+0x39c0` | `+0x36d0` | `0x714e24` |

Each driver passes an immediate `-10` to the same relocated normalization boundary twice, rejects separately recorded overflow, conversion and bound failures, and compares two returned 32-bit fields. For values admitted below `90000`, the fixed multiplication `0x91a2b3c5` followed by shift 43 is exactly division by 3600: the producer checks all 90000 inputs. Equal quotients go to the epilogue without the counter store. On a differing quotient, the code retains the old counter, increments with an all-ones saturation case, reduces modulo 20, and stores the new value before calling the selected record builder. For an old value of `2^64-1`, the locally stored result is 15, while the old value is passed onward. The actual clock inputs and reachability of either route were not executed.

The integer reduction is not inferred from a few examples. Its immediate is `M = 0xcccccccccccccccd`, with `5*M - 2^66 = 1`. For every unsigned 64-bit `n`, the extra term in `n*M/2^66 = n/5 + n/(5*2^66)` is less than `1/20`; the fractional part of `n/5` is at most `4/5`. Therefore the high-half multiply and shift compute `floor(n/5)` throughout the u64 domain. The next mask rounds that quotient down to a multiple of four, and the following scaled subtraction computes `n % 20`. This proof concerns the pinned integer fragment, not arbitrary input validity or later helper effects.

On the differing-quotient route each driver calls its listed builder, then slot `0x57748e8 -> 0x3987ad0`, and then slot `0x57748f0 -> 0x34227e0`. The cutoff builder supplies `-86400` to the normalization boundary twice and locally selects zero for a nonpositive signed final value. The record handoff builds three intermediate results, iterates a 40-byte-stride record selection, calls a separate record-processing boundary, loops, drains one iterator, calls the state-adjustment routine and then drains two further intermediate iterators. The handoff also has a `+2` time-normalization input, a distinct overflow failure boundary and retained unwind paths. The names and full effects of its external collectors and processors are not resolved here. Its local call order and branch bytes are not proof of completed agent pruning.

After the handoff returns, each driver selects the exact binary64 bytes for `5.0` when the saved low byte of its incoming `edx` argument is zero and `1.0` otherwise. For example, an input whose low byte is zero takes the `5.0` arm even when higher bits are set. The corresponding 12-byte label is `prune agents`. The `seconds` column names in `drivers.tsv` reflect the reference convention; the local branch alone does not establish the input's unit. Slot `0x576e9b0` relocates to the selected timing helper. Both finite values take the helper's clock path for every byte value under the modeled comparison. The helper calls clock and difference boundaries; a nonzero returned status takes a local zero-result route, while the other route combines converted fields. After the call, the driver immediately reads a separate lazy-state word. Neither the selected helper after its clock call nor the immediate caller continuation compares the resulting floating value with `1.0` or `5.0`; external callees and other callers remain unexamined.

### Conditional record insertion and table cleanup

The handoff calls `0x33a51f0` at `0x3422ab0` for a selected record, and later calls `0x379fb00` at `0x3422af5` with its first argument advanced by `0x90` and a pointer to the saved third argument. The former can change an ordered index; the latter can change a separate table. The return value and semantic type of the preceding lookup at `0x3596f00` are an already-owned external boundary, so this packet does not assert which agents or accounts are affected.

The insertion routine compares a 32-byte record: a dynamic `memcmp` slot compares the first 20 bytes, followed on equality by a signed 32-bit comparison at offset 20 and unsigned 32-bit comparisons at offsets 24 and 28. The 11 synthetic rows in `comparison-cases.tsv` model this ordering assuming standard unsigned-byte `memcmp` behavior; they are not captured state or target execution. An exact match reaches the low-byte return value 1 without the owner-count increment. On the empty-root path, a nonnull allocation of `0x170` bytes is installed as the root; the routine initializes its count at `+0x16a`, writes two 16-byte pieces of the record, increments the owner's field at `+0x10`, and returns low byte 0. The empty-root, duplicate and insertion witnesses are structural CFG claims; nonempty-tree insertion delegates to another helper whose effects remain unresolved.

The table routine returns directly when the field at `+0x18` is zero. Otherwise it scans control-byte groups and calls a separate predicate until its low result bit clears. If the current pointer-sized field is nonzero, that entry skips the local removal writes. If it is zero, the routine writes either `0xff` or `0x80` to two control-byte positions, decrements the field at `+0x18`, calls an external entry helper, and continues. The `0xff` arm also increments the field at `+0x10`; the marker choice depends on neighboring control bytes. The meanings of the predicate, stored pointer and entry helper are unresolved. `state-properties.tsv` binds the field offsets, marker bytes and insertion sizes to their source instruction bytes; `calls.tsv`, `branches.tsv` and `cfg-claims.tsv` retain the connected edges.

The principal local state branches are:

| Routine and condition | Local effect or next boundary |
| --- | --- |
| Index lookup finds an equal record | Return low byte 1; no owner-count increment. |
| Index root is null and allocation succeeds | Install a `0x170`-byte allocation, initialize the node, copy the record and increment the owner count. |
| Index lookup is non-equal | Continue the ordered search; a nonempty insertion can reach external helper `0x2f11050`. |
| Index allocation returns null | Call the separate allocation-failure boundary. |
| Index slot count is at least 11 at its bounds check | Call the capacity assertion boundary. |
| Cleanup count at `+0x18` is zero | Return before the control-byte stores. |
| Cleanup predicate returns with its low bit set | Repeat the predicate call. |
| Predicate's low bit is clear and the current pointer-sized field is nonzero | Continue without the local deletion writes for that entry. |
| Predicate's low bit is clear and that field is zero | Choose `0xff` or `0x80`, write two control bytes, decrement the entry count, call an external entry helper and continue. |

### Local failure and cleanup evidence

| Condition | Locally observed outcome |
| --- | --- |
| Either normalized 32-bit hour input `>= 921600` | First error-text call boundary, `called Result::unwrap()` diagnostic. |
| Either input `>= 90000` and below the prior boundary | Separate `hour <= 24` assertion call boundary. |
| A selected name byte and negative or unordered timing input | `jb` to the separate nonnegative assertion boundary; `+0.0` and `-0.0` take the other edge. |
| Difference helper returns a nonzero status | Local floating result is cleared before the return path. |
| Pointer returned by the `0x4a0d840` boundary is zero in either alternate builder | A distinct failure call is followed by `ud2`. |
| Selected handoff time conversion fails | Separate `NaiveDateTime + TimeDelta` overflow boundary, followed by `ud2`. |
| New-root allocation returns null | The allocation-failure boundary at `0x33a5448` is called; its external effects are unresolved. |
| Selected node index `>= 11` | The separate `assertion failed: idx < CAPACITY` call boundary is reached. |
| Selected calls unwind | `exception-sites.tsv` records 44 call-site ranges from seven selected LSDAs, including landing targets and raw action indices. External destructors, type tables and action semantics remain unresolved. |

The 27 propositions in `cfg-claims.tsv` query an over-approximation of normal intra-FDE control flow. Conditional branches are both taken, calls are assumed to return and exceptional transfers are excluded. A listed witness does not establish a feasible runtime input. The LSDA records are a separate bounded exception map; they do not prove allocator, destructor or personality behavior.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, compiler/linker flags, two-build comparison, behavior fixtures, helper closure, data/vtable closure and full-ELF identity are **not yet implemented/measured**. No normalized comparison or masks are claimed. The reference is not copied.

The inferred `l1/exchange/begin_block.rs` gives a ten-second skew, modulo-20 saturated counter, and `1.0`/`5.0` timing values; those specific constants and the local counter arithmetic agree with the selected code. Its `record_latency_sample` also computes an elapsed-greater-than-threshold result. The selected timing helper and immediate continuations do not contain that comparison. Whether another source-level mapping or an external caller supplies such behavior remains unresolved, so the reference's comparison is not adopted as a binary finding.

## Results and limitations

The selection contains eleven FDE extents, 6,696 bytes, 1,489 admitted instruction rows, 120 direct branches, 120 call/tail-transfer rows, 377 exact byte contracts, 15 selected relocation slots, 13 extracted state properties, 27 bounded CFG propositions, and 44 call-site ranges in seven LSDAs. These are denominators for the chosen ranges only, not component or node coverage. The two independent regenerations match byte for byte under different hash seeds and time zones. The focused suite passes 39 tests with zero skips, including a Python-only PATH run, signed and unsigned record-ordering boundaries, exhaustive 90000-value hour checks, all 256 name-byte controls, signed-zero/NaN controls, counter boundaries, a 10000-value deterministic wide control, and digest, opcode, valid-but-wrong CFG edge, relocation, name, literal, FDE, LSDA, NOBITS and range corruption controls. Artifact/signature verification, catalogue consistency and input reproduction pass.

Runtime initialization, input validity, floating-point exception masks, clock/calendar helpers, record collector and mutation internals, external failures, reconstructed Rust and binary/runtime equivalence remain open. This does not establish the full first-task or RE-015 component acceptance. All four constants gates remain false; no progress gate is requested. Next: identify the external record-collector and mutation contracts without reusing an already owned function, and connect them to independently validated state fixtures.
