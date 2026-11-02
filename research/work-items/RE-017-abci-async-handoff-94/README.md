# RE-017: async handoff around the node 94 state-location loader

Two task-table variants associated with a previously documented state-location caller reuse a slot for an input pointer and a tagged completion, while paired cleanup bodies dispatch on all 256 values of a state byte; a reconstruction can preserve these transitions without inventing an ABCI-state value as the task result.

- Component ID: `abci` / RE-017, bounded to an upper entry and completion handoff.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a lead only, and no reference implementation is copied.
- Claim status: observations below are fixed, digest-bound bytes; names such as future, scheduler, ready and pending are interpretations, not recovered Rust type names. Reachability and the shared helper's internals remain unresolved.
- Scope included and excluded: 25 selected unwind-described ranges, their selected call/branch windows, two table pairs, slot replacement and result reading. The pre-existing RE-017 loader/GOT sites, the body of its outer caller, the shared state-location owner and the previously catalogued await helper are boundaries, not newly owned code. The captured executable is not run; no network, key or chain is accessed.

## Reproduce

Use Python 3.12 or later from the repository root; development used CPython 3.12.3 on Linux x86-64. The extractor and tests use the standard library plus the existing `tools/elf_index.py` and `tools/fde_extents.py`, with no external processes. The target is read-only mapped and authenticated before parsing. No instruction is executed. Tool output contains no timestamps or host-specific paths.

```sh
python3 tools/abci_async_handoff94.py --out research/work-items/RE-017-abci-async-handoff-94
python3 -m unittest tests.test_abci_async_handoff94 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-abci-async-handoff-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_async_handoff94.py --out work/abci-handoff-a
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/abci_async_handoff94.py --out work/abci-handoff-b
diff -r work/abci-handoff-a work/abci-handoff-b
```

The tool creates the fourteen TSV files and `summary.json`; it does not generate this README or the manifest. The manifest covers every file in this directory except itself. The `work` outputs are disposable.

## Evidence

Addresses are link-time ELF virtual addresses; file offsets and raw bytes are in the tables. The parser reconciles each selected `.eh_frame` FDE and CIE with the unwind index, hashes each entire selected extent, and verifies 55 fixed byte windows. An FDE is an unwind-described range, not proof of all function boundaries. Decoded transfers are limited to pinned `e8`/`e9` instructions, fixed conditional branch forms and RIP-relative LEAs. The whole-`.text` `e8`/`e9` pass is a byte-pattern candidate search and may include unaligned data: it is not a complete or instruction-aligned call graph. The 23 candidate hits for its sixteen specified targets are recorded in `scan-candidates.tsv`.

### Entry and two variants

| Stage | Selected node #94 observations |
| --- | --- |
| Upper driver | `0x2893110` contains direct calls to `0x247bbf0`, `0x247c020` and `0x2885a80`; the latter two call `0x2032480` and `0x22b8920`, respectively. Their selected return checks are in `branches.tsv`. The full set of conditions reaching these sites is not reconstructed. |
| Three selected parent ranges | `0x2032480`, `0x22b8920` and `0x247bbf0` initialize a byte at offset `0x216` from the stack object passed to `0x229ec10`. Each has four inspected relative jump-table entries, including initial and later entries. There is no claim that the tables have only four possible input indices. |
| Box and choose | `0x229ec10` copies `0x6368` bytes, requests another `0x6368`-byte object and copies that object again. After TLS and counter checks it selects `0x2888350` when the tested low bit is clear and `0x23c3c70` when it is set. A TLS word equal to two takes the separate drop/error route. |
| Task allocation | `0x2888350` calls `0x2003d20` and `0x23c3c70` calls `0x200b3a0`. Each prepares a `0x80`-byte allocation with a different relocated table pointer. Their input loads use offsets `0x190` and `0x1f0`, respectively. Allocation-null and reference-count guard branches are preserved. |
| Poll selection | The table at `0x5693650` has a type-8, symbol-zero relative relocation to stub `0x22a4460`, which jumps to `0x1d8e930`. The table at `0x56954a0` similarly targets `0x22a3d20`, which jumps to `0x1d7c8f0`. Both selected scheduler bodies call `0x2013c00`. |
| State-location boundary | `0x2013c00` passes its inner pointer to `0x22ae8a0` at `0x2013c94`. Prior [RE-019](../RE-019-rmp-json-loader-94/EVIDENCE.md) establishes that this same owner has a call using a `l1/src/abci/state.rs` Location. The earlier packet's inner loader call, GOT slots and Location record are not regenerated or re-owned here. |

The two relative relocations selecting poll stubs, and the two selecting reader stubs below, are read directly from `.rela.dyn`; `relocations.tsv` includes the zero file bytes, record file offsets, relocation types and addends. These are selected slots, not a claim that the rest of either table has been recovered. Each observed arm and local displacement is recorded in `edges.tsv`, `branches.tsv` and `jump-tables.tsv`.

### Slot transition and returned values

For both variants, the scheduler passes task offset `0x20` to `0x2013c00`. The latter checks the dword at inner offset `0x10`, hence task offset `0x30`, for zero. It passes inner offset `0x18`, hence task offset `0x38`, to the prior state-location owner. If that call returns with `AL` zero, the bridge calls `0x1fa3d10` on the slot, stores dword `2` at the slot and returns zero; if `AL` is nonzero it returns without this normal cleanup. TLS setup and exceptional cleanup paths are visible in the pinned windows. The two `AL` values are consistent with ready/pending, but those Rust labels are inference.

The tag-zero branch of `0x1fa3d10` passes the pointer at slot offset `8` to `0x1fc6250` and then supplies `0x6368` as the free size. The tag-one branch separately checks the next word and pointer before an optional indirect call and possible free; other tags return along the selected no-op branch. It is therefore a tagged ownership transition, rather than evidence that the boxed `0x6368` bytes themselves are returned to the parent.

On the selected zero-return paths, the two scheduler bodies create a tag-one record and pass it to `0x201c250`. The first two payload words are explicitly cleared; the third is whatever `RDX` contains at that point. `0x201c250` drops the old slot and copies two 16-byte chunks into it. Neither the bytes nor this packet constrain the third word to zero.

Each table's selected entry at offset `0x18` points to a distinct jump stub, `0x229f710` or `0x229f990`; both jump to `0x1d589c0`. On the nonzero return from its own guard helper, that reader saves a slot snapshot, changes the task slot tag to `2`, checks that the saved tag is `1`, and transfers three payload words to its output with output word zero. A different saved tag branches to an error call. The guard-zero route returns without a direct output store by this body; effects of the guard itself and arbitrary pointer aliasing are not established. The local parent calls the previously catalogued helper `0x2046b70`, then branches on the returned byte, and on its zero-byte arm tests the next word before the `Result::unwrap` diagnostic. The helper body is outside this packet. Thus the relationship between its indirect dispatch and the selected reader entry remains an explicit boundary, not a claimed fully proved parent-to-reader execution.

### Future cleanup and state byte

If the slot is still tag zero, the zero-poll cleanup reaches `0x1fc6250` through the slot destructor. Two selected spawn TLS/runtime failure routes and a stack-copy unwind continuation directly call the separate `0x22569c0` cleanup body; an allocation-null branch is separate. Each cleanup body reads the byte at object offset `0x216`, subtracts three in 32-bit arithmetic and uses an unsigned guard before an eleven-entry relative table. For values `0..2` or `14..255`, the selected body returns directly. For values `3..13`, the tables choose the following offsets and conditional actions. The two bodies have the same selected field offsets and case offsets, while their called helper addresses differ. The helper bodies are external boundaries and may themselves fail or unwind. Object-offset ranges below are half-open.

| State byte | Selected action, assuming the called helpers return normally |
| --- | --- |
| `3`, `4` | Read byte `+0x236`. Value `3` calls a helper on `+0x248`; value `4` reads `+0x270`. If the latter is `3`, call a helper on `+0x278`; if it is `4`, call a helper on `+0x290` only when bytes `+0x318`, `+0x310` and `+0x308` all equal `3`. Other values join common cleanup. |
| `5` | Call a helper on `+0x2c8`, overwrite `+0x230..+0x250` with the selected reset bytes, then test the word at `+0x218` before the indirect release path. |
| `6`, `7`, `8` | Call a helper on `+0x2b0`, then overwrite `+0x218..+0x238` with the reset bytes. |
| `9` | If bytes `+0x2c8` and `+0x2c0` both equal `3`, call a helper on `+0x248`; then test the word at `+0x218`. |
| `10` | Call helpers on `+0x21f8` and `+0x230`, then test the word at `+0x218`. |
| `11` | Call a helper on `+0x2230`; conditionally release the pointer at `+0x2220` according to the word at `+0x2218`; call a helper on `+0x250`, then reset `+0x150..+0x170`. |
| `12` | Call a helper on `+0x218`, then reset `+0x150..+0x170`. |
| `13` | Call a helper on `+0x360`, then reset `+0x2c8..+0x2e8` and `+0x230..+0x250`. |

The three selected initial parent arms store byte zero at this offset. If that value is retained until either of the selected heap-object cleanup calls at `0x229ed07` and `0x229edef`, the table guard takes the direct-return path before reading the other cleanup fields; the caller then supplies `0x6368` to its indirect release call. The separate stack-copy cleanup call at `0x229ee6e` is followed instead by a call to the unwind-resume boundary at `0x229ee76`. These observations do not make the rest of the freshly copied object initialized or establish the helper's effects.

The reset bytes are 32 bytes with first byte `1` and the remaining 31 bytes zero: each half is loaded from the two recorded constants. On the selected paths, common cleanup zeros the qword at `+0x208`, the dword at `+0x210`, the byte at `+0x205` and the word at `+0x214`. Some arms test guards for optional indirect calls, then clear bytes `+0x206` and `+0x207`. Their guards admit a nonzero word other than `0x8000000000000000` before using the adjacent pointer; this describes the machine comparisons, not an inferred source type or a guarantee about the callee. `cleanup-stages.tsv` enumerates all 256 byte values for each body, `cleanup-guards.tsv` records 28 synthetic flag/word boundary combinations; `cleanup-fields.tsv` and `cleanup-reset-values.tsv` bind the offsets, guards and reset data to bytes. There is no reachability claim for every state byte.

### Scheduler branch table

The following conditional equations summarize the actual pinned tests for **one successful compare-exchange attempt**. Let `W` be the supplied unsigned 64-bit task word and `N` the candidate replacement. The masks, shift and threshold are independently extracted from both scheduler copies and must agree. Retry interleavings and which raw words are reachable are not modeled. The index selects the corresponding variant's four-entry table; `synthetic-cases.tsv` records 262 synthetic raw words, not target executions.

| Point | Condition, in order | Observation |
| --- | --- | --- |
| Before poll | `W & 4 == 0` | Assertion branch. |
| Before poll | `W & 4 != 0` and `W & 3 == 0` | `N = (W & ~7) + 1`; index `(W >> 5) & 1`. |
| Before poll | `W & 3 != 0` and `W <= 63` | Reference-count assertion branch. |
| Before poll | Otherwise | `N = W - 64`; index `2 + (N < 64)`. |
| After nonzero poll | `W & 1 == 0` | Running-bit assertion branch. |
| After nonzero poll | `W & 0x20 != 0` | Index `3`; this arm does not attempt the selected compare-exchange. |
| After nonzero poll | `W & 4 != 0`, sign bit set | Signed-bound assertion branch. |
| After nonzero poll | `W & 4 != 0`, sign bit clear | `N = (W & ~0x21) + 64`; index `1`. |
| After nonzero poll | `W & 4 == 0` and `W <= 63` | Reference-count assertion branch. |
| After nonzero poll | Otherwise | `N = (W & ~0x21) - 64`; index `2` if `N < 64`, otherwise `0`. |

The table applies only after preceding rows have failed. Target addresses for both variants, five assertion literals and the parent's unwrap literal are retained with their bytes. A tag-two path and unwind continuations exist; their source-level names and all helper effects are not established.

### Prior work and boundaries

[RE-017](../RE-017-abci-state-link-94/README.md) owns the original loader/GOT handoff. [RE-019](../RE-019-rmp-json-loader-94/EVIDENCE.md) owns the shared path loader and Location call sites. [The ABCI state inventory](../abci-state-inventory-94/README.md) records the shared `0x22ae8a0` FDE and its first-party Location sets. [The staking round clock](../staking-round-clock-94/README.md) already covers the original reload and its directly identified host. This packet does not repeat those function bodies or their call sites. The new upper path uses the sibling state-location owner; it does not establish that it executes the exact original RE-017 load.

## Implementation and comparison

Not yet implemented. There is no independent Rust component, Cargo build, target execution, fixture comparison or native equivalence claim. Raw and normalized binary comparisons are not yet measured; no normalization masks are used. The static synthetic cases exercise the stated raw-word equations only.

## Results and limitations

The generator records 25 selected FDEs, 55 fixed byte windows, 67 direct transfers, 113 conditional branches, 50 selected jump-table entries, four relative relocations, 122 cleanup field sites and six bounded ASCII literals. These are selected evidence counts, not function coverage. The focused suite passed 21 tests with no skips; it includes wrong digests, real copy-on-write mutations of an instruction, a relocation and an FDE range, duplicate relocations, NOBITS and range controls, displaced branches, altered tables, bounded-result movement and raw-word edge cases. It does not execute target code or prove concurrent behavior.

This packet does not close the executable entrypoint through the shared await helper, all paths within the state-location owner, block application, state-root inputs, or begin/action/end-block ownership. It does not identify the third completion word, prove the tag meanings as Rust types, or claim any #115 or visor behavior. No full-scope progress gate is requested; the ABCI component remains 0/4. Next question: connect the selected reader table slot to the already-catalogued await boundary without re-owning that function, then trace a previously unowned state mutation downstream of the location-bearing future.
