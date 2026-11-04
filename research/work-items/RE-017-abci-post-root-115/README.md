# RE-017: trace the post-block compact result and its restart check

On one selected loader-linked apply path, the post-block gate queues a height and mixed 32-byte value while a separate 40-byte owner record points to an allocation containing the raw 32-byte value, allowing these two representations to be reconstructed separately.

- Component ID: `abci`; RE-017, with state-root and snapshot implications for RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was only a navigation lead and no reference source was copied.
- Claim status: instruction bytes, relocation records, FDEs, LSDA rows and encoded offsets are observations. Function labels, data roles, copy joins and the unsigned arithmetic interpretation are inferences with conditions below. Runtime scheduling, alias stability, external helper effects, persistence and release equivalence are unresolved.
- Scope included and excluded: one post-engine continuation, a root-related auxiliary-object update, serialization boundary, publication gate, matched-result construction, a separate owner update and a selected restart comparison. Existing loader, initial-driver, block engine, result bridge, queue and old-owner functions are context, not newly owned FDEs. This is not the complete process entry, the full action set, complete state-root algorithm or all failure paths.

## Reproduce

From the repository root, using `artifacts/node/115/hl-node` and the shared ELF/FDE parsers:

```sh
python3 tools/abci_post_root115.py --out work/re017-post-first
python3 -m unittest tests.test_abci_post_root115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/re017-python-only
ln -sf "$(command -v python3)" work/re017-python-only/python3
PYTHONHASHSEED=17 TZ=Etc/UTC PATH=work/re017-python-only python3 tools/abci_post_root115.py --out work/re017-post-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu PATH=work/re017-python-only python3 tools/abci_post_root115.py --out work/re017-post-b
diff -r work/re017-post-a work/re017-post-b
diff -r -x README.md -x MANIFEST.sha256 work/re017-post-a research/work-items/RE-017-abci-post-root-115
(cd research/work-items/RE-017-abci-post-root-115 && sha256sum -c MANIFEST.sha256)
```

When the separate historical capture is available, the optional check authenticates it independently and prints only its original coordinates. It does not alter the #115 evidence:

```sh
python3 tools/abci_post_root115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-post-history
diff -r work/re017-post-a work/re017-post-history
```

The extractor checks the complete #115 digest and size before parsing or creating the output directory. It uses Python's standard library and `tools/elf_index.py` and `tools/fde_extents.py`, rejects ambiguous and `SHT_NOBITS` address mappings, and starts no external process. The focused tests use the captured target and contain no skips. The checks here used Python 3.12.3 on Linux x86-64; GNU objdump 2.42 was used for human inspection only and its output is neither parsed nor included in generated files. No captured node was executed and no network, key or chain operation was used.

## Evidence

All addresses below are link-time ELF virtual addresses before rebasing. The generated tables contain corresponding file offsets and original bytes. `functions.tsv` contains 15 selected FDE extents, their entire bytes and hashes; the tool checks each extent against `.eh_frame_hdr` and rejects an overlapping FDE. These ranges are unwind evidence, not proof of original source-function boundaries or a coverage denominator. `context.tsv` contains 22 bounded windows in previously studied bodies; `transfers.tsv` pins complete instruction bytes and decodes 100 direct branch/call or RIP-slot targets; `operands.tsv` decodes 130 fixed-instruction operands. `boundary-relocations.tsv` includes ten relative relocation records, slot bytes and file offsets, and `joins.json` checks the selected copy geometries. `unwind.tsv` contains 150 selected LSDA call-site rows; `unwind-links.tsv` associates 40 selected call instructions with covering rows without interpreting action-table values. `aux-replay.tsv` compares the same 44 instruction bytes in the normal and selected unwind paths. All of these counts are from the extractor, not from binutils text.

### Navigation and prior ownership

The previously proposed loader handoff (PR #2047) follows the upper continuation `0x2cb6500` through selected parent/stage boundaries to `0x3c12800` and the existing adapter `0x3c13520`. The #115 Location record at `0x64767a8`, file offset `0x64747a8`, points to `l1/src/abci/state.rs:123:37`; the existing reference is `0x3c1352f`, and the following comparison at `0x3c1353b` tests 1. This packet independently checks the Location relocation, reference and comparison as context. It does not claim the loader's existing GOT or call sites.

The prior compact-driver packet follows the selected loader-fed owner into constructor `0x5a6cbc0` and callback `0x5a34440`, and from the callback through `0x4e47900`, `0x4f152a0`, and existing owner boundary `0x4fcac10`. The prior preflight-result packet (PR #2195) maps that boundary through bridge `0x59ec200`, adapter `0x56185e0`, block lane `0x5a04e40`, and selected begin/action/end paths. Its selected begin observation is an unsigned saturating increment at state `+0x28`, followed by ordered stores involving state `+0` and `+8`; it also records other item and failure branches. Those earlier function bodies and stores are contextual findings, not new ownership here. Their join assumes the stated normal returns, direct dispatch/TLS conditions, preserved pointers and no interfering alias writes. The present contribution begins at the selected end and result continuations and does not independently prove that a scheduler actually invokes them.

The historical RE-017 clue remains bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its Location VA `0x56dfbf8`, file offset `0x56ddbf8`, names the same suffix at line 107, column 37; `0x3273856` references it, `0x3273871` compares with 2, and old call `0x3272785` uses slot `0x57755a8`, whose relative addend is `0x3273810`. The optional check reads those facts from the separately authenticated old ELF. The #115 coordinates and comparison are independently read from #115; matching path spelling does not establish equivalent code, types or behavior.

### Selected function map

| Stage | New FDE(s) | Selected operation and boundary |
| --- | --- | --- |
| End-root bridge | `0x548dad0` | Existing selector calls it at `0x5a07fce`. It calls previous compact capture `0x4e46090`, then slot `0x64e7820` with relative addend `0x41c5140`; the selected returned buffer is 32 bytes. It passes the selector-context member at `+0x330`, height and that buffer into `0x4e3a7a0`. |
| Root auxiliary update | `0x4e3a7a0` | Calls slots `0x64e0f80` and, on a selected non-sentinel result, `0x64e0020`, then updates a bounded auxiliary object as described below. It calls `0x50e5fc0` on the selected continuation. These helper bodies and their runtime bindings remain boundaries. |
| Compact snapshot branch | `0x5485a60`, `0x4e49960`, `0x4e35e90`, `0x4e4af80` | On the selector's selected snapshot arm, call `0x5a0801e` enters this chain. The capture reads the compact state height `+0x28`, supplies member `+0x1108` and the height to slot `0x64e61d0`, and calls the encoder. The encoder sets configuration bytes `00 04 00 01 00`, calls `0x5480950`, checks head `0x8000000000000004`, and on that arm calls slot `0x64e09e8`. These observations do not prove successful filesystem persistence or complete serialization semantics. |
| Post-block gate | `0x5a6db30` | The existing bridge calls it at `0x59ec817` with the selected 128-byte engine result, a state-pointer slot and the callback task pointer. It either writes a sentinel, copies the result, calls a failure boundary, or conditionally publishes a 40-byte record. |
| Matched-result builder | `0x5a6d390` | When the existing bridge's pending record is non-sentinel and a `0x68`-byte row's key matches pending `+0x38`, the bridge moves the pending data and calls this builder. Its selected successful allocation is `0xb0` bytes and its 40-byte result has a pointer at `+0x20`. |
| Restart/fallback | `0x5a6d760`, `0x5647da0`, `0x4e45700`, `0x4f2a840`, `0x4fc99a0`, `0x59ed8f0` | Existing parent `0x2cb6500` calls the fallback through slot `0x64e7450` when parent `+0xae8` is the sentinel. The selected direct/matching-TLS chain reaches the 32-byte comparison. Alternative TLS and dispatch branches remain unresolved. |
| Restart owner construction | `0x2504590` | The same existing parent calls this builder with either the fallback result or its prior 40-byte value. It places that value in the constructed body at `+0x6b0`; the parent subsequently requests `0x6f0` bytes and stores the resulting owner pointer at parent `+0xae8`. |

### Auxiliary mutation and unwind

The selector passes its context `+0x330` to `0x548dad0`, which saves and reloads that argument before calling `0x4e3a7a0`. The auxiliary object's role is inferred; it is not established to be the compact consensus-state object. The function calls its lookup boundary before inspecting the old word at object `+0x48`. The fixed bytes `31 c0`, `49 3b 46 48`, and branch `71 24` implement zero minus that word followed by `jno`; the intervening load does not alter flags. Signed overflow occurs exactly when that word is `0x8000000000000000`.

| Observation after the lookup returns | Selected continuation |
| --- | --- |
| Old word is the sentinel | The function bypasses its later explicit object stores; a returned nonzero, non-sentinel value goes through a release boundary first. The lookup's own effects remain unknown. |
| Old word is not the sentinel; returned word is the sentinel | It skips the 80-byte replacement, then calls `0x50e5fc0` and, if that returns, stores the input qword at object `+0x9c` and input dword at `+0xa4`. |
| Both words are non-sentinel | It calls the conversion boundary and `0x4e507b0`, then stores 80 bytes at object `+0x48..+0x97`, a dword at `+0x98` and bytes at `+0xa8/+0xa9`. After `0x50e5fc0` returns it stores the same input qword and dword at `+0x9c/+0xa4`. |
| Release call at `0x4e3a86c` unwinds | Its LSDA row names landing `0x4e3a949`. The landing repeats the same 80-byte stores as the normal path, then reaches the unwind-resume call at `0x4e3a978`; the subsequent metadata and input-word stores are not guaranteed. |

The optional downstream calls additionally depend on object byte `+0xaa`, a separate global byte and a non-sentinel current head. No complete effect or rollback guarantee is inferred for those helpers. In particular, an unwind can follow a visible partial replacement.

### Result transport and two different 40-byte layouts

On the selected snapshot arm, the existing selector calls the root bridge and snapshot wrapper, passes their assembled inputs to existing helper `0x452aab0`, and stages a 128-byte record. The output contains the height at `+0x38`, a staged 32-byte value at `+0x40..+0x5f` (called *mixed* here), and another at `+0x60..+0x7f` (called *raw* here). Under the buffer-preservation assumption below, these are the later helper's output and the earlier formatter's output, respectively. The extractor checks both 16-byte lanes of each 32-byte value and the eight-byte height slice through the selector return and the engine copy. The engine copies that record to its own output `+0x78`; the bridge's gate argument is the same offset within its engine-output stack slot. The selector reads its height before the helper calls, whereas the gate rereads state `+0x28` later; equality between those values additionally requires a stable state pointer and no intervening height change. Before staging, existing call `0x5a07fe5` passes the formatter-output buffer at selector stack `+0x130` to `0x5a03fa0`; existing call `0x5a08267` passes the later helper's buffer at stack `+0x180` to `0x5a046f0`. The checked operands prove these are the buffers later read for staging, but those calls can potentially alter them. Identifying the staged values with the original helper outputs therefore assumes those calls and any aliases preserve the buffers. Both calls remain context, and their exact algorithms and full preimages remain boundaries.

The callback saves its task argument at stack `+0x10` at `0x5a34451`, reloads it for the earlier queue at `0x5a3454f` and for apply at `0x5a34e1d`, and places that task pointer at apply input `+0x28` and a pointer to its pending 128-byte storage at `+0x30`. Checked copy-lane operands project both offsets through the existing wrapper and owner bridge. The bridge reloads the task pointer as the gate's fourth argument and saves the pending pointer in its own stack slot. On the selected normal path, with preserved arguments and no intervening writes through aliases, the gate's task `+0x28` is the same queue-object slot used by the callback's earlier publication call at `0x5a3459c`.

The gate builds a 40-byte queue record from input `+0x38` (eight bytes) and `+0x40..+0x5f` (32 bytes), and calls the same existing queue boundary `0x581a4f0` at `0x5a6dc49` after the selected atomic counter acquisition. Separately, the bridge stores a non-sentinel 128-byte gate output to the pending pointer. A later loop advances in `0x68`-byte rows and, on a key equal to pending `+0x38`, moves the pending value and marks its old head sentinel before calling `0x5a6d390`.

The builder's selected normal branch copies pending `+0x60..+0x7f` into a `0xb0`-byte allocation at `+0x88..+0xa7` and pending height into allocation `+0xa8`. Its returned 40 bytes are pending `+0x18..+0x37` followed by the allocation pointer. On the prior callback's non-sentinel direct-write arm, that 40-byte value is stored in a second captured owner's body `+0x6b0`; the queue record instead contains the height and mixed 32 bytes directly. The checked projections and earlier callback/owner windows do not prove the two owner pointers are unequal at runtime, the row match occurs, or either record reaches external storage.

### Gate branch table

Let `n` be the unsigned qword loaded from state `+0x28`, `S = 0x8000000000000000`, and `head` the first qword of the 128-byte input. The instruction bytes compute `ror64((n * 0xd288ce703afb7e91) mod 2^64, 4)` and compare it with unsigned bound `0x68db8bac710cb`. The modular inverse of the multiplier is 625 and the bound is `floor((2^64-1)/10000)`. If the rotated value `k` is at most that bound, `n = 16 * 625 * k` without u64 overflow; conversely every u64 multiple of 10,000 produces such a `k`. Thus the test accepts exactly multiples of 10,000, including zero. `joins.json` derives the inverse, period and bound check from the pinned operands; the test suite uses independent remainder calculations as a control.

| Ordered condition | Selected observation |
| --- | --- |
| `n` is not a multiple of 10,000, or `head == S` | The gate writes only the sentinel output head, with conditional cleanup of input members. No other output bytes are asserted initialized. |
| Otherwise task flag byte equals 1 | The gate copies all 128 input bytes to output without queueing, before the tag/target checks. Other byte values are not treated as 1. |
| Otherwise state dword `+0x10e8` equals 1 and qword `+0x10f0` is less than `n` | The gate calls an assertion boundary and reaches `ud2` if that call returns. |
| Same tag and target equals `n` | The gate copies the input without queueing. A greater target, or a different tag, proceeds to the queue guard. |
| Queue guard qword at queue object `+0x1c0` is odd | It reverses a selected reference increment and copies the input without queueing. |
| Guard equals `0xfffffffffffffffe` | It calls a separate counter-failure boundary; no successful publication is inferred. |
| Other even guard | A compare-and-swap attempts to add 2 and retries on contention. On acquisition the gate calls `0x581a4f0`, then performs its selected notification/wake sequence and copies the input. Actual scheduling and queue consumption are not shown. |

The test model treats the guard word as a synthetic input; real concurrent changes can change later retries. The earlier end selector has additional context-mode, freeze and interval branches, so this gate table is not a statement that every block produces a candidate record.

### Builder, restart and failure boundaries

`0x5a6d390` has two separately selected payload branches; nonempty payloads with null pointers take diagnostic boundaries, and a null `0xb0` allocation takes an allocation-failure boundary. After its callback through slot `0x64e7370`, a returned leading byte other than `0x44` takes a cleanup call before the recorded allocation path. These are local branches, not a complete validity specification.

When parent `+0xae8` is the sentinel, `0x5a6d760` calls the decode boundary `0x50db0f0`. A decoded head of `S+1` takes a diagnostic path ending at `ud2` if the call returns; `S` returns a sentinel head. Other heads can reach the selected wrapper chain. On its matching-TLS arm `0x59ed8f0` calls previous compact producer `0x5484670` and compares both 16-byte halves of its output `+0x40..+0x5f` with saved-input `+0x30..+0x4f`. Only an all-ones 16-bit byte-comparison mask passes. A mismatch reaches a diagnostic and then `ud2` if the diagnostic returns. The equal arm calls two additional boundaries through slots `0x64e0ad0` and `0x64e0af0`; either zero byte takes a separate diagnostic/trap route. Missing and mismatched TLS take other helpers and are not represented as success. This comparison does not establish that the restart input is the particular owner allocation built above, nor that the compared values are a complete or persisted state root.

The encoder's unexpected result head and its write-like boundary's nonzero result have separate diagnostic paths that reach `ud2` if the diagnostics return. The owner builder has distinct invalid-size and allocation-failure branches. Selected unwind call-site records and raw landing coordinates are retained, but helper side effects and all alternate dispatch paths are not closed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler and linker flags, two-build result, target-derived execution fixtures and raw or normalized implementation comparisons: **not yet implemented/measured**. The packet retains whole selected target FDE bytes and bounded context bytes without normalization masks; they are evidence, not transplanted implementation. Helper, runtime relocation binding, vtable/data and whole-ELF closure remain incomplete. The tests exercise the extractor, arithmetic and static projections rather than executing node code.

## Results and limitations

The focused suite passed 28 tests with no skips, including wrong digest before output, changed bytes in every selected FDE and context window, every pinned transfer and operand, inverted conditional branches, NOBITS and ambiguous mappings, altered relocations, malformed LSDA rows, broken projections, 10,000-height and u64 boundaries, all 32 comparison-byte positions, and the auxiliary normal/unwind byte equality. Two regenerations with different hash seeds and time zones matched byte-for-byte with a Python-only PATH. Artifact verification and the catalogue check passed. The optional historical cross-check verified its separate digest. No whole repository test run, container result, hosted CI result or captured-node execution is claimed.

This is one conditional static path. It does not close all begin/action/end variants, prove the exact mixed hash, identify every helper or guarantee runtime pointer identity, scheduling, persistence or restart round-tripping. No component gate is advanced. Next question: establish the helper and alias conditions relating the `0xb0` allocation to the restart input, and independently trace both 32-byte values through any storage or consumer before implementing the corresponding Rust transition.
