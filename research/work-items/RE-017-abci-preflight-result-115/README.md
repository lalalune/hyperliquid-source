# RE-017: selected ABCI precheck and result handoff in node 115

This packet makes it possible to reconstruct one selected begin-to-item-to-end handoff with two stages of saturating counter stores, separate lookup-key inputs, and a later wrapping atomic height check, while leaving runtime object identity and state-root inputs unresolved.

- Component ID: `abci`; RE-017 investigation, related to RE-009 state roots.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical #94 evidence is navigation input only. No reference source code was copied.
- Claim status: static observation and conditional inference; implementation and runtime identity unresolved.
- Scope included and excluded: one selected lane from an owner-captured context through the block, begin, precheck, per-item handler and end-call boundary, plus two callers' consumption of its result. Excludes the existing loader's GOT and calls, the bodies of already investigated helpers, complete state-root derivation, other lanes, network and node execution.

## Reproduce

Run from the repository root after adding the new files in this packet. The checked input is `artifacts/node/115/hl-node`. The extractor verifies its full digest and size before creating the output; it never executes the binary or invokes external programs. It uses Python standard-library modules and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The recorded run used Python 3.12.3 on Linux x86-64. Set `TMPDIR` to a writable temporary directory before running:

```sh
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_preflight_result115.py --out "$TMPDIR/re017-first"
PYTHONHASHSEED=271828 TZ=Pacific/Honolulu python3 tools/abci_preflight_result115.py --out "$TMPDIR/re017-second"
diff -r "$TMPDIR/re017-first" "$TMPDIR/re017-second"
for f in "$TMPDIR/re017-first/"*; do cmp "$f" "research/work-items/RE-017-abci-preflight-result-115/${f##*/}"; done
python3 -m unittest tests.test_abci_preflight_result115
(cd research/work-items/RE-017-abci-preflight-result-115 && sha256sum -c MANIFEST.sha256)
```

`MANIFEST.sha256` records the hashes of the README and generated evidence. `windows.tsv` records raw bytes and a SHA-256 for each selected window. `functions.tsv` records the whole file-backed FDE extent's hash and file offset. The generator rejects non-file-backed `SHT_NOBITS` sections, ambiguous address mappings, incorrect instruction patterns, missing FDEs and mismatched cross-stage offsets. Its LSDA reader accepts only the encountered call-site encoding, delegates ULEB decoding to the common library and retains raw action values.

Optional historical cross-check, when an independently supplied #94 ELF is available:

```sh
python3 tools/abci_preflight_result115.py --old-elf <historical-node> --out "$TMPDIR/re017-historical"
```

The command verifies both complete digests before printing the release-specific Location records. Its optional output is not part of the required generated files; #115 generation and all tests require only #115.

## Evidence

All code coordinates below are link-time ELF virtual addresses; corresponding file offsets are in the generated tables. Ends in `functions.tsv` are exclusive FDE extents validated using `.eh_frame` and `.eh_frame_hdr`, not a claim that an FDE establishes every source-level function or full path coverage. Names such as `begin`, `group` and `handler` are analyst labels. The raw byte windows and decoded, byte-pattern-checked relative branches are retained independently of human disassembly text.

### Navigation provenance

The historical #94 ELF has SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its loader Location record is VA `0x56dfbf8`, file offset `0x56ddbf8`, with path length 49 and line 107, column 37. The #115 navigation record is VA `0x64767a8`, file offset `0x64747a8`, with path length 20 and line 123, column 37. The optional `--old-elf` check reads the two records, their relative relocations and path suffixes from the respective authenticated ELFs; matching `l1/src/abci/state.rs` suffixes are navigation evidence, not function, layout or behavior equivalence. It does not re-own the loader's original GOT or call sites.

The selected #115 handler has a separate relocated Location record at VA `0x64aa208`, file offset `0x64a8208`, with `l1/src/abci/state.rs`, line 460, column 78; the reference instruction is at VA `0x5485129`. `location.json` retains the record bytes and relocation file offset. A source Location identifies the diagnostic site, not an entire function's source, and does not establish dynamic reachability from the loader.

### Selected call and data path

| Stage | FDE start VA | Selected static evidence |
| --- | --- | --- |
| Owner entry | `0x4fcac10` | Loads an owner pointer from its input `+0x58`; computes owner `+0x6b0`, places it in the bridge input at `+0x50`, and calls the bridge at `0x4fcae48`. |
| Bridge | `0x59ec200` | On the selected matching-TLS branch, moves the context to adapter input `+0x20` and calls the adapter at `0x59ec2a8`; missing or mismatched TLS takes other fallback calls whose semantics are not resolved here. |
| Alternate upper caller | `0x5443930` | Separately calls the same adapter at `0x54439ad`; this is an alternate static entry, not proof that both callers run in one execution. |
| Adapter | `0x56185e0` | Reads its input `+0x20`, and calls the block lane at `0x5618630`. |
| Block lane | `0x5a04e40` | Reads a state pointer from context `+0x450`, applies guards, calls begin at `0x5a04fe9`, later calls the collector and a previously mapped end-selector boundary, and builds the result. |
| Begin | `0x5483850` | Applies the triplet comparison and state stores described below. |
| Collection | `0x5486610`, `0x5961480` | Builds and iterates grouped work; carries a state-pointer slot into the group. |
| Group and precheck | `0x58679a0`, `0x560dca0` | Evaluates a predicate, conditionally performs the precheck, and passes a flag and state-pointer slot into the batch. |
| Batch and item loop | `0x5b31fc0`, `0x5867480` | Iterates selected `0x90`-byte items and emits `0x48`-byte records; the number of items can be zero or more. |
| Location handler and index | `0x54848e0`, `0x4eff000` | Performs the tag, 20-byte lookup, membership, counter and callback branches below. |

`joins.json` records the byte-derived capture and stack offsets. In particular, `0x6b0 + 0x450 = 0xb00` relative to this entry's owner. Existing loader research separately reports a loader-fed pointer at owner offset `0xb00`; equal offsets alone do not prove that these owners or state objects are the same runtime instance. In addition, the previously mapped expanded-object lane uses different field offsets from this lane. The path projection assumes the selected calls return normally, the actual caller selects these branches, and intervening calls do not overwrite aliases. The static edge from the selected block to the selected handler and the arithmetic join are stronger than a source-location association, but are not dynamic evidence of loader-to-handler execution.

### Guards, begin and failure branches

Here `state` is the pointer read by the block lane. For the nested input pointer, the block loads `round` from `+0x18` and `parent_round` from `+0x20`; names are inferred from the nearby diagnostic. The comparisons and destinations are retained in `transfers.tsv`.

| Condition | Observed branch and local consequence |
| --- | --- |
| `state+0x10e8` qword is 1 and unsigned `state+0x10f0 < state+0x28` | Branches to the `freeze_height >= self.locus.context.height()` diagnostic; if the diagnostic call returns, the selected code reaches `ud2`. |
| Same tag and target equals height | Branches to the `!self.state.is_frozen()` diagnostic and the same terminal pattern. A different qword tag bypasses these two checks. |
| Unsigned nested `round <= parent_round` | Branches to the `round > parent_round` diagnostic. |
| `state+0x30` or the compared words at `state+0x18/+0x20` differ from the nested input, or a further pair of words differs | Branches to distinct diagnostic calls; failure formatting and helper effects are not identified. |
| `state+0xb9a` byte is not 3 | Branches to the `features_ok` diagnostic. |
| Begin has `state+0x39b0` low bit set, its compared height equals `state+0x39a8`, and `state+0xb9a` is not 3 | Branches to an `explicit panic` diagnostic after initial begin stores. This is a syntactic branch inside begin; its reachability from this caller depends on intervening state and aliases. |
| Context mode low 32 bits equal 2, and the post-increment comparison differs | Before the end call, the lane atomically increments the qword at the object addressed by `context+0x458`, offset `+0x10`, then reloads that object pointer and word and compares the reloaded word with `state+0x28`. A mismatch calls a diagnostic and reaches `ud2` if the call returns. |
| Batch allocation returns null | Calls its allocation-failure path; the extracted terminal bytes and unwind links do not establish the allocator's complete behavior. |

Begin compares three incoming 32-bit words with `state+0x60..0x6b` lexicographically: the first comparison is signed and the next two unsigned. If the input is later, it copies the old 12 bytes to `state+0x6c..0x77` before installing the new words. It increments `state+0x28` with unsigned 64-bit saturation, stores zero at `state+0`, and stores the incoming round-like word at `state+0x30`, `+0xe08`, and `+0xf28`. Later selected instructions set `state+0` to 1 and `state+8` to 0 before another helper call. The evidence states store order, not that unknown helpers leave these values unchanged.

For context mode 2, the later atomic qword increment wraps modulo `2^64`; unlike the begin and item counters, there is no saturating conditional move at that instruction. The code loads the pointer at `context+0x458` twice, and concurrent writes may intervene, so the compared reread need not be the increment result. Only under a stable pointer and no concurrent or intervening writes does the local projection equal `(old + 1) mod 2^64`; `synthetic-mode2.tsv` records both match and mismatch cases under that restriction. An equal comparison branches directly to the selected end-selector call; other context modes follow a different, incompletely mapped path.

### Precheck, item branches and state writes

The group obtains a state pointer through the captured slot and calls a predicate with selected fields including `state+0x10`, `+0xd88`, `+0xb9a`, and `+0x3e28`. With predicate byte zero, it skips precheck and passes a zero flag. With a nonzero predicate, it calls `0x560dca0`: this function increments and stores the qword at `state+0xb40`, saturating at `2^64-1`, **before** two indirect helper calls. If their result has low 16-bit tag `0x1a2`, it also saturating-increments `state+0xb48` and returns that tag. Otherwise it copies the returned `0x70`-byte result; the group clears the flag before continuing. The helper effects and exact semantic names are unresolved.

For each item reached after normal intermediate returns, a zero flag constructs a result containing code `0xc6`; a nonzero flag calls `0x54848e0`. Both the zero-flag result path and the returned-handler path join the item state update. At that update, if the low 32 bits of the qword at `state+0` equal 1, the code saturating-increments the qword at `state+8` without rewriting the tag qword. Otherwise it writes qword 1 to `state+0` and qword 1 to `state+8`. This is a local store rule; unknown helper calls or unwinding can prevent the update or change state afterwards.

The handler reads a 16-bit item tag. A tag other than `0x1a2` returns a copied variant under leading byte `0x0f`. For tag `0x1a2`, the handler uses a 20-byte inline value at item `+3` for the singleton or hash-index test. Count `state+0x978` selects empty, singleton, or multi-entry handling; singleton and indexed candidates compare all 20 bytes. If this test does not admit the item, the tree walk compares a **separately passed** 20-byte value: the loop loads an item-descriptor pointer at `+0x28`, adds `0x20`, copies those 20 bytes and passes them in the handler's fifth argument. The available bytes do not establish that this value equals the inline item value. If the tree does not admit it, the membership fallback is called with the inline value and state `+0xd88`; a result byte other than 1 produces leading tag `0x0f` and code `0x36` without the handler's `+0xb40` store.

Once admitted, the handler independently saturating-increments and stores `state+0xb40` before the same two helper slots used by the precheck. If the inner result's low 16-bit tag is `0x1a2`, it independently saturating-increments `state+0xb48`. In a synthetic single-item case where the precheck and item both return that tag, the state pointer is the same and intervening helpers do not alter the counters, each of the two fields can increment twice. If precheck instead returns another tag, the first `+0xb40` store already happened; the synthetic `precheck_rejected` case records that distinction. These are conditional local arithmetic consequences, not node execution results or full transaction semantics.

One later branch checks a mode word equal to 1 and a qword threshold against a nonnegative value computed from `state+0x60..0x68`. On that branch, a helper result is multiplied by 5 with overflow saturated to `2^64-1`; the selected returned record's `+8` is then updated with unsigned saturation, and the handler returns code `0xd0`. Otherwise the selected path calls a previously mapped action helper. When an optional callback pointer is nonzero, a further helper's non-`0x1a2` result takes the Location-linked `Result::unwrap()` diagnostic and reaches `ud2` if that diagnostic returns; the `0x1a2` branch calls the callback through a vtable slot. Unknown helper effects are deliberately not modeled.

### Result handoff and unwind information

After the end-selector boundary returns, the block lane copies its 128-byte returned region to output `+0x78..+0xf7`. It separately writes output byte `+0xf8`. Let `old_tag` and `old_value` be the qwords captured before begin, and `new_tag` and `new_value` be the values read from `state+0x10e8/+0x10f0` after the end call. If the bitwise AND of the low 32-bit tag words is nonzero, the byte is 1 exactly when the two value qwords differ; otherwise it is the low byte of the bitwise OR of the low 32-bit tags. It is therefore unsafe to assume all noncanonical inputs produce only 0 or 1. The bridge and alternate caller each test that byte; on zero the bridge skips its selected nonzero-result construction. The bridge later writes a 40-byte aggregate that the owner copies to its output. The identity and origin of every field of that aggregate remain unresolved.

`lsda.tsv` retains 174 selected call-site rows with bounds, landing VAs and raw action fields; `unwind-links.tsv` associates 60 selected direct or slot calls with the rows when applicable. A `no_lsda` or `not_in_table` entry is not a proof that unwinding is impossible, and no language-level cleanup meaning is assigned to a raw action. The following table joins the selected call-site rows to pinned landing instructions. If the exception machinery chooses each listed landing and the intervening calls return normally, the listed continuations reach the common target; this is not a claim that an actual execution enters every landing.

| Unwinding call | Landing VA | Pinned local continuation |
| --- | --- | --- |
| Handler Location diagnostic `0x548513d` | `0x5485171` | Calls `0x5630000` and `0x5620aa0`, then common target `0x63f0a50`. |
| Item-to-handler call `0x5867742` | `0x586794f` | Conditionally calls `0x5951270`; writes the saved `r12` qword through the pointer obtained from the saved item descriptor, calls `0x59d2e10`, then the common target. |
| Batch-to-item call `0x5b3206c` | `0x5b320b3` | Calls `0x5b0a2d0`, then the common target. |
| Group-to-batch call `0x5867bcf` | `0x5867ce6` | Joins a call to `0x59598a0`, then the common target. |
| Collection-result-to-group call `0x59614c4` | `0x59615a0` | Joins a call to `0x5953400`, then the common target. |
| Collector-to-result call `0x54866be` | `0x54866da` | Calls `0x5247710`, then the common target. |
| Block-to-collector call `0x5a052ed` | `0x5a06413` | Joins the selected cleanup sequence at `0x5a06533` and can reach the common target. |
| Group-to-precheck call `0x5867ade` | `0x5867cce` | Calls `0x594eb80` before the group continuation. The precheck's own FDE has no LSDA pointer. |

At item-loop entry `r12` is initialized from descriptor `+8` and advances when selected records are committed. The landing's descriptor-derived store can therefore preserve a partially advanced result length under the same stable-descriptor and normal-calling assumptions; the pointee is not identified as the state object. No helper's destruction, rollback, or alias effects are inferred from its call target.

### Inferences and unresolved joins

`begin`, `block`, `height`, `round`, `counter`, and `end selector` are descriptive labels inferred from the checked operations and nearby diagnostics; they do not establish Rust names or exact source types. The two `+0xb40/+0xb48` stores and the `+0/+8` item stores are established locally, but their full transaction meaning and helper side effects are not. The two 20-byte lookup inputs are distinct static sources; their equality or inequality in a real item is unknown. The owner-offset correspondence with the loader-fed construction is likewise a conditional join, not an observed runtime identity. The end-call result has not been identified as a complete state root.

### Ownership boundaries

The loader handoff, expanded block/root lane, owner result lane and selected end-call target are already covered by `RE-017-abci-loader-handoff-115`, `RE-017-abci-block-root-115`, `RE-017-abci-context-result-115`, and `RE-015-name-gated-cleanup-115`, respectively. `RE-009-abci-freeze-snapshot-115` independently reports the analogous trailing-byte rule and a compact-state root capture at offset `+0x10e8` for different function addresses. This packet verifies the result rule for this different lane; it does not claim the rule was first discovered here, nor does matching the root-capture offset establish object identity. The selected account and action calls stop at helpers investigated in `RE-010-claim-rewards-path-115` and `RE-010-builder-approval-115`. The two shared indirect slots are included only as observed call destinations for comparing the new call sites; their GOT relocations and bodies are not re-owned here. No byte-window or FDE-body coverage denominator is claimed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, two-build comparison, normalized byte comparison and masks: **not yet measured**. The evidence consists of raw #115 bytes, selected transfer and field decoding, FDE/LSDA metadata, and explicitly synthetic arithmetic controls. `synthetic-counters.tsv` assumes one item, stable pointer identity and no helper writes; `synthetic-item-state.tsv` isolates the local tag/count stores; `synthetic-mode2.tsv` assumes a stable pointer and no concurrent writes. None of these files is target execution or proof of end-to-end equivalence.

## Results and limitations

The deterministic output contains 14 selected FDE extents, 70 raw windows, 135 selected transfers, 91 decoded operands, 7 literal references, 174 LSDA rows, 60 selected call-to-unwind links, 8 synthetic counter cases, 4 synthetic item-state cases and 4 synthetic mode-2 cases. These are selection sizes, not a function-coverage denominator. The targeted suite has 29 tests, including corrupted target digest and byte windows, operand and branch corruption, invalid address ranges, NOBITS exclusion, malformed Location and LSDA records, saturating boundaries, distinct 20-byte values and noncanonical tags. No node or visor execution, live network or chain action was used.

This is a selected static path, not the full begin/action/end-block and state-root-input acceptance gate in the component catalogue. Runtime identity between the loader-fed object and this lane, all helper and callback effects, full item schemas, all error precedence, complete unwind cleanup and the bytes contributing to the final state root remain open. No progress gate is requested or advanced.

Next question: using another unowned #115 caller or independently captured static ownership evidence, can the loader-fed `+0xb00` pointer be proved to be the object passed through this selected adapter, and can the end-selector's actual state-root inputs be tied to it without re-owning existing helper bodies?
