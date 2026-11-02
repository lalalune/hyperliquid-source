# RE-017: conditional snapshot and status handoff after the ABCI loader

The selected post-load branch uses a shared date and requested-word field to pair a periodic state path with a status-marker path, and forwards the marker helper's result through a task completion slot before returning the loaded state.

- Component ID: `abci`, bounded RE-017 loader extension.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; this packet copies no reference code.
- Claim status: static byte observations, conditional dataflow inferences, and unresolved runtime behavior are distinguished below.
- Scope included and excluded: one initial-entry and post-loader branch, its paired path factory, selected task-table functions, the ready-result path, and their local failure branches. Existing loader, host, time, formatter, filesystem, and task-constructor functions are boundary context, not newly owned extents. This does not cover begin-block, action dispatch, end-block, state-root calculation, the entire loader, node #115, or visor.

## Reproduce

Run from the repository root with node #94 at the path above and the existing shared `tools/elf_index.py` and `tools/fde_extents.py` present:

```sh
python3 tools/abci_loader_snapshot94.py --out research/work-items/RE-017-loader-snapshot-handoff-94
python3 -m unittest tests.test_abci_loader_snapshot94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-017-loader-snapshot-handoff-94 && sha256sum -c MANIFEST.sha256)
```

For independent regeneration, replace each angle-bracketed placeholder with a different writable directory under a temporary directory before running:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_loader_snapshot94.py --out <first-output>
PYTHONHASHSEED=119 TZ=Pacific/Honolulu python3 tools/abci_loader_snapshot94.py --out <second-output>
diff -r <first-output> <second-output>
```

Observed environment was Linux x86-64 and Python 3.12.3. GNU objdump 2.42 was used only for human inspection during analysis; neither the generator nor the tests call it, or any other external program. The generator first checks the full input SHA-256, uses the repository ELF and FDE readers, checks its fixed byte patterns, and writes no timestamps, machine paths, or environment-dependent content. It statically reads the binary and writes only the requested generated evidence; it never executes the target. File and output hashes are in `MANIFEST.sha256`.

## Evidence

All addresses below are linked virtual addresses (VA); the machine-readable files also record file offsets where applicable. End addresses in `functions.json` and `windows.tsv` are exclusive. The twelve selected ranges in `functions.json` have matching `.eh_frame_hdr` and `.eh_frame` entries and hashes of their entire file-backed ranges. An FDE is an unwind range, not a proof of a complete function inventory or of every control-flow boundary. Selected prior-function windows are explicitly marked `prior-boundary`; they connect the new work to earlier results without claiming those functions. `branches.tsv` decodes only the selected fixed short and near conditional-branch encodings, including their condition, displacement, fallthrough, and target; it is not a whole-function instruction census.

### Entry, paired paths, and prior boundaries

On initial dispatch entry 0, the existing host at `0x22b47c0` reaches `0x22b480f`. When bit 0 of the first input byte is clear, the input word at offset `0x8` is stored at host offset `0x3b10`; bit 0 of the next byte selects the direct route to the existing loader setup. Immediately before the loader, `0x22b4bb4` reads that field and `0x22b4bc5` places the word in the loader input. After the existing loader returns, `0x22b4c32` tests the saved mode bit. Zero branches directly to `0x22b4f5b`; nonzero builds paths and enters the route below. At `0x22b4cd2` the host re-reads the same field for the new path factory. The established loader entry and its original call and GOT slot are outside this packet.

| Step | Bound observation | Boundary or new extent |
| --- | --- | --- |
| Source path | Host references the `abci_state` descriptor and `rmp` extension, with a template containing `hyperliquid_data`; it passes the source pointer and length onward. | Host is prior context. |
| Paired path factory | The indirect transfer at `0x22b4cde` uses relocation slot `0x57739e8` to `0x37ead90`. It obtains a date word, calls prior path builder `0x37eac50` with that word and the selected input, and forms another path with the same formatting arguments. | `0x37ead90` is selected; `0x37eac50` is prior context. |
| Path components | The two directory descriptors spell `periodic_abci_states` and `periodic_abci_state_statuses`. The factory and prior builder both use the same configuration slot, the same date-formatter slot, and the same word-formatter slot. The date formatter references the six bytes `%Y%m%d`. | Descriptor, relocations, instructions and templates are reproduced directly from ELF bytes. |
| Paired output | On normal return, the factory places the prior builder's three words at output offsets `0x0..0x17` and the status path's three words at `0x18..0x2f`. | `path_return` window. |
| Replacement handoff | Host passes source pointer/length and first returned path pointer/length to existing helper `0x37eaa70`, through slot `0x57739f0`. Its nonzero result takes an unwrap-diagnostic branch. | Prior filesystem boundary; no operating-system outcome assumed. |
| Task construction | Host copies the second returned path into an owned three-word value, pairs it with literal `async_touch`, and calls prior constructor `0x2021d10`. That constructor copies an object initially containing word `0xcc`, tag 0, the owned path, and table pointer `0x56967b0`. | Prior constructor, selected table relocations. |

In component notation, the bytes and argument setup support `configured root → data → periodic_abci_states → formatted date → formatted word + .rmp` and `configured root → data → periodic_abci_state_statuses → formatted date → formatted word`. This notation does not assert directory existence or successful file operations. The date and word formatters are boundaries; the stored word has previously been investigated as a requested height, but its semantic type is not independently proved here. Because the host re-reads its field after an intervening call, equality with the pre-call value is conditional on the field not changing.

### Task result flow

The constructed table has RELATIVE entries `0x56967b0 → 0x22a4270 → 0x1d964d0` and `0x56967c8 → 0x229f8f0 → 0x1d579c0`. The former thunk reaches the selected scheduler; the prior await helper loads the table from the task object and calls its `+0x18` entry, the latter thunk. The relationship is conditional on that same constructed object reaching the scheduler and await helper; no schedule is observed.

At `0x1d9657c`, the scheduler invokes bridge `0x2016670` with the object at offset `0x20`. The bridge requires its tag at `+0x18` to be zero, takes the owned path triple at `+0x20`, `+0x28`, `+0x30`, and passes pointer and length to relocated boundary `0x144fd70`, together with the `base/src/fu.rs:250:32` Location. On normal return it drops the taken input, changes the bridge tag to 2, returns `AL=0`, and places the helper's return word in `RDX`.

For that `AL=0` branch, the scheduler prepares a four-word record: tag 1, zero, the helper word, and the helper word again. `0x201ea60` first calls selected cleanup `0x1faf4f0` and then writes that record at object offset `0x38`. The selected finish function `0x1dabb20` uses a compare-exchange with XOR mask 3. After successful exchange it requires old bit 0 set and old bit 1 clear; when old bit 3 is clear, it replaces the completion slot with tag 2. Reader `0x1d579c0` calls the selected readiness guard `0x4f5a350`, checks for tag 1, replaces it with tag 2, and copies the three payload words to the await output behind an output tag 0. The prior await helper copies the 32-byte output to the host.

One conditional arithmetic example, checked by the focused tests, starts with the constructor's `0xcc` word and assumes the scheduler sees it unchanged, successful compare-exchanges, and no intervening state changes or callbacks: the pre-poll transition selects table entry 0 and produces `0xc9`; finish produces `0xca` and preserves the slot; the later subtraction of `0x40` produces `0x8a`, whose bit 1 satisfies the guard's fast readiness test. This is a static model under those assumptions, not evidence that the target actually takes that schedule.

The scheduler's selected release arm and the finish function's last-reference arm both call `0x1d3bdd0`. On its normal path, that function passes object offset `0x38` to `0x1d38d70`, then reaches the existing allocation-release slot with size `0x100`. The slot dropper treats tag 0 as an unpolled owned input: a zero capacity or the sentinel avoids its release call, and other capacities pass the saved pointer and capacity to the release boundary. For tag 1 it branches on the first payload word; in the zero case, a nonzero second payload word is passed to an indirect cleanup call. A tag other than 0 or 1 returns without these payload operations. This bounds the local cleanup behavior, but does not prove external callback or allocator outcomes.

| Condition at selected site | Bound branch or consequence |
| --- | --- |
| Host mode bit clear at `0x22b4c36` | Bypass path and task work; continue at `0x22b4f5b`. |
| Date word zero at `0x37eadd0` | Reach the `Local time out of range for NaiveDateTime` diagnostic at `0x37eaede`. |
| Configuration state nonzero at `0x37eadf5` | Enter the initialization/callback path at `0x37eaef7`; normal return rejoins path construction. |
| Replacement result nonzero at `0x22b4d4f` | Reach the `Result::unwrap` diagnostic path at `0x22b5bc9`. |
| Status length signed-negative at `0x22b4d89`, or allocation returns zero at `0x22b4da2` | Route to the host's existing error paths rather than construct the owned status path. |
| Bridge tag nonzero at `0x2016682` | Enter a diagnostic path whose literal begins `internal error: entered unreachable code: unexpected stage`, rather than take the input. |
| Taken capacity is the sentinel at `0x201670b` | Overflow branch to `blocking task ran twice`, rather than pass the path to the touch boundary. |
| Scheduler bridge `AL & 1` clear at `0x1d96583` | Build the tag-1 completion record at `0x1d96695`. |
| Finish old word lacks bit 0 or has bit 1 at `0x1dabb40` and `0x1dabb48` | Reach the respective `prev.is_running()` and `!prev.is_complete()` assertions; successful exchange alone is not sufficient. |
| Finish old word lacks bit 3 at `0x1dabb50` | Replace the stored slot with tag 2 before returning. |
| Last task reference is released at `0x1dabc23` | Enter the selected task deallocator and its tag-dependent output drop. |
| Output tag is neither 0 nor 1 at `0x1d38d7e` | Return from the output drop without treating its payload as either variant. |
| Reader guard returns zero at `0x1d579dd` | Return without consuming the slot. |
| Reader sees a slot tag other than 1 at `0x1d57a00` | Reach a diagnostic beginning `JoinHandle polled after completion`. |
| Await output byte is nonzero at `0x22b4e87` | Host saves its suspended state and returns pending. |
| Ready first payload word is nonzero at `0x22b4ee8` | Host takes the first error-formatting route. |
| Ready first payload is zero but second is nonzero at `0x22b4f01` | Host takes the unwrap-diagnostic route. |

When both checked ready payload words are zero, the host cleans up the owned path buffers and reaches `0x22b4f5b`. It copies `0x3ae8` bytes from the loader output at host offset `0x3b18`, then copies the same number of bytes to its result at `0x22b5ae8`. The mode-clear bypass also reaches that copy. The labels “snapshot”, “status marker”, “ready”, and “pending” are interpretations of the observed path names, touch boundary, tags, and prior work, not recovered source names.

Prior `RE-009-checkpoint-bundle-markers-94` identified the touch boundary's conditional file check and empty-write path. Prior `RE-009-storage-state-roots` identified the state-directory descriptor; the factory-to-status-path pairing and this task's result handoff are the bounded questions here. Generic formatting adapters and prior filesystem helpers are referenced as boundaries only.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No binary comparison, normalized-byte mask, two-build comparison, runtime fixture, helper closure, or whole-ELF equivalence has been measured. The raw selected bytes, exact ranges, file offsets, relocation records, and derived operands are retained without normalization. The target was not executed. Corruption controls cover a wrong digest, real FDE range byte and index mismatches, duplicate selected FDE/index entries, altered bytes, each selected branch and transfer displacement, relocation type/symbol/addend and duplicates, changed descriptors, templates and Location, and invalid or NOBITS mappings.

## Results and limitations

`summary.json` reports 12 selected FDE ranges, 41 selected byte windows, 71 selected conditional branches, 24 selected transfers, 9 selected table entries, 32 selected RIP references, 42 selected operands, and 16 selected relocations. These are deliberately selected-site counts, not a denominator for the node or for the ABCI component. The focused suite passed 29 tests with zero skips; the two independent generations matched byte for byte. Artifact verification and catalogue checking passed. The repository-wide unittest suite was not run under the stated memory constraint.

No ABCI progress gate is requested. The full component task for begin, action, end, and root remains open, as do the replacement helper's complete contract, potential field mutation across the prior loader, actual runtime reachability, scheduling/interleavings, file-system effects, unwinding and every unselected error path. Next question: which ownership and scheduling invariants bind the constructed task object to the ready reader in all reachable cases, and can the loader-to-snapshot field equality be established without assuming it?
