# RE-017: process entry and checkpoint-result handoff

On a conditional static route, a checkpoint mode-derived byte reaches the later result sink and controls a path into two count-dependent row pipelines, allowing a reconstruction to preserve those decisions even when an earlier sentinel bypassed the checkpoint writer.

- Component ID: `abci`; RE-017 is linked to RE-009 storage and state-root investigation, with an entry-path connection to RE-012.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation clue only. No reference source was copied.
- Claim status: ELF records, selected raw instructions, relocation addends, tables, ranges and encoded operands are observations. Cross-call pointer identity and the effects described for a selected route are conditional inferences, not recorded execution.
- Scope included and excluded: five selected FDEs for two descriptor shims, their thunk and two downstream row pipelines; selected entry/runtime, existing loader and block boundaries as context; a seven-stage two-field projection; and the indicated status, dispatch, sentinel, bucket and exception branches. The previously mapped entry bridge, runtime boundary, GOT slots and prior call sites are context only. Complete begin/action/end-block behavior, all root inputs, actual state persistence and all component gates are excluded.

## Reproduce

Run from the repository root with the authenticated artifact and the existing shared ELF/FDE readers. Use new, empty comparison directories; replace the placeholders with directories and a Python-only executable search path appropriate to the environment.

```sh
python3 tools/abci_entry_checkpoint115.py --out research/work-items/RE-017-entry-checkpoint-115
PATH="<python-only-path>" PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_abci_entry_checkpoint115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PATH="<python-only-path>" PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_entry_checkpoint115.py --out "<tmp-dir>/one"
PATH="<python-only-path>" PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_entry_checkpoint115.py --out "<tmp-dir>/two"
diff -r "<tmp-dir>/one" "<tmp-dir>/two"
diff -r -x README.md -x MANIFEST.sha256 "<tmp-dir>/one" research/work-items/RE-017-entry-checkpoint-115
(cd research/work-items/RE-017-entry-checkpoint-115 && sha256sum -c MANIFEST.sha256)
```

An optional cross-release check reads a separately authenticated historical binary and does not change the generated #115 evidence:

```sh
python3 tools/abci_entry_checkpoint115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out "<tmp-dir>/historical-check"
diff -r "<tmp-dir>/one" "<tmp-dir>/historical-check"
```

Generation and tests used CPython 3.12.3 on Linux x86-64. The extractor verifies the whole #115 digest before output, reads section and unwind metadata using `tools/elf_index.py` and `tools/fde_extents.py`, excludes fileless `SHT_NOBITS` mappings, decodes only listed fixed x86 patterns and uses the shared ULEB reader for the selected exception table. Neither tool nor tests invoke another program. GNU objdump 2.42 was used solely for bounded human inspection. The generated TSV/JSON files contain bytes read directly from the authenticated ELF; synthetic models live only in the tests. No captured binary, service, network, key or chain operation was executed.

## Evidence

All addresses below are linked ELF virtual addresses before load bias. Generated tables include file offsets and raw bytes. An FDE is an unwind-described interval, not proof of a complete source-function boundary. `functions.tsv` contains only the five selected new extents: `0x292c5c0`, `0x292e230`, `0x2c7bb70`, `0x15b5b00` and `0x15b59e0`. The entry stub and bridge were separately proposed in RE-001 entry-start work; the bridge and runtime address are not claimed as new bodies here. `windows.tsv`, `transfers.tsv` and `relocations.tsv` explicitly label previously investigated instructions and slots as `context`; those functions, call sites and GOT entries are not newly owned. Selected exception-table action numbers are retained raw and are not interpreted as complete language-level exception semantics.

### Process entry to a selected loader path

| Stage | Byte-backed observation and condition |
| --- | --- |
| ELF entry | The ELF header names `0x1419300`. At `0x1419318` a RIP-relative address calculation supplies `0x2cef8f0`; the call at `0x141931f` uses an ELF dynamic relocation naming `__libc_start_main`. This entry stub is context; the loaded libc implementation and its invocation of the supplied pointer are not observed. |
| Entry bridge | `0x2cef8f0..0x2cef917` places `0x2cd8370` in a stack word, supplies its address and descriptor `0x6440b48`, sign-extends the first incoming 32-bit argument, forwards the second, clears the fifth argument, and calls slot `0x64e6c30`. The slot has an `R_X86_64_RELATIVE` addend of `0x5c99970`. |
| Runtime dispatch | `0x5c99970..0x5c9a045` saves the bridge's data and descriptor pointers and, on the selected path, calls the method at descriptor offset `+0x28`. The descriptor's two scalar words are 8 and 8; its `+0x28` relative relocation names `0x292c5c0`. The separate `+0x18` entry names the similar `0x292e230`, which is recorded as an alternative method, not asserted to execute on this route. |
| Indirect callback | `0x292c5c0` loads the first word of the supplied object and calls `0x2c7bb70`; the latter calls that word. Thus, if the saved stack word, descriptor binding and normal calling convention are preserved, the target is `0x2cd8370`. The shim clears `eax` after a normal return; the runtime's selected return path forwards that value. This is a conditional static route, not proof of a process exit status. |
| Earlier parent | The already studied `0x2cd8370` calls `0x2ae1690`. On its selected path, a word at parent stack `+0xe0` other than 1 selects the route containing the call to poll B `0x2cde430`. This is an input condition, not a claim about values produced by unexamined helpers. |
| Poll B to loader | With the poll gate nonzero and initial state byte zero, a selected command word is reduced by 2 before a relative table lookup. Word 2 selects a constructor storing byte 2; word 3 selects a constructor storing byte 1. Both call the prior parent `0x2cb6500`, which on the prior selected path reaches `0x2cbbbe0`, `0x2b41b70`, `0x3c12800`, and the Location wrapper `0x3c13520`. These prior calls, their relocation slots and Location are included solely as context. |

The state table has selected resume entries 3 and 4 that point back to the respective already-constructed parent call sites. For the selected command-table arithmetic, words 0 and 1 take fallback index 12; word 14 also selects index 12. Values above the recorded table domain are unresolved, not shown to be rejected. The two byte values stored by the poll constructors are distinct observations from the later checkpoint mode byte; equality between those bytes is not assumed.

The `l1/src/abci/state.rs` record at `0x64767a8` names line 123, column 37; its reference and comparison with 1 are independently checked in the #115 bytes. The loader-to-parent continuation and its alternatives were proposed in `RE-017-abci-loader-handoff-115`, and poll B was separately examined in `RE-009-abci-state-export-115`. Those proposals are not assumed merged or treated as proof of runtime reachability here.

### Conditional state and result route

On the previous loader-parent continuation, a checkpoint helper receives a byte saved from parent `+0xb20`, a pointer to the saved state pointer and an output buffer. The helper's normal selected result uses `setne` after comparing that byte with 2. Its record builder stores a fresh read of the supplied state's `+0x28` word at result `+0x68` and the resulting byte at `+0x70`. The builder's seventh stack argument is located at its frame `+0x140`: six saved registers, the return word and the `0x108` local frame account for that displacement.

`projection.json` derives these positions from the separately pinned source/destination operands and copy lengths. The parent record begins at stack `+0x278`; the result fields move through the following offsets:

| Stage | Word from record `+0x68` | Byte from record `+0x70` |
| --- | ---: | ---: |
| After initial lane and word copies, relative to the parent stack | `+0xd18` | `+0xd20` |
| Four checked copy stages, relative to the parent object | `+0x780` | `+0x788` |
| Callback allocation copied from parent `+0x198` | `+0x5e8` | `+0x5f0` |
| Sink argument formed from callback `+0x580` | `+0x68` | `+0x70` |

The final callback object is associated with the existing descriptor entry `0x64471b8` and adapter `0x2a92960`. The adapter passes its incoming pointer through an existing relative slot to worker `0x5a6e1e0`. The worker saves callback `+0x580` and later passes it as the first argument to sink `0x595a6b0` at `0x5a6f991`. The arithmetic establishes a conditional data-flow join, not that a scheduler invokes the callback or that the intervening functions preserve the memory: it assumes the selected non-pending path, ordinary copy behavior, successful allocation, stable slots and no conflicting writes through aliases.

The same worker has a previously proposed selected block route: it passes the callback's owner to the existing block wrapper, and an expanded-state engine calls begin at `0x5a067ad` and its end selector at `0x5a077e1`. The contextual begin window at `0x5483fd3` reads and stores its state `+0x28` word using unsigned saturation; the end selector's recorded inputs include state `+0x28`, `+0x1c58` and `+0x1c60`. This is context from the earlier block-root and expanded-result proposals, not new ownership of those functions. The checkpoint input pointer and the expanded state pointer need not be identical: the clone, subsequent helper effects and aliasing remain open. Equal `+0x28` offsets alone do not establish identity or a state-root value.

### Sink decisions and the new connection

Let `n` be the sink's second argument, `marker` its qword at `+0x68`, and `flag` its byte at `+0x70`. For unsigned 64-bit `n`, the selected multiply-high and shift compute

```text
bucket = floor(max(n - 1, 0) / 10000) * 10000
```

The multiplier is `0x346dc5d63886594b`, the high-half shift is 11 and the final multiplier is 10000. Their exact bytes are in `fields.tsv`. The reciprocal proof is `multiplier * 10000 = 2^75 + 432`; over the u64 domain the extra term is below the smallest nonzero `1/10000` fractional step, so it cannot change the quotient. The focused suite also checks boundaries and 20,000 deterministic u64 inputs against independent integer division; sampling is not the proof.

| Ordered condition | Selected consequence |
| --- | --- |
| Sink word at `+0x18` is the high-bit sentinel | The selected overflow branch returns before bucket comparison and the encoder call. It does not test the later flag. |
| `bucket <= marker` | Branch directly to the record encoder at `0x50e2f80`; neither marker update nor flag test is reached. |
| `bucket > marker` and preceding helpers return normally | Store `bucket` at `+0x68`, then test `flag`. The store occurs before the test. |
| New bucket and `flag != 0` | Branch to `0x595aac0`, bypassing the additional path beginning at `0x595a7b4`; the shared continuation can subsequently reach the encoder. |
| New bucket and `flag == 0` | Enter the additional path. Later helper results can still skip portions of it; its filesystem effects and all failure cases are not closed here. |

For example, a non-2 checkpoint mode with a configuration head equal to the sentinel skips the checkpoint writer but still builds flag 1 on the selected normal continuation. If that same byte survives the stated copies and a later sink invocation has a greater bucket, the sink takes the nonzero-flag bypass. Therefore flag 1 alone is not evidence that the earlier checkpoint writer ran. When the mode equals 2, flag 0 makes the greater-bucket case enter the additional path. The flag is consulted only on that case, not on every result. The selected encoder call does not prove a file was opened, written or persisted.

### Zero-flag continuation into count-dependent pipelines

On the selected greater-bucket, zero-flag route, the existing sink reaches a predicate call at `0x595a844`. A zero low byte rejoins the common continuation at `0x595aac0`; a nonzero low byte calls the existing adapter through the relative relocation at slot `0x64e09d0`, whose addend is `0x15021d0`. The path-building calls before this predicate and the adapter's helper are separate assumptions; the adapter was already referenced as an existing boundary and is context here.

| Adapter outcome or count | Statically selected continuation |
| --- | --- |
| Adapter's first helper returns tag byte 2 | Call conversion helper `0x14cc980`, set the first result word to 1, and return without either row-pipeline call. On sink result tag 1, an indirect function is called and the common continuation is reached. Actual error type and effects are unresolved. |
| Other tag, 32-byte pipeline | Call `0x15b5b00` and then, after the first returns, call the 24-byte pipeline at `0x15b59e0`. The first pipeline calls `0x153f900` to obtain its input buffer and count, and constructs an end address by adding `count << 5` to the base. |
| Other tag, 24-byte pipeline | Call `0x1540a40` for its input buffer and count. The two LEA operations form `base + count * 3 * 8`. These strides are static pointer arithmetic, not a claim about every field or element type. |
| Count 0 | Both pipelines set output words `+0` and `+0x10` to zero, conditionally call the allocation-release slot if a separate word is nonzero, and return. The untouched middle word is not inferred. |
| Count 1 | Bypass both count-dependent helper calls, then pass the constructed range to the respective processor helper. |
| Counts 2 through 20 | Call `0x14c6f20` for the 32-byte pipeline or `0x14c6d40` for the 24-byte pipeline, before constructing the range. |
| Count at least 21 | Use the respective indirect slots `0x64e0e60` and `0x64e0e58`; their relative addends are `0x152d4b0` and `0x152d390`. The comparison and branch are unsigned. |

These helper selections do not alone prove an ordering, contents, filename policy, persistence or successful processing. In each pipeline the recorded alternate cleanup sequence calls its own cleanup helper and then PLT entry `0x63f0a50`, labelled `_Unwind_Resume` in human disassembly; this is a static instruction sequence, not a decoded exception-to-landing mapping. Entry into either cleanup sequence depends on unwind metadata and helper behavior outside the selected path.

### Selected failure and continuation boundaries

- The bridge clears its runtime mode argument. The runtime's separate check for values greater than 3 is an alternate boundary and is not reached from that argument under the normal ABI. A separate exhausted counter check reaches a failure call and `ud2` if the selected helper returns.
- The runtime call at `0x5c99e21` is covered by an LSDA row with landing `0x5c99f54` and raw action 5. The landing has a path that sets the result register to 101 and rejoins runtime cleanup. The action table and actual exception selection are not decoded, so this is not a guarantee that any particular loader error becomes 101.
- Poll B returns early when its first helper's low byte is zero. A nonzero return from the selected parent poll takes its saved/pending path; only the other branch reaches the later parent copy considered here. The worker can likewise bypass the block call if its selected receive result differs from 1.
- The expanded block engine has separate past and equal target exits before its begin call. The root selector has additional mode, target and period branches; zero-divisor behavior and unselected cleanup remain outside this packet.
- A nonzero checkpoint mode flag changes the greater-bucket continuation only after a marker store and earlier helper calls. Nothing here establishes rollback if a later call fails or unwinds.

### Historical release cross-check

The retired #94 evidence remains bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: caller `0x3272785`, relative slot `0x57755a8`, wrapper `0x3273810`, Location `0x56dfbf8` at `state.rs:107:37`, and a comparison with 2. The optional check authenticates that exact historical ELF, reads its relocation records, call bytes, Location reference and comparison, and then leaves #115 outputs unchanged. Independently, #115 has Location `0x64767a8` at `state.rs:123:37` and a comparison with 1. The similar source-path suffix is navigation evidence only; no #94 address, result tag, layout or behavior is assigned to #115.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependencies, compiler/linker flags, two-build result, target execution, raw and normalized implementation comparisons, masks, dynamic binding closure, helper effects, relocation/vtable closure and whole-ELF comparison are **not yet measured**. The original instruction bytes are static evidence and are not transplanted into an implementation.

## Results and limitations

`summary.json` records 5 new FDE extents, 64 selected windows, 66 selected transfers, 45 decoded operand fields, 16 relocation records, 27 selected table entries, 7 projection stages and 8 contextual runtime LSDA rows. Existing functions and sites in those counts are explicitly marked `context`. These counts are selections, not function coverage or component completion. The focused suite passed 23 tests with zero skips, including changed input hash, each selected window and transfer, malformed/duplicate relocations, non-file-backed and ambiguous mappings, mismatched/overlapping FDEs, truncated exception data, damaged table entries, broken copy joins, row counts around 21, element strides and arithmetic boundaries. The tests do not run node instructions. Two regenerations under different hash seeds and time zones matched byte for byte with a Python-only PATH; the separately authenticated historical check produced the same #115 evidence.

No progress gate is requested. Process startup, scheduler behavior, actual reachability, all block variants, helper and alias effects, the complete sink extra path, all root inputs and final digest remain unresolved. Next question: recover the contents and ordering of the two row-pipeline helpers, close the zero-flag sink path after their normal return, and establish whether the initial marker and later expanded-state word belong to the same logical state across the clone and subsequent writes.
