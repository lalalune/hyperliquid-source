# RE-017: loader-fed checkpoint result and mismatch snapshots

The selected node #115 loader continuation passes its state into an early checkpoint path whose returned flag is `mode != 2`, even when a configuration sentinel bypasses the checkpoint attempt.

- Component ID: `abci`; RE-017 connects to RE-009 storage and snapshots.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a clue only, with no source copied.
- Claim status: selected instructions, file bytes, FDEs, relative relocations and LSDA call-site rows are observations; pointer continuity, semantic labels and relationships across calls are conditional inferences; runtime execution and complete helper effects are unresolved.
- Scope included and excluded: one loader-parent continuation, checkpoint mode/configuration gates, two state-output variants, selected text and binary routing, returned-record fields, the parent's later copies, and two block-comparison failure continuations. Previously studied loader, parent, block, EVM-checkpoint and binary-encoder functions are contextual boundaries, not newly owned FDEs. This is not all begin/action/end-block behavior, all state-root inputs, actual persistence, or a component gate.

## Reproduce

From the repository root, with the authenticated target artifact and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/abci_loader_checkpoint115.py --out research/work-items/RE-017-loader-checkpoint-result-115
python3 -m unittest tests.test_abci_loader_checkpoint115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_loader_checkpoint115.py --out work/re017-checkpoint-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_loader_checkpoint115.py --out work/re017-checkpoint-b
diff -r work/re017-checkpoint-a work/re017-checkpoint-b
diff -r -x README.md -x MANIFEST.sha256 work/re017-checkpoint-a research/work-items/RE-017-loader-checkpoint-result-115
(cd research/work-items/RE-017-loader-checkpoint-result-115 && sha256sum -c MANIFEST.sha256)
```

Use empty comparison directories. The generator verifies the complete target digest before parsing or creating output, uses Python's standard library and the shared ELF/FDE/ULEB readers, refuses fileless `SHT_NOBITS` and ambiguous mappings, and starts no external program. The selected code-coordinate windows are hash-pinned and transfers are decoded only for the fixed x86 forms listed in the extractor. The evidence was generated with Python 3.12.3 on Linux x86-64; GNU objdump 2.42 was used for human inspection only and its output is not parsed or included in the generated evidence. Tests and both different-seed/time-zone regenerations were also run with Python as the only executable in `PATH`.

When the separate historical input is available, this additional check verifies its full digest, original Location and comparison without changing any generated #115 file:

```sh
python3 tools/abci_loader_checkpoint115.py --historical-node references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-checkpoint-historical
diff -r work/re017-checkpoint-a work/re017-checkpoint-historical
```

No node or visor was executed; no live node, key, chain or dataset was accessed. The recorded destination strings in `literals.tsv` are hex bytes from the ELF; the extractor never opens those destinations.

## Evidence

All code and data addresses are linked ELF virtual addresses before rebasing; tables also give file offsets. The 13 FDEs in `functions.tsv` are checked against the unwind header and for interval overlaps. Their exclusive ends describe unwind ranges, not proven complete source functions or a coverage denominator. `windows.tsv` marks 71 new windows and 26 windows from earlier functions as `context`. `transfers.tsv` decodes 125 selected branches and calls; a RIP-slot target is the slot, not a claim of its runtime binding. Three selected `R_X86_64_RELATIVE` records are recorded separately. The old parent slot is an attribution boundary; neither the original loader's GOT nor its existing call is newly owned.

### Pointer and call map

Earlier RE-017 loader work in PR #2047 maps the Location-linked return. On the selected non-pending parent branch, the result begins at stack `+0x730`; the parent separately loads its pointer word at `+0xab0`, which is result `+0x380`. It stores that word at stack `+0x118`, then passes the address of that cell to the checkpoint entry through a relative slot. `joins.json`, the contextual windows and relocation bytes check the arithmetic and the new destination; the existing parent body and loader are not claimed here.

The parent also loads a byte at object `+0xb20` at `0x2cb758f`, saves it at object `+0x2a19` at `0x2cb75cd`, and later reloads that saved byte as the checkpoint entry's second argument at `0x2cb7959`. Assuming the selected path and no intervening write to the saved byte, the final flag is the predicate that the original byte at object `+0xb20` differed from 2. Its earlier producer and the set of runtime-reachable values are unresolved; synthetic tests of all byte values are not a reachability claim.

| Newly selected FDE | Selected role and continuation |
| --- | --- |
| `0x5a6dd30` | Prepares the checkpoint, distinguishes mode 2, checks the configuration head, calls the compact writer on a selected arm, and passes a later height and flag to the record builder. |
| `0x154abf0` | Reads a global marker, pointer and length at `+0x100`, `+0x108` and `+0x110`; produces a three-word result, with separate empty, copy, sentinel and allocation-failure paths. |
| `0x4e4a740` → `0x4e35990` → `0x4e4a960` | Compact dispatch, capture and Location-linked writer. The capture dereferences the input cell, reads state `+0x28`, and passes state `+0x1108` plus that word to the existing EVM-checkpoint boundary before the selected state-output call. |
| `0x50dd9d0` → `0x5482640` | Compact output router and selected text wrapper; the binary arm calls the already studied encoder at `0x5480950`. |
| `0x595ac30` | The relative result slot resolves here. On the selected return, it stores the supplied height at output `+0x68` and the supplied flag byte at `+0x70`. |
| `0x4e46e40` → `0x4e35c10` → `0x4e4ac70` | Separate expanded-layout dispatch, capture and Location-linked writer. It reads state `+0x28` but supplies state `+0x1c78` to the existing EVM-checkpoint boundary. |
| `0x50deb30` → `0x5481690` | Expanded output router and selected text wrapper; its binary arm calls the already studied encoder at `0x5481900`. |

The input-cell and destination-pair instructions are separately checked from the checkpoint entry through the compact dispatch, capture, writer and binary-encoder argument. On the plain dispatch arm, and assuming normal returns, unchanged dynamic bindings, a stable input cell and no conflicting alias writes, the encoder receives a reference to the loader-forwarded state pointer. The capture uses the prior EVM save boundary from PR #2147; its existing slot and body are not re-owned. The compact and expanded member offsets differ: they are not evidence that the two state pointers, types or member contents are equal.

### Startup decisions and result delivery

Let `S = 0x8000000000000000`. The first configuration comparison is zero minus the marker word; the selected signed-overflow branch is taken exactly when the marker is `S`. A zero length instead returns a head of zero, an intermediate pointer word of one and a final length of zero. For a nonzero length, the routine requests that many bytes and copies from the global pointer on the selected non-null allocation path. The head and last word become the length. If that length itself equals `S`, the sentinel continuation is selected after the allocation/copy; the reachability of such an allocation is not established. The marker-sentinel branch does not establish a meaningful pointer word. Lazy initialization and concurrent mutation of the global are not modeled.

| Ordered condition on the selected startup route | Byte-backed continuation |
| --- | --- |
| Formatting helper's low result byte is nonzero | Enter a diagnostic boundary; the selected path reaches `ud2` if that boundary returns. |
| Mode byte equals 2 | Skip the configuration and checkpoint writer; the result builder receives flag 0. |
| Mode byte differs from 2 and configuration head equals `S` | Skip the checkpoint writer; the result builder still receives flag 1. An empty head of zero is not the sentinel. |
| Mode differs from 2 and the head is non-sentinel | Call the compact output path using the captured state cell and a fixed destination. Its returned temporary is conditionally released. A later helper is invoked on the selected normal continuation. |
| Compact output router returns nonzero | The writer takes the separate `state.rs:151:35` diagnostic and reaches `ud2` if the boundary returns; do not infer successful output. |
| Later helper returns a zero first word | Take a separate diagnostic and `ud2` path. The helper's full semantics are not assigned here. |
| Configuration allocation is null | Reach its allocation-failure boundary; the following byte is an `int3` if the boundary returns. No large allocation or node instruction was executed for this observation. |

The flag is therefore a mode projection: the sentinel branch is a conditional static counterexample to interpreting flag 1 as proof that this invocation wrote a checkpoint. Its actual runtime reachability is not established. On the selected normal builder return, the height is a fresh read of state `+0x28`, not necessarily the value read by the earlier capture. The builder's seventh stack argument is located at its frame offset `+0x140`; its six saved registers, return word and `0x108` local frame account for that offset.

The parent places the builder output at stack `+0x278`. Its 16-byte copy from `+0x2d8` carries record `+0x68` to stack `+0xd18`; a separate eight-byte copy from `+0x2e8` carries the record's byte `+0x70` to `+0xd20`. Four bounded copy projections then place these at parent object `+0x780` and `+0x788`, respectively, on the selected non-suspending continuation. Only the flag byte is identified: the seven neighboring bytes copied with it are not asserted initialized or meaningful. `joins.json` records the source, destination, length and tracked offsets for every stage. The projection assumes normal copy-helper returns, the selected control path and no intervening alias writes.

### Conditional connection to the prior block lane

The following is a dependency map, not a new ownership claim for the earlier functions. It connects the newly examined checkpoint and mismatch paths to the already proposed begin/item/end work on the same digest. Each edge assumes the cited packets' selected branches, normal returns, preserved pointer cells, scheduler invocation where applicable, and no conflicting alias writes.

| Stage | Evidence and boundary |
| --- | --- |
| Loader and checkpoint | PR #2047 traces a Location-linked result word `P` at result `+0x380`. This packet checks that the parent stores `P` in the checkpoint input cell, and separately checks the later `rbp`-to-first-argument move for the existing owner constructor. No existing call site or slot is claimed. |
| Owner and driver | PR #2261 projects that constructor's input `P` into its second returned owner's body `+0xb00`. PR #2297 projects that owner to parent `+0x840`, then through a driver task to its initial result and compact block lane. Its owner-to-context arithmetic is `+0x6b0 + 0x450 = +0xb00`. These are earlier proposed observations, not independent execution evidence. |
| Selected block work | PR #2195 follows the compact block lane into begin, item processing and an end selector. Its begin window increments `P+0x28` with unsigned saturation and makes ordered stores at `P+0` and `P+8`; its separate item and end branches have their own assumptions. Those bodies and state-store claims remain prior work. |
| Mismatch return to this packet | This packet additionally checks the existing block's address calculation at `0x5a04f5f`: context `+0x450` is saved as a cell address at stack `+0xe8`. The selected mismatch continuation reloads that same stack slot at `0x5a0610f`, places the cell address in the compact writer's argument, and calls the new compact dispatch. Thus, if the cell still holds `P`, the mismatch output path receives the same pointer value as the startup checkpoint. |

When the startup path actually selects the compact writer, its selected capture precedes the parent's later driver-construction call in instruction order; the driver is scheduled and can be delayed. Neither the static ordering nor the shared pointer-cell projection proves that a block ran, that the initial captured height equals the later height, that a particular mutation preceded the mismatch, or that either output was persisted. The expanded mismatch arm has not been joined to the compact owner and is retained as a separate route.

### Two mismatch paths and output selection

The prior compact and expanded block FDEs contain separately selected comparisons: `0x5a05d28` and `0x5a07548` combine two 16-byte equality masks and take their diagnostic arms unless all 32 byte comparisons match. On the selected failure continuations, the compact arm calls `0x4e4a740` and the expanded arm calls `0x4e46e40`; both supply third argument 1 and a fixed state-output destination. After the selected writer return, each conditionally releases its returned temporary, calls a diagnostic boundary, and reaches its respective `ud2` if that boundary returns. These are new downstream FDEs attached to previously studied block bodies, not a claim of dynamic execution or proof that both contexts contain the identical state object. The captured comparison bytes do not establish that either compared 32-byte value is a complete state root.

Both new routers first compare a nine-byte input with the exact byte string `2f6465762f6e756c6c`; an exact match returns zero before parsing or serialization. Otherwise they call the existing component-parser boundary. If it returns tag 9 and an eligible component whose final suffix folds to the three bytes `726d70`, the compact and expanded routers use their respective binary encoders. The fixed destination literals have that suffix, but this packet does not prove the component parser's output for every possible input. Other selected parser results go to the text arm. The case-fold helper was already examined in PR #2123 and is a boundary here.

The selected binary serializer configuration bytes are `00 04 00 01 00`; a returned leading word other than `S + 4` enters the binary error wrapper. The text arm requests `0x80` bytes, calls its corresponding new text wrapper, and forwards nonzero results to a separate error wrapper. The text wrappers write an opening brace, send the eight-byte `exchange` key to a helper, write colon-space, call their distinct nested value helpers and, on the selected successful path, write a closing brace. Their depth and growth failures are retained; nested fields and escaping are not recovered. On successful selected serialization the router calls the existing preparation boundary; a nonzero preparation result bypasses the output boundary. A zero result allows the output call and conditional buffer release. Neither a zero shortcut result nor an output call proves file creation, durable persistence or an atomic checkpoint.

### Historical release and uncertainty

The retired RE-017 clue remains tied to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: Location `0x56dfbf8` is `state.rs:107:37`; its reference at `0x3273856` and comparison at `0x3273871` check a value against 2. The optional historical check independently authenticates and reads those bytes. Node #115 has a separate Location at `0x64767a8`, `state.rs:123:37`, reference `0x3c1352f`, and comparison against 1. Matching the path suffix is navigation evidence only; it does not equate releases, types, functions or tags.

The 88 selected LSDA rows and 61 call-to-row links retain raw action values and landing addresses. A missing table or row does not prove unwinding is impossible. Helper mutations, allocation success, filesystem completion, the full component-parser state, and scheduler/alias behavior remain unknown. The pre-existing begin/action/end and state-root studies are context; this packet does not fill their entire acceptance scope.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, dependency closure, compiler/linker flags, two-build comparison, raw and normalized implementation comparisons, masks, vtable/relocation closure and whole-ELF equivalence: **not yet measured**. No target bytes were transplanted into an implementation. The focused tests include synthetic cases for mode and sentinel decisions, suffix case combinations, and individual comparison-byte flips under the stated helper assumptions; they are not target execution.

## Results and limitations

The focused suite passed 39 tests with zero skips, including wrong digest before output, corruption of every selected window, invalid and ambiguous mappings, `SHT_NOBITS` rejection, malformed/duplicate relocations, truncated LSDA and nonadjacent overlapping FDEs, all 256 mode-byte values, broken saved-mode and mismatch-cell joins, sentinel neighbors, copy boundaries and every comparison-byte position. Two regenerations with different hash seeds and time zones were byte-identical with a Python-only `PATH`; the optional separately authenticated historical check produced the same #115 files. Artifact digest/signature verification and the catalogue check passed. No repository-wide unittest run, target execution, container result or hosted CI result is claimed.

No progress gate is requested. Next question: identify the later consumer of the parent record's `+0x780/+0x788` fields and establish whether it treats the flag as a mode indicator or assumes an actual checkpoint was produced, without re-owning the prior loader and block FDEs.
