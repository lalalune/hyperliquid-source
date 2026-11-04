# RE-017: join the slow ABCI driver to compact state and the block lane

A captured owner connects the loader handoff to both the driver's initial compact-state root and its later block-entry boundary, while the apply result is copied into a second captured owner's slot.

- Component ID: `abci`; RE-017, with state-root and snapshot implications for RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation clue only, with no reference source copied.
- Claim status: fixed instruction bytes, ELF relocations, selected unwind extents and encoded operands are observations; task roles and cross-call value flow are conditional inferences; runtime scheduling, alias stability, helper effects and complete block semantics remain unresolved.
- Scope included and excluded: one existing loader-parent continuation, the new slow-driver constructor and callback, initial result generation and publication, work receive, selected apply dispatch, 40-byte result update, and failure/unwind arms. Prior loader, owner-construction and block-lane results are contextual boundaries and are not re-owned. This is not an exhaustive begin/action/end-block implementation or a component gate.

## Reproduce

Run from the repository root with the authenticated #115 artifact and the repository's `tools/elf_index.py` and `tools/fde_extents.py` available:

```sh
python3 tools/abci_compact_root115.py --out work/re017-compact-first
python3 -m unittest tests.test_abci_compact_root115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=17 TZ=Etc/UTC python3 tools/abci_compact_root115.py --out work/re017-compact-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_compact_root115.py --out work/re017-compact-b
diff -r work/re017-compact-a work/re017-compact-b
diff -r -x README.md -x MANIFEST.sha256 work/re017-compact-a research/work-items/RE-017-abci-compact-root-115
(cd research/work-items/RE-017-abci-compact-root-115 && sha256sum -c MANIFEST.sha256)
```

If the separately captured #94 artifact is available, its optional check verifies the complete historical hash and prints its original coordinates; it does not change the #115 output files:

```sh
python3 tools/abci_compact_root115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-compact-history
diff -r work/re017-compact-a work/re017-compact-history
```

The tool checks the complete node #115 digest before parsing or creating output. It uses Python's standard library and the shared ELF/FDE parsers, rejects fileless `SHT_NOBITS` mappings and ambiguous ranges, and invokes no external programs. The optional comparison checks the historical digest independently. The focused suite and two-output comparison were run with Python 3.12.3 on Linux x86-64, including a PATH with Python but no binutils. GNU objdump 2.42 was used only for human inspection: its output is neither parsed nor included in generated evidence. Neither node capture was executed; no network, chain or key access was used.

## Evidence

Addresses are linked ELF virtual addresses before rebasing; generated tables also include file offsets. `functions.tsv` reconciles selected `.eh_frame` ranges with `.eh_frame_hdr`, rejects other FDEs overlapping the selections, and hashes each whole range. An FDE is an unwind-described range, not proof of an original source-function boundary, complete control flow or component coverage. `windows.tsv` retains raw selected instruction bytes; `transfers.tsv`, `rip_refs.tsv`, `relocations.tsv`, `literals.tsv`, `immediates.tsv`, and `patterns.tsv` retain the encoded operands and their coordinates. `captures.tsv`, `descriptor_stores.tsv`, `copies.tsv`, `projection.tsv`, `write_projection.tsv`, `parent_projection.tsv`, `context_operands.tsv`, and `flow.tsv` record the bounded joins. `unwind.tsv` keeps the selected LSDAs' raw call-site rows, and `unwind_links.tsv` associates selected direct calls with those rows without interpreting action-table values. Analysis is complete only for the selected windows and their explicitly stated branches.

### Navigation and ownership boundaries

The existing #115 Location record is VA `0x64767a8`, file offset `0x64747a8`, for `l1/src/abci/state.rs:123:37`; the existing reference is at `0x3c1352f` and the following comparison at `0x3c1353b` tests 1. The existing loader-handoff and greeting packets trace a selected Location-linked pointer through an owner builder into the body slot `+0xb00` of a second allocation returned in `rdx`. Those earlier constructor, loader, GOT and call sites are contextual input here, not newly claimed bodies. The present tool rechecks selected parent copies and three operand anchors from the previously mapped block lane, but it does not independently close every prior helper or pointer-preservation assumption.

The historical RE-017 clue remains bound to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its Location VA `0x56dfbf8`, file offset `0x56ddbf8`, names the same path suffix at line 107, column 37; `0x3273856` references it, `0x3273871` compares a result with 2, and the historical indirect call at `0x3272785` uses slot `0x57755a8` with relative addend `0x3273810`. The optional historical check reads these facts from the separately authenticated #94 ELF. The #115 reference and comparison are independently checked from #115 bytes; shared path spelling establishes navigation, not layout or behavioral equivalence.

### Upper entry, captured owner, and two uses

The first four rows of `parent_projection.tsv` recheck the earlier parent's returned `rdx` copy through bounded stack copies to parent object `+0x840`. The parent reloads that word at `0x2cb8863`, increments its reference word, and calls through a relative slot at `0x2cb8915`; the authenticated slot's addend is the new constructor at `0x5a6cbc0`. The selected path assumes the previous `rdx` return is the already documented loader-fed second owner, normal copy-helper returns and no conflicting alias writes. A separate first owner return in the old constructor is not equated with this one.

| Stage | Selected #115 observation |
| --- | --- |
| Task creation | `0x5a6cbc0` saves the owner argument at stack `+0xf8`; the selected `0xb8`-byte copy starts at stack `+0x80`, placing that pointer at task `+0x78`. The descriptor at `0x64b8a00` has size `0xb8`, alignment 8, and a relative callback entry naming `0x5a34440`. The constructor supplies the literal `node slow abci_state driver` to the scheduling boundary. |
| Initial result | The callback loads task `+0x78`, adds `0x10`, and calls `0x5647720` at `0x5a34472`. The literal passed alongside this call is `hardfork_hashes`. On the selected normal branch, wrappers `0x4e46b50` and `0x4f21a90` forward the same owner body to `0x4fc3490`. The simple instrumentation path needs a zero helper return and zero flag; its direct dispatch tests owner byte `+0x150` for zero. |
| Height gate | The gate reads the pointer `P` from owner body `+0xb00`. On each of the two recorded selector arms, it compares qwords `P+0x28` and `P+0x10`. Equal values allow a call to `0x5484670`; unequal values set the result head to `0x8000000000000000`. The selected context/TLS checks and other branches are not treated as unconditional success. |
| Initial output | `0x5484670` reads `P+0x28`, calls the pre-existing snapshot boundary, then the new compact capture path and the pre-existing 32-byte formatter. It calls the pre-existing `0x452aab0` boundary with references to that 32-byte value and the height, plus snapshot-derived inputs. Its output contains the height at `+0x38`, the second helper's 32-byte result at `+0x40..+0x5f`, and the formatter's 32 bytes at `+0x60..+0x7f`. |
| Record publication | On non-sentinel output and a zero callback mode byte, `copies.tsv` and `projection.tsv` trace the height and the second helper's 32 bytes through the gate, wrapper and callback into a 40-byte record. `0x581a4f0` conditionally publishes that record. The formatter's raw 32 bytes at result `+0x60` are not the bytes copied into this record. |
| Work and apply | Later in the same callback, a selected received work item is processed under the literal `spawn_slow_abci_driver_apply_block`. The callback reloads the same task `+0x78` pointer, adds `0x10`, and saves the body as apply input `+0x58`; `0x4e47900` forwards that slot and `0x4f152a0` calls existing owner boundary `0x4fcac10` on its direct arm. Its simple instrumentation and direct-dispatch arms also require a zero helper return, zero flag, and zero owner byte `+0x150`. |
| Apply result update | If that apply result's head is not the sentinel, the callback prepares a 40-byte value and a second captured owner. On the selected direct arm, `0x4f18bd0` tail-calls `0x4fcbe60`, which stores the 40 bytes at the second owner's body `+0x6b0` after its old-value handling. The captured slot differs from the root/apply owner slot; their runtime pointers may still alias. |

This is an ordering claim about selected instructions: the initial root-like result is computed before the later receive/apply loop. It does **not** prove that the initial result is the root after the later block mutation, that the loop recomputes it, or that any particular task ran. “Root”, “height”, “owner”, “apply” and “digest” are descriptive inferences from the prior Location, labels, dataflow and existing analysis; `0x452aab0` and the formatter remain boundaries here.

### The compact pointer passed to the existing block lane

The block call is not joined merely by matching an offset. In the callback the captured allocation pointer is loaded twice from task `+0x78`; both selected uses add `+0x10`. The initial gate reads body `+0xb00`. At `0x5a34e8f`, the apply use writes the same body pointer to stack `+0x98`; the apply input starts at stack `+0x40`, giving input `+0x58`. The apply wrapper loads that word at `0x4e47a39`, stores it at its stack `+0x78`, and passes an input starting at stack `+0x20`, again giving `+0x58`. The direct adapter passes this input to the existing boundary `0x4fcac10`.

The prior `RE-017-abci-preflight-result-115` packet maps that existing boundary's owner `+0x6b0` context through its bridge and adapter to a block-lane context dereference at `+0x450`. The three contextual operand checks here independently give `0x6b0 + 0x450 = 0xb00`, the same body slot observed in the new initial-result gate. The earlier preflight packet then follows a selected begin, collection, item and end-selector continuation. On its recorded normal begin path it reports a saturating increment at state `+0x28`, ordered state `+0` and `+8` writes, and other round/time stores; its item path has separate precheck and handler counters. These state-store observations belong to that prior packet, not to newly owned functions here.

This strengthens the prior open instance-identity question to a concrete **conditional static pointer projection** from the selected driver capture to that block boundary. The join still depends on the prior owner-construction evidence, scheduler invocation, the stated direct/TLS branches, normal helper returns, and no conflicting intervening writes or alias effects. The context anchors alone do not prove those assumptions. In particular, the parent root result and a later block handler are not shown to have executed on any actual instance.

Both direct dispatches test the same owner-relative byte `+0x150`, calculated independently from each wrapper's `+0x130` base and dispatcher's `+0x20` operand. The tests occur at different times, so their values need not match in a runtime invocation.

### Compact root inputs and result transport

`0x4e34ce0` forms 74 pointers relative to `P` and places them in contiguous stack slots from `+0x128` through `+0x370`. For example, capture 28 is `P+0x10e8` and capture 41 is `P+0x10f8`. It requests `0x588` bytes and initializes 59 tag words at a 24-byte stride, then calls the already studied job boundary `0x54423c0`. If the returned byte is 4 it calls the recorded reducer boundary; otherwise it writes zero to the first 32 output bytes and byte 32. Bytes 33 through 39 on that other branch are not asserted to be zero. Prior expanded-layout evidence also calls this job boundary, but equal capture indices do not prove equal field types or layout identity.

The result producer saves its height and two 32-byte outputs separately. Fifteen checked load/store pairs project three slices across the selected first gate arm, the owner wrapper, and the callback: result `+0x38` becomes record `+0`, result `+0x40..+0x4f` becomes record `+8`, and result `+0x50..+0x5f` becomes record `+24`. These equations use actual operand bytes and check copy bounds; their semantic join still assumes intervening calls do not mutate the tracked storage. No digest test vector, complete hash algorithm or independent Rust implementation is claimed.

The output queue masks a ticket to 32 slots, uses a 40-byte stride, and stores the record before atomically setting its selected bitmap bit at block `+0x510`. Its group metadata is at `+0x500` and a new block request is `0x520` bytes. The later work receiver is a different queue operation: it uses 32 slots of 88 bytes, group metadata `+0xb00`, and bitmap `+0xb10`. The binary evidence does not establish that these two queue objects alias or that a peer, file or database consumed either record.

### Apply result into a second captured owner

The existing parent loads a second argument from parent `+0xae8`. The new constructor saves that argument and includes it in its `0xb8`-byte task copy at task `+0xa8`; the initial root/apply owner is instead in task `+0x78`. The callback reloads task `+0xa8`, adds `0x10`, and places that body pointer at the selected write input `+0x28`. No inequality between the two runtime pointer values is established.

On a non-sentinel apply result, the callback copies all 40 result bytes to the write input and calls `0x4f18bd0`. If the direct-dispatch mode byte is zero, that FDE passes the input to `0x4fcbe60`. The latter loads the body pointer from input `+0x28`, acquires the selected guard, and writes the input's first 40 bytes to that body's `+0x6b0..+0x6d7`. `write_projection.tsv` follows the two 16-byte pieces and final eight-byte piece through the callback and update routine; this is a memory update, not proof of disk persistence or the identity of the value as a post-block root. Intervening calls and concurrent aliases can affect the conditional projection.

Before the write, an old head equal to `0x8000000000000000` takes the selected skip-release arm. A non-sentinel old head instead decrements a reference word and, when the old length is nonzero, calls the recorded release boundary. Guard contention follows separate helper paths. The observed write precedes the selected unlock; none of these observations proves rollback or complete concurrency semantics.

### Selected branches and failures

| Condition | Statically observed consequence |
| --- | --- |
| One of the constructor's selected allocation checks fails | It calls the corresponding failure boundary; the selected paths end at `ud2` if those calls return. A nonpositive selected reference increment also reaches that terminal instruction. |
| The initial gate sees unequal `P+0x28` and `P+0x10` | It writes the sentinel head. The callback's subtraction overflow test recognizes that head, skips the initial record construction, and continues to the later driver logic; it does not establish that the driver terminates. |
| A non-sentinel initial result has a nonzero callback mode, or the publication guard is already odd | The selected enqueue is skipped. The separate counter-limit branch goes to a failure boundary. |
| A root-capture allocation fails, or instrumentation chooses another arm | The allocation failure reaches a separate boundary; alternate TLS, logging and helper behavior is not closed. A reducer result other than byte 4 selects the limited zero writes described above. |
| Output queue group advance would exceed its checked bound, or its allocation returns null | Separate failure boundaries are called. Concurrent ordering, progress and allocator effects are not modeled. |
| A work slot is not ready | If the current block has no ready slot, the receiver returns `0x8000000000000001` or `0x8000000000000000` according to a separate bitmap bit; an unavailable next block also returns the former. The callback tests the latter, retries the former after registration, and processes other selected heads; these roles do not establish all valid work variants. |
| The selected work-view TLS pointer is null or mismatched | Distinct fallback calls are taken; their behavior is outside this packet. For matching TLS, the view builder calls its recorded boundary before the apply dispatch. |
| Apply returns sentinel head | The callback bypasses the selected `write_greeting` update. A different head reaches it; a zero dispatch-mode byte selects the in-memory 40-byte update above. Other dispatch arms and external delivery remain unresolved. |
| The old update slot has a sentinel or a non-sentinel head | The sentinel takes the skip-release arm; the non-sentinel arm decrements a reference word and conditionally calls the old-buffer release boundary before writing the new value. |
| Owner bookkeeping acquires its selected guard | A greater time-derived quotient updates body `+0xb60` and clears `+0xb68` before a saturating increment; a non-greater quotient leaves the bucket and increments the counter. Contended guard paths and intervening helper effects remain boundaries. |
| A selected call unwinds | The call-site table for the callback's apply call names landing `0x5a35204`; its selected continuation calls cleanup boundaries, conditionally releases data, drops the captured task and reaches the unwind-resume boundary. The gate and result producer have separate selected release/resume paths. Actual exception occurrence and cleanup helper semantics are not inferred. |

No failure branch establishes rollback. A helper or callback can have side effects before a later failure or unwind, and many alternate branches are not closed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler and linker flags, two-build results, target fixtures, and raw or normalized binary comparisons: **not yet implemented/measured**. Raw selected instruction windows and whole-FDE hashes are retained without normalization masks. Helper closure, runtime relocation binding, vtable/data dependencies and whole-ELF comparison remain incomplete. The negative controls test the static extractor and arithmetic joins; they are not node execution or equivalence tests.

## Results and limitations

`summary.json` records 16 new and 2 contextual unwind ranges, 61 selected byte windows, 74 selected direct transfers, 20 generated evidence files, 74 compact captures, 59 descriptor tag stores, 24 selected copy pairs, 6 projected result slices, 438 raw LSDA rows and 33 direct-call unwind links. All 33 selected call instructions have a covering call-site row; this does not imply that all calls have landing pads. These counts describe the chosen evidence, not function coverage or a completion denominator. The focused suite passed 30 tests with no skips, including bad hashes, corrupted transfer displacements, opcode and capture damage, invalid mappings and NOBITS, broken copy joins, queue geometry, sentinel boundaries and malformed unwind controls. Two differently seeded and timed regenerations and the separate historical comparison produced byte-identical #115 evidence.

The first `abci` component task remains incomplete: the selected prior block lane is conditional, the full begin/action/end-block variant set and complete state-root computation are unresolved, and no runtime identity or execution is proved. No progress gate is advanced.

Next question: resolve the relationship between the two captured owner pointers and trace the next root computation after a normally returning apply, including alias stability across the work-view and block helpers, to determine whether a post-mutation root is ever published on this driver.
