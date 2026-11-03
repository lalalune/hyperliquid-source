# RE-017: connect the ABCI loader handoff to the greeting result

On a selected node #115 path, the loader-forwarded state pointer can be followed through a separate owner allocation to the snapshot input and the resulting greeting's resumable send, provided the recorded helper and alias assumptions hold.

- Component ID: `abci`; RE-017, connected to the RE-009 snapshot and state-root question.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; the retired RE-017 state-link evidence is bound to node #94 digest `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: byte, relocation and unwind observations; conditional pointer-flow, data-layout and arithmetic inferences; actual scheduling, helper side effects and complete ABCI semantics unresolved.
- Scope included and excluded: the selected constructor bridge, greeting task creation and two executor arms, snapshot or alternate result selection, record preparation, selected send and follow-up outcomes, and specified error/unwind paths. The previously studied Location loader, its caller and constructor, snapshot builder, preflight helper and prepared-write helper are contextual boundaries. No existing function or GOT entry is claimed anew. This does not cover the full begin/action/end-block component task.

## Reproduce

From the repository root, with the authenticated #115 artifact and repository readers present:

```sh
python3 tools/abci_greeting_115.py --out research/work-items/RE-017-abci-greeting-115
python3 -m unittest tests.test_abci_greeting_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Check independent output with different hash seeds and time zones. The comparison directories are relative to the repository root:

```sh
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_greeting_115.py --out .re017-greeting-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_greeting_115.py --out .re017-greeting-b
diff -r .re017-greeting-a .re017-greeting-b
diff -r -x README.md -x MANIFEST.sha256 .re017-greeting-a research/work-items/RE-017-abci-greeting-115
(cd research/work-items/RE-017-abci-greeting-115 && sha256sum -c MANIFEST.sha256)
```

If the historical capture is available, the optional check separately authenticates it and validates its original Location and comparison bytes. It does not add or change generated files:

```sh
python3 tools/abci_greeting_115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out .re017-greeting-historical
diff -r .re017-greeting-a .re017-greeting-historical
```

Generation checks the complete #115 SHA-256 before reading evidence or creating output. It uses Python's standard library with `tools/elf_index.py` and `tools/fde_extents.py`; fileless sections are excluded. Exact instruction windows, relative branches, ELF relative relocations, FDEs and LSDA call-site encodings come from the target bytes. This is a fixed-form extractor, not a general x86 decoder. It and its tests execute no external program and do not run either captured binary. Local inspection used Python 3.12.3 and GNU objdump 2.42 on Linux x86-64; objdump text is not parsed or included in generated evidence.

## Evidence

All addresses below are linked ELF virtual addresses before rebasing. `functions.tsv` reconciles selected `.eh_frame` FDEs with `.eh_frame_hdr`, records file offsets and hashes the full unwind-described ranges. The ranges are not proof of source-function boundaries, complete control flow, ownership outside this packet, or a function census. `windows.tsv` retains exact bytes and marks old context. `transfers.tsv` records selected direct branches and calls, `dispatch.tsv` the selected jump-table entries, `relocations.tsv` the new task descriptors plus two contextual anchors, and `flow.tsv` the checked register/slot and copy equations. `unwind.tsv` and `unwind_links.tsv` preserve call-site ranges, landing addresses and uninterpreted action values. Analysis is complete only for the listed windows and selected branches.

### Location and release identity

The existing #115 Location record is `0x64767a8`: its relative relocation names `l1/src/abci/state.rs`, line 123, column 37. The existing caller references it at `0x3c1352f` and compares `rax` with 1 at `0x3c1353b`. These are context anchors, not new loader ownership.

The separately authenticated #94 Location is `0x56dfbf8`, line 107, column 37; its reference is at `0x3273856` and its comparison at `0x3273871` tests `r13` against 2. The optional historical check validates those bytes and the suffix of its file-name string without exporting its historical path. This is a navigation comparison, not an assertion of equivalent layouts or semantics between releases.

### Two distinct owner returns and the missing bridge

Prior #115 loader-handoff evidence records a selected Location-linked state pointer being passed to the already studied constructor `0x5a6bfb0`. The contextual bytes independently show that the upper parent copies a `0x380`-byte result prefix and then separately loads the word at result `+0x380`; the prefix copy does not include that word. On the selected normal path the constructor makes separate `0xb38` and `0xb80` allocation requests, returning their results in `rax` and `rdx`, respectively. The static evidence does not establish equality or inequality of those two runtime pointer values.

The new bridge follows the constructor's first argument, held in `rbx`, through two previously unselected functions. Each row is a statically observed copy or load/store; the pointer identity across intervening calls is conditional on normal returns and no conflicting writes through aliases:

| Stage | Selected evidence and tracked offset |
| --- | --- |
| Existing constructor context | `0x5a6c39c` saves its first argument at stack `+0x1660`; the `0x438`-byte copy at `0x5a6c5d8` places it at the next argument's `+0x420`. |
| New repacker `0x5a08f80` | Loads input `+0x420`, stores it at its stack `+0x460`, and copies `0x470` bytes from stack `+0x10` to the caller's next input. The tracked offset is `+0x450`. It calls the already studied preflight boundary `0x5a07ec0` before that copy. |
| New owner builder `0x5649680` | The contextual call's `R_X86_64_RELATIVE` slot resolves to this FDE. It copies the input into stack `+0x400`, then copies a range beginning at stack `+0x3f8` into output `+0x6a8`. The tracked input `+0x450` becomes output `+0xb00`. |
| Existing constructor context | Copies the builder's `0xb70`-byte output into the second allocation after two words. The tracked location becomes allocation `+0xb10`, or body `+0xb00` after the observed `+0x10` body adjustment. `rdx` returns this second allocation. |
| Earlier snapshot boundary | Existing snapshot evidence forms owner `+0x6b0`, then context `+0x450`; the two displacements join to body `+0xb00`. This packet checks both original instruction bytes as context and does not re-own those functions. |

On the selected prior loader and snapshot arms, this joins the forwarded pointer to the previously mapped snapshot input. It does not prove identity with a separately produced materializer result, absence of mutation by the intermediate helpers, or execution in a particular node run.

One preflight arm can be narrowed further without re-owning that function. If the unsigned comparison at `0x5a07f01` takes its branch and the preflight input's first dword equals 2, the contextual instructions write `0x8000000000000000` to the output and return directly, without an intervening call or store to the tracked input slot. The output write starts at the repacker's stack `+0x480`; the saved pointer is at `+0x460`, so their eight-byte ranges do not overlap. In the new repacker, negating that sentinel sets overflow and branches at `0x5a09032` straight to the recorded copy. This establishes pointer preservation across that selected preflight arm. Other preflight arms and builder/helper alias effects remain unresolved.

### From the owner allocation to the greeting task

The existing upper parent saves the constructor's `rdx`, carries it through four bounded copies to parent `+0x840`, increments its reference word, and calls new task constructor `0x2ad5600` with that pointer in `rcx`. `flow.tsv` calculates the copied offsets, checks that each tracked eight-byte word lies within its source range, and records the separate stack and object coordinate systems. It does not establish helper bindings or alias freedom.

`0x2ad5600` places that argument at task `+0xc8` in a `0x340`-byte allocation and passes a descriptor to a scheduling boundary. A relative descriptor entry selects poll FDE `0x2ad5980`. The poller moves the captured pointer to task `+0x188`, reloads and increments it, then constructs a child input with the pointer at `+0x138`. The selected thread and executor checks choose adapter `0x2b3f300` or `0x2b403a0`; their constructors `0x2cd1070` and `0x2cd1970` make separate `0x3080`-byte allocations. Their descriptors select pollers `0x2b1d9a0` and `0x2b26920`, respectively. Both pollers call the same future `0x2accee0` with the allocation body at `+0x38`. Descriptor relocations establish static destinations, not that a scheduler actually invokes them.

Seven further checked copies move the tracked child input from future `+0x138` to future `+0x11d0`. The snapshot and alternate calls both load that field and add `0x10`, the owner-body adjustment. The same second allocation therefore supplies the selected `+0xb00` snapshot slot if all stated call and alias assumptions hold. Reference-count failure reaches the `ud2` at `0x2ad5879` in the first constructor, while a failed allocation reaches the preceding allocation-failure boundary. In the poller, a nonpositive increment reaches a separate `ud2` path; a pending result stores poll state 3. These are selected branches, not a guarantee of which ones occur.

The snapshot-selection flag is a different value: `0x2ace4f6` loads a byte from the future's temporary stack slot `+0x27`, masks it with 1, and `0x2ace609` saves it at future `+0x2f0`. The same seven copies carry this single byte to `+0x1278`, which state 0 tests. The byte's earlier origin and domain meaning remain unresolved; the checked copy joins also assume no intervening alias writes.

### Greeting future, result and failures

The state byte at future `+0x127a` indexes the eight entries in `dispatch.tsv`; the entry meanings below describe only their first observed actions:

| Index | Target and selected action |
| --- | --- |
| 0 | `0x2ace963`: initialize flags; choose the snapshot or alternate path using byte `+0x1278`. |
| 1, 2 | `0x2acf7af`, `0x2acf79d`: call distinct diagnostic boundaries and continue to a shared boundary if they return. |
| 3 | `0x2acecd1`: resume the greeting-send future. |
| 4 | `0x2ace9a5`: resume the follow-up future. |
| 5 | `0x2ad01e3`: call boundary `0x2ce0de0`; result byte 3 takes its pending path. |
| 6 | `0x2ad03a8`: resume existing write boundary `0x2b7a290`; a low result bit takes its pending path and a nonzero completed result reaches a separate branch. |
| 7 | `0x2ad0273`: call boundary `0x2ae0920`; result byte `0x45` takes its pending path. |

For state 0, nonzero `+0x1278` calls the previously studied snapshot boundary `0x5648a30` with the literal `ReplicaCmd::compute_abci_greeting`. Zero calls new alternate `0x5649060` with `ReplicaCmd::compute_no_abci_greeting`, wraps the returned `0xa0` bytes in a `0xb0` allocation and sets the next result word to `0x8000000000000000`. The common path stores five words at future `+0x1210` through `+0x1237`; on the alternate branch the sentinel controls subsequent use, so the remaining words are not asserted to be meaningful.

The common path constructs the `send abci greeting` operation and calls `0x2b7a140`. A low result bit stores state 3 and returns pending. Otherwise its returned `rdx` is tested: nonzero reaches the `could not send abci_state` diagnostic and cleanup, while zero reaches the `successfully sent abci_state` diagnostic. These literal names identify the code path; static text and a zero helper result do not prove delivery or persistence. On the zero-result path, a nonzero mode byte and a second result word other than `0x8000000000000000` enter `0x2ae27c0`; its `0x45` result suspends in state 4, `0x44` takes the selected completion branch, and other values take another result branch. Its inner future `0x2ae3cc0` reaches the existing write boundary and has distinct `0x45`, `0x44` and `0x3f` result constructions.

The unwind row covering the greeting-send call names landing `0x2acfbb2`. That landing calls a cleanup boundary and reaches code that conditionally releases an auxiliary buffer, clears the ownership flag, and decrements the record and owner reference words. The send wrapper's own unwind paths conditionally call cleanup and release boundaries, set its state byte to 2, and reach unwind resume. `unwind_links.tsv` records raw LSDA action values without interpreting the action table; side effects of the called boundaries remain unknown.

### Alternate-path bookkeeping

The new owner builder initializes the alternate owner's divisor at body `+0xb58` to 60000, bucket at `+0xb60` to 525600 and counter at `+0xb68` to zero. After its aggregate boundary, `0x5649060` uses an atomic byte guard at `+0xb50`. On the recorded normal path it forms a nonnegative numerator, divides by the word at `+0xb58`, and compares the quotient with `+0xb60`. For a nonzero divisor and no intervening writes:

| Condition | Selected owner writes |
| --- | --- |
| Quotient greater than the old bucket | Store the quotient at `+0xb60`, reset `+0xb68` to zero, then increment it to 1. |
| Quotient at most the old bucket | Leave the bucket and increment `+0xb68`, saturating at the largest unsigned 64-bit value. |
| Guard compare-exchange fails | Call the corresponding boundary; the effect of that boundary is unresolved. |
| The selected temporary length is negative or its allocation fails | Call a failure boundary; the negative-length path reaches `ud2` if it returns. |

`bucket_model.tsv` is a synthetic boundary model derived from these instruction constants. The guard and counters are bookkeeping observations, not proof of an ABCI block-state change or a state-root calculation. No divisor validity or helper success is assumed for arbitrary owner instances.

### Selected record serialization

The new send wrapper calls `0x2700cc0`, which reaches `0x232b860` on the recorded encoding routes. That helper dereferences the record pointer, adds `0x10`, calls size pass `0x2cd6aa0`, allocates the reported size, then calls writer `0x2cd6de0`. A result word equal to 8 selects its success handling; other result words follow error forwarding and possible buffer release. Negative size and allocation failure reach their own boundaries. The previously studied prepared-write FDE `0x2b7a290` is a downstream boundary only.

Both size and writer functions calculate the same table index from the input's first word. The selected six entries and output marker bytes are:

| First input word | Selected index and emitted marker | Additional selected writer behavior |
| --- | --- | --- |
| Below `0x8000000000000000` | 0 / `00` | Encodes the word at input `+0x10` as a length, then copies that many bytes from input `+0x8`; more fields follow. |
| `0x8000000000000000` | 1 / `01` | Encodes words from `+0x18`, `+0x08`, then `+0x10`, in that order. |
| `0x8000000000000001` through `0x8000000000000004` | 2 through 5 / `02` through `05` | Selected branches write their marker and report the success word. |

Only these six entries are characterized; the full valid input domain and complete message schema are not established. On the selected caller's little-endian path, `0x2935e30` writes values below 251 as one byte, then uses marker `fb` plus two little-endian bytes below 65536, marker `fc` plus four below `2^32`, and marker `fd` plus eight otherwise. Capacity-exhaustion branches call growth boundaries. `uint_model.tsv` contains synthetic boundary examples; these are not captured node outputs.

### Inferences and unresolved boundaries

The names "owner", "greeting", "send" and "snapshot" are interpretations grounded in the dataflow and embedded labels. The static paths support conditional propagation, output layout and bookkeeping decisions; they do not establish scheduler liveness, peer delivery, persistent snapshot contents, all enum variants, helper effects, or equivalence to a Rust source implementation. No full state-root digest or begin/action/end-block state transition is reconstructed here.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, build flags, fixture replay, two-build byte comparisons, normalization masks, relocation closure, helper closure and whole-ELF comparison: **not yet implemented/measured**. The negative controls exercise the extractor and small synthetic models; they do not execute the node or establish behavioral equivalence.

## Results and limitations

`summary.json` records 20 selected FDEs, 97 selected and 21 contextual byte windows, 78 selected and 5 contextual direct transfers, 24 selected table entries, 42 copy/move rows, 442 LSDA call-site rows and 30 direct-call unwind links. Of those links, 29 have a row covering the whole call instruction and 1 has no LSDA. These are selected evidence counts, not a coverage denominator. The focused suite passed 37 tests with no skips, including each fixed window and direct displacement corrupted separately, digest and relocation failures, out-of-range and fileless mappings, malformed and partially covering LSDA controls, broken pointer and prefix-copy joins, the selected preflight sentinel path and a non-overlap control, marker corruption, unsigned integer boundaries and counter saturation. Two independent regenerations and a separate historical check produced identical evidence files.

The snapshot path is joined to the constructor only under the stated prior-loader, call-return, binding and alias assumptions. The first `abci` task remains incomplete: complete begin/action/end-block entry paths, state transitions, rollback and error semantics, callback effects and final state-root computation are outside these selected windows. No component gate is advanced.

Next question: resolve pointer preservation on the other preflight arms and across the builder's helper calls, then connect the selected greeting/snapshot owner to the complete begin/action/end-block state-root transition and its failure semantics.
