# RE-021: revision-bound private precompile installation and context handoff

This packet establishes one adapter's revision capture, private-precompile overlay and context publication path, allowing reconstruction to preserve the selected standard callbacks while installing the private address range and its address-set state.

- Component ID: evm / RE-021 (continuation of the BLAKE2b packet's unresolved runtime connection).
- Target release and full SHA-256: node #94, Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository and publicly checked main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference implementation text is not copied. Names below are inferred from the target operations.
- Claim status: observations are byte/FDE/RELA/LSDA backed; preservation and address-set meaning are conditional inferences; transaction execution, external helper closure and historical fork names remain unresolved.
- Scope included and excluded: one adapter's initial installation, revision-change hook replay, factory materialization, owned-map copying/insertion/reservation, key-set handoff and selected cleanup paths. Complete FDE bytes are retained for the selected bodies, but only the registry lifecycle within the two larger transaction callers is interpreted. Other transaction phases, private callback bodies, the previously owned standard selector/lookup/dispatch bodies, node #115 and visor are excluded.

## Reproduce

Verification used Python 3.12.3. Run from repository root with Python 3 and the authenticated target at `artifacts/node/94/hl-node`. Only the standard library and the repository's `elf_index.sections`, `fde_extents.eh_frame_records` and `fde_extents.uleb` are used. The target digest is checked before parsing. The tool does not run another program, execute captured instructions, contact a service or require a disassembler.

```sh
python3 tools/precompile_install94.py --out research/work-items/RE-021-precompile-install-94
python3 -m unittest tests.test_precompile_install94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHON=$(command -v python3)
REPRO_A=$(python3 -c 'import tempfile; print(tempfile.mkdtemp(prefix="precompile-install-a-"))')
REPRO_B=$(python3 -c 'import tempfile; print(tempfile.mkdtemp(prefix="precompile-install-b-"))')
PYTHONHASHSEED=1 TZ=UTC PATH= "$PYTHON" tools/precompile_install94.py --out "$REPRO_A"
PYTHONHASHSEED=777 TZ=Pacific/Honolulu PATH= "$PYTHON" tools/precompile_install94.py --out "$REPRO_B"
diff -r "$REPRO_A" "$REPRO_B"
```

The two output directories contain only generated evidence. README and MANIFEST are authored packaging files, not generated analysis. `MANIFEST.sha256` covers all other files in this evidence directory, including this README. No normalization masks are applied. Exact body digests and raw bytes are retained. GNU objdump was used only for human inspection; its formatting, instruction counts and address lists are not inputs to any output or test.

## Evidence

All code/data addresses are ELF virtual addresses before load bias. File offsets, half-open actual FDE ranges, CIE/FDE coordinates and body hashes are in `functions.tsv`. `instructions.tsv` is a restricted byte-shape partition of those exact pinned bodies, including padding and landing paths. It is not an independent disassembler or a proof that every row is reachable. `control-flow.tsv` records direct/conditional/indirect transfers. RIP operands and symbol-free RELATIVE bindings are kept separately; unresolved register calls are not silently assigned a target.

### Ownership and the standard-registry boundary

The existing [compression packet](../RE-021-blake2b-compress-94/README.md) owns the wrapper/compressor evidence. [PR 1373](https://github.com/lalalune/hyperliquid-source/pull/1373), checked at head `cc699eb95941cdf90933f49f4109a4aa32efe0f8`, owns standard registry construction, selector, lookup, precompile dispatch and checkpoint outcomes. Its bodies are not selected here. This packet answers its next question: which concrete adapter supplies the revision and installs the private overlay?

The call at `0x2444a3c` uses RELATIVE slot `0x5773f50` to the external selector `0x4e9d240`. The earlier work supplies the mode-2 address-09 record and its callback identity. This packet proves the new side of that boundary: selecting a mode, copying the returned map without changing its plain callback value, adding disjoint full address keys, and handing that owned map to a concrete context. It does not resubmit the selector, the address-09 object or either BLAKE2b function as new coverage.

### Entry, hooks and revision capture

`entry-binding.json` links the following sites and field offsets from decoded operands and relocations:

1. Adapter `0x247fd20` saves the requested revision from R8D, calls constructor `0x2464bd0`, installs factory vtable `0x56a6850`, and appends a hook carrying vtable `0x56b8038`. The hook's payload is a captured pointer; its borrowed invocation slot is `+0x28` and resolves to `0x24b6590`. Its consuming slot resolves to `0x244fe00`.
2. At `0x2480161`, the adapter compares the initial canonical byte with the requested byte. Equality skips reconstruction. Otherwise it constructs a replacement handler and replays its registered hooks, calling the borrowed slot for a nonzero hook-data pointer or a plain function pointer for the other representation.
3. Both installers retain the twenty captured references, snapshot handler byte `+0x1198`, allocate the replacement factory, release the previous factory, and publish data/vtable at handler `+0x48/+0x50`. Factory allocation is `0xb8` bytes: a reference-count header followed by a `0xa8`-byte payload with twenty pointer words and revision at payload `+0xa0`. Padding is not asserted initialized.
4. After hook replay, `0x24802d1` writes the **raw requested byte** to the replacement handler. The factory already captured the **canonical byte**. For requested byte 10, the handler therefore contains 10 while the factory contains 9. `revision-transition-examples.json` retains representative cases; the tests examine all pairs of input bytes for this bounded normal-return model.
5. The concrete consumer `0x25154a0` first calls an external preparation callback and requires result tag 5. It then loads the factory from context `+0x158/+0x160`. Subtracting the context's `0x110`-byte header gives handler `+0x48/+0x50`. Calling vtable `+0x28` reaches `0x24448a0`. A different preparation tag bypasses materialization and is forwarded through the error-result path.

Constructor dispatch covers every byte input. It has fifteen distinct case paths, each with six allocation-null branches. `revision-cases.json` includes the opcode-table source and hash, canonical store and failure targets; `revision-routes.json` enumerates all inputs. The factory increments its captured byte with byte wrapping and indexes the separate mode table.

| Requested input byte | Captured canonical byte | Registry mode |
| --- | --- | --- |
| 0, 1 | 0 | 0 |
| 2, 3 | 2 | 0 |
| 4 | 4 | 0 |
| 5 | 5 | 0 |
| 6 | 6 | 1 |
| 7, 8 | 8 | 1 |
| 9, 10 | 9 | 2 |
| 11 | 11 | 3 |
| 12, 13, 14 | 12 | 3 |
| 15 | 15 | 3 |
| 16 | 16 | 3 |
| 17 | 17 | 4 |
| 18, 19 | same as input | 5 |
| 20 through 255 | 255 | 6 |

Mode 6 is an observed argument at the external selector boundary. Its selected registry contents are not established by this packet. No historical fork names are assigned to these numeric values, and arbitrary direct factory payload bytes outside the constructor-produced domain are not admitted by the transition model.

### Factory records and preservation of standard callbacks

`private-records.json` reconstructs every full key, tag, callback relocation, vtable size/alignment and record store. `capture-edges.json` records static MOV def-use chains from each retained capture to its record data word. The record order is `0x800`, `0x813`, then `0x801` through `0x812`; all use value tag 2. Capture ordering is therefore significant. The callback bodies are external endpoints, not newly recovered functions.

Materializer `0x24448a0` obtains a borrowed standard registry, forces an owned representation through `0x25b6e20`, stages the twenty private records, calls `0x26ba640`, and returns five words. The record layout in this owned path is key at `+0`, tag at `+24`, data at `+32`, vtable at `+40`, with stride 48. Do not substitute the standard registry's source-object layout for this bucket layout.

The borrowed-copy iterator at `0x20482c0` dispatches value tags 0 and 1 to a plain 16-byte callback-payload copy, tag 2 to a shared-reference retain and tag 3 to an external dynamic clone. The four-entry table is retained in `clone-tag-table.tsv`; invalid tags are outside its domain, not an invented error branch. Full keys and value tags survive insertion into the destination map. `literal-records.json` retains the SIMD constants, including the counter-update and rehash control vectors, together with raw bytes and nested relocation records. Private callback vtable bytes and their null drop slots are retained in `private-records.json`.

Insertion at `0x27c9190` hashes overlapping key words covering all twenty bytes, uses a seven-bit fingerprint, probes sixteen control bytes at a time, and confirms the full key before replacing a value. Replacement returns the previous value without changing the key or item count. New insertion writes the full key/value record, updates mirrored control bytes and item/growth counts, and returns absent sentinel 6. Private keys do not equal address 09. Thus, on normal returns with valid map invariants, the overlay cannot select the replacement arm for a standard address-09 entry.

Reserve `0x4890f10` distinguishes growth from in-place rehash. Growth copies all 48 bytes of each live record; in-place rehash moves all 48 bytes or swaps all six words. Both rebuild controls. `0x488ef00` checks capacity and layout overflow before allocation. The static arithmetic model in `allocation-cases.json` is for this caller's fixed stride 48, not an allocator implementation or a target-execution result.

### Address-set and context state changes

Before publishing the owned registry, `0x25154a0` calls `0x25b6ca0` to derive its key set. On the established owned branch, `0x2048200` extracts sixteen key bytes plus the final four from each occupied 48-byte map bucket. It inserts these into a 20-byte-key set through `0x27c7e10`.

`0x26b8980` consumes that temporary set into the context's set at `+0x80`, again using full-key insertion. Existing keys return 1 without insertion; new keys store all twenty bytes, update controls and counts, and return 0. The destination is extended rather than cleared. The temporary set's allocation is released after consumption, including the recorded unwind paths. Set reserve and low-level allocation remain external helper boundaries.

The old registry at context `+0xe8` is then released and the five-word factory result is stored there at `0x251569d..0x25156c2`. Interpreting the context set as the EVM warm-address set is an inference consistent with its placement and use; the observation is the exact address-set insertion and map-store sequence. Subsequent transaction dispatch is outside the semantic claim.

### Failure and cleanup distinctions

| Trigger | Observed path |
| --- | --- |
| A constructor allocation returns null | Six distinct checked branches per constructor case; exact targets in `revision-cases.json`. |
| A captured-reference increment reaches the checked nonpositive condition | `0x247d7f0` branches to its terminal trap; it does not return a successful capture array. |
| Factory allocation fails | Null path calls the external allocation-error endpoint and traps; an allocation unwind drops the retained captures. |
| Previous factory release unwinds | Both installer landing paths store the replacement data/vtable before resuming the unwind. |
| Owned conversion leaves a borrowed tag | Materializer takes its diagnostic call and trap path. |
| Clone/extend fails while building the map | Selected cleanup helpers release partial values, the partial map and unconsumed private records; callback destruction itself remains external. |
| Capacity or layout arithmetic overflows | The raw allocation helper distinguishes capacity/layout failure and fallible versus infallible handling. |
| Preparation callback returns a tag other than 5 | Consumer forwards the result before any factory call. |
| Auxiliary address processing unwinds | Landing pad `0x25173bb` releases the new owned map and resumes. |
| Releasing an old context-map value unwinds | Landing pad `0x25173e5` **publishes the new map before resuming**; no transactional rollback is claimed. |

`exception-sites.tsv` retains original call-site bytes, protected intervals, landing-pad addresses and action indexes. The factory invocation itself is in a consumer LSDA interval with no local landing pad; the following auxiliary-address calls have a cleanup landing pad. An initial test expectation that conflated these was corrected against the actual LSDA. No personality/action-chain interpretation or observed unwinder behavior is claimed.

### Selected function map

The following table is a navigation map, not a claim that every operation in the two larger callers has been reconstructed. Exact ranges and raw instruction-shaped rows remain in the generated files.

| FDE start | FDE end (exclusive) | Inferred role |
| --- | --- | --- |
| `0x1fa3f30` | `0x1fa4028` | release replaced value during borrowed copy |
| `0x20249e0` | `0x2024a1b` | release temporary address set storage |
| `0x2025340` | `0x2025420` | release partially constructed map |
| `0x202cf90` | `0x202cfc0` | release consuming set iterator storage |
| `0x2048200` | `0x20482bd` | copy full keys from forty-eight-byte map buckets |
| `0x20482c0` | `0x2048429` | clone borrowed entries by value tag |
| `0x24448a0` | `0x2445252` | materialize registry and private records |
| `0x244fd00` | `0x244fd3b` | consuming factory adapter |
| `0x244fe00` | `0x244fedf` | install captured-revision registry factory |
| `0x2456680` | `0x2456a68` | release twenty callback references |
| `0x2464bd0` | `0x2468403` | revision byte to handler table and canonical revision |
| `0x247d7f0` | `0x247d9d3` | retain twenty callback references |
| `0x247fd20` | `0x2480ef4` | adapter setup and revision-change hook replay; downstream transaction semantics unresolved |
| `0x24b6590` | `0x24b666f` | borrowed hook reinstalls captured-revision factory |
| `0x25154a0` | `0x2517556` | factory consumption and context-map publication; later transaction semantics unresolved |
| `0x258d300` | `0x258d374` | release unconsumed array elements |
| `0x25b3780` | `0x25b3879` | release one private key-value record |
| `0x25b6ca0` | `0x25b6e16` | derive address set from owned or borrowed registry |
| `0x25b6e20` | `0x25b6e99` | borrowed registry to owned map |
| `0x26b8980` | `0x26b8ba1` | consume address set into context address set |
| `0x26ba640` | `0x26ba791` | extend owned map with twenty records |
| `0x26ba880` | `0x26ba997` | initialize owned-map seed and copy entries |
| `0x277c590` | `0x277c688` | release replaced value |
| `0x27c7e10` | `0x27c7ff7` | insert or recognize full twenty-byte address |
| `0x27c9190` | `0x27c9401` | insert or replace one full address key |
| `0x488ef00` | `0x488f0a9` | allocate raw bucket storage |
| `0x4890f10` | `0x48914dc` | reserve or rehash owned map |

## Implementation and comparison

Independent Rust implementation, Cargo.lock, compiler/linker flags, native two-build comparison and target-byte equivalence: **not yet implemented/measured**. This is a static research packet with a reproducible extractor and bounded arithmetic/transition models. It does not add a compiling-node claim, an implementation stub or copied reference code.

All code and evidence are qualified by the target digest. Full-body pins admit the restricted byte-shape reader; separately pinned semantic windows bind the discussed operations. Shared ELF/FDE parsing is reused. Sections with SHT_NOBITS are excluded from file-backed address reads. Relocations are resolved only when symbol-free R_X86_64_RELATIVE is established. External helper, allocator, destructor and vtable-call gaps remain visible in `external-edges.tsv`; no normalization conceals them.

The preservation inference assumes valid table/control invariants, allocated and stable nonaliasing storage, ordinary SysV register preservation, and normal returns from opaque allocation/copy/seed helpers. Reference counts and cleanup requests are observed, but actual allocation, deallocation and exception execution are not measured. Context address-set updates need not roll back on later failure. This is not a proof for arbitrary malformed runtime objects or concurrent mutation.

## Results and limitations

The generated `summary.json` supplies exact denominators: 27 selected FDE bodies, 38,214 retained code bytes, 7,633 byte-shape rows, 1,737 control rows, 436 LSDA call-site records, 85 semantic windows, 20 private records and 256 constructor inputs. These are selected-evidence counts, not whole-node function coverage. External control sites and dynamically unresolved sites are counted separately in that file, including operations outside the registry corridor in the two larger callers.

Validation: 37 focused unittest methods pass with zero skips. They cover byte/digest/FDE/range corruption, NOBITS and ambiguous mappings, branch landing alignment, all semantic-window mutations, full private addresses, tags and relocations, capture permutation, all revision inputs, all revision-transition input pairs, allocation boundaries/overflow against an independent minimum-bucket oracle, concrete context/vtable bindings, LSDA distinctions and exact regeneration. The retained evidence is regenerated twice with different hash seeds/timezones and an empty PATH; the two directories and the retained generated files agree byte for byte. Artifact verification and catalogue consistency pass. The full repository test suite, hosted CI, containers and captured execution were not run.

No component gate is requested or changed. The evm milestone remains 0/4. The first component task's broad private-fork and state-transition boundary is only partially resolved: this packet establishes a concrete precompile installation/context corridor, not the complete EVM state transition. Standard lookup/compression evidence remains credited to earlier work. Mode-6 contents, semantic identities of the private callbacks, seed initialization, set reservation, transaction outcomes and complete helper/data closure remain unresolved.

Next question: establish the caller-produced domain and external selector destination for captured revision 255 (mode 6), without duplicating the standard selector body, then connect the installed context map to the already mapped lookup under a concrete transaction callback binding.
