# RE-021: precompile-adjacent logs and post-frame state in node 115

This packet establishes the conditional log construction, nonzero-account collection, bounded ordering, and journal reset/map handoff needed to reconstruct selected precompile-adjacent and post-frame functions in node #115.

- Component ID: `evm`; RE-021 is a bounded extension of RE-011, not a separate row in `docs/TASKS.md`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical #94 clues are in repository history. No unlicensed inferred source was copied.
- Claim status: observed selected ELF bytes, real FDE intervals, relocation records, direct branch encodings, instruction shapes and exception-table records; inferred names, field roles, bounded models and conditional route connections; runtime inputs, aliasing and end-to-end outcome remain unresolved.
- Scope included and excluded: eleven selected #115 FDE intervals, conditional handoff edges from prior research, the two log builders, row collection/lookup, small-sort dispatch, status classification, selected cleanup and map handoff. The already researched frame, precompile lookup, compression, rollback, upstream driver and value-transition helper are dependencies, not resubmitted function bodies. Actual frame-to-classifier status provenance, the remaining large-sort subhelpers, host calls, transaction-wide execution and the component-wide fork matrix are outside the proven scope.

## Reproduce

From the repository root with Python 3.12 and the authenticated node #115 artifact available:

```sh
python3 tools/re21_blake_poststate115.py --out research/work-items/RE-021-blake-poststate-115
python3 -m unittest tests.test_re21_blake_poststate115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-blake-poststate-115 && sha256sum -c MANIFEST.sha256)
```

For a repeatability check, replace `<tmp-dir>` with an existing writable directory:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/re21_blake_poststate115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_blake_poststate115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The historical artifact is optional. If present at the following repository-relative location, the generator can additionally authenticate both releases and check the old and new key/callback/FDE anchors; this does not change its output files:

```sh
python3 tools/re21_blake_poststate115.py --legacy references/can1357-hl/bin/hl-node-mainnet-new --out <tmp-dir>/legacy-check
```

The generator first verifies the full input digest, uses the Python standard library plus `tools/elf_index.py` and `tools/fde_extents.py`, and launches no external commands. It never executes the node. It excludes SHT_NOBITS from file-byte reads. Python 3.12.3 on Linux x86-64 was used; GNU objdump 2.42 was used only for manual instruction interpretation, and its output is not parsed or saved in generated evidence. `MANIFEST.sha256` covers this README and all generated evidence; the generator leaves the README and manifest untouched. The two generated output trees are independent of hash seed and time zone.

## Evidence

Addresses below are ELF virtual addresses (VA) before load bias; relocation addends use the same coordinate system. Generated records include section names, file offsets, exact selected bytes, FDE and CIE bytes, and raw relocation/call-site records. For example, function VA `0x29714f0` corresponds to file offset `0x29704f0`. Ends in the table are exclusive FDE ends; they are not independent proof of source-level function boundaries. Edges and instruction windows are selected, not an exhaustive control-flow graph. Names below describe inferred roles.

### New FDE map and dependency boundaries

| Inferred role | Start VA | End VA, exclusive |
| --- | --- | --- |
| Collect nonzero rows | `0x2346480` | `0x234668e` |
| Small row ordering | `0x26d4140` | `0x26d427a` |
| One-key log constructor | `0x2970eb0` | `0x29710df` |
| Two-key log constructor | `0x29714f0` | `0x2971759` |
| Finalize candidate rows | `0x2972200` | `0x297238e` |
| Take and replace account map | `0x2972c20` | `0x2973124` |
| Reset journal-like state | `0x2973130` | `0x2973434` |
| Classify status byte | `0x299c6d0` | `0x299c929` |
| Look up nonzero account | `0x29dee60` | `0x29defea` |
| Large-row sort adapter | `0x36e3660` | `0x36e3757` |
| Large-row run partition | `0x3dfd7e0` | `0x3dfdeef` |

No selected function start appears in the existing repository work items or the available relevant PR packet bodies. The locally supplied PR snapshot lists file names but does not include every remote PR body, so the search cannot establish absence from unseen bodies.

The earlier address-09 lookup and scaled-route packets establish conditional upstream routes and own their selected functions. Their value-transition dependency contains a direct handoff at `0x2970e88` to the newly selected two-key constructor. In the upstream driver, the selected direct call sites at `0x29663d3`, `0x2966423`, `0x2966846` and `0x29669b5` hand off to the row finalizer, classifier, reset and account-map handoff, respectively. These four call instructions are connection anchors only; the enclosing driver FDE and its complete branch behavior are not analyzed or claimed as new functions here. The connections do not prove that every address-09 call reaches every handoff or that the classifier receives the unchanged frame status.

Within the selected functions, the directly supported path is `0x2972200 -> 0x2346480 -> 0x29dee60`, then, for the relevant row count, `0x26d4140` or the relocation-resolved `0x36e3660`; each selected row is passed to `0x2970eb0`. The indirect large-sort slot at `0x64e6d70` has a relative relocation to `0x36e3660`, whose direct call reaches the selected run-partition function `0x3dfd7e0`. All direct call and branch sites in this paragraph are independently encoded in `edges.tsv`; their presence alone does not establish dynamic reachability or helper side effects.

### Log construction and failure paths

Both builders receive a context in the first argument. The two-key constructor receives two 20-byte keys and a four-limb 256-bit value in the next three arguments; the one-key constructor receives a key and value in the next two. Their observed conditions are:

| Condition | Observed branch |
| --- | --- |
| Context byte +`0x126` is below 14 | Return without appending. |
| Context byte +`0x124` is nonzero | Return without appending. |
| All 32 value bytes are zero | Return without appending. |
| Otherwise, assuming allocations and helper calls return | Construct and append an 80-byte record to the context collection at +`0x00`, +`0x08`, +`0x10`. |

On that normal branch, the first allocation is 96 bytes for the two-key variant or 64 bytes for the one-key variant. The second allocation is 32 bytes in both. The first topic is the 32-byte file literal at `0x4581e0` for two keys, or at `0x458720` for one; each further topic consists of 12 zero bytes followed by a 20-byte key. The second allocation receives the four little-endian limbs in reverse order with each limb byte-swapped, yielding 32 big-endian bytes. The record's 20-byte emitter value is `fffffffffffffffffffffffffffffffffffffffe`; its first 16 bytes are loaded from `0x6017b0` and its last four are stored as an immediate. These are raw layout observations, not a claim about the names or externally observable semantics of the events.

The two allocations have distinct null branches. The call to grow the two-key collection at `0x29716ac` lies in an encoded LSDA call-site range whose landing pad is `0x2971729`; the analogous per-row builder call at `0x29722ed` lands at `0x297236d`. The selected pads reach cleanup and unwind boundaries shown in `exceptions.json` and `edges.tsv`. The seven selected exception tables contain 32 encoded call-site rows in total; action chains and all indirect helper internals are not decoded. Neither allocation failure nor unwinding is equated to a normal precompile status.

### Filtering, lookup and row order

The finalizer independently tests +`0x126 >= 14`, +`0x124 == 0` and +`0x125 == 0`; any failed test returns before collection. It forms a 20-byte-stride key view from context +`0x38` and +`0x40` and supplies the account-map-shaped field at +`0xc8` to the collector. The collector advances 20 bytes per key and builds 56-byte rows only for lookup results with a nonzero 32-byte value. It can allocate, grow and clean up its row vector; failed allocation and unwinding leave normal completion unproved.

The selected lookup at `0x29dee60` returns no row if the map is empty, the search reaches an empty control byte without finding the full key, or the matched value is all zero. A fingerprint candidate with a different key does not by itself terminate the search. It examines groups of 16 control bytes and multiplies a selected bucket index by `0xa8`. A matching tag alone is insufficient: the first 16 key bytes and remaining four key bytes are also compared. The exact key/hash arithmetic resembles the separate general registry lookup previously established in the address-09 packet; it is repeated here only as an independently checked dependency of this different account lookup:

```text
fold(a,b) = low64(a*b) XOR high64(a*b)
h = fold(fold(load64le(key[0:8]) XOR seed,
              load64le(key[8:16]) XOR secret) XOR load32le(key[16:20]), secret)
```

The seed is read from the map. The RIP-relative slot at `0x64dfa78` has a relative relocation to `0x64ffe90` in SHT_NOBITS `.bss`, whose runtime word is read as the secret. The ELF has no file bytes for that storage; its value, a runtime bucket position and any live map contents are not inferred from the file. `summary.json`, `rip-references.tsv` and `relocations.json` record the section and relocation, and a negative test rejects reading its address as file-backed data.

After filtering, the finalizer's count branches are:

| Retained rows | Selected behavior |
| ---: | --- |
| 0 | Skip the row loop. |
| 1 | Enter the row loop without a sort call. |
| 2 through 20 | Call the small ordering function. Its comparison is a 20-byte call through slot `0x64dfb50`, whose dynamic relocation names `memcmp`; assuming ordinary symbol resolution, the observed insertion-style path orders rows by their key bytes. |
| 21 or more | Call the adapter through relocation slot `0x64e6d70`; it calls the selected run-partition function `0x3dfd7e0`. The latter uses an additional relocation-resolved subhelper whose complete behavior remains unresolved. |

The boundary is on retained rows, not the number of input keys. The large adapter computes a scratch-row request as `max(min(n, 0x22e09), n - (n >> 1))` for unsigned count `n`. For 21 through 73 rows it uses its 4,096-byte stack buffer; from 74 rows it enters a separate heap-allocation path with overflow and null branches. A normal heap return frees the scratch allocation. The adapter passes `n < 65` as a flag to `0x3dfd7e0`, so counts 64 and 65 differ even though both use stack scratch. The small synthetic model rejects 21 or more retained rows rather than pretending to model the large sorter; a separate model checks only this scratch/flag decision.

The selected `0x3dfd7e0` body first returns for fewer than two rows. On one observed scan it compares adjacent 20-byte keys through the same `memcmp` relocation, advances in 56-byte row strides, follows different branches for negative versus nonnegative comparisons, and can reverse a run by swapping seven 8-byte chunks per row. An additional indirect call at `0x3dfd975` uses slot `0x64e98f8`, which relocates to `0x428c410`; it is reached only on the selected shorter-run branch when the passed flag is set. That subhelper, other merge paths and the sorter's full ordering and stability are not established by these windows. The counts 21, 64, 65, 73 and 74 in `synthetic-cases.json` are synthetic boundary examples, not live observations.

### Status classifier and state handoff

The classifier indexes the file-backed table at `0x6006ac` after decrementing its input byte. The next independently referenced table begins at `0x600788`, so the tool inspects 55 four-byte cells in that fixed interval. Of these, 34 target a recognized return arm and 21 target `ud2`. This range is an inspection bound, not proof of the valid enum domain, bounds checking or reachability of every value. Three selected return arms are:

| Raw classifier input | Result word | Extra byte written | Arm VA |
| ---: | --- | ---: | --- |
| `0x02` | `0x8000000000000014` | 1 | `0x299c7db` |
| `0x23` | `0x8000000000000000` | 3 | `0x299c7b3` |
| `0x31` | `0x8000000000000009` | not written by this arm | `0x299c915` |

The earlier address-09 research reports these same values as conditional frame statuses for success, insufficient gas, and bad length or final flag. Applying this classifier table to an address-09 result is conditional on that status surviving intervening copies, aliases and helper calls unchanged; this packet does not establish that provenance. No unseen return value or caller behavior is inferred from the arm that does not write the extra byte.

At reset `0x2973130`, selected normal instructions clear context +`0x118`, +`0x28` and byte +`0xb0`, and cleanup precedes a 32-bit decrement of context +`0x120`. If the original value is 1, the decremented result is zero and execution branches to `0x29733ee` before storing the decrement; earlier clears and cleanup are not undone by this evidence. Otherwise the decremented 32-bit result is stored. This describes machine arithmetic, not a claim that every input word is reachable. The failure branch references a descriptor at `0x6440eb0` whose source-path suffix is `z_vendor/revm-state/src/lib.rs`, line 60, column 21. The suffix identifies a label embedded in #115, not a specific upstream source version or a complete fork boundary.

At `0x2972c20`, a normal path takes the 40-byte map-shaped header from context +`0xc8` through +`0xef`, copies it to the output, replaces the context's first 32 bytes with the template at `0x6441bc8`, and stores a derived runtime word at context +`0xe8`. It also clears selected collection/state fields and eventually writes `0xffffffff` to +`0x120`. When context +`0x126` is at most 2 and the taken map is nonempty, a further scan conditionally changes per-entry flag bytes; larger values or an empty map bypass that scan. Allocation, aliases, external callbacks, exceptional cleanup and the ultimate host/database commit are not fully established. The map handoff is a conditional path, not proof of durable state change for any particular address-09 request.

### Cross-release identity

The historical #94 artifact has SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its earlier record begins at `0x574f0a8`, with a 20-byte key ending in `09` at `0x574f0c0`, a callback relocation slot at `0x574f0b0` pointing to `0x4e9d2a0`, and a reported compression candidate at `0x4e9a8a0`. The optional cross-release check authenticated that artifact, read its key and relocation, and checked the wrapper FDE `0x4e9d2a0..0x4e9d47b`. It separately checked #115 key `0x64c0750`, callback relocation `0x64c0748 -> 0x5c165b0`, and adapter slot `0x64eaee8 -> 0x5c16650`, as previously established in the #115 lookup packet. These are different layouts and coordinates; no #94 behavior, FDE length or record offset is transplanted into #115. The #94 compression candidate is historical context, not newly validated by this packet.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency closure, compiler/linker options, two-build comparison, normalization masks, helper/data closure, differential execution and whole-ELF equivalence are **not yet implemented or measured**.

The small Python models in `synthetic-cases.json` use explicit artificial keys, flags, values and seeds. They encode the selected static interpretation and are not captured runtime results or an independent equivalence oracle. The focused suite has 34 passing tests and zero skips. Negative controls cover altered target hashes, missing/duplicate FDEs and relocations, changed instruction and branch bytes, non-file-backed/ambiguous/out-of-range reads, corrupted status cells and source descriptors, truncated exception tables, bit changes across all 160 key bits, malformed inputs, guard boundaries and the 20/21 retained-row boundary and the 64/65 and 73/74 large-adapter boundaries. Each generated file is compared byte for byte with the saved packet.

## Results and limitations

`summary.json` records 11 selected FDE intervals containing 7,519 bytes, 56 selected byte windows, 64 direct edges, 18 RIP references, 13 symbol-free relative relocations, one dynamic symbol relocation, three literals, one source descriptor, 55 bounded status entries and seven LSDA headers with 32 call-site rows. These are explicitly selected records, not a count of all EVM functions, a matched-window denominator, a coverage percentage or a component completion claim.

The `evm` component remains 0/4. Its first task asks for the complete private fork boundaries and state-transition inputs; the conditional paths here do not close that scope. No progress gate or catalogue is changed. Open gaps include exact frame-to-classifier dataflow, live fork inputs and map contents, all branches of the already owned driver, dynamic callbacks, remaining large-sort helper semantics, exception action chains, host/database effects, entire compression behavior, and any validated #115 Rust implementation.

Next question: prove or disprove unchanged propagation of the address-09 frame status into the classifier through the external driver, and close the remaining large-sort subhelper and cleanup effects without reselecting functions owned by another packet.
