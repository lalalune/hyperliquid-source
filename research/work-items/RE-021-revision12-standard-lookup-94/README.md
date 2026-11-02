# RE-021: standard revision-12 provider and creation-time registry lookup

Node #94's standard-handler family maps raw revisions 12–14 to a borrowed mode-3 registry, publishes it in the execution context, and supplies a creation callback that checks a full 20-byte key against that registry and writes status `0x5e` on a hit; a reconstruction can preserve this collision gate and its distinction from ordinary precompile invocation.

- Component ID: `evm`; RE-021 extends the existing BLAKE2b precompile question and is not a new row in the official task queue.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference was a lead only; no reference implementation was copied.
- Claim status: byte windows, FDE/LSDA records, relocations, selected displacements and branch targets are observations. Registry, callback, address-set and hash-table names, and the cross-function composition under normal returns, are inferences. A complete lookup through the borrowed arm, live revision selection and runtime execution remain unresolved.
- Scope included and excluded: the 19 FDE starts in `functions.tsv` are the selected new bodies. The preexisting BLAKE2b wrapper/compressor, registry constructors, frame constructor and the caller FDE at `0x4dd6ea0` are dependency boundaries, not selected or re-exported function bodies. The latter is already documented by `foundation-xor-mixer-94`. Node #115, visor, target execution, emulation, networking and chain access are excluded.

## Reproduce

Run from the repository root with the pinned artifact present. The recorded run used CPython 3.12.3 on Linux x86-64. The extractor imports the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it authenticates the complete input first, rejects SHT_NOBITS as file bytes, and starts no external program. GNU objdump 2.42 was used only for human review of instruction boundaries; its output is neither parsed nor emitted by the extractor or tests. No captured instructions run.

```sh
python3 tools/re21_standard_registry94.py --out research/work-items/RE-021-revision12-standard-lookup-94
python3 -m unittest tests.test_re21_standard_registry94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-revision12-standard-lookup-94 && sha256sum -c MANIFEST.sha256)
```

For an independent comparison, substitute two different empty relative directories for the placeholders. The extractor writes the 14 JSON/TSV evidence files, not this README or the manifest.

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/re21_standard_registry94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_standard_registry94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The two output trees were also compared against the retained generated files. Generation and the focused unittest were run with an empty program-search PATH. Files are deterministically ordered; their contents do not depend on wall time, hash seed, timezone or a host path.

## Evidence

### Coordinates and ownership

All addresses are linked ELF virtual addresses before load bias; the tables give file offsets separately. `functions.tsv` and `unwind-records.json` use the actual `.eh_frame` FDE and CIE records, checked against `.eh_frame_hdr`. The selected 19 FDE ranges contain 33,128 bytes; `function-bytes.json` retains the complete selected ranges. An FDE range is not, by itself, a proven source-function boundary or a whole-node denominator. Forty-nine reviewed fixed byte windows and 55 selected control-transfer sites are retained in `windows.tsv` and `transfers.tsv`; they are not a complete instruction decoder or CFG.

The original `RE-021-blake2b-compress-94` packet identifies the address-09 key and wrapper. Open PR #1373 reports mode-3 membership and the generic registry lineage; open PR #1563 reports how the shared frame constructor copies environment fields. `foundation-xor-mixer-94` already records the relevant alternate caller FDE and an excerpt ending at its hash call. These are external dependencies of the composition here. The new bodies do not claim or repeat their FDEs. The supplied local main and PR snapshot were checked for selected-address overlap; a fresh public-head check was unavailable in this static environment and is required at submission.

| Stage | Selected entry | New observation |
| --- | --- | --- |
| Entry and handler | `0x4463490`, `0x44bc770` | An incoming 20-byte value is staged into an environment; a byte-selected handler and its data are copied into the later engine object. |
| Registry providers | `0x4473320`, `0x4473600`, `0x4474990`, `0x4473710`, `0x4473c70`, `0x4473780` | Six separate adapters call the prior constructors for modes 0–5 and return a zero word plus their constructor result. |
| Revision-12 callback group | `0x4dde9b0` | Eleven allocated callback pairs are constructed; the third descriptor's three method relocations include `0x4da4e20`. |
| Publication and dispatch | `0x47f3090`, `0x4da4e20` | The provider result is installed at context `+0xe8`; the selected frame adapter calls the already documented alternate caller and cleans up its owned frame. |
| Address set | `0x43606b0`, `0x4862a40`, `0x4ad9920`, `0x4b727c0`, `0x488e250` | A separate set is cloned and extended, with full-key matching and explicit allocation and cleanup boundaries. |
| Creation lookup | `0x4da6ff0`, `0x4dd83a0`, `0x488d0b0` | A selected creation callback probes owned or borrowed registry storage for a 20-byte key and writes status `0x5e` when a match is found. |

`relocations.tsv` distinguishes symbol-free `R_X86_64_RELATIVE` records from the `memcpy` `R_X86_64_GLOB_DAT` symbol. The process seed and provider cache slots resolve to `.bss`; their file offsets and runtime contents are not invented. `prior-boundaries.json` checks only the earlier object key and two integration relocations, without reproducing the earlier function bodies.

### Revision selection and the address-09 dependency

The unsigned byte selector at `0x44bc793` compares against `0x13`; larger values take its default. `revision-cases.tsv` decodes all 20 relative jump-table entries, the default case, each case's canonical-byte store, constructor call and provider descriptor relocation. It expands the byte-level result to all 256 inputs; that expansion does not assert that all byte values are valid source enum variants.

| Raw byte | Canonical byte written | Provider mode | Address 09 under prior registry lineage |
| --- | --- | --- | --- |
| 0–1 | 0 | 0 | absent |
| 2–3 | 2 | 0 | absent |
| 4 | 4 | 0 | absent |
| 5 | 5 | 0 | absent |
| 6 | 6 | 1 | absent |
| 7–8 | 8 | 1 | absent |
| 9–10 | 9 | 2 | present |
| 11 | 11 | 3 | present |
| 12–14 | 12 | 3 | present |
| 15 | 15 | 3 | present |
| 16 | 16 | 3 | present |
| 17 | 17 | 4 | present |
| 18 | 18 | 5 | present |
| 19 | 19 | 5 | present |
| 20–255 | 255 | 5 | present on this machine-code default arm |

The last column is **conditional inference** from the earlier registry lineage, not an independently observed runtime table or a claim that a deployed chain accepts any particular raw byte. Each of the six selected adapter FDEs is independently decoded: its RIP-relative cache address, prior constructor call, and zero-plus-pointer result are in `providers.json`. For raw 12–14 the case stores descriptor `0x5721448`; its `+0x28` RELA addend is provider `0x4473710`, which calls the prior mode-3 constructor. The address-09 key at `0x574f0c0` and wrapper relocation at `0x574f0b0` are checked as prior data boundaries; this packet does not reanalyze the wrapper or constructor.

### From caller input to the frame callback

`0x4463490` saves its incoming third argument, reads 16 bytes and then four bytes through it, sets the environment discriminator at `+0x294` to 1, and writes those 20 bytes at `+0x295..+0x2a8`. `flow.json` derives the copy lengths and offsets from selected instruction operands: the handler is at engine `+0x110`, its provider data/descriptor are at engine `+0x158/+0x160`, and the selected execution data/descriptor are at `+0x218/+0x220`. The copy arithmetic assumes the resolved copy helper and intervening calls return normally without destructive aliasing; it does not identify the caller or establish a live request.

For canonical byte 12, the handler's execution-group constructor `0x4dde9b0` writes eleven data/descriptor pairs. The third descriptor is `0x57462b0`; its `+0x28` relocation points to `0x4da4e20`. The constructor asks for eleven 16-byte allocations, each followed by a distinct null branch and a failure call with alignment 8 and size 16 (`allocation-failures.tsv`). The normal stores and the exception call-site table do not establish allocator internals or every cleanup action.

In `0x47f3090`, the first selected callback must return byte 5 before the provider at `+0x158/+0x160` is invoked. The zero-plus-pointer representation returned by `0x4473710` is copied into context `+0xe8`; the routine copies a 40-byte region, but this provider itself establishes only the first two words, so no value is asserted for the remaining three words. On the selected call path, a later environment discriminator equal to 1 reaches the RELA-backed frame constructor `0x4e91cb0`, followed by the execution pair at `+0x218/+0x220`. The earlier frame-constructor result places environment `+0x295..+0x2a8` at frame `+0x60..+0x73`; this is a dependency on PR #1563, not an extra selected body here. The selected `0x4da4e20` adapter forwards that frame to the already documented `0x4dd6ea0` boundary, then invokes a dynamic payload drop and deallocates the 160-byte frame on its normal path.

Consequently, **if** the incoming 20 bytes equal the address-09 key, raw 12–14 are selected, the prior mode-3 and frame-layout findings are accepted, the relevant callbacks are not replaced, the selected validation gates admit the request, allocations succeed, and the intervening helper calls return normally, this path installs a borrowed registry whose prior lineage includes that key and hands the same key to the existing alternate caller. This is conditional static composition, not proof that a live node took the path. The existing caller excerpt shows a zero context word choosing its borrowed arm and reaching a hash call; it does not establish the final match or callback invocation for that arm. That missing edge remains open.

### Separate address-set state

`0x43606b0` tests the provider representation's first word. On zero, it takes the pointer at `+8`, adds `0x28`, and calls `0x4862a40` to clone the separate set. That helper has a zero-mask shortcut, checks selected multiplication/addition limits, and otherwise allocates and copies controls and 20-byte keys while retaining the seed word. `0x4ad9920` reserves as needed, then `0x4b727c0` consumes keys and calls `0x488e250`. The set at context `+0x80` is separate from the provider representation at `+0xe8`.

For the set extension, the selected reserve hint is `remaining` when the destination word at `+0x18` is zero; otherwise it is `((remaining + 1) mod 2^64) >> 1`. Thus a synthetic maximum unsigned word yields zero on the second arm. Whether that input is reachable in a valid container is unknown. The insertion helper hashes overlapping 64-bit key windows, filters candidate controls by a seven-bit fingerprint, and compares all 16 leading plus four trailing key bytes. It checks for zero growth capacity **before** looking for an existing key. A duplicate returns low byte 1; a new key returns 0 after updating both control locations, the two header counters and the full 20-byte key. The `0x203480` constant and relevant byte windows are retained. The exact source types and reserve helper's full side effects remain unknown.

### Creation callback and borrowed-registry membership

The sixth callback pair in `0x4dde9b0` has descriptor `0x57462e0`; its `+0x28` relocation selects `0x4da6ff0`. The handler copy places its data and descriptor at engine `+0x248/+0x250`; `0x47f347e` and `0x47f39e4` each load that pair and call descriptor slot `+0x28`. The former is on the alternate environment-discriminator path; the selected entry `0x4463490` initializes that discriminator to 1, so the initial direct-entry path takes the other arm. The latter is a separate later dispatch site. Their complete dynamic reachability and input production are unresolved.

The adapter supplies byte `0x0c` to `0x4dd83a0` and cleans up its 136-byte frame. On the retained creation-key path, that body copies 16 bytes and four bytes from a prior helper's 32-byte output into a 20-byte stack key. After testing context `+0xe8`, it passes either the owned header there or the borrowed pointer from `+0xf0` to `0x488d0b0`. The mode-3 provider above supplies the borrowed representation. The helper checks the element count, hashes all 20 bytes using runtime seed state, filters 16-byte control groups with a seven-bit fingerprint, and compares 16 plus four bytes for each candidate. It checks candidates before an empty `0xff` control and advances groups by increasing 16-byte strides. It returns low byte 1 for a full-key match and 0 on the selected empty-map or empty-control misses.

The borrowed call at `0x4dd8a74` branches to `0x4dd881c` on a nonzero result. That block writes tag 1 and status byte `0x5e` at output `+0x40`, then takes the common return path. A zero result continues at `0x4dd8a81`. Assuming a valid table and the earlier mode-3 lineage, a derived key equal to address 09 takes the match/status branch; this is a **conditional membership result**, not proof that any live request can produce the key or that this branch calls the BLAKE2b wrapper. The matching key can come from a different creation operation and must not be equated with the initial call-target bytes. The old ordinary-call runtime remains a separate dependency.

### Failure and unwind ordering

| Boundary | Selected observation |
| --- | --- |
| First callback returns a byte other than 5 | `0x47f30eb` branches to the sentinel-bearing return before the provider is invoked. |
| Second callback returns a byte other than 5 | `0x47f31bc` reaches the same error-return block after the provider representation has been copied. |
| Selected subtraction borrows | `0x47f31d3` branches to a separate external failure slot; the context publication already precedes it. |
| Third callback returns a byte other than 5 | `0x47f3212` goes to a separate tagged error-copy path. |
| Environment discriminator is not 1 or frame result is null | The first takes an alternate frame path; the second reaches a separate failure call. Their complete meanings are unresolved. |
| Set clone or extension unwinds | The LSDA interval containing `0x47f312b` and `0x47f313f` lands at `0x47f4e47`, which conditionally drops an owned provider result before continuing unwind cleanup. The set extension may already have mutated its destination. |
| Old owned map drop unwinds | The LSDA interval containing `0x47f3158` lands at `0x47f4e14`; that landing copies the new 40-byte representation to context before `_Unwind_Resume`. This is static ordering, not an observed unwind. |
| Frame body or payload drop unwinds | The adapter's two LSDA intervals land at `0x4da4e7e` and `0x4da4e63` respectively; their cleanup routes differ. |

`exception-sites.json` retains nine selected LSDA headers and 388 call-site entries, 342 with nonzero landing addresses. Action chains, catch types, the complete error algebra and external drop/allocator behavior are not interpreted. The table contains static intervals, not a runtime reachability claim.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, two-build comparison, relocation masks, helper/data closure, captured behavior and whole-ELF comparison: **not yet implemented/measured**. No captured code was executed, and no target bytes were transplanted into an implementation.

The 53 focused unittest methods passed with zero skips. Controls corrupt the full input hash; FDE and unwind-index pointers; section bounds and NOBITS mapping; jump-table and descriptor displacements; canonical byte, provider opcode, relocation type/addend and dynamic symbol name; stack/field copy relations; allocation failure targets; selected branch bytes; and LSDA encoding and ranges. Synthetic controls flip all 160 address bits, probe same-fingerprint wrong keys and deleted/empty controls across triangular groups, and exercise the reserve arithmetic at zero, adjacent values and the maximum unsigned word. These models test bounded predicates and do not execute target instructions or provide a runtime oracle.

## Results and limitations

The new evidence ties a standard-handler revision family and its borrowed provider to context publication, address-set mutation, frame construction, a creation-time registry membership check and the existing alternate runtime boundary. It does not independently prove that the selected borrowed lookup matches address 09, that the wrapper runs, or that the broad HyperEVM state transition and private-fork boundary are recovered. Runtime seeds, arbitrary callback replacements, external helpers, exception action chains and behavior equivalence remain open. The reported counts are selected evidence only, not function coverage. No component gate is requested; `evm` remains 0/4.

Next question: under the existing caller's ownership, review its borrowed-arm comparison and invocation after the retained hash call, then validate the composed address-09 route with an independently authorized target-grounded fixture.
