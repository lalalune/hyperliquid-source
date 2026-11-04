# RE-017: node 115 block execution to selected state-root inputs

This packet makes it possible to reconstruct one selected block path from an outer wrapper through begin-state mutation, a guarded per-item update, the state-root decision and captured inputs, and the return of a result fragment, while retaining the unproved connection to the previously mapped loader as an explicit condition.

- Component ID: `abci`; this state-root question also supports RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` was used for navigation only, with no source copied.
- Claim status: the instruction bytes, operands, relocation entries and Location suffixes are observations; source-level labels, the arithmetic interpretation and value-flow joins below are inferences subject to the stated conditions.
- Scope included and excluded: the selected normal route and the explicitly listed branch/error paths, one guarded item-state handler, the root selector, its capture table, one optional-field callback, one leaf-format branch and a return projection. This is not the process entrypoint, every action or state transition, the complete tree digest, a runtime trace, or a component gate.

## Reproduce

From the repository root, with `artifacts/node/115/hl-node` and the checked-in `tools/elf_index.py` and `tools/fde_extents.py` present, use previously nonexistent output directories:

```sh
python3 tools/abci_block_root115.py --out research/work-items/RE-017-abci-block-root-115
python3 -m unittest tests.test_abci_block_root115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/abci-block-root-check
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_block_root115.py --out work/abci-block-root-check/one
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_block_root115.py --out work/abci-block-root-check/two
diff -r work/abci-block-root-check/one work/abci-block-root-check/two
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-abci-block-root-115 work/abci-block-root-check/one
(cd research/work-items/RE-017-abci-block-root-115 && sha256sum -c MANIFEST.sha256)
```

Generation and the focused suite were run on x86-64 with Python 3.12.3, including with a PATH containing Python and no binutils. The generator checks the complete input digest before creating output and uses only the standard library and the two repository parsers; it neither executes the target nor invokes another program. GNU objdump 2.42 was used for human inspection only, never parsed by the generator or tests. There are no network, key, chain or node-execution effects.

`functions.json` retains the bytes and SHA-256 of each selected FDE extent; `windows.json` pins selected instruction windows; `transfers.tsv` decodes selected instruction-aligned direct, relative-slot and vtable-offset transfers. `captures.tsv`, `jobs.tsv`, `projection.tsv`, `projection.json`, `locations.tsv`, `constants.json` and `summary.json` come from ELF bytes and relocations. Synthetic boundary cases are confined to the focused tests and are not observations from an executed node. The manifest covers this README and all generated files.

## Evidence

All code, data and relocation addresses in this section are linked ELF virtual addresses; the generated records include file offsets. FDE extents are reconciled between `.eh_frame` and `.eh_frame_hdr` and checked for overlapping FDEs, but unwind ranges do not prove function boundaries, complete CFGs or all callers. The 32 extents, 64 pinned windows and 144 selected transfers are bounded records, not a coverage denominator. Labels in the generated records describe observed roles and are not recovered Rust names. External and dynamically bound helpers remain boundaries.

### Selected route

| Stage | Coordinates | Observation |
| --- | --- | --- |
| Outer wrapper | `0x4f122c0`, call `0x4f1234c` | When byte `[rsi+0x20]` is zero, the wrapper passes its original output pointer and its `rdx` argument to `0x4fcb590`, then returns the same output pointer. A second selected call at `0x4f12b02` reaches the same callee after a different TLS-dependent path; that entire alternate path is not mapped. |
| Upper block caller | `0x4fcb590`, call `0x4fcb795` | Loads an owner pointer from its input `+0x20`, forms owner `+0x6b0`, and passes that context to the next adapter. The later load at `0x4fcb86d` uses owner `+0xb00`. |
| Adapter and engine | `0x56186c0` to `0x5a06600` | The adapter forwards the context; the engine loads the state pointer at context `+0x450`, hence the upper caller's later owner `+0xb00` denotes the same slot by offset arithmetic (`0x6b0 + 0x450`). This equality is about addresses, not proof that the slot remains unchanged across calls. |
| Entry checks and begin | `0x5a0668e` through `0x5a067ad`; `0x5483f50` | The entry reads a qword tag at state `+0x1c58`, a qword target at `+0x1c60` and a qword at `+0x28`. With tag exactly 1, a smaller target takes the past-error path and an equal target takes a distinct early exit. The selected begin helper compares three input words against state `+0x60..+0x68`, conditionally replaces them while saving the old words at `+0x6c..+0x74`, saturating-increments `+0x28`, clears the qword at `+0`, and stores one argument at `+0x30`, `+0x1978`, and `+0x1a98`. Its `begin_block` literal is at `0x929dad`. The replacement is a strict lexicographic increase using a signed first 32-bit word and unsigned second and third 32-bit words. |
| Item collection and join | `0x54864a0`, `0x564bab0`, `0x59618e0`, `0x4e44ef0` | The reserve path uses 32-byte elements, checks available capacity and returned element count, and has grow and failure paths. A later join compares two lengths; equal lengths produce spans with 40- and 24-byte strides, while mismatch calls the failure helper and reaches `ud2`. The item types and all action kinds are unresolved. |
| One guarded item handler | `0x5961924` to `0x5868030`, call `0x586816e` to `0x560dbb0` | The guard calls a relative-slot predicate with pointers derived from the same state object and branches around the handler if the predicate returns zero. In the selected nonzero branch, the handler saturating-increments state `+0x16b0` before its inner calls; if the returned 16-bit tag is `0x1a2`, it also saturating-increments state `+0x16b8` and returns that tag. For other tags it copies a `0x70`-byte result. The caller treats `0x1a2` separately before the common continuation. |
| End and hash | `0x5a077e1` to `0x5a08720` | After the selected middle work, the engine calls the end selector. The selector either takes a guard/early-return path, skips hashing, or calls `0x548d8c0` and forwards its 32-byte output with the current `+0x28` word to `0x5a03fa0`. The history wrapper's comparison against `0x33` is an observed threshold, not a proven complete retention policy. |
| Return projection | `0x5a077e6..0x5a0792d`; `0x4fcb79a..0x4fcbbb7` | The engine combines old and new tag information and conditionally compares the payload before writing its trailing result byte. On the selected normal return, 16 bytes plus the following 8 bytes beginning at engine-result `+0x18` are copied through upper-caller stack slots into outer-result `+0`; `projection.tsv` contains all 25 checked operands. This projection is conditional on intervening calls preserving those stack slots and is not a claim about the fragment's source-level type. |

The two saturation idioms can be checked in the pinned windows. For example, at `0x560dbd3` the bytes `48 ff c0` increment the first word, and at `0x560dbdd` the bytes `49 0f 44 c5` select all ones on wrap before the store at `0x560dbe1`; the second word uses the same conditional move after the tag test. This is an unsigned saturation inference from x86 flags and instruction order, not a dynamic test. Other calls may change the same state through aliases; the synthetic counter model describes the local stores under that limitation.

The trailing engine-result byte at `+0xf8` has a separate, exactly selected bit-level rule: take the low 32 bits of the old and new tags; if their bitwise AND is nonzero, write 1 when the old and new payload qwords differ and 0 when they match; otherwise write the low byte of their bitwise OR. For canonical tags 0 and 1 this is a change indication. For other bit patterns it need not be boolean; the focused tests include both disjoint and truncated tag bits. Calls before this comparison are not assumed to preserve the fields unless stated.

### Root decision and failure ordering

Let `n` be the qword read from state `+0x28` in `0x5a08720`, `tag` the **32-bit** word at `+0x1c58`, `target` the qword at `+0x1c60`, `mode` the dword at context `+0`, and `period` the qword at state `+0x4538`. All comparisons of `n` and `target` below are unsigned. This table describes the selector itself; it does not bypass the earlier engine checks.

| Condition in instruction order | Selected consequence |
| --- | --- |
| `n` is not a multiple of 10,000, `tag == 1`, `target < n` | First past-target failure at `0x5a08dc3`, before the mode check. |
| First check did not fail and `mode == 2` | Store raw sentinel `0x8000000000000000` and return before the second past-target check. |
| `mode != 2`, `tag == 1`, `target < n` | Second past-target failure at `0x5a08ddc`; for a periodic `n` this is the first such check encountered. |
| No prior exit, and either `n` is a multiple of 10,000 or `tag == 1` and `target == n` | Call the hash adapter without the interval division. |
| No prior exit, no special condition, `period != 0` | Divide `n` by `period`; zero remainder calls the hash adapter, and nonzero remainder takes the non-hash continuation. The code selects 32- or 64-bit division based on the high halves of `n | period`. |
| No prior exit, no special condition, `period == 0` | The reached x86 division has a zero divisor; any exception handling or validity invariant is outside this static packet. |

The two failure sites reference the same diagnostic literal at `0x929b14` and the `l1/src/exchange/exchange.rs:607:17` Location; the earlier engine equality exit has a separate `l1/src/abci/engine.rs:168:13` Location. The engine tests the full 64-bit tag, the end selector tests 32 bits, and the upper caller initially tests one byte. Do not equate their behavior for malformed representations.

The periodic test's multiply constant is `0xd288ce703afb7e91`, rotate is 4 and unsigned limit is `0x68db8bac710cc`. Its inverse modulo `2^64` is 625. For an input not divisible by 16, rotation places nonzero low product bits above the limit; otherwise write `n = 16*k`. The comparison accepts exactly `k = 625*t` for `t` at most `floor((2^64-1)/10000)`, so it accepts precisely unsigned multiples of 10,000. The suite checks this inferred identity in 105,540 selected evaluations, including both ends of the u64 range; the proof, not sampling alone, supplies the general statement.

As a conditional cross-stage consequence, if the entry tag is the valid qword value 1 and `target == old_n + 1`, the earlier checks permit it and the begin increment makes the target equal to the new `n`; the selector's special branch then applies **if intervening helpers preserve the tag, target and counter**. A target already equal at entry takes the earlier exit instead. The suite models both paths without executing machine code.

### Captures, dispatch and selected serialization

The selected hash call chain is `0x548d8c0` -> `0x4e47350` -> `0x4e34320` -> `0x54423c0` -> `0x57c3b30` -> `0x5b37320`. The straight-line capture setup contains 74 contiguous state-relative pointers. The first descriptor uses a group of 16 pointers; the remaining 58 descriptors each use one subsequent pointer, giving 59 descriptor pairs and 45 distinct descriptor tables. The allocation is 1,416 bytes, or 59 slots of 24 bytes, initialized with a sentinel. These are static setup counts, not a claim that every job executes.

For the selected serial worker, a sentinel slot is initialized through the table's `+0x20` method and visited through `+0x18`; a status byte other than 4 sets the stop byte. The builder calls the reducer only after status 4; the selected failure branch zeroes its local result representation. A parallel/split route exists and is not exhaustively modeled. `jobs.tsv` resolves each method from a unique `R_X86_64_RELATIVE` relocation and lists the capture offset and descriptor size/alignment without claiming all callback bodies.

Descriptor index 13 captures state `+0x1c58`; its 16-byte descriptor uses visitor `0x4d3ebe0` and constructor `0x4d3e540`. Index 26 captures `+0x1c68` and uses a different visitor. The common constructor allocates two 24-byte sentinel slots and has an allocation-failure path. In the index-13 visitor, a 32-bit tag equal to 1 makes the first child receive the eight-byte payload at field `+8`, and then the second child receives the eight-byte literal 1. For other tags the first child is bypassed and the second receives the eight-byte literal 0. Before this, invalid container state returns status 1 or 3; the payload writer must return status 4 before the marker step. Those statements describe selected writes to child state, not the final tree hash or a verified Rust enum.

After reduction, `0x41c5140` has a selected branch for an input whose first byte is not 1. It passes the following 32 bytes to `0x2eabb50` with the shortening flag zero. The formatter writes `0x`, then two lowercase hexadecimal characters per input byte using the table at `0x455d40`, for 66 bytes total. On the successful `0x41c6110` writer path, the emitted bytes are `d9 42` followed by those 66 ASCII bytes; the resulting 68 bytes feed the digest update/final pair. The helper carries a `blake3/src/lib.rs:861:33` Location and initializes with the 32 bytes recorded in `constants.json`, supporting a BLAKE3-family inference. The exact full digest algorithm, all serializer variants and final digest values remain unvalidated.

### Relationship to the earlier loader and release 94

The separate pending loader packet `RE-017-abci-loader-handoff-115` reports that a selected node-115 loader branch clears state `+0x10e8` and that two subsequent projections preserve the 16-byte fields at `+0x10e8` and `+0x10f8` as expanded-object `+0x1c58` and `+0x1c68`. This packet independently observes both latter offsets as hash descriptor inputs, and observes the first as the engine and end-selector field. **Matching offsets are not proof that the constructed object is the runtime object read by this block path.** The prior loader FDEs, GOT slots and call sites are not repinned or counted here; pointer identity and intervening writes are the next join to establish.

The older RE-017 state-link record belongs to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` and can be inspected from repository history at commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`. It records `state.rs:107:37` and a result comparison with 2; the separate node-115 loader packet identifies `state.rs:123:37` and a different comparison with 1. Those are release-specific reports, not a proof of equivalent tags, addresses or layouts. This packet does not use the #94 binary or transfer its bytes or offsets to #115; all new coordinates and behavior above were independently extracted from the authenticated #115 ELF.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler/linker options and two-build comparison: not yet applicable. Raw and normalized binary comparisons and masks: not yet measured. The selected raw target bytes are retained as evidence and are not transplanted into an implementation. Closure of helper semantics, dynamically bound targets, all descriptor callbacks, relocations/vtables/data and whole-ELF comparison remains incomplete.

## Results and limitations

The focused suite passed 24 tests with zero skips, including a bad or missing input with no output, changed bytes in every pinned window, invalid and NOBITS ranges, overlapping FDEs, duplicate/non-relative relocations, corrupted descriptor instructions and offsets, Location corruption, signed and unsigned begin-word boundaries, counter saturation and tag neighbors, noncanonical result-tag bits, the ordered root branches and the exact synthetic leaf preimage. Two full regenerations with different hash seeds and time zones matched byte-for-byte under a Python-only PATH. The artifact digest/signature verification and catalogue check passed. No full repository test suite, target execution, container run or hosted CI result is claimed.

This is one selected path with a meaningful state-update and root-input map, not all begin/action/end-block behavior or all root inputs. The entrypoint above is not the process entrypoint; the predicate internals, other item variants, helper effects and full hash remain open. No component gate is requested. Next question: without re-owning the loader packet's functions, establish the constructed expanded object's pointer flow into the upper caller's owner `+0xb00` slot, then prove which intervening helpers can alter fields `+0x28`, `+0x1c58` and `+0x1c60` before the end selector.
