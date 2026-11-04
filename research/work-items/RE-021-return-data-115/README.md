# RE-021: node 115 return-data and output actions

The node 115 reconstruction can now preserve the selected return-data copy's source-bounds-before-word-charge ordering, connect its memory bytes to word access and RETURN/REVERT action construction, and preserve the resulting buffer's clone and release choices without assuming node 94's ordering.

- Component ID: `evm`; RE-021 is a bounded continuation of EVM task RE-011.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference lead `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no license for implementation reuse; no source was copied. Historical #94 clues are `RE-021-blake2b-compress-94` at commit `2fff9c5e02c5ecd6cb5062f1b23442b5ba712104` and `RE-021-precompile-input-memory-94` at commit `1439cf818cddb99add306e62da2cadb79d037705`.
- Claim status: **observed** for target bytes, indexed FDE/CIE ranges, relocations, selected branch destinations and encoded exception entries; **inferred** for opcode names, object roles and conditional composition; **unresolved** for a live caller, actual buffer aliases, callbacks and execution results.
- Scope included and excluded: the selected `0x3d`, `0x3e`, `0x51`–`0x53`, `0xf3` and `0xfd` table entries, their handlers, the common action builder, its type-1 old-action drop and the selected output-buffer clone/release callbacks. The previously researched address-09 lookup, BLAKE2b wrapper, interpreter dispatcher, memory-growth body and frame driver are dependencies, not selected function bodies. Other table variants, all transaction paths, complete fork boundaries, node/visor execution and a component gate are excluded.

## Reproduce

From the repository root, with the authenticated #115 artifact present:

```sh
python3 tools/re21_return_data115.py --out research/work-items/RE-021-return-data-115
python3 -m unittest tests.test_re21_return_data115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-return-data-115 && sha256sum -c MANIFEST.sha256)
```

To independently compare generated evidence, replace the two placeholders with different empty writable directories:

```sh
python_exec=$(command -v python3)
PATH= PYTHONHASHSEED=0 TZ=UTC "$python_exec" tools/re21_return_data115.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$python_exec" tools/re21_return_data115.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$python_exec" -m unittest tests.test_re21_return_data115
```

The historical artifact is optional and is not required by the normal generator or tests. When available, the following also authenticates it, independently checks the #94 and #115 address-09 keys and callback relocations, checks the two #94 handler FDEs and prints their selected raw instructions and decoded edges. It leaves the #115-generated files unchanged:

```sh
python3 tools/re21_return_data115.py --out <tmp-dir-a> --legacy references/can1357-hl/bin/hl-node-mainnet-new
```

The generator checks the complete #115 SHA-256 before parsing, imports the shared ELF and FDE readers, excludes NOBITS from file-backed mappings, and invokes no external program. Python 3.12.3 was used. GNU objdump 2.42 was used for manual instruction inspection only; generated evidence and tests do not parse or invoke it. No captured code is executed and no network, private key, or chain state is accessed. Source-location suffixes are sanitized in generated records; source prefix bytes are not retained.

## Evidence

### Scope and entry points

All addresses are linked ELF virtual addresses before load bias; generated files give file offsets and exclusive FDE ends. The previously mapped #115 record has key `0x0000000000000000000000000000000000000009` at `0x64c0750` and an `R_X86_64_RELATIVE` callback slot `0x64c0748` resolving to `0x5c165b0`; `address-anchor.json` independently checks this data-only dependency. Earlier lookup work associates that record with the BLAKE2b wrapper and reports a 64-byte output on its ordinary successful path. Neither the prior wrapper nor its output bytes are reselected or predicted here.

The earlier nested-CALL work identifies the pointer-table source at `0x6441f00` and the caller's interpreter dispatch. `opcode-table.tsv` independently reads the seven selected table slots and their actual relocation addends. The following bodies are new selections. Their FDEs are unwind-described ranges, not proof that every instruction in each range is reachable or that all functions have FDEs.

The intended composition is conditional: an earlier lookup packet traces an address-09 callback to a frame result; an unestablished child-to-parent handoff would install a return-data buffer; the handlers selected here can then copy those bytes to interpreter memory and construct, clone or drop a later output action. The separate old-action drop and unwind arms below are local cleanup observations. Neither the handoff nor transaction finalization is inferred from this ordering.

| Inferred role | Start VA | Exclusive FDE end VA |
| --- | --- | --- |
| Shared output drop | `0x161bc50` | `0x161bcda` |
| Shared output clone | `0x161bcf0` | `0x161bd1b` |
| Output promotion to shared ownership | `0x161bec0` | `0x161bfe8` |
| Odd-allocation output drop | `0x161c3f0` | `0x161c4ba` |
| Even-allocation output drop | `0x161c4c0` | `0x161c5a1` |
| Odd-allocation output clone | `0x161c5d0` | `0x161c617` |
| Even-allocation output clone | `0x161c620` | `0x161c66b` |
| Memory load | `0x2997410` | `0x2997548` |
| Memory store | `0x29975b0` | `0x29976dc` |
| Memory byte store | `0x29976e0` | `0x29977d4` |
| Return-data copy | `0x2997bd0` | `0x2997e58` |
| Return-data size | `0x2997e60` | `0x2997eac` |
| Output action builder | `0x29990c0` | `0x29994e1` |
| RETURN entry | `0x2999560` | `0x2999571` |
| REVERT entry | `0x29996d0` | `0x29996ed` |
| Old action type-1 drop | `0x29e15d0` | `0x29e1654` |

`functions.json` retains the complete selected body and FDE/CIE bytes, indices and body hashes. `windows.tsv`, `edges.tsv` and `indirect-transfers.tsv` are reviewed selections rather than a complete disassembly or CFG. Source descriptors reached from selected failure branches contain the suffixes `z_vendor/revm-interpreter/src/interpreter_types.rs` and `z_vendor/revm-interpreter/src/interpreter/shared_memory.rs`; this is evidence of source-path labels, not a source version, exact source body or complete private-fork matrix.

### Return-data size and copy

The table entry for byte `0x3d` relocates to `0x2997e60`. A revision-shaped interpreter byte at `+0x1a9` below 4 returns raw byte `0x2b`. On the canonical stack-count domain, an existing count of 1024 returns `0x2d`; otherwise the routine pushes the 64-bit word at interpreter `+0x160` as a zero-extended 256-bit stack value and increments the count. Names and valid revision domains remain inferred.

The `0x3e` entry relocates to `0x2997bd0`. Its selected gate order is below. The stack pointer and count are at interpreter `+0x28/+0x30`, and each word occupies 32 bytes. The top three words are destination, source offset and size. This order describes the handler *after* the existing dispatcher has charged its own base cost; it is not a total transaction-gas calculation.

| Order | Predicate or action | Selected result and already visible local changes |
| --- | --- | --- |
| 1 | Revision byte below 4 | Return `0x2b`; no handler stack decrement. |
| 2 | Fewer than three stack words | Return `0x2c`; no three-word decrement. |
| 3 | Three words available | Store count minus 3; a size with a nonzero high 192-bit part returns `0x24`. |
| 4 | Normalize source and check it | A source with nonzero high limbs is clamped to `2^64 - 1`; source plus size is saturated at that value. A resulting end greater than return-data length `+0x160` returns `0x2e`. Equality passes. |
| 5 | Calculate additional word charge | Multiply `ceil(size / 32)` by the 64-bit word at schedule `+0x28`, substituting `2^64 - 1` on product overflow. If the remaining gas at `+0x188` is lower, return `0x20` without storing that failed subtraction; equality passes. |
| 6 | Store the successful charge | Zero size returns success here, before checking destination high limbs or expanding memory. The earlier source-end check still applies. |
| 7 | Nonzero size | A destination with nonzero high limbs returns `0x24` after the word charge. Otherwise the routine checks/grows the destination window and performs the selected copy and fill operations. A nonzero growth-helper return is propagated. |

Consequently, for an independently supplied 64-byte return buffer, source 64 and size 0 pass the source check, but source 65 and size 0 return `0x2e`. A bad source and insufficient gas select the source-bound result first; an otherwise valid source with insufficient gas and a wide destination selects the gas result first. The dispatcher may already have charged gas, and later driver/error handling is outside this local ordering. The synthetic gate model tests these facts; it does not run target instructions or establish a live buffer of length 64.

`indirect-transfers.tsv` resolves the copy and fill slots to dynamic symbols `memcpy` and `memset`, and the expansion slot to the previously researched boundary `0x45244c0`. The normal-copy inference assumes the ordinary semantics of those external symbols, valid backing buffers, successful allocation/borrowing and no interposition that changes behavior. Checked range arithmetic, separate failure calls and an unwind landing are retained in the raw evidence; they do not prove their external effects or all possible exceptional outcomes.

### Shared memory and action publication

`field-lineage.tsv` decodes 18 selected field instructions. Conditional on the same interpreter object being supplied, copy, memory-load, memory-store, byte-store and action-building handlers all load a memory object at `+0x10`, use a window base at `+0x18`, and load that object's backing pointer at `+0x20`. The copy reads a return-data pointer at `+0x158`; its length access and the size handler agree on `+0x160`. These equal displacements are static observations, not proof that a particular BLAKE2b output was installed in that buffer.

The selected `MLOAD` and `MSTORE` load/store pairs and `bswap` encodings produce a 32-byte reversal between memory order and the little-endian byte order of a stack word. `byte-lanes.tsv` derives all 32 lanes for each direction from the checked instruction shapes. `MSTORE8` writes the low byte of the value word. On short stack both stores return `0x2c`; after a sufficient stack they consume two words before checking a wide offset. `MLOAD` reads and replaces the existing top word, so its wide-offset exit does not first decrement that count. Memory growth and exceptional helper behavior remain boundaries.

The `0xf3` entry passes raw status 2 to `0x29990c0`; the `0xfd` entry first requires revision byte at least 4 and then passes status 16 to the same body. After two words are available, the builder consumes offset and size. A nonzero high size limb returns `0x24` before the zero-size test. For zero size, a wide offset is not inspected and the builder proceeds with an empty output representation. For nonzero size, a wide offset returns `0x24`; the required memory-growth helper, checked additions and allocation have separate failure exits. On the selected successful nonempty path it allocates `size` bytes and copies the indicated memory slice into the new representation.

The selected output-action gates and their local effects are:

| Order | Predicate or operation | Result or local effect |
| --- | --- | --- |
| REVERT entry | Revision byte below 4 | Return `0x2b` without entering the shared builder. |
| Builder stack | Fewer than two words | Return `0x2c` without the two-word decrement. |
| Builder size | Two words available, high size limb nonzero | Consume both words and return `0x24`; do not publish a replacement. |
| Empty result | Size is zero after the size-width check | Ignore offset width, retain an empty representation and proceed to action replacement. |
| Nonempty result | A high offset limb is nonzero | Drop the temporary empty representation and return `0x24`; do not publish a replacement. |
| Expansion | A required growth-helper call returns nonzero | Drop the temporary representation and propagate its result; any changes inside that helper are outside this packet. |
| Nonempty allocation | Checked arithmetic or allocation reaches a failure boundary | Enter its separately recorded failure or unwind path; ordinary publication is not established. |
| Publication | Allocation/copy and selected old-action cleanup return normally | Install the new representation and write status 2 for RETURN or 16 for REVERT. |

Before replacing the old action, the builder writes zero to interpreter `+0x149`; it then invokes any old action drop. On the normal path it installs the replacement and stores the selected status at `+0x110`. The LSDA entry covering the relevant old-action drop calls points to `0x2999436`, which installs the replacement and status before reaching the unwind-resume boundary. This observation describes selected static landing code; it does not prove exception action-chain semantics, transaction atomicity or the effects of dynamic destructors.

When the old action has the selected tag 0, a nonzero first word whose low 32 bits equal 1 selects the direct call to `0x29e15d0`. That body conditionally calls an inner callback from object `+0x50`, performs a locked decrement through the pointer at `+0x48`, calls the relocated last-reference boundary `0x5bde820` if the decrement reaches zero, and reaches the release boundary with size `0xd0`. The first callback's LSDA landing at `0x29e161f` also performs the decrement, conditional last-reference call, release and unwind-resume sequence. A distinct action-index-1 landing is recorded but not interpreted. These statements assume a valid object and do not establish the dynamic callback, release implementation or concurrent owner state.

### Conditional output-buffer lifetime

`output-vtables.tsv` links the nonempty action builder's two relocated pointer slots to three file-backed method tables. After copying the memory slice, the builder tests the allocation pointer's low bit. An odd pointer selects table `0x64040c0`; an even pointer selects `0x64040e8` and stores the pointer with bit 0 set in the owner word. The observed first and `+0x20` table slots relocate to the following selected bodies. Method names and the meaning of these tables are inferences from the field moves and reference operations, not recovered Rust type declarations. The callback bodies could be shared dependency code; their crate identity, version and license provenance are not established here.

| Selected representation | First slot: clone-shaped method | `+0x20` slot: drop-shaped method |
| --- | --- | --- |
| Odd allocation | `0x161c5d0` | `0x161c3f0` |
| Even allocation | `0x161c620` | `0x161c4c0` |
| Promoted shared owner, table `0x6404008` | `0x161bcf0` | `0x161bc50` |

For either direct table, a clone seeing an already untagged owner performs a locked increment at owner `+0x10`; a nonpositive signed result follows a separate failure boundary. A tagged owner reaches `0x161bec0`, which forms `(data pointer - allocation base) + length`, branches on carry from the addition, allocates a 24-byte header, writes the allocation base and length-shaped word, and initializes its reference word to 2. The preceding subtraction has no separate carry check in this slice, so the span interpretation assumes an ordered input. A locked compare-and-exchange publishes the header to the original owner slot. On the selected success arm the clone receives the same data pointer and length with the shared table. On a failed compare-and-exchange, the body increments the winning header's reference word; if that increment passes its signed-result check, it uses the winning header for the clone and releases its unused 24-byte allocation. This is a conditional static account of the selected paths, not an execution or a proof of arbitrary concurrent schedules.

The direct drop callbacks distinguish tagged owners from shared headers. The even-allocation callback clears the tag bit before the direct release; the odd-allocation callback retains the originally odd allocation address. For a valid ordered span whose data pointer still equals its allocation base, either direct path supplies the payload length as the release size. Once the owner has been promoted, the drop methods decrement the shared reference word and only its zero result reaches the payload and 24-byte header release path; the shared-table drop follows the same last-reference shape. The selected records include overflow/sign checks, allocation failure, reference-count failure and LSDA landings. They do not close the external allocator, all aliasing, dynamic table replacements or exception action chains.

A synthetic example uses a 64-byte byte sequence, source 0, size 64 and destination 0. If the buffer and memory conditions above hold and the separately supplied word-price is 3, the local copy charge is 6 before any memory-growth charge; RETURN can then copy those 64 memory bytes into a new output representation. This is a model example with arbitrary bytes, not a BLAKE2b digest or an execution receipt.

### Release-specific cross-check

The historical `RE-021-blake2b-compress-94` clue remains bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its maintainer review left the captured-execution gate pending; no captured code was executed here. The earlier #115 lookup packet, rather than this packet, examines the target compression candidates. Its key is at `0x574f0c0`, callback relocation `0x574f0b0 -> 0x4e9d2a0`, and `0x3e` slot `0x56ac978` resolves to FDE `0x26bdc30..0x26bdddb` (file offset `0x26bcc30`). The optional check also authenticates #94's `0xf3` slot and action-builder FDE. It compares the 20-byte key with #115's independently extracted key while keeping both releases' relocations and coordinates distinct.

In the selected #94 handler, the charge and successful gas store at `0x26bdcce..0x26bdcf5` precede its source-bound and mode checks at `0x26bdcff..0x26bdd2a`. Its nonzero mode branch bypasses the recorded out-of-bounds status write. In #115, the selected source-bound branch at `0x2997c7c` precedes the additional word charge at `0x2997c96`, with no corresponding mode bypass in this selected handler. The old action builder writes its status-shaped byte at `0x26be8d2` before its old-action drop call at `0x26be926`; the #115 builder's selected status store occurs after its drop on normal return, with a separate landing store. Field offsets, status encodings, state representations and source-level enum identity differ or remain unresolved; this is a static ordering comparison, not behavioral equivalence or a claim about reachable revision values.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, repeat builds, normalization masks, helper/data closure and native or whole-ELF comparison are **not yet implemented/measured**. The extractor and models operate only on static bytes or synthetic inputs; no captured target code is executed or emulated.

The focused tests include altered full hashes, instruction and displacement corruption, out-of-range/ambiguous/NOBITS mappings, damaged FDE and LSDA data, missing/duplicate/wrong relocations, all 160 individual address-key bits, vtable and atomic-exchange corruption, 512 one-bit word-lane examples, 8,193 bounded copy-charge values, and stack, size, source, gas, offset and zero-length ordering controls. Model assumptions are explicit and do not substitute for a target differential test.

## Results and limitations

The selected corpus contains 16 FDE ranges totaling 3,865 bytes, 7 opcode slots, 41 instruction windows, 87 selected relative transfers, 25 indirect transfers, 3 output method tables, 5 shared-table references, 18 field instructions, 64 byte-lane rows, 3 sanitized source descriptors and 10 LSDA headers with 42 call-site entries. These are bounded selections, not a complete CFG, a function-coverage denominator or a component-completion metric. The focused suite passed 45 tests with zero skips; full test discovery was not run under this run's memory constraint.

The actual runtime fork, dispatched table, return-buffer producer, address-09 frame-to-parent buffer alias, memory ownership, dynamic callbacks, complete exception actions, transaction settlement and independently authored Rust implementation remain open. The first `evm` component task covers the broader reth/revm private-fork boundaries and state-transition inputs; this packet does not complete it, requests no gate, and leaves `evm` at 0/4. Next question: establish, through an unowned #115 call boundary, how a successful address-09 child result installs its bytes into the parent return buffer and when its state and gas changes become final.
