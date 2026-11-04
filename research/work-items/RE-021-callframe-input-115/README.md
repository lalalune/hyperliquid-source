# RE-021: node 115 nested CALL input to address-09 BLAKE2b lookup

The selected node #115 path shows how a nested `CALL` can pass a 213-byte slice formed by `CALLDATACOPY` and a low-160-bit target of 09 into the existing BLAKE2b precompile lookup when their backing buffers coincide, enabling the interpreter's stack, memory, gas and frame handoff to be reconstructed together.

- Component ID: `evm`; RE-021 is a bounded extension of RE-011, not an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. Historical packet commit `2fff9c5e02c5ecd6cb5062f1b23442b5ba712104`. No reference-source implementation was copied.
- Claim status: ELF bytes, selected relocations, FDEs, instruction operands and branch destinations are observations; opcode names, field roles and the conditional composition are inferences; actual bytecode, live registry contents, backend choices and whole-state behavior are unresolved.
- Scope included and excluded: an ordinary nested `CALL` on the direct-registry path, with a possible preceding `CALLDATACOPY`, its stack/range validation, memory growth, host gas preparation and child-frame publication. Existing driver, frame, lookup, schedule initializer and precompile code are handoff boundaries, not newly selected functions. This is not a transaction-entry-to-persistence trace, a census of all call variants, a full reth/revm fork map or proof that a live input reaches address 09.

## Reproduce

From the repository root, with the authenticated node #115 artifact present:

```sh
python3 tools/re21_callframe_input115.py --out research/work-items/RE-021-callframe-input-115
python3 -m unittest tests.test_re21_callframe_input115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-callframe-input-115 && sha256sum -c MANIFEST.sha256)
```

For repeatability, substitute two empty writable directory names for the placeholders. Resolve the Python interpreter before clearing `PATH`; the extractor and focused tests invoke no external programs.

```sh
python_exec="$(command -v python3)"
PATH= PYTHONHASHSEED=1 TZ=UTC "$python_exec" tools/re21_callframe_input115.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$python_exec" tools/re21_callframe_input115.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$python_exec" -m unittest tests.test_re21_callframe_input115
```

An optional historical comparison authenticates the separate #94 artifact before reading its record, wrapper call and compressor relocation. It prints the comparison and writes the same #115 evidence files; the ordinary command and tests require #115 only.

```sh
python3 tools/re21_callframe_input115.py --out <tmp-dir-a> --legacy references/can1357-hl/bin/hl-node-mainnet-new
git show 2fff9c5e02c5ecd6cb5062f1b23442b5ba712104:research/work-items/RE-021-blake2b-compress-94/README.md
```

Observed environment: Python 3.12.3, Linux x86-64. GNU objdump 2.42 was used only for manual instruction interpretation; generated files and tests neither invoke it nor parse its output. The extractor verifies the entire artifact SHA-256 before parsing, imports the repository's `elf_index` and `fde_extents` readers, excludes SHT_NOBITS from file-byte reads, verifies unique relocations and fails on unexpected byte shapes. It is not an x86 emulator. No node, visor or captured machine code was executed, and no network or chain state was accessed.

## Evidence

Addresses are ELF virtual addresses before load bias; file offsets are measured from the start of the corresponding artifact. `functions.tsv` records actual indexed FDE/CIE coordinates, exclusive extents, file offsets and body hashes; `bodies.json` retains all selected body bytes. An FDE is an unwind-described range and does not establish a complete source function or reachability. `windows.tsv` gives fixed checked byte windows; `edges.tsv` decodes only the explicitly selected relative branches, calls and RIP references. `relocations.tsv` includes raw RELA entries and dynamic-symbol names, and `literals.tsv` gives the raw bytes of the relevant key and schedule fields. `exceptions.tsv` decodes selected LSDA call-site records without interpreting action chains. `sources.tsv` records selected relocation-resolved location descriptors with sanitized path suffixes. These files are a selected static analysis, not a complete CFG.

### Newly examined FDEs and the dispatch boundary

| Inferred role | FDE start VA | End VA, exclusive | Key evidence |
| --- | --- | --- | --- |
| Opcode 37 input copy | `0x29977e0` | `0x2997a47` | Three-word stack gate, copy charge, source selection, zero fill. |
| CALL range construction | `0x29998f0` | `0x2999afd` | Four additional words, both ranges and memory growth. |
| Opcode f1 CALL | `0x299b050` | `0x299b3f3` | Target projection, static-value gate, host call and child action. |
| Host call preparation | `0x4335cf0` | `0x4336560` | Account load, dynamic fees, forwarding cap and stipend. |
| Lazy code preparation | `0x433c700` | `0x433c823` | Conditional account +`0x70` pointer publication. |
| Memory expansion | `0x45244c0` | `0x452465e` | Saturating cost arithmetic, ordered metadata/gas writes, zero fill. |
| Capacity reservation | `0x5be8d40` | `0x5be8dce` | Required capacity and allocation boundary. |
| Alternate input copy | `0x5be8e10` | `0x5be8f68` | Borrowed-buffer bounds, prefix copy and zero fill. |

The previously mapped driver loads a relocated 256-entry pointer table from `0x6441f00` at `0x29a1535`, copies it into an allocated table, retains the allocation in its context at `0x29a17f5`, and reloads it at `0x29a336c`. At `0x29a3390` it fetches a byte, advances the instruction pointer, loads a function pointer indexed by that byte, subtracts the corresponding two-byte base charge and calls the function. The two selected `R_X86_64_RELATIVE` table slots are `0x64420b8` (index `0x37`, addend `0x29977e0`) and `0x6442688` (index `0xf1`, addend `0x299b050`). The labels `CALLDATACOPY` and `CALL` are inferred from the index and behavior, not recovered source names. Normal relocation, a live context using this table and no later mutation are required for this composition.

The vector copied from `0x601aac` supplies the two-byte value at `0x601ab6`; the corresponding table offset for index `0x37` is `0x86e`, and the value is 3. This is a selected construction path, conditional on the later table retaining that value. The dispatcher's subtraction at `0x29a33b0` writes its result in place before the carry branch at `0x29a33b7`: if the gas word is 2 and charge is 3, its local stored value wraps to the maximum u64, the driver sets AL to raw `0x20`, and the opcode handler is bypassed. Later cleanup or overwrites are not inferred.

### Input copy and range gates

All rows are reached only after the rows above them and relevant allocation/borrow operations succeed. Stack words below are 256 bits, stored in four little-endian 64-bit limbs; raw result bytes are not asserted to be original enum names.

| Stage | Predicate or operation | Observed result or local state change |
| --- | --- | --- |
| Copy stack | Fewer than 3 words | Return `0x2c`; no three-word decrement. |
| Copy stack | At least 3 words | Consume destination, source offset and size; high size limbs return `0x24`. |
| Copy word charge | `ceil(size/32) * schedule[+0x28]` | Multiplication overflow substitutes maximum u64; subtraction failure returns `0x20` without storing the failed subtraction. |
| Copy empty | Size is zero | Return success before testing destination or source offset high limbs and without expanding memory. |
| Copy destination | Nonzero size and a high destination limb is nonzero | Return `0x24`; otherwise calculate required words, with a saturated end on addition carry, and expand if needed. |
| Copy source | A high source limb is nonzero | Use maximum u64 as the source offset. |
| Copy bytes | Direct input and valid materializable ranges | Copy the available source prefix and zero-fill the remaining requested bytes. The zero-size shortcut above takes precedence. |
| Alternate input | Input representation selects the helper at `0x5be8e10` | Check backing and slice bounds; use the same prefix/zero-fill shape on its normal path. Bounds, overflow and borrow failures reach separate helpers. |
| CALL initial stack | Fewer than 3 words | Return `0x2c` before the initial decrement. |
| CALL static value | After the first 3 words have been consumed, value is nonzero and bit 0 of the static-context byte is set | Return `0x27`; the four range words have not been consumed. |
| CALL range stack | Fewer than 4 words remain | Return `0x2c`; the initial 3 words remain consumed. |
| CALL size | A high limb of the corresponding input or output size is nonzero | Return `0x24` even when the low limb is zero. |
| CALL zero size | Size is zero after the size-width check | Ignore the corresponding offset's high limbs and use the all-ones empty-range sentinel. |
| CALL nonzero range | A high offset limb is nonzero | Return `0x24`; otherwise expand memory when necessary. A later end-add carry reaches a separate error helper, conditional on expansion returning. |

For a nonempty successful input range, the helper returns the start and exclusive end after incorporating the interpreter's memory-base field; it returns output start/end separately. The caller stores input start/end at child-frame +`0x58` and +`0x60`, writes zero at +`0x50`, and stores output bounds at +`0x70` and +`0x78`. `lineage.json` extracts the displacements of 25 specific instructions and checks the helper-result, stack-spill, frame and router field relationships. Its relations depend on the selected normal control flow, not just equality of numeric offsets. The bound check in the earlier-owned router subtracts start from end, compares end with its backing length and, on an invalid slice, supplies length zero to the callback. Slice lifetimes, external `memcpy`/`memset` behavior and aliasing remain assumptions.

### Memory, host gas and target projection

For a materializable monotonic expansion, the selected memory helper computes the new total from saturating u64 operations:

```text
linear = min(words * schedule[+0x50], u64_max)
square = min(words * words, u64_max)
total = min(linear + floor(square / schedule[+0x58]), u64_max)
delta = total - previous_total
```

A zero divisor takes a separate failure helper. The stores at `0x452451a` and `0x4524524` update the word count and new total **before** the gas subtraction at `0x452452e`. On insufficient gas the helper returns `0x21` without updating the gas field, yet those metadata writes have occurred; the backing-buffer resize has not. On success it stores remaining gas, checks byte-count and backing-base overflow, optionally reserves capacity, and zero-initializes the new range. The backing borrow counter and exceptional cleanup are separate state, not a claim of successful whole-transaction persistence. A nonmonotonic prior total is outside the model.

The schedule construction boundary stores 3 at +`0x28`, 3 at +`0x50`, 512 at +`0x58`, 64 at +`0x70`, 9000 at +`0x78`, and 2300 at +`0xc0`. The earlier preflight packet associates one normally initialized mode-13 schedule with these fields; this packet does not establish the live selected schedule. As a synthetic arithmetic example, copying 213 bytes to offset zero from an adequately long direct source, with initially empty memory and these fields, has 7 words: the conditional base, copy and expansion charges are 3, 21 and 21, respectively. The resulting 45 covers these copy-related charges only, not preceding bytecode, CALL costs or the precompile. It is not a captured execution.

The CALL takes requested gas, target and value as its first three words. High requested-gas limbs select maximum u64. The target is projected to the low 160 bits in big-endian order at `0x299b130` and stored at frame +`0x90..+0xa3`; the upper 96 bits do not participate. Thus any 256-bit target whose low 160 bits equal 9 forms the same 20-byte key as `literals.tsv`. The same key is also copied to frame +`0xa4` on this path.

The host helper first charges schedule +`0x78` when value is nonzero; a borrow reaches raw `0x20`. It calls the account-loader relocation at `0x4335db5`, then can call the selected lazy code helper. Other access and account-dependent charges are conditional on inputs and are not reduced to a universal number here. If earlier charges and account handling pass, the selected revision-gated cap is `remaining - floor(remaining / schedule[+0x70])`, and the amount charged to the caller is the lesser of that cap and requested gas. With a nonzero value the returned child amount can add schedule +`0xc0` with saturation. A zero cap divisor and account-loader failures have separate branches. The models exercise these conditional calculations only; they do not assert actual account availability, runtime gas or fork membership.

### Child action and composition with the prior lookup

On the successful path, `0x299b2a8` requests a `0xd0`-byte frame allocation. Allocation failure reaches a separate helper. The frame is copied, then the handler stores action tag 1 at interpreter +`0xb8`, its pointer at +`0xc0`, and byte 0 at +`0x110`; it returns raw `0x04`. Replacement of an existing action can invoke cleanup. The LSDA entry for the selected action-publication region points to a landing path that publishes the new action and resumes unwinding; it is not an ordinary success return.

The earlier driver reads this action at `0x29a33e7`, follows the zero-byte action branch, and, subject to the intervening counter/borrow checks, passes the action tag and pointer to the prior frame at `0x29a3b13`. The prior frame takes variant 1, checks depth, performs its transfer gate where required and calls the router at `0x296e9c0`. The router addresses frame +`0x90` as its lookup key, looks it up through `0x2a6c360`, then calls the returned record's +`0x18` field. Its slice path uses the frame's +`0x50`, +`0x58` and +`0x60` fields. PR #2049, `RE-021-blake2b-lookup-115`, owns and analyzes these driver, frame, registry and callback FDEs; the short windows here are interface checks, not a second implementation of those functions.

That prior packet derives address-09 registry installation for certain builder modes and maps success, error and checkpoint restoration. A lookup hit and the callback's 213-byte length check are conditional on normal relocation and initialization, the relevant registry mode, normal frame transfer, valid backing bounds, a preserved frame and no intervening mutation. Relating a prior copy to the bytes borrowed by the router also assumes that its backing buffer and the interpreter's written buffer are the same object; this packet does not close that aliasing relationship. In particular, a static opcode table does not prove that any real program executes `CALLDATACOPY` immediately before `CALL`, that the selected buffer contains 213 bytes, or that the callback returns normally.

### Historical comparison and exception boundaries

Historical node #94 has SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional digest-checked comparison reads its key at VA `0x574f0c0`, file offset `0x574d0c0`, and #115's key at VA `0x64c0750`, file offset `0x64be750`; both are 19 zero bytes followed by `09`. The #94 record's slot at `0x574f0b0` has addend `0x4e9d2a0`. Its wrapper's call at `0x4e9d3bd` uses relocation slot `0x5776f28` with addend `0x4e9a8a0`, the historical compression candidate. The #115 record's corresponding callback slot is `0x64c0748`, addend `0x5c165b0`, which calls the adapter through `0x64eaee8`, addend `0x5c16650`. The wrappers' separately read length comparisons both encode 213, but their instruction forms, layouts and coordinates differ. The old compression candidate is not copied or claimed equivalent to a #115 body; the earlier #115 packet separately records its own backend clues.

The eight selected FDEs contain six LSDAs with 37 call-site entries. The decoded records include cleanup landing pads for the CALL action, input copies and memory expansion. `exceptions.tsv` retains their raw bytes and offsets; action chains, destructor internals and the behavior of all external failure helpers remain unresolved.

The #115 failure paths also retain these distinct source-location witnesses. Each row resolves the reference instruction to a descriptor and then follows that descriptor's relative relocation to a sanitized binary path suffix; line and column come from the descriptor bytes.

| Selected reference VA | Descriptor VA | Sanitized suffix | Line:column |
| --- | --- | --- | --- |
| `0x2997a11` | `0x64bfd40` | `z_vendor/revm-interpreter/src/interpreter/shared_memory.rs` | 539:23 |
| `0x2999af0` | `0x6443880` | `z_vendor/revm-interpreter/src/instructions/contract/call_helpers.rs` | 50:16 |
| `0x45245f8` | `0x648f230` | `z_vendor/revm-context-interface/src/cfg/gas_params.rs` | 592:22 |
| `0x43364c1` | `0x6486af8` | `z_vendor/revm-context-interface/src/cfg/gas_params.rs` | 627:21 |
| `0x43364d0` | `0x6486b10` | `z_vendor/revm-interpreter/src/instructions/contract/call_helpers.rs` | 182:9 |

These labels associate selected failure sites with vendor-named interpreter and context-interface paths. They do not identify exact source versions, prove the names of surrounding Rust functions, or establish the full boundary between vendored and privately modified code.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependencies, compiler/linker settings, two-build comparison, normalization masks, helper/data/relocation closure, differential execution and whole-ELF comparison: **not yet implemented or measured**.

The focused standard-library suite has 25 passing tests and zero skips. The tests compare every generated evidence file byte for byte, authenticate the target, and exercise corrupted hashes and instruction bytes, a changed frame displacement, NOBITS and ambiguous mappings, malformed branches, missing/duplicate/wrong relocations, invalid source suffixes and changed descriptor references, truncated or malformed LSDA records, every bit of the 160-bit target projection, ignored upper target bits, copy padding, stack and range error precedence, in-place base-charge underflow, guarded copy charge, expansion metadata ordering, saturation and gas-cap boundaries. The arithmetic and byte-copy cases are synthetic models under the stated assumptions; they are not executions of target instructions or independent proof of complete behavior.

## Results and limitations

`summary.json` records 8 selected FDEs totaling 5422 bytes, 71 selected fixed-byte windows, 71 relative branches/calls, 12 RIP-indirect calls, 2 RIP data references, 10 route relocations, 10 literal rows, 25 field-lineage instructions, 15 location descriptors with their own relocations and 37 exception call sites. These are selected evidence counts, not total functions, branch coverage, matched windows or a component completion percentage. Earlier-owned bodies appear only through interface windows and explicitly cited prior findings. No catalogue or component gate is changed; HyperEVM remains **0/4**.

The component's first task requests complete reth/revm private-fork boundaries and state-transition inputs, which this conditional nested-call path does not establish. Dynamic account contents, input provenance before the interpreter, remaining CALL variants, external allocator/destructor behavior, all compression rounds and actual native behavior remain open.

Next question: establish or disprove the shared backing-buffer relationship and connect separately observed #115 caller bytecode and interpreter input to these dispatches, then validate state and rollback under an explicitly authorized offline differential protocol.
