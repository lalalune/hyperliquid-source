# RE-021: interpreter input through conditional code publication around the BLAKE2b call

The selected node #94 interpreter path makes calldata-to-call-input, return-data handling, and conditional account code publication reconstructible with explicit byte order, gas, journal updates, and failure ordering; its connection to the earlier BLAKE2b lookup depends on separately researched call-frame and registry paths.

- Component ID: `evm`; RE-021 continues the unresolved runtime connection in `RE-021-blake2b-compress-94`, rather than adding an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was not copied into this work.
- Claim status: **observed** for ELF bytes, FDE/CIE and exception records, relative relocations, operand values, and branch destinations; **inferred** for interpreter, opcode and buffer names and for composition with prior work; **unresolved** for live reachability, dynamic helper behavior, source types and native equivalence.
- Scope included and excluded: the selected zero-tag table's input, memory, return-data, immediate-push and RETURN handlers, their copy helpers, return assembly, and one selected creation-result-to-account publication route. Earlier call-frame, growth, provider, lookup and compression bodies are dependencies, not selected again. Other opcode tables and revisions, node #115, visor, captured execution and the complete HyperEVM component are excluded.

## Reproduce

From the repository root with the pinned artifact present, using Python 3.12.3 and only the standard library plus `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/re21_input_memory94.py --out research/work-items/RE-021-precompile-input-memory-94
python3 -m unittest tests.test_re21_input_memory94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-precompile-input-memory-94 && sha256sum -c MANIFEST.sha256)
```

For two independent exports, first ensure the two relative output directories are empty:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_input_memory94.py --out work/re21-input-memory-a
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_input_memory94.py --out work/re21-input-memory-b
diff -r work/re21-input-memory-a work/re21-input-memory-b
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_input_memory94
```

The generator authenticates the complete ELF before parsing, excludes SHT_NOBITS from file-backed reads, checks each selected FDE against the unwind header and body hash, and invokes no external program. GNU objdump 2.42 was used for human inspection only; generated evidence and tests do not parse its output. Addresses below are linked ELF virtual addresses before load bias; file offsets appear in the TSV records. Ends are exclusive. There are no execution or network side effects.

## Evidence

### Corpus and ownership

`functions.tsv` records **19 selected FDE intervals, 5,717 bytes** and their file offsets, hashes and unwind coordinates. `function-bytes.json` and `unwind.json` retain the complete selected bytes and raw CIE/FDE records. `instructions.tsv` has **1,404 linear byte-shape rows**, `control.tsv` has **275** selected-body control rows including returns, and `windows.tsv` contains **56** reviewed semantic windows. The fail-closed walker checks local direct branch destinations against instruction boundaries; linear decoding is not a reachable control-flow graph. `operands.tsv` decodes **57** reviewed values, `failure-branches.tsv` binds **54** interpreted branch decisions to their decoded destinations, and `relocations.tsv` retains **29** relevant raw RELA entries. These are selected-corpus counts, not a node or component coverage denominator.

The prior compression packet identifies the address-09 record, wrapper and compression body. Open PR #1373 covers the standard registry and lookup; #1413 covers a private-provider runtime; #1563 covers transaction-frame construction. An earlier separate `RE-021-interpreter-callframe-94` draft describes the zero-tag interpreter loop, a DELEGATECALL frame and its parent-result insertion, but is not part of this base checkout. The new packet selects none of those bodies. Its combined route depends on review and integration of those prior results, not just the presence of similarly named fields. No live table selection is established.

### The selected dispatch entries and memory layout

The earlier interpreter-loop draft records indexed dispatch from a zero-tag table. Here `opcode-map.tsv` reads **12** `R_X86_64_RELATIVE` slots from that table, including:

| Bytes | Selected FDE starts | Inferred role |
| --- | --- | --- |
| `0x35`, `0x36`, `0x37` | `0x26bdae0`, `0x26bdbc0`, `0x26bd8b0` | Read, size and copy the input buffer. |
| `0x51`, `0x52`, `0x53` | `0x26bd420`, `0x26bd5f0`, `0x26bd7a0` | Read a 32-byte memory word, write a word or write one byte. |
| `0x5e`, `0x5f`, `0x60` | `0x26bd260`, `0x24e6c90`, `0x24e5650` | Copy memory, push zero or push one immediate byte. |
| `0x3d`, `0x3e`, `0xf3` | `0x26bdf10`, `0x26bdc30`, `0x26beaf0` | Read return-buffer size, copy return data, or publish a return action. |

The table and operation names are interpretations of relocation and instruction evidence, not recovered symbols. The byte operands in this corpus consistently use stack pointer/count `+0x120/+0x128`, input pointer/length `+0x48/+0x50`, memory pointer/window start/window end `+0xe8/+0x110/+0xf0`, gas `+0x1e0`, and status `+0x1f3`. `CALLDATACOPY` computes its destination from memory pointer plus window start; the previously drafted call-range helper reports the same pair when copying a call input. That correspondence is conditional on both handlers operating on the same interpreter object and on ordinary nonaliasing copy behavior.

`PUSH1` deducts 3 gas before its stack-limit test, loads a byte through the program pointer at `+0x1d0`, writes a zero-extended 32-byte word, and advances that pointer. `PUSH0` deducts 2, writes a zero word and increments the count. On their valid stack domain, an insufficient charge writes `0x50`; a full stack writes `0x5c` after the charge. The generated table does not establish how the program buffer is padded or how arbitrary invalid stack counts arose.

`CALLDATALOAD` charges 3 before its one-word stack check; it reads at most 32 input bytes and right-pads with zeros before assembling the stack word. A high input offset or an offset at/after the input length yields zero. `CALLDATASIZE` charges 2, then pushes the input length, with its own full-stack failure. `MLOAD` reads memory in big-endian word order; `MSTORE` applies the inverse transformation, and `MSTORE8` writes the low byte of its value word. `mstore-lanes.tsv` follows all 32 byte lanes through the pinned unpack, shuffle and pack shapes. These are selected instruction-derived relationships, not a Rust layout identity.

### Input copy and failure order

For `CALLDATACOPY`, the three stack words are destination, source offset and size, with destination at the top. The selected machine-code order is:

| Gate or action | Observed consequence |
| --- | --- |
| Fewer than 3 stack words | `0x5b`; no copy charge and no three-word decrement. |
| Size has a nonzero high limb | The count is already reduced by 3; `0x54` precedes the gas charge. |
| Base charge cannot be paid | `0x50`; the reduced count remains and the failed gas subtraction is not stored. |
| Size is zero after payment | Return without validating either offset or expanding memory. |
| Nonzero size with high destination limbs | `0x54` after the base charge. |
| Nonzero size with high source limbs | Source is clamped to the maximum 64-bit offset; the normal out-of-source arm zero-fills. |
| Destination range exceeds the current window | Call the prior growth boundary through the recorded relocation; a false return writes `0x51`. |
| Source begins inside the input | Copy the available prefix with the relocated `memcpy`, then zero-fill the remainder with the relocated `memset`. |

The base charge is `3 + 3 * (min(size + 31, 2^64 - 1) >> 5)` for a size that fits a word. The separately researched growth helper adds its own charge; a successful base charge does not imply successful growth. The code also has range-addition and internal window-underflow failure calls. Allocator, libc interposition, panic and exceptional effects are not closed.

`MCOPY` uses the same three-word and base-charge structure, checks the two nonzero-length offsets, grows for the larger end and tail-calls selected adapter `0x21c27c0`. That adapter checks source and destination ranges and resolves its final indirect jump to `memmove`; overlapping ranges therefore require the ordinary semantics of that external symbol. The tests use explicit overlap examples rather than claiming a captured execution.

### Return data and action publication

`RETURNDATASIZE` reads the buffer length at `+0x1c0`. `RETURNDATACOPY` uses the pointer/length at `+0x1b8/+0x1c0`, deducts the same base charge, and performs its source-end check **before** its zero-length branch. With mode byte `+0x1f0` equal to zero, source end greater than the buffer length writes `0x5d`; equality passes. Thus a zero-length copy with an offset past the end still fails in that mode. With a nonzero mode byte the same check is bypassed; selected helper `0x26bc9e0` copies the available prefix and zero-fills the rest, subject to normal external copy behavior. The mode's source-level name and valid domain are unresolved.

The `0xf3` table slot relocates to `0x26beaf0`, which supplies status 2 to `0x26be730`. This helper pops the offset and size, accepts zero size without checking the offset, and on the nonzero normal path allocates a separate buffer and copies the selected memory range into it. It writes the status byte at `+0x1f3`, drops the old action at `+0x150`, installs the replacement and writes its tag at `+0x188`. Short stack, oversized operands, failed growth, allocation and bounds paths remain distinct. Its **9** exception call-site rows appear in `exception-sites.tsv`; the row covering the old-action drop lands at `0x26be9ee`, where the replacement action and tag are installed before unwind resumes. Status is written before the drop. These are static unwind edges; action chains and actual destructor effects are not inferred.

### Conditional creation-frame result and account writes

The earlier private-handler construction records descriptor `0x56bfb60`. The new relocation record at descriptor `+0x28` resolves to adapter `0x276e120`, which copies a 64-byte result and calls `0x279e770`. The previous executor evidence is needed to establish which frame and callback reach it; assuming that descriptor remains installed, the executor selects its frame-tag-1 arm, and the RETURN result is forwarded unchanged, this is one possible continuation of the return action above. The new bodies do not independently prove that those guards hold for a live transaction.

The selected result body checks its status byte at `+0x38` first. Its branches, in observed order, are:

| Condition | Result and ordering |
| --- | --- |
| Status at least 5 | Call the existing rollback boundary; retain the original status. |
| Nonempty output begins with `0xef` | Call rollback and set status `0x63`. |
| Output length exceeds the selected cap | Call rollback and set `0x62`. The default cap is `0x6000`; a configuration flag selects another word. |
| Length times 200 overflows a 64-bit product | Take a distinct failure call; its complete effects are unresolved. |
| Product exceeds remaining gas at `+0x28` | Call rollback and set `0x50`; equality passes. |
| Context depth at `+0xa8` is zero | Call a distinct failure boundary **after** storing reduced gas. |
| All checks pass | Store reduced gas, decrement depth, prepare the code object and enter the account helper. |

`synthetic-creation-cases.tsv` illustrates these gates with synthetic scalar inputs; `failure-branches.tsv` and `operands.tsv` provide the independently decoded branch and operand coordinates. The product-overflow example uses a raised size cap and does not establish that such configuration is reachable.

On the selected nonzero preparation-mode branch, `0x26bcaa0` receives a tag-zero buffer, checks `length + 33`, allocates, copies the input, and writes 33 trailing zero bytes before an external analysis helper. Its nonzero-tag branch copies the existing representation instead, so padding is not claimed for every representation. On normal completion `0x279e770` calls `0x2788050` with the prepared code object and the saved 20-byte account key.

The account helper calls the existing digest boundary, looks up the full key and requires a current journal. If account flag mask `0x04` is clear it appends a tag-2 journal record and sets that bit; it then appends a tag-9 record, stores the returned 32 digest bytes at account `+0x68..+0x87`, and replaces the account's first 64 code-object bytes. The prior digest research identifies the external slot but is not reselected here. If dropping the old code unwinds, the call-site record covering that drop lands at `0x27881be` and installs the replacement before resuming unwind; the digest store and journal operations have already occurred. These observations do not establish persistent database writes, complete rollback effects, atomicity, or arbitrary helper behavior. `exception-sites.tsv` retains **31** call-site records across **4** selected tables; action chains remain opaque.

### Conditional 213-byte example

`synthetic-flow.json` supplies a deliberately synthetic program and input. Its first segment pushes size 213 and zero offsets, then copies the input into memory. On the bounded growth model, empty memory and 45 gas at copy entry suffice: 24 for the copy and 21 for growing to 224 bytes. The first 213 resulting memory bytes equal the supplied input. The first four input bytes encode 12 and the last is 1; the prior BLAKE2b packet reports a 213-byte wrapper, a rounds/gas comparison and a final-flag check. Those prior facts and this synthetic payload are separate evidence.

The example then supplies stack word 9 and a requested child gas of 255 to the previously drafted DELEGATECALL path. Only if its table, frame, address-copy, host, revision, registry, lookup and wrapper guards all hold, the earlier draft's copied memory slice and 20-byte target can be composed with the prior address-09 lookup. For a separate hypothetical normal resume, the example independently chooses 20,000 gas and a fabricated 64-byte return buffer, copies that buffer back and packages it with the new RETURN handler. The resume gas is **not** derived from the preceding call or initial gas. The prior result-insertion path leaves one stack word; the example retains that word beneath the copy and return arguments. In this second segment the three pushes before `RETURNDATACOPY` cost 7, the copy costs 9, and the two pushes before `RETURN` cost 5, leaving 19,979 in the bounded projection. If that return is also forwarded through the selected creation-frame callback, its first byte is not `0xef`, the code-size and depth guards pass, and the account/hash/allocator helpers succeed, the synthetic calculation charges 12,800 gas, leaving 7,179 before conditional code installation. **That 64-byte value is not a predicted BLAKE2b result**, and the example is not evidence that a live node executes the program.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, two-build comparison, normalization masks, dependency and whole-ELF closure, and native behavioral comparison are **not yet implemented/measured**. No executable bytes are transplanted.

The focused tests check the full digest, selected body corruption, incorrect FDE start/end expectations, invalid/NOBITS/ambiguous file ranges, unsupported or truncated instruction shapes, a branch into an instruction, altered operand and relocation bytes, wrong symbols, the selected RETURN landing and corrupted exception headers. Synthetic controls check all 256 single-bit word lanes, 8,193 bounded copy lengths against an integer oracle, 4,097 creation-size/gas boundaries, thousands of bytewise copy cases, overlapping copies, stack/gas boundaries, high limbs, zero lengths and the two return-mode classes. The models do not run or emulate captured instructions. Actual test and deterministic export results are recorded in the accompanying draft and run report.

## Results and limitations

This packet fills a previously unowned portion of input preparation, parent output publication and one conditional creation-frame account update around the address-09 path. It does not establish the initial input producer, the dynamic selection of the table or callbacks, the exact creation-frame handoff, arbitrary revisions, full helper/allocator/destructor behavior, exception action chains, live transaction reachability, private-fork boundaries, complete state-transition inputs or binary equivalence. The broader first HyperEVM task remains unfinished; `evm` stays **0/4** and no gate is advanced.

The supplied PR snapshot and the base work items were checked for the selected FDE entries. Public main and PR heads were not refreshed in this offline run and require a submission-time check. Next question: bind the producer of the interpreter input buffer and independently review the earlier call-frame-to-registry composition without selecting its already owned functions again.
