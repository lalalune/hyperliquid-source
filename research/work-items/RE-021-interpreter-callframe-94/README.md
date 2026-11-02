# RE-021: contract call frames to the precompile lookup in node 94

A reconstruction can now carry a contract's DELEGATECALL target from a 256-bit interpreter stack word into the 20-byte frame key used by the previously mapped BLAKE2b lookup, and can restore the parent interpreter's result, gas and return data after the child completes, under the explicitly stated callback and helper conditions.

- Component ID: `evm`; continuation of `RE-021-blake2b-compress-94`.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is not implementation source for this packet.
- Claim status: **observation** for byte patterns, selected FDE ranges, displacement-derived branches, relocation records and LSDA call-site entries; **inference** for opcode and field names and for composition with earlier pending work; **unresolved** for live callback selection, arbitrary hook replacements, opaque helpers, source-level type identity and native behavior.
- Scope included and excluded: the selected table's four call-family entries, one DELEGATECALL path, its range and host adapters, the plain interpreter loop and the child-result adapter/inserter. The existing registry, runtime lookup, dispatcher and compression functions are dependencies, not newly selected bodies. Other opcodes, other revision tables, node #115, visor, captured execution and complete HyperEVM reconstruction are excluded.

## Reproduce

Use the repository root and the authenticated #94 artifact. Python 3.12.3 was used; the exporter uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It hashes the complete input before parsing, rejects NOBITS-backed reads, checks the selected body hashes, and launches no external program. GNU objdump 2.42 was used for human inspection only; no generated row or test parses its output. All addresses below are linked ELF virtual addresses before load bias; TSV files also record file offsets. FDE ends are exclusive.

```sh
python3 tools/evm_callframe94.py --out research/work-items/RE-021-interpreter-callframe-94
python3 -m unittest tests.test_evm_callframe94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-interpreter-callframe-94 && sha256sum -c MANIFEST.sha256)
```

For deterministic regeneration, replace the placeholders with two different empty relative directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/evm_callframe94.py --out <tmp-dir-a>
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/evm_callframe94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The exporter generates the 21 JSON/TSV evidence files. README and MANIFEST are packaging files; MANIFEST hashes every other file in this directory. The focused tests and both exports also passed with an empty program-search PATH. The generator contains no clock, random, host-path or disassembler-output dependency.

## Evidence

### Boundaries and dependencies

The 11 selected FDE intervals contain 10,187 bytes. Their actual CIE/FDE records and full bytes are in `unwind.json` and `bodies.json`; `functions.tsv` gives file coordinates and hashes. `windows.tsv` has 44 selected semantic windows, and `control.tsv` has 96 selected direct transfers. These are bounded selections, not an exhaustive instruction or control-flow census. The exception ledger has 49 call-site rows; it does not decode action chains or exception types.

Existing work is necessary for the complete composition. The prior BLAKE2b packet binds the address-09 object to its wrapper. Open PR #1373 maps the standard registry, and open PR #1413 maps a revision-18 provider, context installation and runtime lookup. In particular, #1413's recorded builder instructions select a `0x800`-byte source at `0x56ac788` and carry it into the handler on the raw revision `0x12` branch. This packet does not select or re-export that builder body. The connection to its table is conditional on that pending evidence and on subsequent callbacks leaving the table and provider in place.

For the callback connection, the constructor body already selected by #1413 places vtables `0x56bfa70` and `0x56bfb00` in execution pairs `+0x10` and `+0x40`; their `+0x28` relocation slots are the two adapters selected here. In that prior executor body, the `+0x208/+0x210` pair is called at `0x2515c21`, and the `+0x238/+0x240` pair is called at `0x251664b` on a result-handling branch. These observations compose with the earlier handler-to-engine layout only if those callbacks are retained and their branch preconditions hold. The old constructor and executor are dependencies, not newly selected FDEs.

The handoff can be followed through the existing #1413 evidence without selecting that executor again. With its context error tag equal to 5, action tag `0x6c` selects entry zero of the earlier packet's table at `0x3e5784`, whose recorded target `0x2515cd5` calls the private runtime via the handler pair at `0x2515d09`. In the earlier runtime's ordinary precompile result path, `0x278997f` writes outer result tag zero; the executor's nonfatal and tag-zero branches then select the result callback at `0x251664b` if a parent frame is present. Its separate outer tag-4 path does not follow that route. This is a composition of the earlier packet's table, runtime and control-flow records with the new action and result evidence; it does not claim that arbitrary initial state satisfies these predicates.

### Fetch, opcode table and frame layout

The relative relocation at `0x56bfa98` installs the selected loop adapter `0x276d8e0`, which calls `0x279ee30`. On its zero-tag table branch, the loop loads a byte using the pointer at interpreter `+0x1d0`, increments that pointer, and calls the pointer at table `+8 + 8*byte`. `dispatch.json` pins these instruction bytes and decodes both displacements. A nonzero table tag takes the distinct external helper at `0x26bc860`; this packet does not infer its behavior.

The loop first moves a 56-byte state object out of the input argument and resets the input to three file-backed 16-byte literals and a zero word. On the zero-tag path it calls a prior-action cleanup helper, sets action tag `0x70`, passes two old pointer/size pairs to an external cleanup slot when their size words are nonzero, and installs the moved state at interpreter `+0xe0`. It checks interpreter status before the first fetch. On that path's exit, if the action tag is not `0x70`, it moves the 64-byte action into the return object and resets the interpreter action tag to `0x70`; the other arm builds a default result. Both cases move the 56-byte interpreter state back into the input argument and reset that interpreter state using the same three literals and zero word. The selected moves are in the loop windows; `loop-reset-literals.tsv` independently resolves both sets of RIP-relative loads to the same file-backed bytes. The identity and behavior of the external cleanup routines remain assumptions, including on exceptional exits.

The four queried table slots are backed by `R_X86_64_RELATIVE` records. Opcode names are interpretation of the selected slots and their operations, not recovered symbols:

| Byte | FDE start | Frame value tag | Frame scheme byte at `+0x9e` | Target key at `+0x60` | Selected difference |
| --- | --- | ---: | ---: | --- | --- |
| `0xf1` | `0x24ec990` | 0 | 0 | stack target | A nonzero value with the low bit of interpreter flag `+0x1f2` set writes status `0x56`. |
| `0xf2` | `0x24f2320` | 0 | 1 | stack target | The recipient and caller fields are copied from the current interpreter address. |
| `0xf4` | `0x24ea6d0` | 1 | 2 | stack target | The recipient, caller and value fields are copied from the current interpreter. |
| `0xfa` | `0x24e6e80` | 0 | 3 | stack target | The frame flag at `+0x9c` is set to 1. |

`variants.tsv` records the table slots, actual relocated targets, frame bases, tag stores and raw scheme-store bytes. The selected `0xf4` handler reads the top stack word for requested gas, then reads the next word for the target. The stack buffer has 32-byte words. It subsequently calls the four-word range helper, so a normal route needs at least six available words; the `0xf1` route consumes an additional value word before that helper. Underflow writes status `0x5b`; earlier decrements of the stored stack count are visible and are not described as rolled back.

`frame-copies.tsv` records 14 decoded load/store chunks. For `0xf4`, the inferred recipient comes from interpreter offsets `+0x80..+0x93` into frame `+0x74..+0x87`, and the inferred caller from `+0x94..+0xa7` into `+0x88..+0x9b`. Its two interleaved vector moves copy interpreter `+0x60..+0x7f` to frame `+0x08..+0x27`. In `0xf2`, both address fields receive interpreter `+0x80..+0x93`; in `0xf1` and `0xfa` the same source supplies the caller field. The field names are inferred from the surrounding frame use; the source and destination displacements are extracted from the instruction bytes. The table checks the two interleaved value moves with fixed encodings and the adjacent address moves with decoded displacements.

`delegate-key-lanes.tsv` symbolically follows the selected `0xf4` byte-load, spill and store shapes. The 20 host-key bytes and frame bytes `+0x60..+0x73` take source byte positions 19 down to 0 of the second stack word. The other 12 bytes of the 32-byte word are not read for that key in this slice. The first two bytes are kept in callee-saved registers; the other lanes use stack spills. This relation assumes the intervening calls return normally and do not modify the saved values through an alias. The six entries in `synthetic-addresses.tsv` are illustrations of this byte relation, not captured node executions: the word 9 yields nineteen zero bytes followed by `09`, while changing only bits above 159 preserves that key.

For a normally allocated `0xf4` frame, the handler stores value tag 1 and scheme 2. Prior PR #1413 reports that its private runtime uses frame `+0x60` as the precompile key and bypasses that lookup only for scheme 6; its static-address and dispatcher lineage depends in turn on PR #1373 and the earlier compression packet. Thus an input word 9 can be composed with that lookup without a key-endianness guess, **if** the reported revision, callbacks, registry contents, normal helper returns and prior account/depth guards hold. This is not proof that a live transaction reaches the wrapper.

The earlier compression packet also reports the wrapper's 213-byte input requirement, final-flag check and comparison of supplied gas with the decoded round count. If the composed path reaches that wrapper, its supplied gas is subject to the frame-forwarding cap described below; the wrapper still has its own independent rejection conditions. The wrapper body and compression behavior are not re-exported or revalidated here.

### Memory, host and gas branches

The shared helper `0x24e8800` requires four additional stack words, then reduces the stored stack count before examining the two ranges. Nonzero high limbs in selected size/offset checks take status `0x54`; a failed memory-growth callback takes `0x51`; a short stack takes `0x5b`. It constructs an input buffer and an output range, has separate zero-size paths, and can call an allocator, copy function and dynamic destructor. `0x5773f40` relocates to `0x4e8fcb0`. On the normal bounded arithmetic path, that helper charges the increase in `3*w + floor(w*w/512)`, where `w` is the byte extent rounded up to 32-byte words. Its actual machine code saturates the add-before-rounding and the square on unsigned overflow; it has distinct subtraction, capacity, allocation and overflow exits. It subtracts the charge before the allocation/growth path, so no general rollback on later failure is asserted. `synthetic-memory.tsv` is a projection of these instructions, including large values, not a behavioral fixture.

The two range halves have different cleanup ordering. The first size/offset checks can fail before the temporary buffer exists; after its allocation and copy, the second half's high-limb failure or growth failure destroys that temporary buffer through its stored function pointer. Both halves have checked range-end additions and separate old-length-underflow exits. The cost helper has separately recorded old-length, old-square, cost-delta and new-end overflow or underflow transfers, as well as insufficient-gas and capacity-growth branches. These calls and transfers are anchored in `control.tsv`; the ultimate panic, allocation and dynamic destructor semantics remain external.

After the range helper succeeds, `0x1ebec00` calls a previously studied account boundary and packs its result. A low result byte of 2 leads the handler to status `0x65`. Otherwise, for the recorded revision-18 `0xf4` body, bits 0 and 8 of the packed host word select 100 or 2600 each; a middle byte of 2 suppresses the bit-8 part. These are raw predicates, not a claim that every synthetic host word is valid. If gas remaining after memory processing is below that charge, the handler records status `0x50`; equality continues. On continuation it caps forwarded gas at `remaining - floor(remaining/64)`, takes the minimum of that cap and the requested word, and stores the parent remainder. The `0xf1` body additionally has 9000/34000 value-dependent charges and a saturating 2300 child stipend; `0xf2` has a 9000 value charge and the same stipend. `synthetic-gas.tsv` labels 288 modeled inputs explicitly; it is not evidence that those inputs occurred on the target.

Once the selected checks succeed, the handler allocates a 160-byte frame, copies the assembled fields, replaces the interpreter action pointer at `+0x150`, writes action tag `0x6c` at `+0x188`, and writes status `0x20` at `+0x1f3`. The plain loop stops on the nonzero status and carries the action out. Open PR #1413's executor supplies the next callback to the already mapped private runtime, subject to the conditions above.

| Selected `0xf4` gate | Failure destination | Earlier visible effects |
| --- | --- | --- |
| First or second stack word absent | Status `0x5b` at `0x24ea7fe` | The count has already been decremented when only the first word existed. |
| Fewer than four remaining range words | Helper status `0x5b` | The two initial words have already been removed from the count. |
| Selected oversized range operand | Helper status `0x54` | The helper has already removed its four words. |
| Range expansion cannot pay | Helper status `0x51` | Earlier range processing may already have changed memory or gas. |
| Host result low byte equals 2 | Status `0x65` at `0x24ea9e9` | Range processing ran first; the host adapter can replace the context error slot. |
| Remaining gas is below the computed charge | Status `0x50` at `0x24ea9e9` | Host and range processing ran first; the failed subtraction is not stored. |
| Frame allocation returns null | Allocation-failure call and `ud2` | The normal gas deductions precede the allocation. |
| Old action drop unwinds | Landing `0x24eac0e`, then unwind resume | The replacement pointer and tag are installed in the landing. |

`control.tsv` also binds corresponding first/second-word, range-helper, host, gas and old-action-drop transfers in all four handlers. The `0xf1` and `0xf2` handlers additionally guard their third stack word; the `0xf1` static-value branch writes `0x56`. The `0xf4` and `0xfa` handlers show a null allocation branch in their own bodies, whereas `0xf1` and `0xf2` call the external allocation helper `0x251aea0`; its failure behavior is not inferred here.

The failure ordering is material. `drop-landings.tsv` links each of the four old-action drop calls to its actual LSDA landing. If that drop unwinds, the landing installs the replacement pointer and tag `0x6c` before resuming unwinding; it does not execute the later normal-path status `0x20` store. This is a static exception edge, not an observed unwind or a claim about final transaction state. Allocator, destructor and exception action semantics remain external.

### Returning to the parent interpreter

The result-callback relocation at `0x56bfb28` resolves to `0x276def0`; its indirect slot `0x5774df8` resolves to `0x4e8f2b0`. The callback replaces the context error slot with tag 5 and, if the old tag was not 5, returns that older error through a separate cleanup arm. On the selected tag-5 arm it forwards the child outcome to the insertion helper. The association with a particular executor callback remains dependent on the earlier revision-18 construction and normal selection, not merely the existence of this vtable.

`0x4e8f2b0` clears interpreter status and replaces its return-data object before testing the outcome byte. For status `0..4`, it adds the child remaining-gas and refund words to parent `+0x1e0/+0x1e8`, copies at most `min(max(end-start, 0), return_length)` bytes to the supplied output range, and pushes 1 when interpreter byte `+0x1f0` is zero, or 0 when it is nonzero. Statuses `0x10..0x15` return remaining gas and copy data but do not add the refund word; zero and nonzero flag bytes push 0 and 1 respectively. Other statuses push 0 or 2 for zero and nonzero respectively, with no such gas credit or data copy on that selected arm. Status `0x65` reaches a separate fatal call. A stack count of `0x400` writes `0x5c` instead of a push; checked gas addition, signed refund addition and output-range addition have separate overflow exits. The status and return-data replacement happen before several of those exits, so this is not an atomicity claim.

`synthetic-outcomes.tsv` tabulates the instruction-derived partition for all 256 result-byte values and both normalized flag classes: 0 represents a zero byte and 1 represents any nonzero byte. It does not establish that all result bytes or either flag class are valid or reachable in the target. `constants.tsv` records the flag-comparison offsets and the three pushed values; `control.tsv` binds the selected mode branches to their push sites. `exception-sites.tsv` records the return-data destructor's landing separately. The precise source enum names, destructor/copy semantics and later transaction-level settlement are not inferred from these local status bytes.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, two-build comparison, normalization masks, helper/data closure, native behavior and whole-ELF identity are **not yet implemented/measured**. There is no transplanted machine code.

The focused suite passed 54 tests with zero skips. Controls reject altered target hashes, code bytes, FDE ranges and duplicates, NOBITS and ambiguous mappings, missing or changed relocations, bad direct and indirect branches, corrupt key-load/spill/destination and frame-copy bytes, changed dispatcher and loop-literal encodings and malformed LSDA/landing records. The tests exercise every one of the 256 target-word bits, all 256 synthetic result bytes in both flag modes, gas thresholds and an independent integer memory-cost formula over 8,193 bounded sizes. These are static extraction and model checks, not differential execution. The two empty-PATH generations with different hash seeds and time zones match each other and the 21 retained evidence files byte for byte; artifact verification and catalogue consistency pass.

## Results and limitations

The evidence establishes one conditional contract-opcode-to-frame-to-parent-result relation, not the full component's first task. The unselected revision-18 builder, executor, installed provider, lookup and wrapper are credited dependencies, including open PRs that must be reviewed before assuming their composition. Dynamic registrations, nonzero table-tag dispatch, complete helper and storage effects, all allocation and exception actions, runtime seeds, live reachability and native equivalence remain open. The `evm` component remains 0/4; no progress gate is advanced.

Ownership was checked against existing work-item evidence and the supplied open/merged PR snapshot. Networking was outside this run, so the submission account must refresh public main and PR heads. Next question: independently reconstruct the selected interpreter frame and return-data contracts in Rust and validate the composition with the provider under separately authorized differential execution.
