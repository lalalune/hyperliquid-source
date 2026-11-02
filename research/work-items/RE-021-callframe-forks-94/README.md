# RE-021: standard call frames for the address-09 lookup

On successful branches with a stack target of nine, raw selectors 9/10 and 18 build the same DELEGATECALL lookup-key lanes and carry the nonempty input length into frame `+0x38`, while using different gas rules; this gives a reconstruction concrete frame, failure-order and callback contracts at the existing address-09 lookup boundary.

- Component ID: `evm`; RE-021 continues the existing BLAKE2b question and is not a new row in the official task table.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred can1357 reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation is copied.
- Claim status: **observed** for authenticated bytes, relocations, FDE/LSDA records and the selected displacements; **inferred** for opcode and field names, pricing equations, and composition across previously documented boundaries; **unresolved** for actual provider selection, lookup hit, helper effects and behavioral equivalence.
- Scope included and excluded: eight previously unselected call-family FDEs in two standard-handler tables, their common memory-range and host adapters, one loop adapter, one result adapter, selected failure and unwind paths, and short integration anchors in earlier selector/executor code. Existing BLAKE2b wrapper and compression, registry constructors, the interpreter loop, runtime lookup and parent-result helper are dependencies, not selected FDEs. Node #115, visor, captured execution, networking, complete database behavior and full HyperEVM recovery are excluded.

## Reproduce

From the repository root, with the pinned node #94 artifact available:

```sh
python3 tools/re21_callframe_forks94.py --out research/work-items/RE-021-callframe-forks-94
python3 -m unittest tests.test_re21_callframe_forks94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-callframe-forks-94 && sha256sum -c MANIFEST.sha256)
```

The analysis used CPython 3.12.3 on Linux x86-64. The generator uses the standard library and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`, verifies the complete input digest before parsing, and rejects SHT_NOBITS for file-backed reads. It calls no external program and does not run or emulate captured code. GNU objdump 2.42 was used only for human instruction review; its output is not parsed or written by the generator or tests.

For independent regeneration, substitute two different empty relative directories for the placeholders:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_callframe_forks94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_callframe_forks94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_callframe_forks94
```

The generator writes all 23 JSON/TSV files in this directory. README and MANIFEST are packaging files. The manifest covers every other file in this directory; the tool and test are separate new repository files.

## Evidence

### Coordinates, ownership and table selection

All code and data addresses are linked ELF virtual addresses before load bias; tables also report file offsets. `functions.tsv` and `unwind.json` record actual `.eh_frame` FDE/CIE coordinates and exclusive extents, checked against `.eh_frame_hdr`; `bodies.json` contains the selected interval bytes. An FDE interval is not by itself a validated source-function boundary or a complete function census. `windows.tsv`, `transfers.tsv` and `immediates.tsv` contain selected fixed byte shapes, not a complete x86 decoder or a complete CFG.

The existing compression packet binds the file-backed 20-byte key at `0x574f0c0` and the callback relocation at `0x574f0b0` to wrapper `0x4e9d2a0`. Open PR #1373 owns the standard registry construction, lookup and dispatcher; PR #1676 owns the selector and standard executor; PR #1689 owns a different interpreter family and the shared child-result helper. Their selected function bodies are not reselected here. The small selector, constructor and executor bytes in the `*-boundaries` records are explicit integration anchors, not added FDE coverage.

`selector-boundaries.tsv` reads the signed table words for raw bytes 9, 10 and 18, and checks the case-local source LEA and copy size. Cases 9 and 10 select `0x5723e88`; case 18 selects `0x5724688`. Each source is copied as 2,048 bytes, and the following common copy puts the selected representation into the handler. The selected function-pointer slots are zero in the file; their actual callback addresses come from the symbol-free `R_X86_64_RELATIVE` records, not the unrelocated words.

| Opcode byte | Raw 9/10 target | Raw 18 target | Inferred frame kind |
| --- | --- | --- | --- |
| `0xf1` | `0x4c94040` | `0x4c947a0` | CALL |
| `0xf2` | `0x4c98090` | `0x4c986d0` | CALLCODE |
| `0xf4` | `0x4c91eb0` | `0x4c92430` | DELEGATECALL |
| `0xfa` | `0x4c914c0` | `0x4c90e50` | STATICCALL |

The opcode names are inference from the selected table positions and frame operations. No claim is made that all byte values are valid source revision variants or that either table was selected in a running node.

### From the selected tables to the existing lookup

`callback-boundaries.tsv` binds the two earlier constructor results to descriptor methods. The loop descriptors `0x5745d40` and `0x5745bf0` both have a `+0x28` relocation to the newly selected `0x4da4c60`. The corresponding child descriptors have a `+0x28` relocation to prior adapter `0x4da4e20`. Both result descriptors bind to newly selected `0x4da6590`. `handoff-boundaries.tsv` records the selector's copy offsets and the earlier executor's table, loop, child and result descriptor offsets; `action-table-boundary.json` retains the action-table entry and the selected indirect call shapes.

Under the earlier handler-to-engine `+0x110` copy relation, normal returns, and unchanged callback pairs, the handler's table representation at `+0x198` becomes the executor's table argument at `+0x2a8`. Its callback group at `+0xe8` places the loop, child and result descriptors at engine offsets `+0x210`, `+0x220` and `+0x240`. These are offset relations across the earlier executor boundary, not evidence of a live callback installation. On the zero table-tag branch, `0x4da4c60` advances the supplied table by eight bytes and calls the existing loop at `0x4c09420`; a nonzero tag calls a separate loop boundary. The loop's fetch and dispatch behavior remains a prior dependency.

The selected opcode handlers allocate a 160-byte frame and, on the normal publication path, install its pointer at interpreter `+0x150`, action byte `0x6c` at `+0x188`, and status byte `0x20` at `+0x1f3`. With the earlier executor's context-status and action-table conditions satisfied, its `0x6c` arm calls the child descriptor, whose prior adapter enters `0x4dd6ea0`. PR #1676's borrowed-arm account does not independently prove its final lookup match and invocation. Therefore this packet establishes a conditional handoff **to** that runtime boundary, not a fresh object-returning lookup, a BLAKE2b invocation, or live reachability.

After a child result, the selected result adapter `0x4da6590` replaces the context error slot with tag 5. If the old tag was 5 it calls the shared result helper through relocation slot `0x5774df8`; otherwise it returns the old error and takes its child-payload cleanup path. The slot resolves to `0x4e8f2b0`, whose parent gas, return-data and result-stack behavior is the separate PR #1689 dependency. No arbitrary callback replacement or destructor behavior is assumed.

### Key lanes and frame layouts

For both selected `0xf4` handlers, the first two stack words are consumed before the range helper. The selected byte-load and store shapes put source positions 19 down to 0 of the second 32-byte little-endian stack word into both the host key and frame `+0x60..+0x73`. `delegate-key-lanes.tsv` derives all 40 rows from those instruction operands and checks that the two destinations use the same source lane. A test flips each of the 256 bits: the upper 96 bits do not affect these 20 copied lanes. `object-boundary.json` derives the little-endian stack-word representation of the existing file-backed key and confirms that this projection gives nineteen zero bytes followed by `09`; it is a synthetic projection, not a captured call.

For both `0xf4` variants, `delegate-payload-flow.json` traces four eight-byte words through the range helper and the caller's two 16-byte loads, spills, reloads and stores. The second word from the top at helper entry has its low limb loaded at `0x4c91b56` into `r14`; on the inspected nonempty input path the helper uses that register as the allocation and copy size, saves it at local `+0x38`, and returns it at output `+0x10`. The frame construction copies that word to frame `+0x38`, through raw-9 sites `0x4c92088`, `0x4c9209a`, `0x4c921dc`, `0x4c921e1` and their raw-18 counterparts. The input buffer object starts at frame `+0x28`; the other three traced words land at `+0x28`, `+0x30` and `+0x40`.

The ELF dynamic symbol and relocation records bind the indirect copy slots used by the memory helper and the two frame copies to `memcpy`; runtime loader resolution and interposition remain assumptions. With a nonzero input length of 213, valid stack and memory ranges, successful helpers and allocations, and an ordinary non-aliasing copy, the frame's length field is 213. The earlier compression packet establishes that the separate wrapper tests for 213, but a frame reaching that wrapper is not proven here. Empty input uses a different helper arm; no successful target behavior follows from the synthetic 212/213/214 controls.

`frame-layout.tsv` checks the following stores in all eight selected functions:

| Opcode | Value tag at frame start | Scheme byte at `+0x9e` | Byte at `+0x9c` |
| --- | ---: | ---: | --- |
| `0xf1` | 0 | 0 | copied from interpreter flag |
| `0xf2` | 0 | 1 | copied from interpreter flag |
| `0xf4` | 1 | 2 | copied from interpreter flag |
| `0xfa` | 0 | 3 | 1 |

For `0xf4`, the saved interpreter address, caller and value fields are copied into the frame before the allocation. `0xf1` and `0xf2` consume a third word before the common range helper; the `0xf4` and `0xfa` paths consume two. The byte-lane proof above is for `0xf4`, not a claim that every target-copy instruction in the other six functions has been separately traced.

### Host classification and result packing

The selected host adapter `0x44c9ec0` calls the existing primary account boundary. Its successful arm reads the returned account pointer and assembles three portions of the word consumed by the opcode handlers. Let `r` be the byte loaded from this adapter's input at `+0xb0`, `a` the returned account, `c` the resulting Boolean class, `p` the primary result byte and `s` the secondary result byte. The normal return is `p | (s << 8) | (c << 16)`. This is a byte-level relation; `r` is not asserted to equal either selected raw table case. The control-flow and operand pins are in `host-classification.json`.

| Observed input condition | Class `c` |
| --- | --- |
| `r <= 4` | `(a[+0xb0] & 0x0c) == 0x08` |
| `r > 4`, the 32 bytes at `a+0x68` equal the two recorded constants or are all zero, the four qwords at `a+0x40..+0x5f` are zero, and the qword at `a+0x60` is zero | 1 |
| `r > 4`, any of those checks fails | 0 |

On the successful path, `s` defaults to 2; if the dword at `a+0x00` equals 3, a secondary boundary is called and its success result byte supplies `s`. A non-success result from either boundary enters the context-error replacement path and returns low byte 2. The primary and secondary adapters, their valid output-byte domains, and any allocation or state effects remain separate boundaries. In particular, names such as account emptiness and coldness are hypotheses; the table above states the compared bytes and qwords without assuming a source-level type. `host-constants.tsv` shows that the two comparison halves concatenate to the conventional empty-input Keccak digest, but this identity alone does not identify the account fields.

### Selected gas and failure ordering

The tables below describe charges after the selected range and host calls have succeeded. They use the raw packed host result `h`, a Boolean `v` for the observed zero/nonzero value word, and the particular machine-code arms in `windows.tsv`; labels such as cold, empty or new account are not assumed to cover every possible host value. If `h & 0xff == 2`, the handlers write status `0x65` before these pricing calculations.

For raw 18, define `P(h)` from the observed low-bit, bit-8 and second-byte tests:

```text
first  = 2600 if (h & 1) != 0 else 100
second = 0 if ((h >> 8) & 0xff) == 2
         else 2600 if (h & 0x100) != 0 else 100
P(h)   = first + second
```

| Opcode | Raw 9/10 selected charge | Raw 18 selected charge |
| --- | --- | --- |
| `0xf4`, `0xfa` | 700 | `P(h)` |
| `0xf2` | 700 plus 9000 if `v` | `P(h)` plus 9000 if `v` |
| `0xf1` | 700 plus, if `v`, 34000 when bit 16 of `h` is set or 9000 otherwise | `P(h)` plus, if `v`, 34000 when bit 16 of `h` is set or 9000 otherwise |

The raw-9 `0xf1` instructions encode the combined values 9700 and 34700; `immediates.tsv` retains those bytes separately. `0xf1` and `0xf2` add a saturating 2300 to the forwarded child amount when `v` is nonzero. For the inspected normal gas path, the remaining word is reduced by the selected charge, the child request is capped at `remaining - floor(remaining / 64)`, and the parent remainder is stored before frame publication. Equality with the charge proceeds; a smaller word writes `0x50`. The instruction-derived test projection is synthetic and assumes a valid prior memory result and host return.

| Selected gate | Observed branch and ordering |
| --- | --- |
| Missing initial stack words | Writes `0x5b`; when the first word exists, its count decrement has already been stored. |
| `0xf1` nonzero value and low bit of the interpreter flag set | Writes `0x56` before the range-helper call. |
| Fewer than four range words | `0x4c91b10` writes `0x5b`; it returns a zero first word. |
| Selected nonzero high range limbs or failed memory-growth call | Writes `0x54` or `0x51`; the helper has already updated the stack count, and later failure arms also drop the temporary buffer. |
| Host result low byte is 2 | Writes `0x65` after range processing. |
| Remaining gas is below the selected charge | Writes `0x50`; no later frame publication occurs on that arm. |
| Selected `0xf4` or `0xfa` allocation returns null | Takes its allocation-failure call and `ud2`; the normal charge precedes the allocation. |
| Old action drop unwinds | Each of the eight LSDA intervals names a landing which installs the replacement pointer and action `0x6c`, then resumes unwinding without the later normal-path `0x20` store. |

The `0xf1` and `0xf2` handlers use a separate allocation helper whose full failure contract is not established here. Earlier stack, memory, host or gas effects do not imply transaction-wide persistence or atomicity. `exceptions.json` records nine selected LSDA tables and their call-site intervals; action chains and exception types remain opaque.

The host adapter calls account boundaries `0x44bb790` and, on one tagged arm, `0x44ba840`. Its backing account loaders, valid packed-result domain and effects are not recovered by this packet.

The selected range helper's diagnostic records contain sanitized suffixes `revm-interpreter-15.0.0/src/instructions/contract/call_helpers.rs` and `revm-interpreter-15.0.0/src/interpreter/shared_memory.rs`. `source-locations.tsv` retains the binary location records, relocations, length, full-path hash and relative suffix without publishing the embedded host path. These are dependency/version clues, not proof that the upstream crate is unmodified or that the reth/revm private-fork boundary is complete.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker settings, independent builds, target behavior, raw/normalized code comparison, relocation masks, complete helper closure and whole-ELF comparison are **not yet implemented or measured**. No machine code is transplanted into an implementation.

The focused suite passed **43 tests with zero skips**. Controls cover wrong input digest; missing, duplicate and inconsistent FDEs; changed body bytes; out-of-range, crossing, ambiguous, non-executable and NOBITS reads; relocation type/addend/duplication; changed selector, callback, key lane, frame store, immediate, source location, host constant and LSDA landing bytes; and signed branch displacements. Synthetic cases cover the host-class predicate and normal bit packing, selected host-bit partitions, zero/equal/insufficient gas, forwarding cap, value charges, 2300 stipend, payload-word copies with lengths 212/213/214, and all 256 single-bit changes to the projected stack target. These are static extraction and model controls, not target execution or a native behavior oracle.

## Results and limitations

`summary.json` records 12 selected FDE intervals totaling 15,326 bytes, eight selected opcode slots, eight frame layouts and action publications, 40 key-lane rows, eight payload-word rows supported by 36 instruction pins, 40 host-class instruction pins and seven host-class branches, 37 reviewed windows, 51 selected direct transfers, 47 immediate operands, and 82 call-site entries in nine LSDAs, including eight checked old-action-drop landings. These are finite selected-corpus counts, not whole-node coverage or matched-code denominators. The six callback and twelve handoff rows include prior-function integration anchors and are not counted as new FDEs.

The requested unowned object-returning runtime lookup is still not independently closed: the only direct route in this composition crosses the already-owned `0x4dd6ea0` boundary, and its borrowed-hit-to-wrapper edge is not established by this packet. Runtime hash seeds, register/alias assumptions across dynamic helpers, arbitrary hooks, external database and allocation behavior, complete unwind actions, live revision choice and target equivalence remain open. The broader first HyperEVM task, including private-fork boundaries and state-transition inputs, is not complete; no progress gate is requested and `evm` remains 0/4.

Next question: independently review the existing borrowed lookup's full-key hit and dispatch under its current ownership, then validate the composed frame and error contracts with a separately authorized target-grounded harness.
