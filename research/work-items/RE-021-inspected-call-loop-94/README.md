# RE-021: inspected-family interpreter call-frame preparation

Node #94's inspected-family revision-9 and revision-12 tables connect input-copy handling to distinct `0xf4` frame builders, so a reconstruction can preserve the conditional 213-byte input handoff, 20-byte target, charges and failure order.

- Component ID: `evm`; RE-021 continues the existing BLAKE2b precompile investigation and is not an official task-queue row.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference implementation was copied.
- Claim status: **observed** for ELF bytes, selected FDE/CIE and exception records, relocations, byte lanes, immediate fields and direct transfers; **inferred** for opcode, frame, gas and host names and for composition under the stated conditions; **unresolved** for method selection by a live node, the interpreter action's downstream owner and the B-family runtime lookup.
- Scope included and excluded: two descriptor methods, both table-loop forms, two table wrapper methods, the selected `0x37` input-copy handler, two selected `0xf4` handlers, their common range and host adapters, and action replacement/drop. The existing address-09 object, compressor, provider builder, callback at descriptor `+0x28`, runtime lookup, external account and allocation helpers are dependencies, not newly selected bodies. Node #115, visor, target execution and complete HyperEVM recovery are excluded.

## Reproduce

From the repository root, with the authenticated node #94 artifact available and Python 3.12.3 on Linux x86-64:

```sh
python3 tools/re21_inspected_call94.py --out research/work-items/RE-021-inspected-call-loop-94
python3 -m unittest tests.test_re21_inspected_call94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For two independent outputs, replace the placeholders with different empty directories:

```sh
PYTHON_BIN=$(command -v python3)
PATH= PYTHONHASHSEED=1 TZ=UTC "$PYTHON_BIN" tools/re21_inspected_call94.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$PYTHON_BIN" tools/re21_inspected_call94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
PATH= "$PYTHON_BIN" -m unittest tests.test_re21_inspected_call94
```

The generator verifies the whole input digest before parsing and uses only Python's standard library and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py` readers. It rejects NOBITS, ambiguous and crossing file mappings. Its restricted LSDA call-site reader follows the encoding and bounds approach in the pending RE-021 call-frame work; action chains and exception types are not decoded. GNU objdump 2.42 was used only for human instruction review: no generator or test calls it, or parses its output. No target instructions are run or emulated. `MANIFEST.sha256` covers this README and all generated files.

## Evidence

### Coordinates and ownership

All addresses are linked ELF virtual addresses before load bias, with exclusive ends. `functions.tsv` records file offsets, FDE/CIE/LSDA addresses and interval hashes; `bodies.json` retains the selected interval bytes. `unwind.json` records the original CIE, FDE and header-index bytes. FDE ranges are unwind ranges, not a complete source-function inventory. `windows.tsv` records fixed byte predicates, `edges.tsv` selected relative transfers, and `exceptions.json` LSDA call-site entries. These records do not claim a complete CFG.

The previous compression packet identifies the address-09 object. Pending PR #1373 maps one registry/lookup family, #1612 maps the inspected provider and descriptor construction, and #1799 maps a different interpreter family. None of the 12 FDE starts selected here appears in the checked-out work-item evidence or available previous PR packets. In particular, the earlier callback method at descriptor `+0x28` and the existing B-runtime body are not reselected. The supplied PR inventory does not include the contents of every PR, and no network refresh was performed; a submission-time overlap check remains necessary.

### Descriptor to interpreter action

The `+0x18` and `+0x20` RELATIVE slots of descriptor `0x56e70f0` resolve to `0x329a050` and `0x3291a00`, respectively. The two 369-byte FDE intervals select `0x37a5840` when the table representation's first word is nonzero; when it is zero they advance the table pointer by eight bytes and select `0x37a59c0`. The methods move a 56-byte state value into the loop and, after a normal return, copy the resulting state and 64-byte action to their outputs. These descriptor methods are distinct entry points; their actual invocation by a particular engine is not established. Pending #1612 associates this descriptor with a callback group but describes a separate `+0x28` method.

`adapter-comparison.json` compares the two target intervals. They differ in eight PC-relative fields. Masking exactly four bytes at offsets `0x3c`, `0x46`, `0x51`, `0x7e`, `0x9f`, `0xd8`, `0xe7` and `0xf6` makes the remaining bytes equal; the generator independently decodes and checks both targets of every masked field. These are within-target instruction displacements, not declared ELF relocations, a rebuilt-code comparison or a whole-function equivalence claim.

On entry, both loops first call the selected old-action drop at interpreter `+0x150`, set action byte `+0x188` to `0x70`, conditionally release two old memory-shaped allocations when their respective size words are nonzero, and copy the supplied 56-byte state to interpreter `+0xe0`. The second release scales its size word by eight. These effects occur before the first status-byte test. If the initial old-action drop unwinds, each selected LSDA landing writes `0x70`, calls the recorded state-cleanup boundary and resumes unwinding without reaching the normal state replacement. The allocator and cleanup boundaries are not decoded here.

In the raw loop, `0x37a5a70` loads one byte through the interpreter pointer at `+0x1d0`, increments that pointer, and calls `table[byte]` with eight-byte slots. The pair loop at `0x37a58f0` uses the byte times 16, loads a data/descriptor pair, and calls descriptor `+0x28`. Both repeat while interpreter status `+0x1f3` is zero. A nonzero status ends the loop; if action byte `+0x188` is not `0x70`, the loop moves the 64-byte action starting at `+0x150` to its result and resets that action byte to `0x70`. When the action byte is `0x70`, the alternative arm builds a default-shaped result and copies the current status and selected interpreter words into it.

The RELATIVE descriptor slots in `wrappers.json` bind `0x56ee670 + 0x28` to `0x3587550` and `0x56f38e0 + 0x28` to `0x37d05b0`. Both wrapper methods temporarily decrement the instruction pointer and restore it before delegation only when the status byte is zero. One tail-calls the stored function pointer; the other tail-calls a stored pair's descriptor `+0x28` method. Their nonzero-status return leaves the decrement in place. This describes the method's instruction behavior, not a claim that the normal loop invokes it with nonzero status. The earlier inspected installer has a separate zero-representation helper boundary; whether it installs either descriptor above for a live invocation remains unresolved. The origin and installation of a particular pair table remain a prior, external boundary.

`opcode-tables.tsv` reads every slot and RELA record for two file-backed 256-entry tables. Both tables' `0x37` entries bind to `0x37b9060`. Their `0xf4` entries bind `0x56fdf80` to `0x37bf1d0` and `0x56fb780` to `0x37be6a0`. Pending PR #1612's case records and retained constructor bytes associate the first source table with input revision bytes 9/10, and the second with 12–14; that association depends on the earlier packet rather than reselecting its constructor FDE here. Those tables may be supplied to the raw loop, or their function pointers may be supplied through a compatible wrapper pair. Which table a live engine installs, whether it uses the `+0x18` or `+0x20` entry, and whether intervening callbacks replace an entry, are not established by these data records. Opcode and delegate-call names are inferred from the table positions and the frame operations.

### Input-buffer to frame-memory handoff

The shared `0x37` handler interprets three 32-byte stack words as destination, source offset and length, with destination at the top. This is an inferred input-copy operation from the selected table position, field offsets and copy calls. The input pointer/length are at interpreter `+0x48/+0x50`. The destination base is the sum of fields `+0xe8` and `+0x110`; the separate range helper later uses that same sum to read the selected frame input. This correspondence requires the same interpreter object, successful copy and growth helpers, valid nonaliasing buffers and no intervening mutation.

| Selected input-copy condition | Observed local order or result |
| --- | --- |
| Fewer than three stack words | Store status `0x5b` before decrementing the count or charging. |
| Nonzero high limbs of length | Store the three-word decrement and status `0x54`, without the base charge. |
| Insufficient base charge | Store status `0x50` after the decrement, without storing a failed subtraction. |
| Zero length after payment | Return before the two offset checks or memory expansion. |
| Nonzero length and nonzero high destination limbs | Store status `0x54` after the charge. |
| Nonzero high source limbs | Clamp the source offset to the maximum 64-bit word; an offset at or past input length selects zero filling. |
| Required memory window exceeds its current extent | Call the recorded growth slot; zero return stores status `0x51`. |
| Source starts within the input | Copy the available prefix and zero-fill the remaining requested bytes; a selected source-end overflow follows a separate failure call. |

For a 64-bit length, the initial charge is `3 + 3 * (min(length + 31, 2^64 - 1) >> 5)`, before a separate possible growth charge. `input-copy-constants.json` reads the rounding and shift immediates and checks the multiplication instruction shape; `imports.json` identifies both `memcpy` and `memset` from ELF relocation and dynamic symbol data. Other overflow diagnostics and external helpers remain boundaries.

In a synthetic case, copying 213 bytes from input offset zero to memory offset `d`, then selecting the unchanged range `d..d+213` in either `0xf4` handler, carries those 213 bytes into the frame and charges 24 for the input-copy base operation. That relationship also requires the same interpreter and the successful, ordinary, nonaliasing copy behavior above. The 41 `input-copy-cases.json` rows and 212/213/214 tests are projections of the selected source and charge predicates, not node executions or proof that the frame reaches the BLAKE2b wrapper.

### Target, input and charges

Both selected handlers consume two 32-byte stack words before calling the range helper. The second word's bytes 19 down to 0 are assembled into the 20-byte host argument and independently into frame offsets `+0x60..+0x73`; `address-lanes.tsv` derives all 40 source/host/frame rows from the fixed byte shapes. As a synthetic projection, a little-endian 256-bit word of value 9 yields nineteen zero bytes followed by `09`; changing any of the upper 96 bits does not change that projection. This is not a captured invocation.

`0x37bd260` requires four more stack words. On the inspected nonempty-input arm it takes the low word of the second of those four as the allocation and copy length, subject to the high-word, range, allocation and memory-growth checks in `windows.tsv` and `edges.tsv`. It returns that length in its output word at `+0x10`. The handlers copy that word into frame `+0x38`; the returned four-word buffer representation begins at frame `+0x28`. The copy slot's dynamic relocation and symbol record identify `memcpy` (`imports.json`); loader interposition and its runtime behavior remain external. Given length 213, a valid range, successful allocation/copy and no intervening mutation or aliasing, the frame length is 213. The previous BLAKE2b wrapper tests that length, but this packet does not show that this frame reaches the wrapper.

After the range helper, `0x32fe900` calls an external account boundary. Its success-tag arm packs three returned bytes into a word; its non-success arm replaces a context error-shaped value and returns low byte 2. The handlers check that low byte before calculating a charge. For the other values, write `h` for that packed word:

| Selected table | Charge after successful range and host calls |
| --- | --- |
| `0x56fdf80` | 700 |
| `0x56fb780` | `(2600 if h & 1 else 100) + (0 if (h >> 8) & 0xff == 2 else 2600 if h & 0x100 else 100)` |

`cost-constants.json` reads the immediate bytes in the selected bodies. Equality with the charge proceeds; a smaller available word takes the failure arm. On the successful subtraction path, the remaining word is reduced by the forwarded request, capped at `remaining - floor(remaining / 64)`; when the requested 256-bit value does not fit in 64 bits, the inspected arm selects that cap. The 50 `synthetic-cases.json` rows test selected host and charge boundaries, not target execution or actual host return domains.

### Selected failures and action ownership

| Condition | Observed local effect |
| --- | --- |
| Fewer than two initial words, or fewer than four words at the range helper | Status `0x5b`; if one initial word existed its count was already decremented. |
| Selected nonzero high input/output range limbs | Status `0x54`; the range helper has already stored the four-word count decrement, and its later output failure releases the temporary buffer. |
| A selected memory-growth callback returns zero | Status `0x51`, with the later output branch also dropping the temporary buffer. |
| Host result low byte is 2 | Status `0x65` after range preparation; the charge and normal frame publication are bypassed. |
| Available gas is below the selected charge | Status `0x50`, with the temporary buffer dropped. |
| The selected 160-byte frame allocation returns null | Calls the recorded allocation-failure slot and reaches `ud2` if it returns. The normal charge precedes this allocation. |
| Old-action drop unwinds | The FDE exception table names a landing that installs the new pointer and action `0x6c` before resuming unwind; the later normal-path status `0x20` store is not on that landing. |

On the selected normal path, the handlers allocate and copy a 160-byte frame, drop the old action via `0x37f9580`, store the new pointer at interpreter `+0x150`, action byte `0x6c` at `+0x188`, and status `0x20` at `+0x1f3`. The separate action-drop table (`action-table.json`) maps its index zero to the `0x6c` arm: a dynamic payload drop followed by a tail call through the recorded deallocation slot with size 160. Dynamic destructor, allocator, host and memory-growth implementations remain external. No transaction-wide rollback or persistence guarantee follows from these local stores.

The two FDE exception tables record the old-action-drop call sites and their distinct landing addresses. The other protected intervals, including range cleanup, are also retained, but action chains and behavior of external unwind helpers are not reconstructed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, compiler/linker flags, two-build result, rebuilt-byte comparison, native behavior, helper closure and whole-ELF equivalence are **not yet implemented/measured**. The only masked comparison is the explicit within-target adapter comparison above; it is not a reconstruction comparison.

The focused suite passed **23 tests with zero skips**, including digest and selected-byte corruption, missing/duplicate FDEs, non-file-backed and crossing ranges, altered branch displacements, missing/duplicate/wrong relocations, corrupted dynamic import names, changed table or lane operands, corrupted input-copy arithmetic, input-copy and gas boundary projections, corrupt exception headers and all 256 single-bit target-word changes. Two generations under different hash seeds and timezones with an empty executable-search PATH matched byte-for-byte. These are extraction/model controls, not native behavior tests.

## Results and limitations

`summary.json` records 12 selected FDE intervals totaling 6,324 bytes, 53 fixed windows, 54 selected transfers, 512 opcode relocation records across two tables, four descriptor and four helper relocations, two symbolic imports, 40 address lanes, 33 call-site rows in six LSDAs, four action-table entries, 50 gas cases and 41 input-copy cases. These are selected-corpus counts, not node coverage or matched-code denominators.

The new result is a bounded interpreter-to-action path. It does **not** independently establish that the action reaches the earlier B-runtime callback, that its lookup finds the address-09 object, or that a BLAKE2b invocation occurs. The first HyperEVM component task, its private-fork boundaries and all state-transition inputs remain incomplete; no progress gate is requested and `evm` remains 0/4. Next question: under the existing ownership constraints, establish the action-to-B-runtime handoff and review that runtime's lookup-to-dispatch edge without reselecting its already exported FDE.
