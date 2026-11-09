# RE-009: reconstruct the three sibling state-export output routers 0x422f320, 0x50ddcc0 and 0x4773b90 of node #115

This packet lets a reimplementation of the state-export output step decide, for three bodies that the ten-copy router packet does not cover, exactly when output goes nowhere (`/dev/null`), when the rmp serializer is chosen (last path component with an ASCII case-insensitive `rmp` extension, component tag 9, not `..`, dot not in the first byte), how each body drives its serializers (one call, a four-way enum jump table, or header + optional field + body), how a 0x80-byte JSON buffer is grown, and in which order the parent check, atomic write, buffer release and error conversions run. A Python model of each body reproduces the recorded call sequence and return value of the real code bytes on 10,659 generated cases, and 104 deliberate corruptions (model mutants, code-byte patches, out-of-range input) are all detected.

- Component ID: RE-009 (storage / state roots; abci state export output)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace at `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied
- Claim status: observation for the control flow of the three bodies as executed by the evaluator; inference for the meaning of the stubbed callees (see Limits)
- Scope included: the three bodies in full (FDE sizes 834, 840, 862 bytes), their tail (parent check, atomic write, release) and their error and allocation-failure branches. Excluded: the bodies of every callee (all replaced by recording stubs), the callers, the types of the values being written.

## Reproduce

Run from the repository root with the standard library only; nothing is executed from the node binary, it is read as bytes:

    python3 tools/state_export_sibling_router_115.py --out research/work-items/RE-009-state-export-sibling-router-115
    python3 -m unittest tests.test_state_export_sibling_router_115

The tool first checks the binary SHA-256 above, then regenerates `cases.tsv`, `controls.tsv`, `unit_names.json`, `summary.json` and `measure.json` byte for byte (no clock, no randomness, no absolute path). One run takes about 15 s and 245 MB; the 24 tests take about 15 s. It uses the shared evaluator `tools/decimal_scaled_u64.py` (`Image`, `Machine`) and does not call objdump or readelf.

## Evidence

Coordinates are virtual addresses of the PT_LOAD image (`.text` file offset differs from the VA by 0x1000, `.rodata` matches).

| body | entry | FDE size | value argument | rmp side | JSON side |
|---|---|---|---|---|---|
| A | 0x422f320 | 834 | pointer to pointer to value | one call 0x3d517e0 | slice writer 0x4301950, copied into a 0x80 buffer, grown by 0x43bd910 when longer than 0x80 |
| B | 0x50ddcc0 | 840 | byte-sized enum, jump table at 0x91a3e4 (4 entries) | one name call 0x57cf860 per variant | serializer struct + 0x56183d0 |
| C | 0x4773b90 | 862 | pointer to pointer to value | 0x477be60 header, 0x4778560 field when header byte +0xb is set, 0x47789c0 body | serializer struct + 0x4783f20 |

Shared front (all three, read from the code bytes and exercised by the evaluator):

1. length 9 and bytes equal to the 8-byte immediate `0x6c756e2f7665642f` plus `l` return 0 immediately, with no call.
2. otherwise a 0x40-byte iterator `{ptr, len, tag 6, flags 0x0201, absolute = len != 0 && first byte == '/'}` is passed through GOT slot 0x64e0938 (relocation target 0x5cab560) and the result byte at +0 must be 9; a two-byte name `..` is refused; the name is scanned backwards for `.`; a dot at index 0 or no dot means JSON; otherwise 0x159fca0 compares the tail with the 3-byte literal at 0x4659e5 (`rmp`).
3. rmp: `Vec{cap 0, ptr 1, len 0}` and a reader struct `{&Vec, 0x01000400, 0}` are built; JSON: 0x80 bytes are allocated through slot 0x64df480 (target 0x6355830), failure calls slot 0x64df498 (target 0x141e264) and never returns.
4. tail: parent check slot 0x64e0028 (target 0x15020f0); only when it returns 0, atomic write slot 0x64e09e8 (target 0x15024a0) with `(buf, len, path, path_len, extra)`; then the buffer is released through slot 0x64df4a0 (target 0x635de30) when its capacity is not 0, and the write result (or the parent-check result) is returned.
5. errors: a serializer failure releases the Vec when its capacity is not 0, builds `{0x8000000000000000, rax, rdx}` and returns the converter result (0x422f740, 0x50df400, 0x4773fc0); a JSON writer error (B, C) releases the buffer when the capacity written back is not 0 and calls 0x50df4c0 / 0x4773ef0 with the error pointer; a capacity equal to `i64::MIN` (negation overflow, `jo`) calls the same function with the buffer pointer (A: 0x422f670).

Slot 0x64df508 (memcpy in A) has no relative relocation in `.rela.dyn`, so the evaluator treats it as an imported copy. Variant-name sites of body B are parsed from the jump table and the fixed `lea rsi / lea rdi / mov edx` pattern; `unit_names.json` lists the four (address, length, raw bytes) rows. Entries 4 to 7 that follow the four-entry table in `.rodata` belong to a different table, and a tag byte above 3 makes the evaluator run into other code (test `test_tag_outside_jump_table_is_refused`).

Coverage of the real code: `summary.json` lists every decoded instruction of each body (A 201, B 207, C 205) and the ones never executed. For each body the 21 unexecuted instructions are the exception landing pads that follow the non-returning allocation-error call and end in `_Unwind_Resume`; all other instructions are executed by at least one case.

## Implementation and comparison

`tools/state_export_sibling_router_115.py` has three parts. `Env` is the shared callee environment: every callee records its arguments in a log and returns what the case decides (component tag and name, serializer status pairs per stage, JSON bytes and written-back capacity, allocation success, parent and write results). `model()` is an independent, procedural Python model of the three control flows that only talks to `Env`. `Rig` runs the real bytes of the body in the shared evaluator with every call target replaced by a stub that decodes its arguments from registers and memory (and checks the contract: value pointer forwarded, `rmp` literal, 0x80 allocation size, reader flags `0x01000400`, alignment 0) and writes its results back into evaluator memory, so the code under test must carry the bytes (for example the JSON text copied into the buffer, the write length) through its own registers. A case passes when the machine's `(return value, call log)` equals the model's, including every pointer and the bytes handed to the writer.

Cases come from 53 path/component fronts (exact and near `/dev/null`, upper and mixed case extensions, `..`, `.`, dot at index 0, trailing dot, non-9 component tags, relative and doubled separators) crossed with per-body serializer scenarios (success with 0, 1, 5, 129 and 300 bytes and capacities 0, n, n+7; failure at every stage with five status pairs and two pre-failure capacities; JSON lengths 0 to 300 around the 0x80 and 0x81 thresholds, written-back capacities 0x80, 0, 0x300 and `i64::MIN`, writer error with and without capacity, allocation failure), while parent result, write result and the `extra` argument cycle through four combinations and body B cycles its four enum tags.

Negative controls (104, all detected): 49 model mutants (A 17, B 16, C 16: always JSON, always rmp, ignore the component tag, skip the `..` test, no `/dev/null` shortcut, prefix match, wrong absolute flag, accept a dot at index 0, wrong extension offset, case-sensitive extension, write despite parent failure, write before the check, free always, leak, keep the Vec on failure, ignore capacity overflow, grow one byte early, shifted enum names, field call always); one flip of every executed short (`0x70`..`0x7f`) conditional jump of every body (A 11, B 14, C 12 = 37; the three per body inside the unexecuted landing pads are not used), and per body five code-byte patches (the `.` and `..` immediates, the component-tag compare, the 0x80 allocation size, the reader-flag constant; 15 in total); and three enum tags outside the jump table, which the model refuses. A control counts as detected when the patched or mutated side disagrees with the reference on a probe case (every 11th case) or breaks a stub contract. No control was dropped for being undetected.

## Results and limitations

`measure.json`: 10,659 cases, 104 negative controls, 104 detected, 0 mismatches. Per-body counts and the SHA-256 chain over all case digests are in `summary.json`; `cases.tsv` lists every second case (5,330 rows: body, index, path and name in hex, component tag, enum tag, scenario, parent and write results, return value, number of recorded calls, 12-hex digest of the full log); the unlisted cases are covered by the chain hash.

Limits: every callee is a stub, so nothing here proves what 0x3d517e0, 0x4301950, 0x43bd910, 0x57cf860, 0x56183d0, 0x477be60, 0x4778560, 0x47789c0, 0x4783f20 or the five error converters do, only how the three bodies call them and what they do with the results; their output arguments are inferred from how the bodies read them. The component function 0x5cab560 is stubbed with a component tag and name chosen by the case rather than derived from the path, because its own behaviour belongs to another packet. The types written by the three bodies and their callers are not identified. The ten-copy router (0x2e4-byte body), the pretty-JSON writers and the parent check / atomic write bodies are covered by other packets and are only called here.

Next question: the callers of 0x422f320, 0x50ddcc0 and 0x4773b90, to find which state values are written through each, and the serializer bodies behind 0x4301950 / 0x56183d0 / 0x4783f20.
