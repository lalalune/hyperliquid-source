# RE-004: isolated-margin signed notional carrier and decimal digits in node #94

This packet establishes that the `ntli` field of `UpdateIsolatedMarginAction` is carried as an exact signed 64-bit integer between the selected reader and text writer, with a checked unsigned-64 input path and an exact decimal-digit output that handles the minimum signed value.

- Component ID: RE-004, assets and fixed-point quantities; the signed notional carrier of the isolated-margin action.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only.
- Claim status: observations are the bytes, FDE records, selected edges, table entries and field offsets; the arithmetic and field-flow descriptions are deductions from those bytes. The economic unit, parser's lexical input grammar, runtime call sequence and downstream admission rules are unresolved.
- Scope included and excluded: the selected action-dispatch arm, the action reader's field routing and payload store, the eight primitive integer load arms, the action text writer's field routing, and its signed decimal-digit builder. Other action arms, container/key iterator internals, fallback parser, allocator and error-helper internals, state mutation, binary #115 and target execution are excluded.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and its standard library. The generator authenticates the full input digest first, imports the repository ELF and FDE parsers, reads file-backed bytes only, writes only its selected output directory, invokes no external program and never executes the captured node. FDE extents describe unwind ranges, not a complete function census. No network, key or chain access is involved.

```sh
python3 tools/isolated_ntli_carrier94.py --out research/work-items/RE-004-isolated-ntli-carrier-94
python3 -m unittest tests.test_isolated_ntli_carrier94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-isolated-ntli-carrier-94 && sha256sum -c MANIFEST.sha256)
python3 tools/isolated_ntli_carrier94.py --out <tmp-dir-a>
python3 tools/isolated_ntli_carrier94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

`evidence.json` contains the input hash, complete selected FDE bytes and hashes, original file offsets, FDE coordinates and arithmetic constants. `windows.tsv` preserves the selected instruction bytes; `branches.tsv` decodes selected direct edges; `calls.tsv` validates the four direct calls; `writer-edges.tsv` labels six writer error and capacity edges; `rip-references.tsv` decodes 13 data references; `texts.tsv` records the exact named fields and diagnostic prefixes; `fields.tsv` reads the three field names through RELATIVE relocations. `tag-cases.tsv`, `presence-cases.tsv`, `duplicate-cases.tsv` and `digit-cases.tsv` are static model results. All are generated directly from ELF bytes and deterministic integer operations. The files contain no disassembler output.

## Evidence

Addresses are linked ELF virtual addresses before load bias; file offsets are separate in the generated evidence. Ends are exclusive. The FDE record and the unwind search-table entry must agree for each selected range.

| Role | FDE start | FDE end | FDE record |
| --- | --- | --- | --- |
| Selected variant dispatcher | `0x3358d10` | `0x335ad16` | `0xdf9468` |
| Action reader | `0x3a75470` | `0x3a75fb0` | `0x11d05a4` |
| Signed-value reader | `0x3b3fa20` | `0x3b3fb75` | `0x11db128` |
| Action text writer | `0x374b200` | `0x374b446` | `0xe4e9b8` |
| Signed digit writer | `0x3bec4a0` | `0x3bec674` | `0xe9d018` |

The variant arm loads the 26-byte action name, points at the three-field descriptor, and calls the action reader at `0x335938a`. A reader result tagged `9` leads to a 16-byte payload copy and stores action variant `0x98`. The descriptor at `0x56f1c08` has three relocated names, in order: `asset`, `isBuy`, `ntli`. Its string pointers and lengths are read independently from the ELF.

The selected map-like path in the reader dispatches key indices 0, 1 and 2 through the signed-relative jump table at `0x5aa290`. Index 2 calls the signed-value reader, for both inline and separately held values. Its successful value is saved as an eight-byte word; the payload store writes that word at reader output `+8`, the asset word at `+0x10`, and the side byte at `+0x14`. After the variant wrapper strips the reader's leading status area, those are action payload offsets `+0`, `+8` and `+0xc`. The writer independently loads a word at payload `+0` for the `ntli` field, then calls the digit writer. The `asset` and `isBuy` fields are written before `ntli`.

The writer checks the initial builder result before any field. A nonzero result from either of the first two field helpers exits through the common return; a rejected key-builder state reaches a separate error helper before the raw word load. A short output buffer enters a growth helper and retries the append. The digit builder has its own capacity check and growth retry. `writer-edges.tsv` records the taken and fallthrough destinations; helper effects and actual allocation success are not assumed by the branch map.

Presence and failure ordering is observable without assigning undocumented behavior to the error constructors. The reader tests whether each of the three fields was seen; the first absent-field diagnostic it requests is `asset`, then `isBuy`, then `ntli`. A duplicate recognized field selects a duplicate-field diagnostic with that field's name. A narrow byte-checked walker follows those three branch predicates for all eight presence combinations; `presence-cases.tsv` records its destination and the independently expected class. `duplicate-cases.tsv` records both sides of each duplicate guard. These are static paths, not target execution. The presence table assumes successful field readers and a side byte of 0 or 1; it stops at diagnostic construction rather than predicting the helper's returned status. Unexpected container tags go to a separate fallback helper; a field-value helper failure propagates to a separate result path. Neither the internals of those helpers nor arbitrary JSON lexical acceptance are claimed.

The eight entries of the signed-value reader's table at `0x5b1e0c` select these exact load forms. The selected opcode recognizer and an independent width/signedness model agree on the 40 boundary rows in `tag-cases.tsv`.

| Input tag | Load | Selected result |
| --- | --- | --- |
| 1, 2, 3 | zero-extended 8-, 16-, 32-bit integer | accepted as signed 64-bit value |
| 4 | 64-bit word followed by sign-bit test | values through `2^63-1` take the value path; words with bit 63 set take the diagnostic-building path |
| 5, 6, 7 | sign-extended 8-, 16-, 32-bit integer | accepted with sign preserved |
| 8 | 64-bit word | accepted with its bits preserved |
| other | separate helper | not characterized here |

The diagnostic-building helper is an external boundary; this packet does not claim its returned error representation or execution effects. A valid signed minimum has bits `0x8000000000000000` and is accepted on tag 8, while the same bits on tag 4 take the diagnostic branch. Thus the source tag matters even when the eight payload bytes match. These are properties of the selected typed-value path, not assertions that every textual parser emits every tag.

### Exact output digits

At the digit writer entry, `neg` and `cmovs` form the unsigned magnitude of the input word. This handles `-2^63`: the selected magnitude is `2^63`, even though it cannot be represented as a positive i64. For each four-digit chunk the target uses `M = 0x346dc5d63886594b` and high-product shift 11, corresponding to `(x*M) >> 75`, followed by a remainder. It decomposes that remainder using the multiplier `0x147b` and a 200-byte table of pairs `00` through `99` at `0x5b988d`. A negative input adds a minus sign. Zero produces the digit `0`. No scale division or rounding appears on this selected signed-integer-to-digits path.

The quotient identity is valid for every magnitude in `0..=2^63`: `10000*M = 2^75 + 432`. For `x = 10000*q + r`, the emitted integer bound verifies `q*432 + r*M < 2^75` at the maximum possible `q` and `r`, so the high product equals `q` throughout the domain. The tool also checks all 10,000 possible four-digit remainders against `((r >> 2)*0x147b) >> 17 = floor(r/100)` and validates all 100 digit-pair table entries. At most four four-digit chunks and a final leading group are needed, and the longest signed result has 20 bytes. The integer argument above, table check and instruction interpretation support the full-domain claim; the 66 emitted cases and 20,000 extra deterministic test values are controls, not exhaustive target execution.

For example, the static lift emits `0`, `9999`, `10000`, `9223372036854775807`, and `-9223372036854775808` for the corresponding input words. The output builder's growth branch and its retry are pinned, but successful allocation and buffer ownership are assumptions at this boundary. The selected writer calls the builder with the raw word; it does not establish the amount's financial unit or that all i64 words pass the later action handler.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo lockfile, compiler comparison, raw/normalized machine-code comparison, relocation closure or whole-ELF claim is made. The Python digit lift uses the target's extracted reciprocal and digit bytes and is compared with Python's independently expressed signed decimal formatting. The numeric load recognizer interprets only the eight pinned opcode forms and compares them with a separate type-width model. Neither is an emulator or a run of the captured node.

## Results and limitations

The packet binds 5 selected FDE ranges, 4 direct calls, 13 data references, 6 text records, 6 labeled writer branches, 39 checked byte windows, 33 selected branch edges, 3 field relocations, 8 typed-integer arms, 40 boundary rows, 8 presence combinations and 6 duplicate-guard combinations. The formatter model produces 66 retained examples, and its pair quotient is checked for all 10,000 four-digit remainders. The focused suite has 26 passing tests with no skips, including changed digest, FDE bytes, instruction bytes, numeric opcode, field relocation, digit table, branch/call opcode, range and NOBITS controls; it also compares 20,000 deterministic 64-bit words, all signed integers from -10,000 through 10,000, all 512 one-byte signed/unsigned cases and all 131,072 two-byte signed/unsigned cases.

The reader and writer are separately reached components with compatible payload layouts and the same binary action title; this is a static representation link, not evidence of a single live round trip. The signed-value fallback path, textual number tokenizer, error-helper effects, allocation failure effects, floating conversions and later margin admission are not reconstructed. No full RE-004 progress gate is requested.

Next question: trace an address-disjoint producer of the input token to these typed integer tags and establish which source representations and bounds the action can actually receive.
