# bridge: JSON-text readers of the bridge event-name enum in node #115

This packet makes the path from JSON text to the bridge event tag in node #115 reconstructible from byte evidence: the four serde_json-shaped readers that read the six-name event enum (`Deposit` .. `RequestedValidatorSetUpdateEvent`) as a value or as an object key can now be rebuilt with their exact whitespace set, quote dispatch, string-parse call, hand-off to the `&str` name visitor, error finishing rule, colon rule, reader-position and scratch-word updates, and the proof runs the original reader code and the original merged visitor body together on 41,604 byte-derived cases (0 mismatches) with 55/55 negative controls detected.

- Component ID: `bridge` (no TASKS row; this is the JSON front end of the enum whose name visitors are owned by the merged `bridge-event-name-codec-115` packet)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was used
- Claim status: observation (decoded bytes, relocations, compared outcomes); inferences are listed separately below
- Scope included: four FDE-bounded reader bodies in two copy families (`0x1e20b30` and `0x3fb9fa0` as value readers, 291 B each; `0x1dee070` and `0x3f7bff0` as key readers, 385 B each), the two `&str` result visitors they call (`0x2864e60`, `0x44466c0`, 369 B each, run from file bytes inside every reader case), the bit-test whitespace loop, quote dispatch, every error branch, and a raw-byte census of every direct call site of the ten merged name visitors (33 sites in 12 host functions). Excluded: the string parser, the code-error constructor, the invalid-type constructor and the error finisher (recording stubs), the eight larger host functions that call the tagged visitors (listed in `visitor-call-sites.tsv`, not decoded), any gate change.

## Reproduce

Run from the repository root with the connected #115 binary (no execution of the binary, no external program; standard library plus `tools/fde_extents.py`, `tools/elf_index.py` and the merged `tools/re007_json_identifier_reader_115.py`, `tools/re007_margin_mode_codec_115.py` and `tools/bridge_event_name_codec_115.py`):

```
python3 tools/bridge_event_json_reader_115.py --out research/work-items/bridge-event-json-readers-115
python3 -m unittest tests.test_bridge_event_json_reader_115
sha256sum -c research/work-items/bridge-event-json-readers-115/MANIFEST.sha256
```

The tool refuses any input whose SHA-256 is not the one above. Peak resident set about 345 MB, about 50 s. `cases.tsv` holds every 8th case row (and every mismatch, of which there are none); `summary.json` records the SHA-256 of the complete 41,604-row table, which the tool recomputes on every run.

## Evidence

Coordinates are virtual addresses of the file-backed sections; every number is read from the ELF bytes with the shared parsers (no disassembler output is part of any evidence file).

- `functions.tsv`: the four readers and the two visitors, each an FDE start, int3-padded to its FDE end, decoded to the last byte (72, 101, 72, 101 and 93, 93 instructions), no LSDA. The readers' variant pools are the pools of the visitor they call (`0x643e050` for family 1, `0x648a528` for family 2).
- `instructions.tsv`: all 532 decoded instructions. A `jmp` whose target is the next instruction is a multi-byte nop (`66 .. 2e 0f 1f 84 ..`, alignment padding before the whitespace loop in the value readers); it is modelled as a fall-through jump.
- `literals.tsv`: the whitespace mask `0x100002600` (bits 9, 10, 13, 32), every `cmp` immediate (`0x22` quote, `0x3a` colon, `0x7d` brace), the code stores (`5` end of input in value readers, `3` in key readers, `0xa`, `0x11`, `6`), the error tag store (`6`: tags 0..5 are the names, 6 is `Err`), and the rip-relative description pools.
- `callees.tsv`: per body the roles of its callees: string parser (GOT slot `0x64e08f8`, the same slot the merged margin-mode readers use), name visitor, code-error constructor (`0x1d75420` / `0x3ef1a90`), invalid-type constructor (`0x1d76fd0` / `0x3ef2ab0`, value readers only), error finisher (`0x2cf8390` / `0x4671240`), unwrap panic slot `0x64df520`.
- `visitor-call-sites.tsv`: every direct `call rel32` whose target is one of the ten merged name visitors, with its host function (FDE start and size) and whether this packet decodes the host: 33 sites, 12 hosts. Four hosts are the readers decoded here; eight (`0x1a8b7e0`, `0x3204ab0`, `0x4af2d60` of 1,769 B; `0x1fabc40`, `0x394d730`, `0x56835d0` of 760 B; `0x1fae860`, `0x3952710` of 610 B) call the tagged and byte visitors and have landing pads.
- `cases.tsv`, `outcomes.tsv`, `paths.tsv`: per case input bytes, start position, result tag, result word, final reader position, scratch word and ordered calls; outcome census (every reader reaches all of: tags 0..5, code error, unknown-name finish, parse error, and for value readers the invalid-type finish); path census (executed-instruction count per outcome).
- `negative-controls.tsv`, `code-damage.tsv`, `range.tsv`: the controls below.

Observed behaviour of the readers (reader fields: buffer pointer `+0x18`, length `+0x20`, position `+0x28`, scratch word `+0x10`; output: tag byte at `+0`, a word at `+8`):

1. Position at or past the end: report code error 5 (value) or 3 (key). Otherwise read the byte at the position. Whitespace (tab, newline, carriage return, space, via the 64-bit mask and a bound guard `cmp 0x22`) advances the stored position; reaching the end afterwards reports the same code with the position already advanced.
2. A non-quote byte: value readers call the invalid-type constructor and then the error finisher; key readers report code `0xa` for `}` and `0x11` for every other byte with no finisher.
3. A quote consumes the quote, clears the scratch word to 0 and calls the string parser. A parse error is returned as is by the value readers and passed through the error finisher by the key readers.
4. The parsed text (pointer, length) is handed to the `&str` result visitor. Its `Ok` byte 0 selects the tag (byte 1); `Err` makes the reader call the error finisher with the visitor's error word, store tag 6 and the finished error. The reader itself contains no name compare.
5. Value readers return the name tag with the reader pointer in the word. Key readers first skip whitespace again (end of input: code 3), require `:` (anything else: code 6) and consume it.

## Implementation and comparison

`tools/bridge_event_json_reader_115.py` runs the original machine code of each reader in the interpreter of the merged margin-mode tool (extended by the merged JSON-reader tool with `neg` and `bt`, and here with the multi-byte nop). When the reader calls its visitor, a stub reads the text from the reader's memory and runs the original visitor body in the interpreter of the merged event-name tool (`run_visitor`, its own recording stub for the unknown-variant constructor); the visitor's `Ok`/`Err` result is written back into the reader's stack slot and the arguments the real visitor passed to its unknown-variant callee (text, pool, count 6) are logged as an event. Each case compares tag, word, final position, scratch word and the ordered event list with `recon(...)`, an independent pure-Python reconstruction that classifies names with the exact-match model of the merged event-name packet. Cases: byte-sweep first bytes, whitespace-prefix runs, every visitor input of the merged packet that is valid UTF-8 and free of quote and backslash (quoted, unterminated, and for keys with whitespace before the colon), name tails with colon variants, every start position inside a framed buffer, escape and control-byte strings, closing and stray bytes.

- Reconstruction match: 41,604/41,604 (value readers 2 x 9,668 cases, key readers 2 x 11,134); 758 cases accept a name; the real visitor body ran in 26,374 cases (every case that reached the visitor call).
- Negative controls: 55, all detected: 26 mutated reconstructions (whitespace set changes, nine wrong name classifiers - prefix, case fold, swapped withdrawals, alphabetical tags, first four bytes, last 16 bytes, length only, first byte, 25-row table - wrong code values, missing or extra finisher, scratch word not cleared, whitespace position not advanced, colon handling), 22 single-byte damages in the readers (value readers five sites, key readers six: two whitespace-mask bits, the quote compare, the first 8-byte code store, the error tag store, the colon compare) each run on a 744-case (value) or 857-case (key) battery, 6 single-byte damages inside the real visitors (length bound, length bias, first literal dword; run through the value readers on a 1,934-case battery), and one out-of-range control (start positions 0, 1, 2, 3, 2^64-1 and 2^63 on a two-byte buffer equal the reconstruction in all four bodies, and four mid-function addresses are not FDE starts).

## Results and limitations

`measure.json`: cases 41,604; negative_controls 55; negative_detected 55. Executed-path census: 178 distinct (body, instruction count, outcome) paths.

Inferences (not observations): the stub roles come from call order and argument shapes; the tag-6 byte as the error marker is inferred from the stores; reading the enum as serde `variant_seed` / `deserialize_identifier` is an inference from the shape; the string-parse stub is a documented model (closing quote, `\"` `\\` `\/` `\b` `\f` `\n` `\r` `\t`, ASCII `\uXXXX`, errors for end of input, control byte, bad escape, non-ASCII `\u`) shared by the interpreted run and the reconstruction, so what the packet proves is the code around the parser and the visitor.

Limits: the string parser, code-error constructor, invalid-type constructor and error finisher are not reconstructed; the unwrap panic is unreachable only because `position + 1` is never 0; the eight larger host functions that call the tagged and byte visitors are not decoded; inputs that are not valid UTF-8 are excluded because the real parser (not modelled) decides them; no Rust implementation is claimed and no component gate is requested.

Next question: the eight larger visitor hosts (`0x1a8b7e0`/`0x3204ab0`/`0x4af2d60`, `0x1fabc40`/`0x394d730`/`0x56835d0`, `0x1fae860`/`0x3952710`), which call the tagged `&str` and byte visitors and two other calls each and are the payload-bearing readers of the event variants; and the string parser at GOT slot `0x64e08f8`.
