# RE-007: margin-mode enum readers over JSON text (node #115)

This packet reconstructs how node #115 reads the margin-mode enum (`normal`, `noCross`, `strictIsolated`) out of JSON text: it can now be rebuilt as four small readers (two that read the enum as a value, two that read it as an object key) with their exact whitespace set, first-byte dispatch, name compare, error codes, error-finishing rule, reader-position and scratch-word updates, and the ordered callee calls, and the reconstruction is proven against the original machine code on 24,080 byte-derived cases with 56/56 negative controls detected.

- Component ID: `risk` (task RE-007; the `RE-007-margin-mode-codec-115` packet owns the msgpack serializers and the name visitors, this packet owns the JSON-text front end of the same enum)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; no reference source was used
- Claim status: observation (decoded bytes, relocations, compared outcomes) with the inferences listed separately below
- Scope included: four FDE-bounded bodies, `0x1e201f0` (376 B) and `0x3fba8b0` (376 B) as value readers, `0x1def7c0` (487 B) and `0x3f7fe90` (487 B) as key readers; the bit-test whitespace loop, quote dispatch, name classification, colon scan, every error branch; the variant-name pools and the raw-byte family scan. Excluded: the callee bodies (string parser, error constructors, error finisher), which are recording stubs; the five other bodies that spell the same names (see the family scan); any gate change.

## Reproduce

Run from the repository root with the connected #115 binary (no execution of the binary, no external program, standard library plus `tools/fde_extents.py`, `tools/elf_index.py` and the merged `tools/re007_margin_mode_codec_115.py`):

```
python3 tools/re007_json_identifier_reader_115.py --out research/work-items/RE-007-margin-json-identifier-readers-115
python3 -m unittest tests.test_re007_json_identifier_reader_115
sha256sum -c research/work-items/RE-007-margin-json-identifier-readers-115/MANIFEST.sha256
```

The tool refuses any input whose SHA-256 is not the one above. Peak resident set about 260 MB, about 100 s. `cases.tsv` holds every 4th case; `summary.json` records the SHA-256 of the complete 24,080-row table, which the tool recomputes on every run.

## Evidence

Coordinates are virtual addresses of the file-backed sections; all numbers are read from the ELF bytes with the shared parsers (no disassembler output is part of any evidence file).

- `functions.tsv`: the four bodies, each an FDE start, int3-padded to its FDE end, decoded to the last byte (98, 98, 128, 128 instructions), no LSDA.
- `instructions.tsv`: all 452 decoded instructions (bytes, op, branch target).
- `literals.tsv`: the whitespace mask `0x100002600` (bits 9, 10, 13, 32: tab, newline, carriage return, space), every `cmp` immediate (`0x22` quote, `0x3a` colon, `0x7d` brace, name lengths 6/7/14), the `xor [rip+disp]` name literals read from the target bytes (`norm`+`al`, `noCr`+`ross`, `stri`+`ctIs`+`Isolated` words), and the code stores.
- `variant-pool.tsv`: the `&[&str; 3]` pools `0x643e188` and `0x6475de0` resolved through their RELATIVE relocations: `normal`, `noCross`, `strictIsolated`, in tag order.
- `callees.tsv`: per body, the roles of its six (value) or five (key) callees: string parser (GOT slot `0x64e08f8`), code-error constructor, unknown-variant constructor, error finisher, invalid-type constructor (value readers only), and the unwrap panic slot `0x64df520`. The two copies call different code-error/unknown/finish targets (`0x1d75420/0x2cf1360/0x2cf8390` against `0x3ef1a90/0x45a8fe0/0x4671240`).
- `family-scan.tsv`: a raw-byte scan of every FDE body of at most 4,000 bytes for a `xor/cmp r32,[rip+disp32]` whose target spells at least three of the name words. It finds exactly nine bodies; the four above are decoded here, five more (`0x1fa4630`, `0x1fac540`, `0x3945390`, `0x394a4e0`, `0x567f110`) are listed as not decoded here.
- `cases.tsv`, `outcomes.tsv`, `paths.tsv`: per case input bytes, start position, result tag, result word, final reader position, scratch word and ordered calls; outcome and path (executed-instruction count) census.
- `negative-controls.tsv`, `code-damage.tsv`, `range.tsv`: the controls below.

Observed behaviour of every body (reader fields: buffer pointer `+0x18`, length `+0x20`, position `+0x28`, scratch word `+0x10`; output: tag byte at `+0` and a word at `+8`):

1. If position is at or past the end: report a code error (value readers 5, key readers 3). Otherwise read the byte at the position. A byte above `0x22` can never be whitespace (the compare is a bounds guard for the bit test); whitespace bytes advance the stored position, and reaching the end after whitespace reports the same code error with the position already advanced.
2. A non-quote byte: value readers call the invalid-type constructor (pool `0x6424020` in `0x1e201f0`, `0x647f218` in `0x3fba8b0`) and then the error finisher; key readers report code `0xa` for `}` and `0x11` for every other byte, with no finisher.
3. A quote consumes the quote, clears the scratch word to 0 and calls the string parser. A parse error returns that error as is in the value readers and passes it through the error finisher in the key readers.
4. The parsed text is classified by length (6, 7 or 14) and an exact byte compare against `normal`, `noCross`, `strictIsolated` (tag 0, 1, 2). An unknown text calls the unknown-variant constructor with the text, the pool and count 3, then the finisher.
5. Value readers return the tag with the reader pointer in the word. Key readers first skip whitespace again (end of input: code 3), require `:` (anything else: code 6) and consume it.

## Implementation and comparison

`tools/re007_json_identifier_reader_115.py` runs the original machine code of each body in the interpreter of the merged margin-mode tool, extended with `neg` and a register `bt` (decoded from the bytes, unmodelled forms rejected). Each case builds a reader (buffer bytes, start position), runs the body once with recording stubs for the callees and compares tag, word, final position, scratch word and the ordered call list (with decoded arguments) with `recon(...)`, an independent pure-Python reconstruction of the five steps above. The string parser stub is a documented model (`json_str`: closing quote, `\"` `\\` `\/` `\b` `\f` `\n` `\r` `\t`, ASCII `\uXXXX`, errors for end of input, control byte, bad escape, non-ASCII `\u`); it is the one assumption shared by the interpreted run and the reconstruction, so everything the packet proves is about the code around it. Cases: 256 first-byte sweeps, 585 whitespace-prefix runs times three tails, every name mutation input of the merged packet quoted/unquoted, colon tails and whitespace variants, every start position inside a framed buffer, escape and control-byte strings, closing/stray bytes.

- Reconstruction match: 24,080/24,080 (value readers 2 x 5,257 cases, key readers 2 x 6,783).
- Negative controls: 56, all detected: 23 mutated reconstructions (whitespace set changes, prefix/case-fold/swap/length-only/first-4-bytes/two-name classifiers, wrong code values, missing or extra finisher, scratch word not cleared, whitespace position not advanced, colon handling) and 32 single-byte damages to the code or its name literals (eight per body: two whitespace-mask bits, the quote compare, three length gates, the first name literal byte, and the first 8-byte store, which is the end-of-input code in the value readers and the scratch-word clear in the key readers), each run on a 310-case (value) or 399-case (key) battery, and one out-of-range control (start positions 0, 1, 2, 3, 2^64-1 and 2^63 on a two-byte buffer must equal the reconstruction in all four bodies, and two mid-function addresses must not be FDE starts).
- Equivalent mutant (recorded in `code-damage.tsv`, not counted as a control): changing the first `cmp $0x22` bound guard to `0x23` changes no outcome on the 310/399-case batteries (and none on the 256 first-byte sweep in the tests) in any body, because the bit test cannot select a byte above `0x22` and the later quote compare still rejects `0x23`.

## Results and limitations

`measure.json`: cases 24,080; negative_controls 56; negative_detected 56. Executed-path census: 172 distinct (body, instruction count, outcome) paths; outcome counts in `outcomes.tsv`.

Inferences (not observations): the stub roles come from call order and argument shapes (the panic slot is the last instruction before int3); the tag-3 byte as the error marker is inferred from the stores; reading the enum as serde `variant_seed` is an inference from the shape.

Limits: callee bodies are not reconstructed (string parser, error constructors, finisher); the unwrap panic is unreachable only because `position + 1` is never 0; the five other bodies that spell the names (family scan) are not decoded here; no Rust implementation is claimed and no component gate is requested.

Next question: the string-parse callee at GOT slot `0x64e08f8` and the error finisher `0x2cf8390` / `0x4671240`, whose reconstruction would remove the shared model assumption above.
