# transport: reconstruct node #115 HPACK Huffman encoder, length-prefixed string literal and indexed-name literal (0x179d760, 0x17acf90, 0x17ad380)

- Component ID: transport (Network transport; vendored `h2` crate HPACK encoder used by the node's HTTP/2 server side)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30` (main when the packet was made); no reference source was copied. The RFC 7541 Appendix C.4 vectors in the tests are public-standard values.
- Claim status: observation (byte-replayed behaviour) plus inference (role names `huffman_encode`, `encode_str`, `encode_literal_name_index`, which follow the observed wire output and are not symbol names)
- Scope included and excluded: three function bodies replayed on the image bytes, the 257-entry code table they read, and a model of the BytesMut slots. Excluded: the dynamic-table functions (`0x17aca30`, `0x17acc80`, `0x17ac730`), the 11,216-byte header-block encoder `0x17ad510` that calls these three, and every decoder.

This packet makes the HPACK string / literal wire output of node #115 reconstructable without the binary: the Huffman code table (257 x `(bits, code)` read from `.rodata` at `0x487490`), the Huffman bit packing with all-ones padding, the string-literal length prefix (`0x80 | len` below 127 bytes, otherwise `0xff` plus a 7-bit continuation varint of `len - 127`, with the body shifted right to make room) and the literal-with-indexed-name head (4-bit prefix `0x0f` / `0x1f` plus a varint of `index - 15`, `0x10` for the never-indexed flag) are now a short executable Python model that equals the real machine code on 10,139 generated cases.

## Reproduce

From the repository root with the authenticated target present (no network, the binary is never executed; the tool only reads ELF bytes and interprets them):

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
python3 tools/transport_hpack_encode_115.py --out research/work-items/transport-hpack-encode-115
python3 -m unittest tests.test_transport_hpack_encode_115
(cd research/work-items/transport-hpack-encode-115 && sha256sum -c MANIFEST.sha256)
```

The tool uses only the standard library and the repository parsers `tools/elf_index.py` and `tools/fde_extents.py`; it calls no external program. Python 3.12. Regeneration writes every file in this folder except `README.md` and `MANIFEST.sha256` and is deterministic (no clock, no unseeded randomness, no host path). Peak memory is below 1 GB.

## Evidence

Coordinates are virtual addresses of the PIE image (`.text`, `.rodata`); file offsets come from the section headers read by `elf_index`.

| Function | Entry | FDE end | Bytes | Role observed |
| --- | --- | --- | --- | --- |
| `huffman_encode` | `0x179d760` | `0x179d8fc` | 412 | `(src ptr, src len, &mut BytesMut)`, table lookup `[byte << 4]` gives `(bits, code)`, 40-bit accumulator, one byte flushed at a time, final byte padded with ones |
| `encode_str` | `0x17acf90` | `0x17ad371` | 993 | empty source writes one `0x00` byte; otherwise pushes a placeholder, calls `huffman_encode`, then writes `0x80\|len` or `0xff` + varint and shifts the body |
| `encode_literal_name_index` | `0x17ad380` | `0x17ad504` | 388 | `(index, value ptr, value len, sensitive, &mut BytesMut)`; index <= 14 is one byte (`\|0x10` when sensitive), larger indexes use prefix `0x0f`/`0x1f` plus a varint of `index - 15`; ends with a tail jump to `encode_str` |

* [functions.tsv](functions.tsv): entry, FDE end, byte length, SHA-256 of each body, instruction counts (decoded / executed by the cases).
* [huffman-table.tsv](huffman-table.tsv) and [table-checks.tsv](table-checks.tsv): the 257 entries read from `0x487490` (16-byte records, `bits` then `code`, both little-endian u64) and the checks run on them: the Kraft sum is exactly 1, the sorted left-aligned codes are prefix free, the shortest code is 5 bits and the longest 30, and five anchor entries (symbol 0 = 13 bits `0x1ff8`, `' '` = 6 bits `0x14`, `'0'` = 5 bits `0x0`, `'a'` = 5 bits `0x3`, EOS = 30 bits `0x3fffffff`) equal the published HPACK table. The Kraft and prefix-free results are derived from the bytes; the anchors are the independent public values.
* [coverage.tsv](coverage.tsv): every decoded instruction of the three bodies with an executed flag. Executed: 86 of 101, 143 of 249 and 99 of 99. Unexecuted rows are panic landing pads and the unrolled tail that writes 4 to 7 varint bytes (a body of at least 2,097,279 Huffman bytes, which does not fit the 4 MB emulator heap).
* [digest.tsv](digest.tsv): per case family counts, emulated instruction counts and mismatches (0), the SHA-256 of all expected outputs, and how many times the reserve slot and the put slot were reached.
* [cases-sample.tsv](cases-sample.tsv): every second case with an input of at most 60 bytes and an output of at most 64 bytes (input, expected output, steps); the full set is regenerated by the tool, its output digest is in `digest.tsv`.

Call facts used: `encode_str` calls `huffman_encode` by direct `call` (`0x17acfd1`); `encode_literal_name_index` ends with `jmp 0x17acf90`; `encode_str` is also called five times and `encode_literal_name_index` twice from the header-block encoder `0x17ad510`, `huffman_encode` has the single caller `0x17acf90`. The three bodies reach the BytesMut reserve slot `0x64dfc90`, the put-slice slot `0x64e0670` and the panic slots `0x64df520`, `0x64df620`, `0x64df840`, `0x64df848`, `0x64df898`; the struct layout used by all three is `{ptr, len, cap}` at offsets 0, 8, 16.

## Implementation and comparison

`tools/transport_hpack_encode_115.py` contains (1) an offline x86-64 interpreter (decoder, memory, machine) that runs the original bytes of the three functions, (2) a harness that models only the two BytesMut slots (reserve grows the buffer to at least `max(2*cap, len+n, 64)`; put-slice appends; the reserve stub rejects any second argument other than 1, which is the only value the call sites pass) and turns every panic slot into an exception, and (3) the reference model, written from the wire format: `huffman_ref`, `varint_ref`, `string_ref`, `literal_ref`.

Cases (generated deterministically from a fixed seed; the generator never looks at emulation results):

| Family | Cases | What it covers |
| --- | --- | --- |
| huffman-single | 256 | every source byte value alone |
| huffman-random | 1,900 | strings up to 30 bytes over six alphabets (digits, lower case, URL characters, all 256 values, high bytes, control bytes), random existing destination bytes and spare capacity (0 forces the reserve slot) |
| string-sweep | 420 | `n` x `'0'` for n = 0..419: Huffman length 0..262 bytes, crossing the 127 and 255 prefix boundaries |
| string-boundary | 40 | exact Huffman lengths 125..127, 128, 129, 253..257 and the neighbours, with destination prefix bytes |
| string-random | 3,100 | random strings up to 50 bytes |
| literal-sweep | 900 | index 0..149 x sensitive x three values |
| literal-boundary | 120 | indexes 14/15/16, 142..145, 16398..16400, 2097166..2097168, 2^28, 2^35, 2^42, 2^49, 2^56 (+15), both flags |
| literal-random | 3,400 | random indexes (small, below 5000, below 2^30), flag, value up to 40 bytes |
| string-huge | 3 | strings whose Huffman length is exactly 16,510 and 16,511 bytes (first byte `a`) and 16,511 bytes (first byte `0xff`): the 2-byte / 3-byte varint boundary at `0x3fff` / `0x4000` |

Result: 10,139 cases, 19,192,240 emulated instructions, 0 differences. Each case compares the appended bytes with the model and also checks that the bytes already in the destination are untouched.

Negative controls (109 made, all counted, [controls.tsv](controls.tsv)): single-byte code mutants of every executed conditional jump (condition inverted) and of immediates (low bit flipped, about 70 of them, skipping stack-frame arithmetic and compares against bounds of 0x10000 or more, whose boundary lies beyond the emulator heap: `0x200000` and `0x10000000` in `encode_str`), plus table mutants (bits + 1 and code ^ 1 for symbols 0, `'0'`, `'a'`, 0x7f, 0x80, 0xff). A mutant counts as detected when any case differs, raises or halts. Each is first run on a probe subset (every 31st case of six families plus all boundary cases), then on the three huge cases; a mutant claimed as equivalent instead must agree with the model on every 20th of all cases. Result: 104 detected, 5 equivalent, 0 unexplained. The five equivalents are in [equivalent-mutants.tsv](equivalent-mutants.tsv) with the reason: two overflow guards that cannot fire (`0x179d7cf`, `0x179d83b`), a flush-loop bound that only delays a complete byte (`0x179d855`), the placeholder length byte that every path overwrites (`0x17acfb0`) and a lower-bound check of the body shift (`0x17ad139`). One more control class lives in the tests: a tampered image fails the SHA-256 check, an address outside every section is rejected, and a reserve call with a changed argument stops the harness.

## Results and limitations

Machine-readable: [measure.json](measure.json) (`cases` 10,139, `negative_controls` 109, `negative_detected` 104, `equivalent` 5). Tests: `tests/test_transport_hpack_encode_115.py`, 20 tests, no skips, about 8 seconds.

* Passed: model equals the machine code on all 10,139 cases; the table is a complete prefix code and reproduces the four RFC 7541 Appendix C.4 Huffman vectors (`www.example.com`, `no-cache`, `custom-key`, `custom-value`) in both the model and the emulated code.
* Not shown: bodies longer than about 4 MB of Huffman output (the 4 to 7 byte varint tail); the BytesMut growth policy (only the contract used by these bodies is modelled, the real reserve/put code is not reconstructed here); who builds the index and the sensitive flag for `encode_literal_name_index` (that is the header-block encoder `0x17ad510`); any decoder; runtime reachability and which requests the node actually encodes.
* No component gate is requested; this is one part of the `transport` behaviour gate, not its whole scope.

Next question: the dynamic-table side of the same encoder, the dynamic-table functions `0x17acc80` (called with a size argument by `0x17aca30` and `0x17ac730`) and `0x17aca30` (stores a size at `+0x50` and clears or trims the slot ring), which have a self-contained state (a ring of 0x60-byte slots plus a position index) and can be replayed the same way.
