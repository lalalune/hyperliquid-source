# transport: HPACK header-field decode path of node #115 (integer, Huffman, string, table lookup, literal, header builders, drop)

This packet makes it possible to re-implement, from bytes, how the bundled h2 stack of node #115 decodes one HPACK literal header
representation: the prefixed integer `0x177b320`, the nibble-table Huffman decoder `0x179d5b0`, the string reader `0x177be90`, the
index lookup `Table::get` `0x177b6c0` (the 61-row static table with its http `StandardHeader` ids, the ring-buffer dynamic table with its
head wrap, error 5 for a bad index), `Header::clone` `0x177e900` and the literal representation `0x177bb00` that joins them, including
which builder is called with which cursor position and which input prefix is consumed. It also reconstructs what the two header
builders do with a decoded name and value: the by-index builder `0x1797e20` (selector table, per-kind validation, the allocated copy of a
field value) and the by-name builder `0x17985c0` (pseudo-header table keyed on name length and bytes, UTF-8 and method/status checks,
error codes 0, 7, 8 and 9, the order of the name/value/produced-name drops), together with the string parsers `0x1798c00`, `0x17a0950`,
the status parser `0x179b360` and the header/method drops `0x177dd80`, `0x177de60`. Pure Python models reproduce every output field,
the cursor, the consumed input and the release events on 32,639 generated inputs, and 381 deliberately wrong variants are all separated
or explained.

- Component ID: transport (Network transport), work item `transport`
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: repository main at `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: observation for addresses, table bytes and executed behaviour; inference for the h2/HPACK role names
- Scope: `decode_int` (+ cursor byte helper `0x17ab010`), Huffman decode, `decode_string`, `Table::get`, `Header::clone`,
  `decode_literal`, the two conversion helpers it calls for real (`0x177b440`, `0x177b570`), the builders `0x1797e20` and
  `0x17985c0` with their parsers (`0x1798c00`, `0x17a0950`, `0x179b360`) and the drops `0x177dd80`, `0x177de60`. Inside `decode_literal`
  the builders and the drop stay recording stubs (that test checks the call contract); the builders and drops are executed for real in
  their own case streams. Excluded: the representation loop `0x177c2d0`, the encoder side (a separate packet), log record formatting,
  async I/O, the http-crate parsers `0x2e4fe40` (method) and `0x2e51760` (header name) and the allocator, which are stubs.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/transport_hpack_decode_115.py --out research/work-items/transport-hpack-decode-115
python3 -m unittest tests.test_transport_hpack_decode_115
(cd research/work-items/transport-hpack-decode-115 && sha256sum -c MANIFEST.sha256)
```

Standard library plus the repository's `tools/elf_index.py` and `tools/fde_extents.py`. The tool refuses a binary whose SHA-256 differs,
never executes it and calls no other program. The interpreter section of the tool is the shared offline x86-64 interpreter skeleton with
one added opcode (`D2`, byte shift by `cl`, needed by `0x177b33e`) and a zero-length read shortcut.

## Evidence

Addresses are linked ELF virtual addresses. Function ends are the FDE ends.

| Function | Range | Role (inferred from behaviour and the h2 source layout) |
| --- | --- | --- |
| `0x177b320` | `[0x177b320,0x177b431)` | prefixed integer, `rdi`=result, `rsi`=cursor `{&buffer, pos}`, `edx`=prefix bits |
| `0x17ab010` | `[0x17ab010,0x17ab03a)` | cursor get-one-byte used for bytes 3 and 4 of an integer |
| `0x179d5b0` | `[0x179d5b0,0x179d75a)` | Huffman decode `(out, src, len, scratch)` over the table at `0x4884a0` |
| `0x177be90` | `[0x177be90,0x177c2cb)` | string reader `(out, decoder, cursor)`; scratch buffer at decoder `+0x40` |
| `0x177b6c0` | `[0x177b6c0,0x177bafa)` | `Table::get(out, table, index)`; jump table at `0x482198`; ring `{cap, ptr, head, len}` of 72-byte headers |
| `0x177e900` | `[0x177e900,0x177eb02)` | `Header::clone`; kind byte at `+0x40`, jump table at `0x4822e4` |
| `0x177bb00` | `[0x177bb00,0x177be7d)` | literal representation `(out, decoder, cursor, arg)`; integer prefix is `2*arg+4` |
| `0x177b440`, `0x177b570` | `[0x177b440,0x177b563)`, `[0x177b570,0x177b6b8)` | take a decoded string off the input: advance past the length prefix, split plain bytes off the buffer |
| `0x1797e20` | `[0x1797e20,0x179821b)` | by-index builder `(out, selector, header, value)`; jump table at `0x48618c`, selector = kind - 1 |
| `0x17985c0` | `[0x17985c0,0x1798a73)` | by-name builder `(out, name, value)`; pseudo-header jump table at `0x486238` indexed by name length - 5 |
| `0x1798c00`, `0x17a0950` | `[0x1798c00,0x1798c73)`, `[0x17a0950,0x17a09e8)` | UTF-8 checked string parsers for `:path`/`:authority`/`:scheme` and `:protocol` |
| `0x179b360` | `[0x179b360,0x179b3b5)` | three-digit status parser (100..999) |
| `0x177dd80`, `0x177de60` | `[0x177dd80,0x177de2f)`, `[0x177de60,0x177de81)` | header drop by kind (jump table `0x4822cc`) and method drop |

Observed behaviour, each point checked against the code by the case stream (`cases.tsv` keeps sampled lines, `measure.json` the totals):

1. Integer: `mask = !(0xff << prefix)` as an 8-bit value. A first byte whose masked bits are not all ones is the value; otherwise up to four
   more bytes are read, the first adds `(b & 0x7f) + mask` **in 8 bits** (a prefix of 8 wraps: `ff 01` gives 0), later ones add
   `(b & 0x7f) << 7*i`. A continuation bit on the fifth byte gives error `0x0b`; exhaustion gives error 1.
2. Huffman: two lookups per byte (high, low nibble); entry = next state (u64), symbol, flags (bit 2 emit, bit 4 error, bit 1 accepting);
   accepted when the input ends in state 0 or on an accepting entry; the scratch buffer is not cleared and an error leaves partial output.
3. String: empty input gives error 0; a declared length beyond the input gives error 2; Huffman failure gives error 6 with the cursor
   already past the whole string.
4. `Table::get`: index 0 and an index beyond the live dynamic entries give error 5 (`out[0]=5`, `out[0x40]=8`). Indices 1..61 jump through
   the table at `0x482198` to code that writes the header directly: kind 2 `:authority`, 3 `:method` (GET = 1, POST = 2), 4 `:scheme`,
   5 `:path`, 7 `:status`, kind 0 a field whose name is an http `StandardHeader` id (byte at `+8`, word at `+0` zero) and whose value is a
   `Bytes` at `+0x20`. `static-rows.tsv` lists all 63 indices with the header the code produced next to the RFC 7541 appendix A row;
   all 61 rows agree (`gzip, deflate` is the only non-empty value among the named fields). The 47 field ids are strictly increasing in
   name order, the http crate's alphabetical enum layout. Index >= 62 reads ring slot `head + (index - 62)` minus capacity once when it
   reaches the capacity (`cmovae`), then calls `Header::clone`.
5. `Header::clone` copies by kind: a field clones its name only when it is a custom name (word at `+0` non-zero) and always its value,
   in that order, through the vtable slot 0; authority/scheme/path clone their one `Bytes`; the method is copied inline for tags 0..9
   and through `0x17a06c0` for the allocated tags >= 10; status is a 16-bit copy. Empty values keep the dangling pointer 1.
6. `decode_literal`: integer (prefix `2*arg+4`); a failure returns its code. Non-zero index: `Table::get` (error 5 returned without reading a
   string), one string, cursor rewound to before the string, conversion, then the by-index builder `0x1797e20` with selector
   `kind-1` (0 for field kinds) and finally the header drop `0x177dd80`; a string failure drops the header first. Zero index: two strings,
   cursor rewound to the start, conversion of the name then of the value, then the by-name builder `0x17985c0`; a failure of the second string
   releases a Huffman first string through its vtable drop slot.
7. Conversion `0x177b440`: moves the cursor past the length prefix (offset), a Huffman string (already decoded) also moves it past its
   encoded bytes and is returned unchanged, a plain string is split off the front of the input buffer, so the consumed prefix grows and
   the cursor goes back to 0. A buffer whose data word has bit 0 set (vec-backed) has its stored offset advanced by the position; the
   advanced offset reaching 59 bits takes the reserve/panic path (`call 0x161d5f0`).

8. By-index builder: output kinds are 0 field, 2 authority, 3 method, 4 scheme, 5 path, 6 protocol, 7 status, 8 error (error byte at `out[0]`).
   Field (selector 0): a custom name is cloned through the vtable, std names store only the id byte; every value byte must be above `0x1f`
   (or tab) and not `0x7f`, else error 7 (the cloned name, then the value, are dropped); a valid value is copied into a fresh allocation
   (data word `ptr|1` with the vtable at `0x64df8c0`, or the pointer itself with `0x64df8c8` when the allocation is odd; an empty value uses
   the static empty vtable `0x6403fc0` and the dangling pointer 1), then the original is dropped; a failed allocation panics. Authority,
   scheme, path, protocol (selectors 1, 3, 4, 5) keep the value `Bytes` as is when it is valid UTF-8 and its vtable is non-null; invalid
   UTF-8 drops it and gives error 7; a null vtable gives error 7 without a drop. Method (selector 2) goes through the method parser
   (tag `0xb` = error 7), status (selector 6) requires exactly three digits with a first digit 1..9 (else error **8**), both dropping the
   value afterwards. `0` as first digit is refused because the `lea -0x3a` / `cmp 0xf7` test is a range check on `'1'..'9'`.
9. By-name builder: an empty name gives error 0. A name starting with `:` is looked up by length (5..10 only) and then exact bytes:
   `:path`, `:method`, `:status`, `:scheme`, `:protocol`, `:authority`; anything else gives error 9 (value then name dropped). The
   UTF-8 pseudo values are consumed by the parser (its failure drops the value itself and the builder only drops the name), a method or
   status value is dropped after parsing; a status that does not parse (0) gives error 7. Other names go to the header-name parser and a
   failure gives error 7; the value check and allocation are those of point 8, and a produced custom name is dropped first when the value
   is invalid; the order of drops is always (produced name,) value, name.
10. Header drop `0x177dd80`: kind 0/1 drops a custom name (if the name vtable is non-null) and then the value; kinds 2, 4, 5, 6 drop their one
   `Bytes`; kind 3 frees the method buffer only for tag >= 10 and a non-zero length; kinds 7, 8 and unknown kinds release nothing. The
   method drop `0x177de60` additionally ignores tag `0xb`.

Raw files: `cases.tsv`, `static-rows.tsv`, `table-summary.tsv`, `call-sites.tsv` (found by scanning `.text` for `E8 rel32`, not by
disassembler output: `decode_literal` has three callers, one with the immediate argument 1, i.e. the 6-bit prefix), `controls.tsv`,
`equivalent-mutants.tsv`, `measure.json`.

## Implementation and comparison

`tools/transport_hpack_decode_115.py`: `model_int`, `model_huffman`, `model_string`, `model_ring_get` (+ `static_header`),
`clone_events`, `model_conv` and `model_literal` are the independent pure models; `STATIC_ROWS` is the RFC 7541 table typed from the
specification and `STATIC_FIELD_IDS` are the ids read from the code (only their ordering is cross-checked, by name order). `HdrRig`
runs the real bytes of all functions in the table above with the library routines modelled as stubs: BytesMut reserve / put_slice /
split_to, freeze `0x177e700`, the panic routines, the log gate, the vtable clone/drop slots, `0x17a06c0`, and recording stubs for the
builders `0x1797e20`, `0x17985c0` and the header drop `0x177dd80`. The stubs are assumptions about library semantics, not recovered
code, so the result for `decode_literal` describes the call contract (arguments, order, cursor, consumed input), not the built header.

The builder section adds `BuildRig`/`NameRig`/`DropRig` (the real builder, parser and drop bytes with stubs for the allocator, memcpy,
`core::str::from_utf8`, the method and header-name parsers and the vtable slots, which record their arguments) and the models
`model_idx`, `model_name_build`, `model_drop`.

Comparison (`measure.json`): 4,200 integer, 4,204 Huffman (4 specification vectors), 4,200 string, 4,070 `Table::get` (index 0..69 swept
once, then random rings of capacity 1..6 with random head/length and random entries of every kind), 4,000 `decode_literal` cases
(random prefix arg 0..2, index 0 / static / dynamic / out of range, plain and Huffman strings, truncations, eight different input
data words), 4,368 by-index builder cases (all seven selectors, valid/invalid values, null vtables, odd and even allocations, 80 status
edge strings, out-of-memory), 4,321 by-name builder cases (every pseudo name, near-miss names, std/custom/upper-case names, invalid
names and values, the same status edges, out-of-memory) and 3,276 drop cases (every header kind, method tags 0..12, kinds 9..255)
give 32,639 exact matches; 1,662 distinct instructions executed.

Negative controls (381, `controls.tsv`): 157 conditional jumps flipped (76 of them in the two builders), 185 byte/word immediates changed by +1
(118 of them the row constants of `Table::get`), 8 Huffman table bytes corrupted, 31 wrong models (UTF-8 check skipped, control bytes
allowed, name leak on error, leading zero status, wrong tens digit, `:path` prefix match, drop order swapped, inline method freed, plus the earlier set: wrong mask width, three continuation bytes, no 8-bit wrap,
shift by 8, wrong overflow code, ignored error entries, no padding check, state-only / flag-only accept, buffer kept, no length check,
flipped Huffman bit, no cursor advance on error, zero offset, static table one row short, ring wrap off by one, plain prefix, no rewind,
wrong selector, plain string not consumed, vec offset not advanced, 60-bit overflow test). 370 are detected by a differing result within
700 sampled cases; 11 are in `equivalent-mutants.tsv` with the reason (one capacity test whose only effect is whether `reserve` runs,
seven log-record branches that all end in the same error-2 store, three unwind landing pads); 0 undetected.

## Results and limitations

- 32,639 / 32,639 cases equal; 381 negative controls = 370 detected + 11 equivalent + 0 undetected.
- The log-record branch of `decode_string` and the unwind pads are not executed; their equivalence rests on reading the disassembly.
- Inside the `decode_literal` stream the built header is not checked (recording stubs); the builders are verified separately with the
  same argument layout. The http-crate method parser, header-name parser (std-name set limited to the 47 static-table names), allocator
  and `from_utf8` are stubs, so their semantics are assumptions, not recovered code.
- No component gate is requested.

Next question: the representation loop `0x177c2d0` that calls `decode_literal` three times, then the http-crate parsers `0x2e4fe40` / `0x2e51760`.
