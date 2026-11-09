# RE-009: reconstruct the state-export nil, struct and data file writers 0x50de300, 0x50de520 and 0x1740650 of node #115

- Component ID: abci / RE-009 storage and state roots (state-export file writers)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source is used
- Claim status: observation (bytes, call sites, 12,000 executed cases) plus inference (names of the callee roles)
- Scope included and excluded: the three writer bodies, the real serde_json key writer 0x510d230, the real ASCII-case compare
  0x159fca0 (three-byte path), the real RawVec grow pair 0x5963a10 / 0x5963650. Excluded: the msgpack and JSON
  serializers the bodies call (0x50da6c0, 0x175ef30, 0x175cc70, 0x50a44d0, 0x50472b0, 0x50a3510), the components iterator
  slot 0x64e0938, the directory and file slots 0x64e0028 / 0x64e09e8 and the error constructors; these are contract stubs.

With this packet the behaviour of three of the state-export file writers can be rebuilt without the binary: which path
selects msgpack (`rmp` extension, ASCII case-insensitive, dot not at index 0), which selects pretty JSON, what a nil
export contains (`0xc0` or `null`), how the three-field object is laid out byte by byte (`{`, newline, indent, key,
`": "`, value, `,` newline, ..., newline, indent, `}`), and every failure path (allocation failure, serializer error,
depth underflow, directory step failure that skips the write).

## Reproduce

Working directory: repository root. Python 3 standard library plus the repository's own evaluator
`tools/rmp_map_pairs_115.py` (imported, not copied) and `tools/fde_extents.py` / `tools/elf_index.py` through it.
The binary is never executed and no external program is called.

```
python3 tools/re009_state_export_nil_struct_115.py --out research/work-items/RE-009-state-export-nil-struct-115
python3 -m unittest tests.test_re009_state_export_nil_struct_115
```

The tool refuses to run unless the input SHA-256 equals the value above. One generation takes about 32 s and 380 MB.
`MANIFEST.sha256` lists every file of this folder except itself.

## Evidence

All addresses are virtual addresses of the node #115 ELF. Extents come from the FDEs.

| body | VA range | size | instructions executed / total |
| --- | --- | --- | --- |
| nil writer | 0x50de300-0x50de518 | 536 | 126 / 133 |
| struct writer | 0x50de520-0x50deb26 | 1,542 | 317 / 354 |
| data writer | 0x1740650-0x1740910 | 704 | 161 / 177 |
| key writer (real) | 0x510d230-0x510d438 | 520 | 119 / 131 |
| grow (real) | 0x5963a10-0x5963a9e | 142 | 39 / 41 |
| finish grow (real) | 0x5963650-0x5963739 | 233 | 57 / 74 |
| ASCII-case compare (real) | 0x159fca0-0x159fde1 | 321 | three-byte path only (SSE loop is not decoded) |

Common front (all three bodies, `bodies.tsv` lists every call site found by decoding the bytes):

1. Length 9 and bytes `/dev/null` (one 8-byte immediate compare plus one byte): return 0, nothing else happens.
2. Components state `(ptr, len, tag 6, word 0x0201, absolute-root byte)` is passed to slot 0x64e0938
   (`Path::components().next_back()` by role); tag 9 is Normal(ptr, len), any other tag selects JSON.
3. A Normal name of length 2 equal to `..` selects JSON; otherwise the name is scanned backwards for `.`; no dot or a dot at
   index 0 selects JSON; the text after the dot goes to 0x159fca0 with the 3-byte string `rmp` at 0x4659e5. Equal selects msgpack.
4. The finish step is shared: slot 0x64e0028(path) returns 0 or an error word; only when it returns 0, slot
   0x64e09e8(buf, len, path, path_len, extra) writes the file and its word is the result; the buffer is then freed
   (always for the nil writer, only when capacity is non-zero for the others).

Nil writer 0x50de300: msgpack path calls the real try-allocate 0x5963650 (eight bytes, align 1, i.e. malloc(8)), stores `0xc0`, length 1; on allocation failure it
builds the record `(0x8000000000000000, 0, 0x2600000003)` and returns 0x50df400(path, record). JSON path: malloc(0x80), the four bytes `null`, length 4.

Struct writer 0x50de520: msgpack path sets an empty Vec (cap 0, ptr 1, len 0) and a serializer configuration (dword 0x1000400,
byte 0), calls 0x50da6c0 and requires the result triple `0x8000000000000004, _, _`; any other triple frees the buffer
and goes to 0x50df400(path, triple). JSON path: malloc(0x80), `{`, depth 1, indent string at 0x91b3c4 (two spaces), then
three fields with key strings at 0x91c305 (3 bytes), 0x91c308 and 0x91c309 (1 byte each): the real key writer 0x510d230
emits newline (first) or `,` newline, depth indents, `"`, escaped key, `"`; the body writes `": "`; the values come
from 0x50a44d0(data+0x30), 0x50472b0(data) and 0x50472b0(data+0x18); the last two return an error word which frees the buffer and is passed to
0x50df4c0(path, word). After the values: depth 0 panics (subtract overflow, location 0x64a1e40), else depth-1, newline, depth-1 indents, `}`.

Data writer 0x1740650: msgpack path calls 0x175ef30(out, vec, data) with the same triple rule and error constructor 0x1740910; JSON path: malloc(0x80), empty buffer
(len 0, no brace), serializer state `(writer, 0x4801fc, 2, depth 0, has_value 0)`, call 0x175cc70(data, state); a non-zero word frees the buffer and goes to 0x17409d0(path, word).

Growth: every push first checks `cap - len < n`; the real 0x5963a10 grows to `max(2 * cap, len + n, 8)` through malloc (cap 0) or the
realloc slot 0x64df588; a failed allocation panics with (align 1, new capacity).

## Implementation and comparison

`tools/re009_state_export_nil_struct_115.py`: `model_nil`, `model_struct`, `model_data` are the reconstruction (about 150 lines).
`Env` is the shared callee environment (one behaviour for every stubbed callee, an event log of every call with its
arguments, buffer bytes at write time, frees and allocations). The model calls `Env` methods directly; the evaluator
runs the real bytes and routes each callee address or import slot to the same `Env` methods. Result, panic kind and arguments, the complete event list, callee-saved registers and the stack
pointer must be identical. Generated cases (12,000: 3,600 nil, 4,400 struct, 4,000 data) vary the path (34 file names, 10
directory prefixes, special paths, trailing slashes), component tag, forced `..` and non-Normal components, which
allocation event fails (none or the 1st to 3rd), serializer outcome and size, per-value sizes and failures, depth
after the values (0-3), indent length (0-3), directory and write results and the extra argument.

Negative controls (`controls.tsv`): 14 model mutants (extension case, prefix match, hidden-file dot, absolute flag,
nil byte, null text, config dword, open brace, colon order, depth check, free, directory result), every conditional
jump of the three bodies inverted in the bytes (reached ones), four stored byte constants changed (0xc0, `{`, `}`, newline),
and five input controls (truncated binary, bit-flipped binary, shifted body address, unknown import slot, unknown call target).
82 controls exist and all 82 are detected; 4 inverted jumps sit on unreached landing pads and are listed as unreached.
`equivalents.tsv` lists four mutants of the `..` test that cannot change any result (a two-byte name never has a
non-empty extension after a dot at index >= 1), so the test is behaviourally redundant; they are excluded from the 82.
The test file proves the equivalence exhaustively over all 65,536 two-byte names.

## Results and limitations

- `measure.json`: cases 12,000; negative controls 82; detected 82; mismatches 0.
- `summary.json`: per-body outcome counts, coverage per function, hash of all case rows. `cases-sample.tsv` lists every second case with its result and an event-log digest; the digest line covers all 12,000.
- Limits: the serializer, value, components, directory and file callees are contract stubs, so what is established is the
  control flow, buffer handling, call order, arguments and error plumbing of these three bodies, not the encoding of the values.
  Instructions not reached are landing pads, the allocation-error tails and the unused aligned-allocation branches of 0x5963650. The 16-byte SSE loop of 0x159fca0 is not executed
  (the extension has three bytes). The component stays unfinished; no gate is requested.
- Next question: the msgpack serializer 0x50da6c0 and the JSON field value writers 0x50a44d0 / 0x50472b0 that fill the three fields of the struct writer.
