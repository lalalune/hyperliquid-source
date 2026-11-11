# action-wire: reconstruct the vote-record serializer, its MessagePack integer writer and the Vec reserve helper, node #115

This packet turns three observed code families into one executable reconstruction: the exact bytes the
governance vote record `{choice, weight}` appends to its output buffer for every flag byte, choice tag and
64-bit weight, the shortest-form unsigned MessagePack integer rules (positive fixint, `0xcc`, `0xcd`, `0xce`,
`0xcf` with big-endian payloads and their exact thresholds), and the buffer-growth rule of the reserve helper
(minimum capacity 8 or 4 or 1, doubling, overflow and zero-size aborts), all proved against the original
machine code with 47,844 executed comparison cases and 54 negative controls that are all detected.

- Component ID: `action-wire`
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (origin/main when the tool was produced)
- Claim status: observation (instruction-level behaviour, executed from the file bytes) plus inference
  (the Rust-level names `serialize`, `write_uint`, `Vec::reserve`)
- Scope: the three record serializers `0x241cb90`, `0x3c31a70`, `0x4d974e0`; the three integer writers
  `0x25e9f10`, `0x3d51450`, `0x57cfd20`; the three reserve helpers `0x231e050`, `0x43bd910`, `0x5963a10`.
  Not included: the `finish_grow` callees `0x231dc90`, `0x43bd550`, `0x5963650` and the error handler slot
  `0x64df498` (modelled as the only stubs, see Limits), the callers of the record serializers, and any
  consensus gate.

This follows the merged `action-wire-vote-choice-weight-struct-115` packet, which pinned the bytes of the three
record serializers and named the integer writer as an unresolved callee; here the writer and the reserve
helper are decoded, executed and reconstructed together with the serializer.

## Reproduce

```
python3 tools/action_wire_vote_weight_writer_115.py --out research/work-items/action-wire-vote-weight-writer-115
python3 -m unittest tests.test_action_wire_vote_weight_writer_115
```

The tool checks the SHA-256 of the input first, reads only the ELF bytes (sections, `.rela.dyn`, the unwind
table through the repository's shared parsers) and never runs the binary or an external program. Two runs into
different folders are byte-identical; peak memory is about 360 MB and the run takes about 40 seconds.
`MANIFEST.sha256` lists every file but itself.

## Evidence

All addresses are virtual addresses of the `.text` section; function extents are the unwind (FDE) records.

| role | copy 1 | copy 2 | copy 3 | FDE bytes | decoded instructions |
| --- | --- | --- | --- | --- | --- |
| record serializer | `0x241cb90` | `0x3c31a70` | `0x4d974e0` | 1,048 | 265 |
| unsigned integer writer | `0x25e9f10` | `0x3d51450` | `0x57cfd20` | 901 | 240 |
| `Vec<u8>` reserve helper | `0x231e050` | `0x43bd910` | `0x5963a10` | 142 | 41 |

(`functions.tsv`, `callees.tsv`, `instructions.tsv` for the first copy, `coverage.tsv`.) Each body decodes
linearly to its FDE end with no gap. The callee relation is derived from the decoded bodies and checked:
a serializer calls exactly its family's writer and reserve helper, a writer calls the reserve helper, and the
reserve helper calls its `finish_grow` and the error slot `0x64df498` (a GOT-style indirect call).
Executed instructions: 1,638 of 1,638 (every instruction of all nine bodies is run by at least one case).

Observed behaviour (each item is reproduced by the interpreter, not read from a disassembly):

- Record serializer. The serializer-state flag byte at +0x1b is a whole byte. The header byte is
  `((flag ^ 1) << 4 | 0x82) & 0xff`: flag 0 gives `0x92` (two-element array), flag 1 gives `0x82` (two-entry map),
  flag 2 gives `0xb2`, flag 3 `0xa2`, flag 255 `0xe2`. Any nonzero flag writes the key `a6 "choice"`; only flag
  exactly 1 writes the key `a6 "weight"` before the weight. The choice is `a3 "yes"` for tag 0, `a2 "no"` for
  tag 1 and `a7 "abstain"` for every other tag byte. The weight then goes through the integer writer; if the
  writer returned a status other than 2, the serializer returns `0x8000000000000000` plus the status word and the
  payload word instead of the `0x8000000000000004` success word (reachable only with a replaced writer, tested so).
- Integer writer. value < 0x80: one byte, the value itself. Otherwise the marker `0xcc` (< 0x100, one byte),
  `0xcd` (< 0x10000, big-endian 16 bit), `0xce` (< 2^32, big-endian 32 bit) or `0xcf` (big-endian 64 bit). The result
  record holds the word 2 and the marker byte (0 for the fixint, whose value is stored in the next byte).
- Reserve helper. The callers reserve only on the slow path: one byte when capacity equals length, n bytes when
  fewer than n are spare. The helper aborts with `(0, length)` when the element size is 0 or `length + additional`
  carries; otherwise the new capacity is `max(length + additional, 2 * capacity mod 2^64, minimum)` with minimum 8
  for element size 1, 4 for sizes below 0x401, 1 otherwise; it calls `finish_grow(old capacity, pointer, new capacity,
  alignment)`, aborts with the callee's two error words on failure, and stores pointer and capacity on success.

## Implementation and comparison

`tools/action_wire_vote_weight_writer_115.py` holds (1) an interpreter for the x86-64 subset the nine bodies use
(the evaluator of the merged governance-vote codec tool, extended with byte shifts and rotates, `bswap`,
`test r/m8`, `js`/`jns`, `cmov` and `setcc`), (2) an environment that runs the real nested calls (serializer ->
writer -> reserve helper) with a buffer that really moves on every growth, and (3) an independent pure-Python
reconstruction (`recon_record`, `recon_uint`, `recon_grow`) returning the same observation tuple: appended bytes,
final length, capacity and data pointer, the 24 bytes of the result record, the list of reserve calls and the list
of `finish_grow` arguments, or `abort(rdi, rsi)`.

Cases (`measure.json`, `summary.json`): 47,844 executed comparisons, all equal.

| stream | cases per copy | inputs |
| --- | --- | --- |
| integer writer | 744 | 31 values (width edges and pseudo-random magnitudes) x length 0/3 x spare 0..9, plus allocation failure |
| record serializer | 8,280 + 96 + 24 | flags 0,1,2,3,255 x tags 0,1,2,255 x 9 weights x length 0/5 x spare 0..22 (every reserve edge), plus allocation failures and replaced-writer error statuses |
| reserve helper | 6,804 | 9 capacities (including 2^63 edges) x 3 lengths (including 2^64-1) x 7 additions x 3 alignments x 6 element sizes x success/failure |

Negative controls (`negative-controls.tsv`), 54 of 54 differ from the original or are rejected: 28 wrong
reconstructions (wrong thresholds, little-endian, swapped markers, swapped or ignored header modes, missing or
extra keys, swapped names, strict tags, wrong minimum capacities, no doubling, missing reserves, unchecked
overflow), 21 single-byte corruptions of the code (immediates, shift counts, `bswap` register, opcode of `cmova`,
branch condition, `lea` displacement, literal bytes of the names), 3 out-of-range inputs, one flipped input byte
that must fail the SHA-256 gate and one mid-function address that is not an FDE start.

## Results and limitations

- 47,844/47,844 cases match, 1,638/1,638 instructions executed, 54/54 negative controls detected.
- All three copies match the same reconstruction on every case of their streams.
- Limits: `finish_grow` and the error handler are stubs by design (the allocator is not reconstructed here:
  modelled as an in-place-then-moved buffer returning a new pointer, or failing with two fixed error words);
  the stub boundary is the exact set of arguments listed above. The reserve helper's callers outside these
  serializers, and the callers of the record serializers, are not reconstructed. The packet establishes
  behaviour of these nine bodies only; it requests no component gate.
- Control sample sizes: 744 writer cases, about 1,700 record cases and about 620 reserve cases (first copy) are
  re-run for each corruption control; wrong-reconstruction controls reuse their stored original outcomes.

Next question: reconstruct `finish_grow` (`0x231dc90`) and the allocator slots it calls, which would replace the
two stubs left in this flow.
