# RE-010: MessagePack-to-Content lifecycle on node #115: nested decode, allocation order, cleanup and drop glue

With this packet, the whole life of a MessagePack-decoded serde `Content` value on node #115 can be rebuilt as code,
not one function at a time: how nested arrays, maps, ext values and strings become a `Content` tree, in which order
the allocator is called (collection buffers, the ext `Vec` and `Box`, the clamp and the doubling grow), what a failed
decode releases (collected elements, a staged map key, buffers) and in which order the drop glue frees a finished
tree. The earlier RE-010 packets stubbed these callees; here every function on the path runs as original bytes with
real recursion across frames, and only the allocator wrappers, the panic functions and `_Unwind_Resume` are scripted.
The reconstruction is the pure `Model` class (about 300 lines) in `tools/re010_content_lifecycle_115.py`. The tool runs
16,224 nested decode, drop and UTF-8 cases from the bytes with 0 mismatches. 103/103 wrong models, corrupted images and
out-of-range inputs are rejected.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `0781ce048`. `references/can1357-hl` was not used.
- Claim status:
  - Observation, proved by running the original bytes against the reconstruction: result trees, error forms,
    allocator call order and sizes, drop/free order, cursor and depth write-back, landing pads and the no-leak
    property of every run.
  - Inference: the serde / rmp_serde names (`Content`, `ContentVisitor`, `Newtype`, `RawVec::grow`,
    `str::from_utf8`) and the Rust names of the allocator wrappers.
  - Unresolved: the allocator wrapper bodies, the panic functions, the custom-`io::Error` arm of the error drop
    (never reached by a decoder error), and the `panic_add` landing pads (need depth 0xffff at a collector exit).
- Scope included: three copies of the value reader (0x17fb290, 0x2f7f5e0, 0x47d2470) with everything they reach
  (38 functions, listed in `functions.tsv`): the scalar leaf 0x14b9940, visit_map / visit_seq / visit_ext of each
  copy, the three access helpers (219 B), `from_utf8` 0x16815e0, the grow pair 0x16a0730 / 0x16a06c0 with
  `finish_grow` 0x16a0810, `drop_result` (73 B), the Content drop glue (445 B, 3+6 instantiations), the Vec drop
  (172 B) and the io::Error drop (206 B).
- Scope excluded: the allocator / realloc / free wrappers behind the GOT slots 0x64df480..0x64df590, the panic and
  alloc-error functions, `_Unwind_Resume`, and the byte-slice visitor 0x21e2670 (not on this path).

## Reproduce

```
python3 tools/re010_content_lifecycle_115.py --out research/work-items/RE-010-content-lifecycle-115
python3 -m unittest tests.test_re010_content_lifecycle_115
cd research/work-items/RE-010-content-lifecycle-115 && sha256sum -c MANIFEST.sha256
```

The tool and tests use only the Python 3 standard library and the shared `tools/elf_index.py` and
`tools/fde_extents.py`. They call no external program and never execute the binary. The input SHA-256 is checked first.
Generation takes about 2.5 minutes. Two generations (different `PYTHONHASHSEED` and `TZ`) were byte-identical.

## Evidence

| file | content |
|---|---|
| `functions.tsv` | the 38 functions reached: FDE extent, LSDA, instructions, instructions reached, prologue pushes |
| `calls.tsv` | every call of those functions: offset, form, target, real function or stub role |
| `lsda.tsv` | the LSDA call-site rows of every reached function |
| `tables.tsv` | marker (225) and ext (18) jump tables of the value reader, the 21-entry drop table, the 7-entry result-drop table |
| `coverage.tsv` | every instruction of the copy-0 functions: reached, and taken / not-taken edges of every conditional jump |
| `cases.tsv` | every third nested case of copy 0: input, outcome, result tree, allocator events, drop events, final state |
| `utf8.tsv` | every fourth `from_utf8` input with the reference and the real result |
| `mutants.tsv` | the 103 negative controls and whether each was detected |
| `summary.json`, `measure.json` | counts, outcome classes, SHA-256 of the full result stream |

## Implementation and comparison

`Model` reads a document and returns the tree, the allocator events and the final state:

- **Scalars and strings.** Fixint, negative fixint, nil, bool, u8..u64, i8..i64, f32 / f64 follow the marker. A str that
  is valid UTF-8 is `Str`, otherwise `Bytes`. A string or bin longer than the input fails with the short-EOF error
  without consuming. A length prefix cut short consumes the rest. Marker 0xc1 is error tag 2.
- **Collections.** A non-empty array or map first allocates `min(n, clamp) * element` bytes (32 B items, clamp
  0x8000; 64 B pairs, clamp 0x4000), then reads exactly `n` items. Growth beyond the clamp is a realloc to
  `max(2 * cap, 4)` elements; a 0x8001-item array and a 0x4001-pair map exercise it (1 MiB to 2 MiB).
- **Ext.** A tag byte is read, then `n` data bytes. The result is `Newtype(Box(Seq[I8 tag, Bytes data]))`: the
  `Vec` is allocated first with capacity 4 (128 B) and the box (32 B) last.
- **Depth.** Each collector or ext lowers the u16 budget by one; at 0 on entry the panic path runs, reaching 0 after
  the decrement returns error tag 8. A collector error leaves the budget lowered; ext restores it; success restores it.
- **Failed decode.** The collector drops the items it collected, in order, then frees its buffer. A map whose value
  fails first drops the staged key.
- **Drop glue.** `Newtype`: child then the 32 B box. `Seq`: items in order then `cap * 32`. `Map`: per pair key
  then value, then `cap * 64`. Strings and bytes are borrowed and free nothing.
- **Allocation failure.** An allocator returning null calls alloc-error, which unwinds through the landing pads: no
  block is left alive and none is freed twice.

The interpreter keeps real call frames and a heap that faults on use after free, double free, a free with a size
different from the allocation and an unknown pointer. The unwinder walks the frames, restores the callee-saved
registers from the prologue pushes and enters the first landing pad of the LSDA table. After each decode, the result
is released by running the original `drop_result` and the run must end with zero live blocks.

Cases (per copy unless noted): every marker byte with four tails, 42 peeked markers, string and bin forms, 1,100
generated nested documents with up to 1,400 truncations, depth budgets, failed allocations at 4 positions,
ext and fixext forms, huge declared lengths, nesting depths up to 1,025, reserved-marker positions; the
two growth cases run on copy 0 only. `from_utf8` is run directly on 2,776 inputs against a reference of the Rust rule
table (also checked against Python's decoder in the tests).

## Results and limitations

- 16,224 cases, 0 mismatches; 103 negative controls (24 wrong models, 2 wrong UTF-8 models, 66 inverted conditional
  jumps of the real bytes, 11 range / corruption controls), 103 detected.
- 4,195 of 5,469 instructions of the 38 functions were reached over all copies; the per-instruction table for copy 0
  is `coverage.tsv`. Unreached code is listed row by row in `coverage.tsv` (copy 0) and `functions.tsv` (all copies); it
  includes the custom io::Error drop arm and the `panic_add` pads.
- Peeked markers are limited to the canonical normalized forms.
- The allocator wrappers are stubs; their size / pointer contract is inferred from the callers.
- Next: the bodies of the allocator wrappers, and the callers that hand a `Content` to the Action payload structs.
