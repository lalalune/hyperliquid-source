# RE-010: recursive MessagePack Content flow of node #115 (value reader, map / seq collectors and ext visitor run as one machine)

With this packet, the whole `deserialize_any` recursion of node #115 can be rebuilt as one function instead of
four stubbed ones: a MessagePack document goes in, and the exact `Content` tree comes out, together with the
order of every allocation, vector growth, element drop and free that the original performs on the way, the
depth-budget bookkeeping, and every EOF / invalid-marker / depth error. The three earlier RE-010 packets
rebuilt the value reader, the map / seq collectors and the ext visitor one at a time with their neighbours
scripted; here the neighbours are the bytes themselves. The value reader calls the map collector, which calls
the value reader again for each key and value, which calls the seq collector, and so on, through the real call
sites of one deserializer copy:

- set 0: value reader 0x17fb290, map 0x21e0380, seq 0x21e1c10, ext 0x21e1930;
- set 1: value reader 0x2f7f5e0, map 0x3b68660, seq 0x3b69610, ext 0x3b69ad0;
- set 2: value reader 0x47d2470, map 0x57af090, seq 0x57af540, ext 0x57afa00;
- the shared scalar leaf 0x14b9940 (665 B) behind GOT slot 0x64dffb0.

The reconstruction is the pure recursive `FlowModel` class in `tools/re010_content_flow_115.py`. The tool runs
the original bytes of all 13 bodies over 18,021 MessagePack inputs (0 mismatches) and rejects
107/107 wrong models, corrupted images and out-of-range inputs. The binary is never executed.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `0781ce048`. `references/can1357-hl` was not used.
- Claim status:
  - Observation, proved by running the original bytes against the reconstruction: the call graph between the
    four bodies of each copy set, the result `Content` tree, the error payload bytes the original defines,
    the ordered callee events (`alloc`, `grow`, `free`, `drop` with the dropped subtree, `utf8`, panics), the
    deserializer cursor / remaining length / peek / depth after the call.
  - Inference: the serde / rmp_serde names (`deserialize_any`, `ContentVisitor`, `Content` variants), the
    meaning of the stubbed services (allocator, `RawVec` grow, free, `str::from_utf8`, drop glue).
  - Unresolved: the bodies of those services, and the unwinder (a panic ends a run; the landing pads of the
    individual bodies are covered by the earlier packets, not walked through frames here).
- Scope included: the four bodies per copy set and the shared leaf as real recursive code, their LSDA call-site
  tables, both jump tables of the three value readers, the closure of every real call inside each set.
- Scope excluded: the bytes visitor (0x21e2670 / 0x57afce0, reached from other callers), the TagOrContent key
  reader that sits above this flow, the stubbed services, the unwinder, the `Content` drop glue bodies.

## Reproduce

```
python3 tools/re010_content_flow_115.py --out research/work-items/RE-010-content-flow-115
python3 -m unittest tests.test_re010_content_flow_115
cd research/work-items/RE-010-content-flow-115 && sha256sum -c MANIFEST.sha256
```

The tool and tests use only the Python 3 standard library and the shared `tools/elf_index.py` and
`tools/fde_extents.py` parsers. They call no external program and never execute the binary. The tool checks the
input SHA-256 first. Generation takes about 130 s and about 370 MB. Two generations (`PYTHONHASHSEED=0`,
`TZ=UTC` and `PYTHONHASHSEED=12345`, `TZ=Asia/Seoul`, empty PATH) produced byte-identical output.

## Evidence

All numbers and tables are produced by the tool from ELF bytes: section headers via `elf_index`, FDE and LSDA
via `fde_extents` and the uleb call-site table, `.rela.dyn` RELATIVE relocations for the GOT slots, `.rela.plt`
for `_Unwind_Resume`, and fixed-pattern instruction decoding.

| file | content |
|---|---|
| `functions.tsv` | per set and kind: FDE extent, LSDA, instruction and call counts, frame size, static EOF error constant |
| `call_graph.tsv` | every call site of the 13 bodies: role, callee kind, callee start, whether an LSDA range covers it, landing pad and action |
| `lsda.tsv` | the call-site tables of all bodies in all sets |
| `tables.tsv` | the marker (225) and ext (18) jump tables of the three value readers: index to arm offset |
| `coverage.tsv` | every instruction of the set-0 bodies and the leaf: reached by the recursive runs or not, taken / not-taken edges |
| `cases.tsv` | a sample of the cases: input, peek slot, depth, failing-allocation index, outcome, decoded tree or error bytes, callee events, state |
| `mutants.tsv` | the negative controls and whether each was detected |
| `summary.json`, `measure.json` | totals, outcome classes and instruction coverage |

### Call graph (observed, `call_graph.tsv`)

Each copy set is closed with 7 real call edges: the value reader calls the leaf (+0x9e), its own map (+0x136),
seq (+0x1f0) and ext (+0x63c) bodies; the map collector calls back into the value reader of the same set at
+0xde (key) and +0x152 (value), the seq collector at +0xaf (element). All three sets share these offsets. Mixing bodies of two sets is
rejected by the tool (`mixed_sets_*` controls). Every other call is a service stub.

### Behaviour (reconstructed and proved)

- **Content tags** seen in the heap: 0 Bool, 1..4 U8..U64, 5..8 I8..I64, 9 F32, 0xa F64, 0xd Str (borrowed),
  0xf Bytes (borrowed), 0x12 Unit, 0x13 Newtype(Box), 0x14 Seq, 0x15 Map; a collection keeps `(cap, ptr, len)`
  and the tree compares `cap` as well.
- **Depth budget.** Entering a map, seq or ext first checks the u16 budget in the deserializer: 0 panics
  (`panic_sub`); decrement to 0 returns `Err` tag 8 without calling the collector. A successful collector
  restores the budget with a `panic_add` check at 0xffff. **A map or seq `Err` leaves the nested spend in place
  (every level on the failing path stays decremented); an ext `Err` restores it.**
- **Allocation clamp.** The first allocation of a collector is `min(count, 0x4000) * 64` for maps and
  `min(count, 0x8000) * 32` for seqs, so a 32-bit count of 0xffffffff followed by no data allocates 1 MiB,
  fails with EOF and then drops what it collected and frees the 1 MiB block. Growth at a full vector goes
  `cap -> max(2 cap, 4)` (the two oversize cases, one element past each clamp, reach it).
- **Error cleanup.** A failing element inside a collector drops every collected element in order (key, then
  value for a map), frees the buffer, and returns the same error bytes. A failing map *value* additionally drops
  the already-read key first. The error payload passes unchanged through every enclosing level.
- **Strings and bytes.** str / bin lengths of 1, 2, 4 bytes; a length past the input returns `Err` tag 1 with
  the constant `0x2500000003` and consumes nothing after the prefix; invalid UTF-8 becomes Bytes, not an error;
  the validator runs once per string (`utf8` event) and not for bin.
- **Scalars.** Built by the shared leaf: big-endian payload at +1/+2/+4/+8 of the Content; a short payload
  swallows the rest of the input and returns `Err` tag 1 with the leaf's EOF constant.
- **Ext.** `ext8/16/32` and `fixext1..16`: the visitor reads the type byte and `n` data bytes into a two-element
  `Seq` of `I8(tag)`, `Bytes(data)` (first push grows the empty Vec to 4), the value reader boxes it
  (`alloc(32)`) as `Newtype`. A short payload drops the I8 element and frees 128 bytes.
- **Peek.** A peeked discriminant (flag + data byte) is consumed once and goes to the table; nested reads see no
  peek.
- **Unreachable here.** The `None`/`Err` niche early stops of the collectors and the post-collector count
  mismatch need a child that returns a short count or a `None` tag; the real children never do. The eight
  conditional jumps that guard them are the only image flips the sample does not detect (listed in the tool).

## Implementation and comparison

Not yet implemented in Rust. The reconstruction is the pure Python `FlowModel`. The comparison object per case
is (outcome, `Content` tree or the error bytes the original defines, ordered callee events, cursor / remaining /
peek / depth). Event arguments are semantic (sizes, caps, dropped subtrees), not addresses.

| group | cases per set | mismatches |
|---|---|---|
| all 256 first bytes x tails x depths | 2,176 | 0 |
| every peeked discriminant x data x tails | 555 | 0 |
| 160 generated nested documents: full, every truncation, depth budgets, failing allocations, trailing data | 3,160 | 0 |
| huge counts, clamp overflow, ext length edges | rest | 0 |
| total over 3 sets | 18,021 | 0 |

Negative controls (107, all detected):

- 29 wrong models: depth off by one, never restored, restored on error, ext error not restored, unclamped cap,
  seq clamped like map, wrong growth, reversed cleanup, no free, key not dropped, values skipped, unsigned ext tag,
  missing newtype, u16 ext length, doubled fixext length, bin as str, invalid UTF-8 as str, wrong EOF advance,
  swapped key / value, wrong box size and others;
- 66 corrupted images: one conditional-jump condition flipped in the set-0 copy (39 value reader, 10 map, 8 seq,
  9 ext); each changes at least one result;
- 12 out-of-range inputs and boundaries: flipped digest, a non-FDE start, a wrong size for the kind, a wrong
  anchor, mixed copy sets, a truncated sweep, an unmapped read, a wrong leaf extent, a discriminant past the
  table, a count past the input, a zero budget.

## Results and limitations

- 18,021 cases, 0 mismatches, 107/107 negative controls detected (`measure.json`).
- Instruction coverage of the set-0 bodies by the recursive runs: ext 141/175, map 204/248, prim 190/196, seq 128/159, vr 425/484 (`coverage.tsv`, covered = 0 rows).
- Stub contracts are assumptions shared with the earlier packets: the grow stub doubles (min 4), the allocator
  returns fresh blocks, drop glue is recorded not executed. A panic ends the run; the pads are not walked.
- Bytes the original leaves undefined in error payloads (stale frame bytes) are not compared; only the bytes the
  model defines are.
- Nothing here claims a component gate. No Rust code is added.

Next question: put the TagOrContent key reader (0x1a7e1a0 / 0x30fb4f0 / 0x48cd3a0), which calls the map / seq
collectors above this flow, on top of the same machine, and add an unwinder so the landing pads of nested frames
are walked.
