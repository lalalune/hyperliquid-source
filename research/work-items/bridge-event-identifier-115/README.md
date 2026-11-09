# bridge: bridge event-name identifier pair deserializers in node #115

This packet makes the node #115 deserializers that read the six bridge event names
(`Deposit` .. `RequestedValidatorSetUpdateEvent`) out of a serde `Content`
identifier/value pair reconstructible and checked: an independent Rust port can
now fix which Content tags are accepted as a variant index (U8 and U64, 0..5),
which go to the exact-name visitors (String/Str to the `&str` visitor,
ByteBuf/Bytes to the `&[u8]` visitor), which are an invalid-type error, and the
exact order of every drop, free and error constructor call, including the owned
String/ByteBuf free and the value-Content drop on errors. The five host bodies are
run from file bytes with the real name visitors (the merged bridge event-name
packet) running inside each case.

- Component ID: `bridge`. No RE task owns these bodies; this is not a gate claim.
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce048` (HEAD of the work tree). No
  reference source was used.
- Claim status:
  - Observation: body extents (FDE), instruction bytes, jump tables, callee
    roles, pools, and the interpreted outcome and call record of every case.
  - Inference: that the enum is the bridge event kind (from the names only);
    the roles of the callees (drop, free, invalid-value, invalid-type) come
    from their position and arguments in the body.
  - Unresolved: the three 1,769-byte hosts (`0x1a8b7e0`, `0x3204ab0`, `0x4af2d60`)
    use a test-byte opcode the shared decoder lacks and are not covered.
- Scope included: hosts `0x1fae860`, `0x3952710` (610 bytes, families 1 and 2,
  one-byte `Result` visitor form) and `0x1fabc40`, `0x394d730`, `0x56835d0`
  (760 bytes, families 1, 2 and 3, tagged 32-byte visitor form); the visitors they
  call (`0x2864e60`, `0x2864770`, `0x2864d00`, `0x28641d0` and the family 2 and 3
  siblings) as nested real callees.
- Scope excluded: the 1,769-byte hosts, payload decoders after the name, callers
  of the hosts.

## Reproduce

From the repository root (Python 3 standard library only, no external program,
the binary is never executed):

```
python3 tools/bridge_event_identifier_115.py --out research/work-items/bridge-event-identifier-115
python3 -m unittest tests.test_bridge_event_identifier_115
```

The tool refuses any input whose SHA-256 differs from the value above. Two
regenerations to different folders are byte-identical. It takes about four
minutes and well under 1 GB; cases are run, compared and counted one at a time.

## Evidence

All coordinates are virtual addresses of the ELF; the tool reads bytes with the
shared `elf_index` and `fde_extents` parsers.

- `functions.tsv`: the five host extents, LSDA and body hashes.
- `instructions.tsv`: decoded instruction rows (address, length, bytes, op, target).
- `jump-tables.tsv`: the 15-row Content dispatch table (tag 1 = U8, 4 = U64,
  12 = String, 13 = Str, 14 = ByteBuf, 15 = Bytes, all others share the
  invalid-type target) and the two six-row index tables.
- `callees.tsv`: roles per host (str/bytes visitor, drop, free, invalid-value,
  invalid-type, resume) and the per-family variant and type pools.
- `cases.tsv`: a thinned sample of the interpreted cases with the call record.
- `paths.tsv`: per host, arm and outcome: case count and step range.
- `damage-controls.tsv`, `negative-controls.tsv`: control results.
- `summary.json`, `measure.json`: counts.

Observed behaviour (identical in all five hosts):

- Tag 1 (U8) reads the byte at +1, tag 4 (U64) the word at +8; a value 0..5 is
  the variant index (second jump table), anything larger calls invalid-value
  with Unexpected tag 1 and the value. The identifier Content is dropped in both
  cases.
- Tags 13/15 call the str/bytes name visitor on (ptr, len) at +8/+0x10, then
  drop the identifier Content. Tags 12/14 call the visitor on (ptr, len) at
  +0x10/+0x18 and free the owned buffer (ptr, cap, 0) only when cap is nonzero,
  with no drop of the identifier.
- Every other tag (including 2, 3, 5..11, 16.. and out of range) calls
  invalid-type with the Content and the family type pool and consumes it.
- Success returns the index in byte 0 and moves the value Content to +8
  unchanged; any error sets byte 0 to 6, carries the error record at +8 and
  drops the value Content unless its tag is the 0x16 niche.

## Implementation and comparison

The independent reconstruction is `recon()` in the tool (pure Python, no
interpreter state). Each case is run in the interpreter and compared on the
outcome and on the ordered call record. Counts:

- 99,560 cases (5 hosts x 19,912), 99,560 matches, 0 mismatches. Cases cover
  every integer boundary (0..8, 0xff, 0x100, 2^32, 2^63, 2^64-1), 21 other tags,
  four text arms over the ~1,000 name mutations of the event-name packet, owned
  and borrowed buffers, and three value-Content tags.
- 88 negative controls, 88 detected: 29 deliberately wrong reconstructions
  (integer bounds, truncation, drop/free order and conditions, lossy handling, the
  nine wrong name matchers), 54 damaged-code controls (immediates flipped in
  executed compares, swapped entries in all three jump tables of each host), 5
  out-of-range controls (truncated binary, non-FDE entry, wrong family, missing
  and foreign-object drop stubs).
- 21 unit tests (identity, roles, tables, behaviour, controls, packet
  consistency).
- A Rust implementation is not part of this packet: not yet implemented.

## Results and limitations

- Reconstruction matches the interpreted bytes in 99,560 of 99,560 cases; all
  88 controls are detected.
- The callee roles are assigned from call order and argument shape; the stubs
  record calls and do not model the allocator or error formatting.
- The 1,769-byte hosts were only found as callers of the visitors; their shape
  was not read, and they are left out.
- No progress gate is requested.

Next question: add the `test r/m8, r8` form to the shared decoder only if needed
and run the three 1,769-byte hosts (`0x1a8b7e0`, `0x3204ab0`, `0x4af2d60`), which
sit one level above these identifiers.
