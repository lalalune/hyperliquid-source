# vaults: reconstruct the node #115 Vault struct serializers (tagged writer 0x44a66f0, MessagePack writer 0x44a6a20, key-prefix writers 0x44f9110 / 0x44f9180)

This packet makes it possible to re-implement, in a few dozen lines, how node #115 writes the 13 element `Vault` record
(`name`, `description`, `create_time`, `vault_user`, `leader`, `user_states`, `leader_commission`, `is_closed`, `lockup_duration`,
`allow_deposits`, one extra record helper, `always_close_on_withdraw`, `relationship`): the exact field order, which record
offset feeds which callee, which callee and key text is used in the named and the compact form, the one byte MessagePack
container header (`0x8d` map of 13 versus `0x9d` array of 13), the inline key bytes and growth requests of the buffer, and the
24 byte result record produced by every failure path. A rule list written from those findings reproduces the real bytes on
11,200 generated cases, and 52 deliberately wrong rule lists, corrupted code bytes and out of range inputs are all refused.

- Component ID: vaults (field names and record offsets only; no vault arithmetic is claimed)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `main` at the time of the run; no reference source was copied, field names are the
  strings stored beside the serde field tables of the binary (`struct Vault with 13 elements`)
- Claim status: observation (stub-level behaviour of four functions, verified by evaluation) and inference (the meaning of each
  callee, which is only identified by its argument shape)
- Scope included and excluded: the four function bodies listed in `sites.tsv`, evaluated with every callee replaced by a recording
  stub. Excluded: the bodies of the callees, the tail targets `0x4199450` and `0x3c6f4e0`, the sibling JSON writer `0x44a6320`, the
  three deserializer families, and any gate request.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/vault_serializers_115.py --out research/work-items/vaults-struct-serializers-115
python3 -m unittest tests.test_vault_serializers_115
```

Python 3 standard library only plus the repository parsers `tools/elf_index.py`, `tools/fde_extents.py` and the evaluator of
`tools/bole_rate115.py`. The binary SHA-256 is checked first. Nothing is executed from the binary; no objdump or readelf output
is parsed. Two regenerations into different folders are byte identical. The tool runs in about one minute and stays well below
1.5 GB of memory (cases are streamed one at a time and only counters are kept).

## Evidence

Coordinates are ELF virtual addresses of the file-backed sections.

| file | content |
|---|---|
| `sites.tsv` | FDE start and end, size, decoded instruction count and call targets with counts, for the four functions |
| `canonical_calls.tsv` | ordered stub calls and decoded arguments of the four canonical cases (each function, flag 0 and 1) |
| `failure_records.tsv` | for every stub call in turn, the 24 byte record the function returns when that call fails |
| `reserve_requests.tsv` | growth requests of the MessagePack writer for spare capacity 0..14 at start length 0 and 3 |
| `record_influence.tsv` | flipping bit 0 of each record byte in turn: which stub calls see a changed argument (record bytes that no call sees are only passed on by pointer) |
| `cases_sample.tsv` | the first 400 + 40 generated cases with a digest of log, result, lengths and buffer |
| `negatives.tsv` | every wrong rule list, corrupted code byte and out of range input, and whether it was refused |
| `summary.json`, `measure.json` | counts: 11,200 cases, 0 mismatches, 52 controls, 52 refused |

Observed behaviour (the rule list in `model()` of the tool is written against these, not generated from the stub log):

- `0x44a6a20` (1165 bytes) is the MessagePack writer. The serializer object is `rdx`: capacity `[+0]`, buffer `[+8]`, length
  `[+0x10]`, named flag byte `[+0x1b]`. It writes `((flag ^ 1) << 4) | 0x8d` first (flag 1 gives `0x8d`, flag 0 gives `0x9d`, flag 2 gives
  `0xbd`), then for named form (flag exactly 1) inline keys as a fixstr tag plus text: `0xa4 name`, `0xab description`, `0xab create_time`;
  `vault_user`, `leader` and the other keys go through the string callee `0x41c6610` or the keyed callee `0x44fbe10` with the key
  pointer and length. Room tests: a one byte write grows when capacity equals length; a 4 or 11 byte run grows when
  capacity minus length is below the run size; the growth callee `0x43bd910` receives (serializer, length, count, 1, 1).
- `0x44a66f0` (816 bytes) is the tagged writer. The flag byte is `[rdx+0xb]`. Flag 0 calls begin routine `0x3d50270`, any other value
  `0x3d4f6d0`, both with 13; a returned tag other than 2 becomes the error record. Named form (flag exactly 1) writes each key through
  `0x41c6110` before its value; the keyed helper `0x44fb6f0` always receives its key text.
- Both writers read the record at these offsets: `+0x28/+0x30` name text, `+0x40/+0x48` description text, `+0x80` time, `+0x8c` vault user,
  `+0xa0` leader, `+0x50` user states, `+0x70` leader commission (64 bit), `+0x78` lockup (64 bit), `+0xb4` dword `is_closed`,
  `+0xb5` byte `allow_deposits`, the whole record for the extra helper, `+0xb6` byte `always_close_on_withdraw`, `+0xb7` byte `relationship`.
  Order of calls: name, description, create_time, vault_user, leader, user_states, leader_commission, is_closed, lockup_duration,
  allow_deposits, extra, always_close_on_withdraw, relationship.
- Record bytes read by the writers themselves (`record_influence.tsv`, identical for both writers and both flags): `+0x28`, `+0x30`, `+0x40`, `+0x48`
  (text pointer low byte and length low byte of name and description), `+0x70..+0x7f` (commission and lockup words) and `+0xb4..+0xb7`; the
  bytes `+0xb5`, `+0xb6`, `+0xb7` each change two calls (the dword at `+0xb4` and their own byte). Time, user, leader, user states and the
  extra helper receive record pointers and the writers read none of those bytes.
- Result record (24 bytes at `rdi`): success stores only the tag word `0x8000000000000004` and leaves the other 16 bytes alone. A failure
  of a string, begin or key-prefix callee gives `(0x8000000000000000, first value, second value)`; a failure of a record callee
  copies the callee's three words unchanged. No later stub is called after a failure.
- `0x44f9110` (99 bytes) and `0x44f9180` (92 bytes) are the key-prefix writers used by the tagged writer: flag byte `[rsi+0xb]` zero tails
  straight into `0x4199450` / `0x3c6f4e0`; otherwise they write `leader_commission` (17 bytes) respectively `sub_deployers` (13 bytes, a field
  of another record) and tail only when the write returned 2.

## Implementation and comparison

`tools/vault_serializers_115.py` loads the binary after the digest check, decodes the four function extents with the shared FDE parser,
and runs the real bytes in the evaluator with recording stubs (`word`, `rec`, `begin`, `reserve` and `tail` result conventions). Each
case fills a record, serializer object, text area and buffer with generated bytes, chooses the flag byte, capacity, length and an
optional failing stub call, runs the bytes, and compares call log, 24 byte result record, capacity, length and the whole 1 KiB buffer
with the independent rule list. Any write outside the result, serializer words and buffer is a failure. Callee sets and tail targets
are re-derived from the bytes and must equal the stub tables. Not executed or implemented in Rust: no Rust path is provided.

Controls (52): 28 wrong rule lists (inverted header, wrong offsets, width mix-ups, never or early growth, wrong error tag, swapped
begin routine, swapped helper order, missing call, cleared result, key text, prefix errors), 16 corrupted code bytes (offsets,
immediates, an inverted jump, key lengths), 5 out of range inputs (interior address, address before a function, address outside the
file, wrong digest, corrupted key table) and 3 unmodelled callees. The tool refuses to write evidence unless all cases agree.

## Results and limitations

- 11,200 cases (10,400 for the two Vault writers, 800 for the prefix writers), 0 mismatches; 52 controls, 52 refused. Branch counts are in
  `summary.json` (named 5,320, compact 5,080, failing 4,447, growth exercised in 2,415).
- Unproven: what the callees actually write (they are stubs), the identity of the extra helper at `+0 / whole record`, the meaning of the
  `0x8000000000000004` / `0x8000000000000000` tags beyond "ok / error", and whether `0x44a6a20` is used for the on-disk or the wire form.
  The stub growth rule (new capacity = length + count + 64) is the harness contract, not a claim about the real allocator.
- No component gate is requested.
- Next question: the third family member, the compact JSON writer `0x44a6320` (976 bytes, `{` / `: ` writer with indent state), and the
  tail target `0x4199450` to close the `leader_commission` value encoding.
