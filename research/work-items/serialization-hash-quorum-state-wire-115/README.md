# serialization: reconstruct the node #115 serializers of the six-field quorum record (5 MessagePack bodies, 3 JSON bodies)

This packet makes the wire form of one six-field state record of node #115 rebuildable as executable code: the record has the fields `tracker`, `qrs`, `highest_quorum_height`, `htm`, `adu` (an f64) and a sixth field whose key `h` is written by its own helper. A reconstruction can now write it in MessagePack (array form for struct-as-map byte 0, map form with five keys for byte 1, map form without keys for any other byte) and in JSON (`{`, the key, `: `, then the helpers), with the exact field order, field offsets (`+0x0`, `+0x48`, `+0x80`, `+0x60`, `+0x88`, `+0x90`), argument shapes, three different error-propagation shapes and the JSON depth/flag bookkeeping, and every claim is re-derived from the code bytes by running the original instructions and comparing 11,720 cases with an independent Python model (0 mismatches, 93 of 93 negative controls detected).

- Component ID: `serialization` (struct serializers over `serde_json` and `rmp-serde`-shaped writers; the state it writes belongs to the hard-quorum and signature-tracker records, see Limits). Not a RE-001, RE-004, RE-006, RE-010, RE-011, RE-014 or RE-015 packet.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`). Nothing here is taken from node #94.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No inferred reference source was read or copied.
- Claim status:
  - **Observation:** FDE extents, decoded instruction bytes, immediates, key strings read from the pools, the interpreted results of the original bytes on the listed inputs, the neighbouring rodata texts.
  - **Inference:** the serde roles (header, str, u64, f64 and record helpers) from their call shapes and result checks, and that the five-key run is one struct. The record's Rust type name is unresolved.
  - **Unresolved:** the type name, the callers of the eight bodies, and the internals of every stubbed helper.
- Scope:
  - Included: eight complete bodies, every byte of each FDE extent decoded: MessagePack `0x275f130`, `0x275f560` (copy family 1), `0x4214250`, `0x4214480` (family 2), `0x5af9430` (family 3); JSON `0x275ef30`, `0x275f360` (family 1), `0x5af9660` (family 3). The sixth-field key and the `adu` key are read from the helper bodies by byte pattern (`helper-keys.tsv`).
  - Excluded: all helper bodies (stubbed with recorded arguments) and the callers. Family 2 has no JSON body among the eight lea sites of the key run. No progress gate is requested.
  - None of the eight entries appears in a reconstruction under `research/work-items` (two RE-001 census records list some of them as addresses only).

## Reproduce

From the repository root on Linux x86-64 with Python 3 and the standard library only (plus `tools/elf_index.py` and `tools/fde_extents.py`):

```
python3 tools/hash_quorum_state_wire_115.py --out research/work-items/serialization-hash-quorum-state-wire-115
python3 -m unittest tests.test_hash_quorum_state_wire_115
```

The tool checks the full SHA-256 of the input first, never executes the capture, starts no process and makes no network access. The output has no time, randomness, absolute path or unordered iteration; two runs are byte-identical. A run takes about 7 s and 260 MB. `MANIFEST.sha256` holds the output hashes.

## Evidence

Addresses are virtual addresses. Every number below is produced by the tool from the ELF bytes.

### The eight bodies

| Body | Style | Entry | FDE bytes | Instructions |
| --- | --- | --- | --- | --- |
| rmp-a1 | MessagePack | `0x275f130` | 546 | 141 |
| rmp-a2 | MessagePack | `0x275f560` | 546 | 141 |
| rmp-b1 | MessagePack | `0x4214250` | 549 | 142 |
| rmp-b2 | MessagePack | `0x4214480` | 549 | 142 |
| rmp-c1 | MessagePack | `0x5af9430` | 546 | 141 |
| json-a1 | JSON | `0x275ef30` | 503 | 119 |
| json-a2 | JSON | `0x275f360` | 503 | 119 |
| json-c1 | JSON (third family) | `0x5af9660` | 557 | 127 |

`functions.tsv` has the hash of each body, `instructions.tsv` every decoded instruction and `callee-roles.tsv` the call target of each role. The three copy families differ only by their helper addresses; within a family the two bodies differ by the type-specific helpers for `tracker` and `qrs` (and by the JSON `tail` helper).

### MessagePack shape

```
struct-as-map byte at serializer +0xb:
  0      -> array header helper, count 6
  other  -> map header helper,   count 6
then for each field, in order tracker, qrs, highest_quorum_height, htm, adu:
  if the byte == 1: str helper writes the key (lengths 7, 3, 21, 3, 3)
  value helper: tracker (out, value, ser), qrs (out, ser, value+0x48), u64 (out, ser, [value+0x80]),
                htm (out, value+0x60, ser), f64 (xmm0 = [value+0x88]) 
last: tail helper (out, ser, value+0x90), which writes its own one-byte key h
```

Error shapes, as read from the exits: the header and the u64 helper return `2` in the first result word on success, otherwise the first two words are re-wrapped as `(0x8000000000000000, w0, w1)`; the str helper (and the f64 helper in the `ret` form of families 1 and 3) returns `2` in `rax`, otherwise `(0x8000000000000000, rax, rdx)`; the record helpers (`tracker`, `qrs`, `htm`, `tail`, and the f64 helper of family 2) succeed with `0x8000000000000004` in the first word, otherwise all three words are copied. Success stores only the first word, so the other two stay untouched. The tool's `ret` and `out` f64 forms are both executed (families 1 and 3 versus family 2).

### JSON shape

```
depth = ser[+0x18]; depth == -1  -> panic through slot 0x64df520 (nothing written)
ser[+0x18] = depth + 1; ser[+0x20] = 0
writer Vec: if cap == len grow(len, +1); store '{'
key helper (state on stack, key tracker, 7) ; state byte 1 -> panic through slot 0x64df730
writer Vec: if cap - len <= 1 grow(len, +2); store ": "
tracker helper (value, ser) -> non-zero rax is returned as is
ser[+0x20] = 1
qrs, highest_quorum_height, htm helpers (state, key, len, value pointer); non-zero rax returned;
  after qrs and after highest_quorum_height a non-zero state byte calls the error constructor (slot 0x64e0b08)
  and returns its result; after htm the state byte is NOT read
adu helper (state, value+0x88), tail helper (state, value+0x90), end helper (copy of the 16-byte state); return 0
```

Third-family JSON body `0x5af9660` (`json-c1`): same depth/flag/brace/separator prologue (the overflow, format and error-constructor slots are the same three), but every field after the first goes through a keyed helper `(state, key, len, value pointer)`: `qrs`, `highest_quorum_height`, `htm` and `adu` (the f64 key is written in the body, not in a callee), a non-zero state byte after each of the first three calls the error constructor, and the state byte after `adu` is not read. The tail helper `(state, value+0x90)` runs last; the end helper `(ser+8, writer)` is called only when the state byte 0 is clear and the state byte 1 is non-zero, so a tail helper that leaves state byte 0 set or clears byte 1 skips it and the body still returns 0.

The no-check after `htm` in the family-1 JSON bodies is a fact found by the evaluator: the first model checked all three and the machine code disagreed on 18 of 264 sampled cases in each JSON body.

### Keys

`field-keys.tsv` lists, for every body, the `lea` of each key pool and the length loaded next to it: `tracker`, `qrs`, `highest_quorum_height`, `htm`, `adu` (JSON bodies write the first four; `adu` is written inside the `0x282d550` helper). `helper-keys.tsv` reads the sixth key from the three MessagePack tail helpers and the two JSON tail helpers: one byte, `h`, at `0x5f6b4d` (family 1), `0x7c8682` (family 2), `0x93e633` (family 3). In `.rodata` the run `tracker qrs highest_quorum_height htm adu` is followed by `h` and sits between the texts `struct HashHardQuorum with 3 elements` and `struct HashSignatureTracker with 6 elements`; the field count loaded by every header call is 6 (`mov $6,%edx` is checked next to both header calls of each MessagePack body), which matches the second text, but the tool does not prove the name.

## Implementation and comparison

Not yet implemented as Rust. `tools/hash_quorum_state_wire_115.py` holds the instruction decoder and interpreter (the instruction subset these bodies use; anything else raises), the stubs with recorded arguments, and two independent models, `recon_rmp` and `recon_json`, written from the reading above. Each case seeds the input block with words tagged by their own offset (so a wrong field offset changes the log), runs the body, and compares the ordered call log (role, key text, value offset), the appended bytes, the end length, the depth word, the flag byte and the three result words.

| Metric | Value |
| --- | --- |
| Bodies | 8 (5 MessagePack, 3 JSON) |
| Decoded instructions | 1,072 |
| Cases | 11,720 (MessagePack 7,400 = 5 bodies x 40 seeds x 37 flag/failure combinations; family-1 JSON 2,640 = 2 x 1,320; third-family JSON 1,680) |
| Mismatches | 0 |
| Cases listed in `cases.tsv` | 3,907 (every third plus any mismatch); the SHA-256 of the whole stream is in `summary.json` |
| Negative controls | 93, all detected (`measure.json`) |

The 93 controls: 32 deliberately wrong models (16 MessagePack, 12 family-1 JSON, 4 third-family JSON; each differs from the model on listed cases, the number of differing cases is in `negative-controls.tsv`), 51 corrupted code bytes (30 in the MessagePack bodies, 14 in the family-1 JSON bodies, 7 in the third-family JSON body: key-length immediates, field displacements, the f64 displacement, flag compares, branch polarity, call targets, the brace and separator bytes; each makes the interpreter disagree with the model or refuse), and 10 out-of-range inputs (tampered or empty input, an entry that is not an FDE start, reads below and beyond the sections, a store outside scratch memory, a load of an unset scratch byte, a call to an unmodelled target, the step limit).

## Results and limitations

- 11,720 cases, 0 mismatches, 93 of 93 negative controls detected. No progress gate is requested.
- Helper bodies are stubs, so their wire output (for example how a record helper encodes its value) is outside this claim; only their order, arguments and result handling are.
- The Rust type of the record and its callers are not identified; the field-count and the neighbouring text point at `HashSignatureTracker`, which is an inference.
- Family 2 has no JSON body among the lea sites of the key run; other copies of these serializers that do not load the key pools by `lea` would not be found by this scan.
- The panic slots are modelled as stops, not as unwinding.

Next question: which type owns this record (callers of the eight bodies), and what do the `tracker` helpers `0x28a77d0` / `0x28a8c20` / `0x5371160` (and the other copies) write?
