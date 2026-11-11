# bridge: bridge event-name decoder in node #115

This packet makes the node #115 decoder of the six bridge event names
reconstructible from byte evidence: `Deposit`, `InvalidatedWithdrawal`,
`RequestedWithdrawal`, `FinalizedWithdrawal`, `FinalizedValidatorSetUpdate` and
`RequestedValidatorSetUpdateEvent`. It covers all ten exact-name visitors in the
three copy families. An independent Rust implementation can now fix:
- the variant tag order (0 `Deposit` .. 5 `RequestedValidatorSetUpdateEvent`);
- the length-indexed dispatch every visitor runs first (`len - 7`, 26 rows, 5
  lengths reach a compare arm, the 21 other rows and every length outside
  7..32 go straight to the unknown-variant path);
- the exact, case-sensitive full-length match, with the two 19-byte withdrawal
  names split by their first byte;
- the result encoding and the error behaviour, including lossy UTF-8 reporting
  and the free of the converted copy for `&[u8]` input.

- Component ID: `bridge` (Bridge and withdrawals). No RE task owns these names.
  The packet is a step toward the component's first task (message and event
  lifecycle). It is not a gate claim.
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`.
  No reference source was used. The names come from the binary's own pools,
  immediates and SSE literals.
- Claim status:
  - Observation: the ten body extents, instruction bytes, length tables, name
    literals, pools and relocations, and the interpreted outcome of every case.
  - Inference: that the enum is the bridge event kind (from the names only).
  - Unresolved: the payload-carrying variant bodies and the event stream that
    uses them (see Limits).
- Scope included:
  - five `&[u8]` visitors: `0x28641d0`, `0x2864770`, `0x4445a30`, `0x4445fd0`,
    `0x5ae4080`;
  - five `&str` visitors: `0x2864d00`, `0x2864e60`, `0x4446560`, `0x44466c0`,
    `0x5ae4620`;
  - ten length tables (one per visitor) in `.rodata`;
  - three name pools (`&[&str; 6]`): `0x643e050`, `0x648a528`, `0x64bc6c0`.
- Scope excluded:
  - the `visit_u64` index path (`variant index 0 <= i < 6` is a message shared
    with other six-variant enums of the same families, so its owner is not
    unique);
  - serializers and payload decoders of the event variants;
  - the callees (lossy conversion, free, unknown-variant constructors), which
    are stubbed by their call contract.

None of the ten bodies or three pools appears in any file under `research/`,
`tools/` or `tests/` at the source commit, or in the file list of an open PR.

## Reproduce

```
python3 tools/bridge_event_name_codec_115.py --out research/work-items/bridge-event-name-codec-115
python3 -m unittest tests.test_bridge_event_name_codec_115
```

The producer checks the input SHA-256 first and refuses any other file. It uses
only the Python 3 standard library plus `tools/fde_extents.py` (FDE extents) and
`tools/elf_index.py` (section headers; SHT_NOBITS sections are excluded from
address resolution). It does not run the binary or call an external program.
Two runs with different `PYTHONHASHSEED` and `TZ` values, and a PATH without
binutils, produce byte-identical files.

## Evidence

Coordinates are virtual addresses in node #115. Every row is generated from
file bytes.

| File | Rows | Content |
| --- | ---: | --- |
| `functions.tsv` | 10 | entry, FDE end, bytes, decoded instruction count, LSDA, body SHA-256, callees |
| `instructions.tsv` | 2,054 | every instruction of the ten bodies (bytes and decoded op) |
| `length-tables.tsv` | 260 | 26 rows per visitor: row address, rel32, target, `compare` or `miss`, names of that length |
| `visitor-literals.tsv` | see file | length bias, bound and miss target; per-byte compares, first-byte splits, dword immediates, 16-byte SSE literals, result stores |
| `name-pool-refs.tsv` | 10 | the `lea` that loads each visitor's pool |
| `name-pools.tsv` | 18 | each pool slot, its `.rela.dyn` RELATIVE entry, the text address and length |
| `callees.tsv` | 8 | callee role bound from body shape |
| `visitor-cases.tsv` | 4,936 | one row per input: outcome of all ten visitors and the reconstruction verdict |
| `paths.tsv` | 600 | (function, interpreted instruction count, outcome) path classes and their input counts |
| `negative-controls.tsv` | 10 | mismatch counts of deliberately wrong reconstructions |
| `summary.json` | - | totals |

Observations:

1. Length gate. Every visitor starts with `lea rX,[rdx-0x7]; cmp rX,0x19; ja miss`,
   then `lea rY,[rip+table]; movsxd rX,[rY+rX*4]; add rX,rY; jmp rX`. The
   tool requires exactly this shape (bias -7, bound 25, one `ja`) and reads all
   26 rows of each table. Across the ten tables, 50 rows reach a compare arm
   and 210 rows equal the `ja` target. The compare rows are exactly lengths 7,
   19, 21, 27 and 32, which are the name lengths. The tool fails if any row
   disagrees with the name lengths.
2. `&str` visitors (342 and 369 bytes, no LSDA):
   - `Deposit` is two overlapping dword xors (`'Depo'` at +0 and `'osit'` at +3);
   - each longer name is two overlapping 16-byte `movdqu` loads, two `pcmpeqb`
     against `.rodata` literals, `pand`, `pmovmskb` and `cmp eax,0xffff`;
   - the two 19-byte names are tried in sequence (`RequestedWithdrawal`, then
     `FinalizedWithdrawal`).
3. `&[u8]` visitors (1,429 and 1,415 bytes, with LSDA): one `cmp byte [rsi+k],imm`
   per name byte. Length 19 loads the first byte and branches on `'F'` or `'R'`.
4. A match stores `0x09 | tag << 8` as a word (tagged form) or `{0, tag}` as two
   bytes (Result form). The tag is the pool index.
5. A miss calls the unknown-variant callee of the output form with
   `(text, len, pool, 6)`. `&[u8]` visitors first call the lossy conversion
   (slot `0x64df640`), report the converted text, and free an owned copy
   (slot `0x64df4a0`).
6. Each family has its own pool and unknown-variant callees: tagged
   `0x17fbba0`/`0x2f7fef0`/`0x47d2d80`, Result `0x2cf1360`/`0x45a8fe0`.
   `0x63f0a50` is the landing-pad resume target.

Inference (not proven by bytes): the enum is the bridge event kind of the
deposit/withdrawal and validator-set-update stream. Nothing in this packet
shows where the event is produced or consumed.

## Implementation and comparison

The reconstruction is the pure function `recon_visitor(kind, form, text)` in the
tool:
- `length_row(len)` returns `len - 7` when it is below 26, otherwise no row;
- `recon_classify` returns the declaration index of an exact match;
- the result is the tagged word or `(0, tag)`, or `Err(text)` with the lossy
  conversion and owned-copy free for `&[u8]` input.

It shares no code with the interpreter. Each of the ten bodies runs from its
original bytes in a small x86-64 subset interpreter:
- unknown opcodes, reads outside file-backed sections and stores outside
  scratch memory are rejected;
- calls are allowed only to the bound callee roles, and the call arguments are
  checked (pool address, count 6, converted text, freed buffer).

Inputs (4,936) are built from the names:
- every prefix, one-byte extensions and the `\0`-suffixed form;
- lower and upper case;
- each position replaced by 37 byte values and by its case flip;
- invalid UTF-8 tails and an embedded `é`;
- cross-name splices and concatenations;
- runs of `A` and `0x80` of length 0..39.

Every input runs through all ten visitors.

## Results and limitations

- 49,360 / 49,360 visitor cases match the reconstruction (4,936 inputs × 10
  visitors). Exactly 6 inputs are accepted, 414 inputs are invalid UTF-8, and
  2,070 cases free an owned copy.
- 600 distinct path classes are exercised (`paths.tsv`).
- Negative controls: all 10 are caught (`negative-controls.tsv`):

| Wrong reconstruction | Mismatching cases |
| --- | ---: |
| prefix match | 480 |
| case folding | 1,360 |
| swapped 19-byte withdrawals | 20 |
| alphabetical tag order | 50 |
| first dword only | 37,650 |
| last 16 bytes only | 14,250 |
| length table only | 47,000 |
| length and first byte only | 44,480 |
| 25-row table (length 32 misses) | 10 |
| raw error text for `&[u8]` | 2,070 |

- The unit tests also mutate the capture bytes and check that the interpreter
  follows them:
  - a length-table row redirected to a miss row;
  - the bound `0x19` lowered to `0x18`;
  - the `'Depo'` immediate;
  - one byte compare of the `&[u8]` visitor;
  - a tag store;
  - an SSE literal;
  - an undecodable opcode, an unbound callee and a wrong pool, all rejected.

Limits:
- Only the ten visitors are interpreted. The callees are stubs bound by their
  call contract, not reconstructed.
- The `visit_u64` index path, the serializers and the payload decoders of the
  event variants are not covered.
- No Rust implementation yet. No progress gate is requested.
