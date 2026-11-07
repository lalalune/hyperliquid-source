# RE-010: MessagePack TagOrContent key reader of the tagged Action visitor (node #115)

With this packet, the key read inside the internally tagged MessagePack `Action`
visitor can be rebuilt as code. That visitor is `visit_map` 0x1fb1750 and its copies;
it calls the reader at +0xfd. The packet covers how node #115 reads one msgpack
value and turns it into `TagOrContent`:

- marker decoding: fresh or peeked, including the "no peek" niche;
- every length prefix and its short-read behaviour;
- borrowed str/bin payloads, the UTF-8 rule, and the `Tag` versus
  `Content::Str` / `Content::Bytes` decision against the tag name;
- recursion into map, array and ext with the u16 depth budget, including when
  the budget is restored and when it is not;
- the remaining-length check after a map or array visit;
- the forwarding of all scalar markers to the generic `deserialize_any`;
- every landing pad.

The reconstruction is the pure `Model` class in
`tools/re010_tag_or_content_key_115.py`. The tool runs the original bytes of all three
copies over 11,284 cases with the callees scripted. The binary is never executed.
The result is 0 mismatches, and 52/52 wrong models and corrupted images are rejected.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `7ff06a097`. `references/can1357-hl` was not used.
- Claim status:
  - Observation, proved by running the original bytes against the reconstruction:
    control flow, constants, jump tables, call arguments, result bytes,
    deserializer write-back, LSDA call sites and landing pads.
  - Inference: the serde and rmp names (`TagOrContentVisitor`, `Content::*`
    discriminants, rmp `Marker`, `Error::InvalidMarkerRead`, `InvalidDataRead`,
    `TypeMismatch`, `LengthMismatch`, `DepthLimitExceeded`).
- Scope included: the full bodies of 0x1a7e1a0, 0x30fb4f0 and 0x48cd3a0 (2,378 B each),
  their two relative jump tables each, and their LSDA call-site tables. These are the
  callees of `visit_map` +0xfd in 0x1fb1750, 0x3952ed0 and 0x5687260.
- Scope excluded: callee bodies, all stubbed by contract:
  - the map, array, ext and bytes visitors 0x21e0380, 0x21e1c10, 0x21e1930
    and 0x21e2670 (plus their copies);
  - the generic `deserialize_any` GOT 0x64e3a90;
  - bcmp, from_utf8, the allocator, the panics and the drops.

## Reproduce

```
python3 tools/re010_tag_or_content_key_115.py --out research/work-items/RE-010-tag-or-content-key-115
python3 -m unittest tests.test_re010_tag_or_content_key_115
cd research/work-items/RE-010-tag-or-content-key-115 && sha256sum -c MANIFEST.sha256
```

The tool and tests use only the Python 3 standard library and the shared
`tools/elf_index.py` and `tools/fde_extents.py` parsers. They call no external
program and never execute the binary. The tool checks the input SHA-256 first.
Generation takes about 100 s.

Two generations produced byte-identical output: one with the default environment,
one with `PYTHONHASHSEED=12345`, `TZ=Asia/Seoul` and a PATH without binutils.

## Evidence

All numbers and tables are produced by the tool from ELF bytes:
- section headers via `elf_index`;
- FDE and LSDA via `fde_extents` and the uleb call-site table;
- `.rela.dyn` RELATIVE and `.rela.plt` JUMP_SLOT relocations;
- fixed-pattern instruction decoding.

| file | content |
|---|---|
| `functions.tsv` | per copy: FDE extent, LSDA, caller site, instruction and call counts, per-copy rip-relative constants and jump-table addresses |
| `call_sites.tsv` | the 30 call sites by offset, their role, each copy's target, and landing pad and action |
| `dispatch.tsv` | the 225-entry marker table and the 18-entry ext table, with the arm offset of each entry and whether it was executed (identical offsets in all copies) |
| `lsda.tsv` | the call-site table, the same in all copies |
| `coverage.tsv` | every instruction of the anchor copy, whether it was covered, and the taken and not-taken edges |
| `cases.tsv` | the 5,641 base cases with outcome, result bytes, callee sequence and deserializer state after the call |
| `mutants.tsv` | 12 wrong models and 40 corrupted images, with the number of cases each one changes |
| `summary.json` | totals |

### Interface (observed)

The call is `rdi` = out `Result<TagOrContent, rmp::Error>` (0x28 B), `rsi` = the
deserializer, and `rdx`/`rcx` = tag name pointer and length. The low byte of `r8`
is a flag that is only read on the bin path.

The deserializer fields used are:
- +0x10 input pointer;
- +0x18 remaining length;
- +0x20 peeked marker kind, where 1 means none;
- +0x21 peeked marker data;
- +0x22 u16 depth budget.

The kind byte is always reset to 1 on entry.

### Behaviour (reconstructed and proved)

- **First byte.** If nothing is peeked and the input is empty, the result is
  `Err(kind 0, eof)`. Otherwise one byte is consumed:
  - <0x80 is FixPos and >=0xe0 is FixNeg. Both go to the generic `deserialize_any`
    with (kind, data) = (0, b) or (0xe0, b).
  - 0x80-0x8f is a map with n = b&0xf, and 0x90-0x9f is an array with n = b&0xf.
  - 0xa0-0xbf is a str with len = b&0x1f.
  - Any other byte is dispatched on its full value. For bytes >=0xc0 the data
    byte passed on is `b & 0x1f`, not 0: a fresh `0xc0` nil is forwarded as
    (0xc0, 0x00), `0xcc` as (0xcc, 0x0c).
- **Peeked marker.** A peeked marker uses the same arms with its stored (kind, data).
  Kinds 0x01..0xbf other than 0x80/0x90/0xa0 reach `ud2`; they are not Marker
  discriminants. The table has 0xe1 entries; e1..ff are not marker kinds.
- **Forwarded markers.** nil, bool, float, the ints and FixNeg are forwarded to
  GOT 0x64e3a90 with the tag name still in rdx/rcx. Its result is the whole return.
  0xc1 (reserved) returns `Err` with the word 0xc102 at +8, which reads as
  TypeMismatch(Reserved).
- **Length prefixes.** These are big-endian, 1/2/4 bytes for 8/16/32. A short
  length read consumes the remaining bytes and returns `Err(kind 1, eof)`; for
  1-byte prefixes "remaining" is 0. A short payload keeps the length bytes
  consumed, leaves the payload in place, and returns `Err(kind 1, 0x2500000003)`.
- **bin (c4/c5/c6).** The result depends on the low byte of r8:
  - r8b = 0: the borrowed slice goes to the bytes visitor (`{ptr, end, 0}`).
  - r8b != 0: the result is `Tag` if the length equals the name length and bcmp
    is 0. Otherwise it is `Content::Bytes(ptr, len)` (0x0f).
- **str (a0..bf/d9/da/db).** `from_utf8` runs first.
  - Valid UTF-8: equal to the name gives `Tag` (only byte +8 = 0x16 is written).
    Otherwise the result is `Content::Str(ptr, len)` (0x0d).
  - Invalid UTF-8: the result is `Content::Bytes(ptr, len)`, or 0x16 with the
    slice still written if the bytes equal the name.
- **map/array (80/de/df, 90/dc/dd).**
  - Depth 0 panics with a subtraction overflow. That call site has no landing
    pad, so the panic escapes.
  - The depth is decremented. If it reaches 0, the result is `Err(8)` and the
    depth stays at 0.
  - Otherwise the visitor is called with `{de, n}`. If the visitor returns `Err`,
    its 32 bytes are returned and the depth is **not restored**.
  - On `Ok`, remaining 0 gives `Ok(content)`. Remaining > n panics with a
    subtraction overflow, and the pad drops the content unless its tag byte is
    0x16.
  - Otherwise the result is `Err(LengthMismatch(n - remaining))` (byte 4,
    u32 at +0xc). The content is dropped and the depth is restored; 0xffff panics
    with an addition overflow and the pad drops the result.
- **ext (c7/c8/c9 read a length; d4..d8 are 1/2/4/8/16).**
  - The depth handling is the same as for map/array, and the visitor gets
    `{de, len, 0}`.
  - `Ok` boxes the 32-byte content in a 0x20-byte allocation and returns
    `Content::Newtype(box)` (0x13).
  - If the allocation fails, `handle_alloc_error` runs and the pad drops the stash.
  - Both `Ok` and `Err` **restore** the depth, unlike map/array `Err`.
  - A short ext length also writes (kind, data) into bytes +9/+10 of the error.

## Implementation and comparison

The `Model` class is a pure reconstruction of the function. It does not read the
binary except for the per-copy addresses of the static error constants and the
panic locations, which are bound by lea offset.

The `Machine` interprets the original instructions of each copy with contract
stubs:
- visitor results scripted by the case, including a callee that changes the depth;
- bcmp on the real bytes;
- from_utf8 using Python's strict UTF-8, which rejects surrogates the same way
  Rust does;
- an allocator with a failure switch;
- panics that always unwind into the LSDA pad.

Every non-panicking callee call of every base case is also made to unwind once
(5,643 cases), and so is every cleanup inside a pad, which then terminates.

- 11,284 cases, 0 mismatches in each of the 3 copies (result bytes, callee
  sequence with arguments, deserializer write-back, outcome).
- 558/563 instructions and 50/51 conditional jumps covered both ways in each copy.
- 12/12 model variants rejected: fresh data byte kept whole, map Err restores
  depth, ext Err keeps depth, bin ignores flag, invalid UTF-8 as Str, no payload
  length check, depth limit <=1, short length not consumed, Tag keeps slice,
  mismatch reports remaining, drop regardless of tag, nil as Unit.
- 40/40 image mutants rejected: 34 immediate or condition flips and 6 jump-table
  entry swaps.

## Results and limitations

- **Uncovered code.** The 5 uncovered instructions are `jmp`s after calls that
  never return (panics and `handle_alloc_error`). The one jump not taken both
  ways is the ext-table bound `ja` at +0xce. It is unreachable because only
  c7..c9 and d4..d8 reach that arm, so `kind-0xc7 <= 0x11` always holds.
- **Callee contracts.** Callee bodies are stubbed. The visitor contracts (result
  layout, remaining count at access+8, depth change) are taken from how this
  function reads them. They are not proved here.
- **Names.** Serde and rmp names are inferences from the layout and the
  discriminant values. The Content discriminants used (0x0d Str, 0x0f Bytes,
  0x13 Newtype, 0x16 Tag niche) match serde's `Content` declaration order.
- **Depth asymmetry.** The map/array `Err` path does not restore the depth
  budget, while the ext path does. This is a byte-level fact. Whether a caller
  relies on it is not examined.
- No component gate is advanced by this packet.
