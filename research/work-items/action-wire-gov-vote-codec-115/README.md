# action-wire: governance vote and proposal-category name codecs in node #115

This packet makes the two governance unit-enum codecs of node #115 reconstructible
from byte evidence. It covers the vote choice `yes`/`no`/`abstain` and the proposal
category `accelerated`/`constitutional`/`ecosystem`/`electoral`, including their
MessagePack serializers and all 18 exact-name visitors. An independent Rust
implementation can now fix the tag order, the wire bytes and reserve calls of every
arm, and the exact error behaviour of every visitor. It can also fix two dispatch
facts the names alone do not give:
- the vote serializer is a total test/cmp chain, so every tag byte above 1 writes
  `abstain`;
- the category serializer is an unchecked jump table, so only tags 0..3 are
  defined.

- Component ID: `action-wire`. These are user action payload enums. No RE task
  owns these names; RE-010's `RE-010-gov-vote-path-115` traced the govVote
  decoder and vote state, not these codecs. See Limits.
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`.
  No reference source was used. The names come from the binary's own pools and
  immediates.
- Claim status:
  - Observation: the 22 body extents, instruction bytes, dispatch rows, name
    literals, pools and relocations, and the interpreted outcome of every case.
  - Inference: the governance meaning (vote choice and proposal category).
  - Unresolved: the struct-level serializers that embed these codecs (see Limits).
- Scope included:
  - two vote serializers (`0x3c32d70`, `0x4d98860`);
  - two category serializers (`0x3c31230`, `0x4d96fd0`);
  - eight vote visitors and ten category visitors in three copy families;
  - six name pools (`&[&str; 3]` vote: `0x642f0c0`, `0x6475fe0`, `0x649c1b8`;
    `&[&str; 4]` category: `0x642f1a0`, `0x6476010`, `0x649c1e8`).
- Scope excluded:
  - the `{choice, weight}` struct serializers `0x241cb90`, `0x3c31a70` and
    `0x4d974e0`;
  - the category-key field writer `0x245a590`;
  - the msgpack identifier decoders that also load the vote pool (`0x1debd70`,
    `0x1e20760`, `0x1fa4a20`, `0x1fa9ba0` and their copies);
  - the action handlers.

## Reproduce

From the repository root, with Python 3 and no other program:

```
python3 tools/action_wire_gov_vote_codec_115.py --out research/work-items/action-wire-gov-vote-codec-115
python3 -m unittest tests.test_action_wire_gov_vote_codec_115
```

The producer:
1. Refuses any input whose SHA-256 is not the #115 digest.
2. Locates every body by its `.eh_frame` FDE through the shared
   `tools/fde_extents.py` parser and reads sections through `tools/elf_index.py`.
   NOBITS sections are excluded from VA reads.
3. Decodes each body linearly with a fixed x86-64 subset decoder. Any byte outside
   the subset is rejected, not skipped.
4. Runs every case through the original instructions in a small interpreter.
   External callees are replaced by stubs whose role is derived from the body
   shape. Stores outside the scratch regions are rejected.

All outputs are deterministic. No timestamps, no absolute paths, and sorted
iteration only. A run takes about 23 s.

Human-readable excerpt (GNU objdump, `-M intel`) of the family-1 `&str` vote visitor
`0x23c18b0`. It is not used by the tool:

```
23c18b0: cmp rdx,0x2 ; je 23c18d9            # len 2 -> "no"
23c18b6: cmp rdx,0x3 ; jne 23c18e9
23c18bc: movzx eax,WORD PTR [rsi] ; xor eax,0x6579 ; movzx ecx,BYTE PTR [rsi+0x2] ; xor ecx,0x73
23c18d0: mov WORD PTR [rdi],0x9                # Ok(yes)  = 0x09 | 0 << 8
23c18e0: mov WORD PTR [rdi],0x109              # Ok(no)
23c18e9: cmp rdx,0x7 ; ... xor 0x74736261 ("abst") / 0x6e696174 ("tain" at +3)
23c1902: mov WORD PTR [rdi],0x209              # Ok(abstain)
23c190c: lea rcx,[rip+...] # 0x642f0c0 ; mov r8d,0x3 ; call 0x17fbba0   # unknown_variant(text, pool, 3)
```

## Evidence

Coordinates are virtual addresses in the #115 image. `name-pools.tsv` also records
the file offset of each `.rela.dyn` entry.

| File | Rows | Content |
| --- | ---: | --- |
| `functions.tsv` | 22 | role, FDE extent, decoded instruction/byte counts (decoded bytes = FDE bytes for all 22), LSDA, body SHA-256, callees |
| `instructions.tsv` | 2,159 | every decoded instruction: VA, length, raw bytes, operation, branch target |
| `callees.tsv` | 10 | callee role bound from the bodies: 2 grow helpers, 5 unknown-variant callees (2 Result form, 3 tagged form), the lossy-UTF-8 and free slots `0x64df640`/`0x64df4a0`, `_Unwind_Resume` on landing pads only |
| `serializer-dispatch.tsv` | 18 | vote chain rows (`movzx`, `test`/`je`, `cmp 1`/`jne`) with raw bytes; category jump-table rows read as rel32 from `.rodata` (`0x7b389c`, `0x91524c`) with their arm VAs |
| `serializer-arms.tsv` | 86 | per arm: fixstr marker store, reserve bound, name-byte stores, `Ok` word, grow `additional` immediates |
| `visitor-literals.tsv` | 434 | per visitor: length gates, byte compares, xor immediates, movabs words, SSE compare rows, result stores |
| `name-pool-refs.tsv` | 18 | the single RIP-relative `lea` of each visitor and the pool it names |
| `name-pools.tsv` | 21 | each pool slot: RELATIVE relocation file offset, text VA, length and text |
| `serializer-cases.tsv` | 2,188 | every serializer case with appended bytes, grow calls, final length, result word and verdict |
| `visitor-cases.tsv` | 3,252 | every input against all 18 visitors (58,536 cells) with the reconstruction's vote and category tags |
| `paths.tsv` | 438 | distinct interpreted (function, step count, outcome) paths with input counts |
| `negative-controls.tsv` | 13 | each deliberately wrong reconstruction with the number of cases that catch it |
| `summary.json` | - | counts, names, pools, callee roles, unchecked heads, verdict flags |

Byte observations:

- Vote serializers. `movzx ecx, byte [rsi]` is followed by `test ecx,ecx; je`
  (tag 0 → `yes`) and `cmp ecx,1; jne` (tag 1 → `no`). Every other byte reaches
  the `abstain` arm (`0x3c32d7a..0x3c32d81`, `0x4d9886a..0x4d98871`).
  - Each arm writes the fixstr marker (`0xa3`, `0xa2`, `0xa7`). It grows by 1 if
    `len == cap`, then compares `cap - len` with `name_len - 1` and grows by
    `name_len` if not larger. It stores the name bytes with immediate stores and
    returns `0x8000000000000004`.
- Category serializers. The head is
  `push push push mov movzx lea movsxd add jmp` with no compare. The four table
  rows lead to arms laid out in code order accelerated, ecosystem, electoral,
  constitutional. The tag order still comes from the table:
  0 accelerated, 1 constitutional, 2 ecosystem, 3 electoral. This matches the pool
  order.
- Visitors.
  - `&str` visitors gate on the length (2/3/7 for vote; 9/11/14 for category,
    where ecosystem and electoral share length 9). They then compare whole words
    with xor loads. The 11- and 14-byte names use two overlapping qwords
    (`accelera`/`elerated` at +3, `constitu`/`tutional` at +6). The two 9-byte
    names use one qword plus a final byte (`ecosyste`+`m`, `electora`+`l`).
  - `&[u8]` visitors compare byte by byte. They then call the lossy UTF-8
    conversion (slot `0x64df640`) on failure and report the converted text. They
    free the owned copy (slot `0x64df4a0`) when one was made.
  - Result-form visitors write `{0, tag}`, or `{1, error@+8}` on failure.
    Tagged-form visitors write `0x09 | tag << 8` or the 32-byte error.
- Pools. Every visitor's single RIP-relative `lea` names its family's pool. The
  unknown-variant call receives `(text, len, pool, 3)` for vote and
  `(..., 4)` for category. The pools are read through their RELATIVE
  relocations; their order is the declaration (tag) order.

## Implementation and comparison

The reconstruction is the pure-Python functions `arm`, `recon_serialize`,
`recon_classify`, `recon_visitor` and `lossy` in the producer. They are written
from the observations above, not derived from the interpreter. Results:

- Serializer cases: 2,188 / 2,188 match.
  - Every declared tag at lengths 0/1/7/64 with 0..20 spare bytes, which covers
    both reserve edges of each arm.
  - For the vote chain, also every tag byte 3..255 with no spare room and with
    ample room.
- Visitor cases: 58,536 / 58,536 match.
  - The 3,252 inputs are every name, every prefix and one-byte extension,
    case-folds, and the byte mutations at each position with 30 byte values.
  - They also include cross-name splices, runs of `A` and `0x80`, and 239 inputs
    that are not valid UTF-8.
  - Exactly 7 inputs are accepted (the 7 names). 2,390 cases free an owned lossy
    copy.

Negative controls. Each wrong reconstruction runs through the same comparison and
must disagree with at least one case. All 13 are caught:

| Control | Caught by |
| --- | ---: |
| serializer str8 marker (`0xd9 len`) instead of fixstr | 2,188 |
| serializer reserve on `cap - len == name_len` | 58 |
| serializer without the name reserve | 974 |
| alphabetical tag order (abstain, no, yes); the category names are already alphabetical | 1,348 |
| vote tag taken modulo 3 | 676 |
| vote dispatch as a checked table (tags > 2 write nothing) | 1,012 |
| visitor prefix match | 584 |
| visitor case folding | 590 |
| `yes`/`no` swapped | 36 |
| first dword only | 16,208 |
| length gate only | 29,704 |
| length + first byte only | 25,626 |
| report raw bytes instead of the lossy conversion | 2,390 |

The unit tests (26) also cover these checks:
- a wrong digest is refused;
- the packet files are byte-identical to a fresh run;
- MANIFEST hashes;
- known outputs of each codec;
- byte mutations of the image that must change the interpreted outcome:
  - a swapped jump-table row;
  - the chain `cmp 1` changed to `cmp 2`;
  - a name immediate in each codec;
  - a reserve bound;
- rejection of `ud2`, unmodelled calls, a wrong pool argument, stores outside
  scratch, and out-of-range reads;
- the table-head rule refuses a compare;
- the chain rule and the table rule refuse each other's shapes.

Rust implementation: not yet implemented.

## Results and limitations

- 22 / 22 selected bodies decode fully (decoded bytes = FDE bytes).
- 2,188 / 2,188 serializer cases and 58,536 / 58,536 visitor cases match.
- 13 / 13 negative controls are caught.
- The governance meaning is an inference.
  - The category pool `0x642f1a0` follows the field names `title`, `description`,
    `category`, `nonce` in the same pool region.
  - The vote pool follows `id`, `choice`, `nonce`.
  - The struct serializer `0x241cb90` writes the keys `choice` and `weight`
    around the vote arms.
- Only the selected bodies are interpreted. The callees are stubs, so the
  allocator, the lossy conversion and the error constructors are modelled by
  their call contract, not executed.
- Family 1 has no standalone vote or category serializer. Its vote arms are
  inlined into `0x241cb90`, which is out of scope here.
- No progress gate is requested. This is one bounded codec family, not the
  `action-wire` component scope.

Next question: reconstruct the `{choice, weight}` struct serializers `0x241cb90`,
`0x3c31a70` and `0x4d974e0`, with their map/array mode flag at `+0x1b` and the
weight writer `0x25e9f10`. Then reconstruct the category field writer `0x245a590`.
