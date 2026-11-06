# risk: oracle outcome-kind decoder (exact-name visitors and serde_json readers) in node #115

This packet makes the node #115 oracle outcome-kind decoder reconstructible from
byte evidence. It covers the unit enum `StandaloneOutcome`/`Question`/`QuestionOutcome`
(tags 0..2), whose name pool sits next to the `l1/src/clearinghouse/oracle/oracle.rs`
location string, through every decode entry that references its pools:
- six exact-name visitors (`&str` and `&[u8]`) in three copy families;
- four serde_json slice readers in two families: a variant-key reader for the
  `{"Name": ...}` form and a bare string identifier reader for the `"Name"` form.

An independent Rust implementation can now fix all of the following, each checked
against the original machine code on every case:
- the tag order, and the exact accept set (byte-exact, no prefix or case folding);
- the visitor error text, including the lossy UTF-8 path and the owned-copy free;
- the JSON whitespace set (space, `\t`, `\n`, `\r` only: `0x100002600`);
- every reader failure exit with the serde_json error code passed to the position
  error, and the reader index left behind;
- which reader wraps a string-scanner error in `fix_position` (the key reader)
  and which returns it unchanged (the identifier reader).

- Component ID: `risk` (clearinghouses and oracles; the enum's pool is adjacent
  to `l1/src/clearinghouse/oracle/oracle.rs`). No work item or open PR names
  these bodies, pools or names. No task ID is claimed.
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`.
  No reference source was used. The names come from the binary's own pools,
  immediates and `.rodata` literals. No #94 result is used.
- Claim status:
  - Observation: the 10 body extents and instruction bytes, the name literals,
    pools and relocations, the reader error-code immediates and whitespace mask,
    the callee roles, and the interpreted outcome of every case.
  - Inference: that the readers are serde_json `deserialize_enum` variant-key and
    `deserialize_identifier` paths, and the serde_json `ErrorCode` names of the
    codes 3, 5, 6, 10 and 17 (see Inferences).
  - Unresolved: the struct or action that carries this enum, the outcome
    semantics of the three variants, and the MessagePack readers (see Limits).
- Scope included:
  - visitors `0x25d3a80`/`0x25d3ca0` (family 1), `0x44647c0`/`0x44649e0`
    (family 2) and `0x54797f0`/`0x5479a10` (family 3);
  - variant-key readers `0x1debf40` (family 1) and `0x3f7ea60` (family 2);
  - identifier readers `0x1e21040` (family 1) and `0x3fba720` (family 2);
  - the three name pools `0x6432d68`, `0x648b648` and `0x64aa178`.
- Scope excluded:
  - the callees, which are stubbed by role: the string scanner, unknown-variant,
    position-error, invalid-type, fix-position, lossy conversion and free;
  - the callers that use the decoded tag.

## Reproduce

From the repository root, with Python 3 standard library only:

```
python3 tools/risk_outcome_kind_codec_115.py --out research/work-items/risk-outcome-kind-codec-115
python3 -m unittest tests.test_risk_outcome_kind_codec_115
```

The producer first checks the SHA-256 of `artifacts/node/115/hl-node` and refuses
any other input. It reads sections through `tools/elf_index.py`, and FDE extents
through `tools/fde_extents.py`. It never executes the capture and starts no
external program. Output is byte-identical across runs, hash seeds and time zones.
Producer run time is about 20 s; the unittest takes about 40 s.

## Evidence

All addresses are virtual addresses in node #115. File offsets are derived
through the section headers (SHT_NOBITS sections are excluded).

| File | Content |
| --- | --- |
| `functions.tsv` | 10 bodies: FDE extent, decoded instruction count, LSDA, body SHA-256, callees |
| `instructions.tsv` | all 999 decoded instructions with their raw bytes |
| `callees.tsv` | 16 callees with the role bound from the call-site shape |
| `visitor-literals.tsv` | visitor length gates, byte compares, qword immediates, SSE2 literals, result stores |
| `reader-literals.tsv` | 20 `.rodata` name literals loaded by the readers, read from the file |
| `reader-codes.tsv` | per reader: each exit's error-code immediate and its VA, the whitespace mask, byte bounds, the invalid-type argument |
| `name-pools.tsv`, `name-pool-refs.tsv` | the three `&[&str; 3]` pools from RELATIVE relocations, and which body references which pool |
| `visitor-cases.tsv` | 2,333 inputs × 6 visitors |
| `reader-cases.tsv` | 5,230 JSON slices × 4 readers |
| `paths.tsv` | 306 distinct (body, step count, outcome) paths |
| `negative-controls.tsv` | 16 deliberately wrong reconstructions and how many cases each loses |
| `summary.json` | totals |

### Visitors

Each family has a `&[u8]` visitor (540 bytes, LSDA present) and a `&str` visitor
(162 bytes). Both gate on the input length (8, 15 or 17). The `&[u8]` visitor
then compares byte by byte (`cmp BYTE PTR [rsi+k], imm`). The `&str` visitor
compares a qword for `Question`, two overlapping qwords (`+0` and `+7`) for
`QuestionOutcome`, and an SSE2 `pcmpeqb` over 16 bytes plus one byte for
`StandaloneOutcome`. A match writes the word `0x09 | tag << 8` to the output.

Any other input goes to the unknown-variant callee with the family's pool and
the count 3. The `&[u8]` visitor first converts the input with a lossy UTF-8
callee and frees the converted copy when it is owned (`test rsi,rsi; jle`).

Family 1 `&str` visitor (objdump, for reading only):

```
25d3ca0: cmp rdx,0x8 ; je 25d3ce0
25d3ca6: cmp rdx,0x11 ; jne 25d3cf8
25d3cac: movdqu xmm0,[rsi] ; movzx eax,BYTE PTR [rsi+0x10] ; movd xmm1,eax
25d3cb8: pcmpeqb xmm0,[rip+..] ; pcmpeqb xmm1,[rip+..] ; pand ; pmovmskb ; cmp eax,0xffff
25d3cd7: mov WORD PTR [rdi],0x9                       ; StandaloneOutcome
25d3ce0: movabs rax,"Question" ; cmp [rsi],rax ; mov WORD PTR [rdi],0x109
25d3cf8: cmp rdx,0xf ; xor/xor/or of [rsi] and [rsi+7] ; mov WORD PTR [rdi],0x209
25d3d27: lea rcx,[rip+0x6432d68 pool] ; mov r8d,0x3 ; call 17fbba0
```

### Readers

The reader input is a serde_json slice deserializer:
- slice pointer at `+0x18`;
- length at `+0x20`;
- index at `+0x28`;
- scratch length at `+0x10`, which is cleared before the string call.

Output: byte 0 holds the tag, or 3 for `Err`. The qword at `+8` holds the
deserializer on success, or the error.

Variant-key reader (`0x1debf40`, `0x3f7ea60`):
1. Skip whitespace with `bt` on the mask `0x100002600`. This is applied only to
   bytes `<= 0x22`; larger bytes take the non-quote exit.
2. End of input gives code 3. A first byte other than `"` gives code 10 if it
   is `}` and 17 otherwise. In both cases the index is left on that byte.
3. Set the index past the quote, clear the scratch and call the string scanner
   through slot `0x64e08f8`. A scanner error is passed to `fix_position`.
4. Match the name with the same three compares as the `&str` visitor, against
   `.rodata` literals. A mismatch calls unknown-variant with the pool and 3,
   then `fix_position`.
5. Skip whitespace (bytes `<= 0x3a`). End of input gives code 3; any byte other
   than `:` gives code 6. A `:` is consumed and the reader returns the tag.

Identifier reader (`0x1e21040`, `0x3fba720`):
1. Skip whitespace in the same way.
2. End of input gives code 5. A non-quote byte calls the invalid-type callee with
   the visitor and the expected-type argument (`0x6423c60` in family 1,
   `0x647f038` in family 2), then `fix_position`.
3. A scanner error is returned **without** `fix_position`.
4. A mismatch is an unknown-variant error passed to `fix_position`. A match
   returns the tag and leaves the index after the closing quote.

Both readers have an unreachable panic exit (slot `0x64df520`) for an index of 0
after the increment. The interpreter rejects any case that reaches it, and none do.

Family 3 has no reader that references its pool `0x64aa178`. Only its two visitors
do.

### Callee stubs

The callees are not interpreted. Each is replaced by a stub bound to a role from
the call-site shape:
- The string scanner: the string runs to the next `"`. A backslash, a control
  byte or the end of input is a scanner error. On success the index moves past
  the closing quote.
- unknown-variant: records the text, the pool and the count.
- peek-error: records the code and the current index.
- invalid-type: records the index and the expected-type argument.
- fix-position: wraps its error.
- lossy: the visitors' lossy UTF-8 conversion.
- free: the visitors' free of an owned copy.

The pure-Python reconstruction uses the same scanner model. The comparison
therefore proves the bodies' own control flow, not the scanner's escape handling.

## Implementation and comparison

There is no Rust implementation yet. The reconstruction is the pure-Python
`recon_visitor` and `recon_reader` in `tools/risk_outcome_kind_codec_115.py`. It
is written from the semantics above and is independent of the interpreter. The
interpreter runs the original bytes for a fixed x86-64 subset and rejects:
- any other opcode;
- a read of unset scratch memory;
- a store outside scratch memory;
- an unmodelled call;
- an unbalanced stack;
- any call argument that differs from the expected pool, count or deserializer.

| Comparison | Cases | Match |
| --- | --- | --- |
| reader (4 bodies × 5,230 slices) | 20,920 | 20,920 |
| visitor (6 bodies × 2,333 inputs) | 13,998 | 13,998 |

The 5,230 reader slices are:
- every name with 14 leading and 12 trailing variants (whitespace, vertical
  tab, form feed, `}`, `{`, `!`, `:`, `;`, a quote, NUL, and others);
- truncated strings, and strings with escapes and control bytes;
- every visitor input wrapped as `"..."`: followed by `:`, or preceded by a
  space with no colon.

The 2,333 visitor inputs are every name, every prefix, every single-byte
mutation (55 byte values plus a case flip), case variants, invalid UTF-8, and cross-name splices.

Negative controls: each wrong reconstruction must disagree with the interpreted
bytes on at least one case, and every one does.

| Wrong reconstruction | Cases lost |
| --- | --- |
| reader: tab is not whitespace | 172 |
| reader: vertical tab and form feed are whitespace | 338 |
| reader: identifier wraps scanner errors in `fix_position` | 682 |
| reader: key reader returns scanner errors unwrapped | 682 |
| reader: end-of-input code off by one | 48 |
| reader: `}` gets the generic non-quote code | 80 |
| reader: `;` accepted as the separator | 90 |
| reader: prefix name match | 3,136 |
| reader: alphabetical tag order | 292 |
| visitor: prefix match | 2,478 |
| visitor: case folding | 270 |
| visitor: first two tags swapped | 12 |
| visitor: first dword only | 9,300 |
| visitor: length gate only | 13,494 |
| visitor: length and first byte only | 12,426 |
| visitor: raw bytes as error text (no lossy conversion) | 537 |

The unittest adds byte-level corruption controls on a copy of the capture:
- a name immediate in a visitor;
- the `.rodata` `Question` literal used by the key readers;
- the ExpectedColon code immediate;
- the tab bit of the whitespace mask;
- a `ud2` at a body entry.

Each one changes the interpreted result or is rejected. The unittest also checks
a wrong digest, a wrong pool, an unmodelled call, a store outside scratch, an
out-of-range read, and a `.bss` read (NOBITS has no file bytes).

## Results and limitations

- 34,918 of 34,918 cases match, all 16 negative controls are caught, and 306
  distinct paths are exercised. Each reader ok/err exit and each visitor
  accept/reject exit is reached.
- The serde_json `ErrorCode` names are an inference from the public crate's
  declaration order: 3 EofWhileParsingObject, 5 EofWhileParsingValue,
  6 ExpectedColon, 10 ExpectedSomeValue, 17 KeyMustBeAString. Only the numbers
  are observations.
- The meaning of the variants is inferred from their names and the
  `oracle.rs` location string only. The packet does not show which oracle
  record or action holds the enum.
- The string scanner, the error constructors and the lossy/free helpers are
  stubbed. Escape decoding (the `Copied` scanner result) is not exercised.
- No progress gate is requested. The `risk` component's first task (margin and
  liquidation formulas) is not advanced by this packet beyond the decoding of
  this one oracle enum.

Next question: which struct deserializers call the key readers `0x1debf40`
and `0x3f7ea60`, and does the MessagePack path for this enum share the family-3
visitors `0x54797f0`/`0x5479a10`?
