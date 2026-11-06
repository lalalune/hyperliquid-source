# RE-010: internally tagged Action content visitor, map and seq forms (node #115)

With this packet the step in front of the MessagePack `Action` variant dispatch can
be rebuilt as code: how node #115 turns a msgpack map or array into
`(variant index, buffered Content)` before it knows the variant. That covers the
`type` tag lookup, duplicate and missing `type`, the cautious 16,384-pair
pre-allocation, the remaining-entry count write-back, every error exit, and every
exception landing pad. The reconstruction is the pure `Model` class in the tool.
The tool runs the original bytes of all six copies over 3,989 cases (callees
scripted, the binary never executed) and shows 0 mismatches.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `a1a8d5431`; `references/can1357-hl` was not used
- Claim status: observation (control flow, constants, call arguments, result bytes,
  call-site tables and landing pads, all proved by running the original bytes against
  the reconstruction); inference (the serde names `TaggedContentVisitor`,
  `TagOrContent`, `Content::Map`, `size_hint::cautious`, `missing_field`,
  `duplicate_field`, and that the tag field is `type`)
- Scope included: the full bodies of the three `visit_map` copies 0x1fb1750,
  0x3952ed0 and 0x5687260 (1230 B each) and the three `visit_seq` copies 0x1fb1d20,
  0x39535e0 and 0x5687730 (294 B each), including the LSDA call-site table of each
  map copy. Scope excluded: callee bodies (the key reader 0x1a7e1a0 and its copies,
  the value reader 0x17fb290, the seq-rest reader 0x21e1c10, the error formatter
  0x18be120, the drops, and the allocator), all stubbed by contract. The Action
  identifier decoders 0x1af3b70 / 0x328bc70 / 0x48cccb0 are the subject of the
  RE-010 action-msgpack-identifier work and are only called here.

## Reproduce

```
python3 tools/re010_tagged_content_visitor_115.py --out research/work-items/RE-010-tagged-content-visitor-115
python3 -m unittest tests.test_re010_tagged_content_visitor_115
cd research/work-items/RE-010-tagged-content-visitor-115 && sha256sum -c MANIFEST.sha256
```

Only the Python 3 standard library and the shared `tools/elf_index.py` and
`tools/fde_extents.py` parsers are used. No external program is called, and the
binary is never executed. The tool checks the input SHA-256 first, then writes
`functions.tsv call_sites.tsv cases.tsv coverage.tsv mutants.tsv summary.json`. It
exits non-zero if any case mismatches, any wrong model survives, or any image
mutant survives. A full run takes about 93 s. Two runs with different
`PYTHONHASHSEED`/`TZ` gave byte-identical output.

## Evidence

All addresses are virtual addresses in the `.text` of node #115. File offsets are
derived through the section headers, and NOBITS sections are excluded.

How the six functions were found: an `e8 rel32` scan of `.text` for calls into the
three Action identifier decoder copies, grouped by FDE extent, gives exactly these
six functions. Each 1230 B body calls one decoder copy plus a key reader; each
294 B body calls one decoder copy. A repo search found these addresses only as
call-census rows (RE-001 `callers.tsv`), and no open or merged PR names them.

Facts read from the bytes and checked by `Fn` (`functions.tsv`, `call_sites.tsv`):

- FDE extent, the `sub rsp` frame (0x108 / 0x58), and the LSDA pointer of each copy.
  The map copies have a 15-row call-site table. The seq copies have no LSDA.
- Every call site is bound to a role by its offset in the function. Copies of the
  same form are required to match the anchor instruction by instruction (except
  `call`/`lea`/`callr` displacements), and to have the same relative call-site table.
- The five GOT slots resolve through `R_X86_64_RELATIVE`: alloc 0x6355830,
  handle_alloc_error 0x141e264, dealloc 0x635de30, the in-cleanup panic
  0x1680cab, and the vec grow 0x16a06c0. The resume call is the `_Unwind_Resume`
  PLT stub (checked through `.rela.plt`).
- Each copy loads the format pieces 0x4325c4 (missing field) and, for map, 0x43351a
  (duplicate field), plus its own `<str as Display>::fmt` copy (0x24a7c50,
  0x46dd7f0, 0x5616320) as `rip`-relative `lea` operands.

Human-readable excerpt (objdump; not part of the generated evidence) of the
visit_map head of 0x1fb1750:

```
1fb176e: mov ebx,[rdx+8] ; cmp ebx,0x4000 ; mov r13d,0x4000 ; cmovb r13d,ebx   # cautious capacity
1fb1781: test ebx,ebx ; je 1fb195e                                              # empty map -> missing field
1fb178c: shl r15d,6 ; call [alloc]                                              # 64-byte (Content, Content) pairs
1fb17cf: dec ebx ; mov r14b,0x5c                                                # remaining count, tag = None
1fb1834: mov [rax+8],ebx ; ... ; mov r8d,1 ; call 1a7e1a0                       # write back count, read key
1fb187f: cmp ecx,0x16 ; je tag ; cmp ecx,0x17 ; je end                          # TagOrContent::Tag / end of map
1fb1920: cmp r14b,0x5c ; jne duplicate ; ... ; mov edx,1 ; call 1af3b70         # read the tag value
1fb1a41: mov [out+8],r14b ; mov byte [out+0x10],0x15 ; ... ; mov qword [out],0  # Ok((tag, Content::Map(vec)))
```

### Reconstructed behaviour (`Model.visit_map`, `Model.visit_seq`)

`visit_map(out, visitor = {name_ptr, name_len}, access = {des, remaining: u32})`:

1. `remaining == 0`: the result is `Err(missing_field(name))`. The formatter is
   called with the pieces 0x4325c4 and the `&str` (name_ptr, name_len). Then the
   empty vec (cap 0, dangling 8, len 0) is dropped through the vec drop callee.
   Nothing is read.
2. Otherwise allocate `min(remaining, 0x4000) * 64` bytes. On a null return,
   `handle_alloc_error(8, size)` is called, which does not return.
3. Loop, with `tag = 0x5c` (None) at the start. Before each key read, the count
   left after this entry (`remaining - 1 - k`) is written back to `access+8`. Then the
   key reader is called as `(dst, des, name_ptr, name_len, r8 = 1)`. Its 40-byte
   result is read as: dword 1 = Err; otherwise byte +8 is 0x16 (the key is the tag),
   0x17 (no more keys), or any other value (a buffered Content key, 32 bytes at +8).
   - Tag key while a tag is already held: `Err(duplicate_field(name))` (pieces 0x43351a).
   - Tag key otherwise: identifier decoder `(dst, des, edx = 1)`. Byte 0 == 9 is Ok,
     and byte 1 is the variant index that is kept (an index of 0x5c still means "no tag").
     Any other byte 0 gives `Err(32 result bytes)`.
   - Content key: the value reader `(dst, des)`. Dword 1 = Err: drop the key, Err.
     Otherwise push `(key32, value32)`, calling the grow callee first when
     `len == cap`. Growth is reachable only after more than 16,384 pairs.
   - The loop ends after the count is used up, or at the 0x17 key.
4. After the loop, no tag gives `Err(missing_field(name))` and then the vec drop
   callee. Otherwise the result is `Ok`: qword 0 at +0, the tag byte at +8, 0x15
   (`Content::Map`) at +0x10, and `cap, ptr, len` at +0x18/+0x20/+0x28. Bytes
   +0x11..+0x17 are seven bytes copied from uninitialised stack padding (the model
   marks them as the stack fill).
5. Error exits (key/value/identifier Err, duplicate) store `Err` at +0 = 1 and 32
   bytes at +8, and then drop the pairs in place. For each pair the key Content is
   dropped, then the value Content (callee 0x230ce30). The buffer is then freed with
   `dealloc(ptr, cap * 64, 0)` when `cap != 0`.

`visit_seq(out, visitor, access)`: `remaining == 0` gives missing field. Otherwise the
count is written back as `remaining - 1` and the identifier decoder is called. On Err,
the 32 result bytes are returned. Index 0x5c gives missing field. Otherwise the rest
reader `(dst, access)` is called. A nonzero byte 0 gives Err with bytes +8..+0x28.
Otherwise the result is `Ok`: tag at +8, seven padding bytes, and the 32-byte
Content at +0x10.

Exception paths (map only, from the LSDA, and reproduced by the model's `unwind`
and `drop_rest`):

| call site | landing pad | cleanup before `_Unwind_Resume` |
| --- | --- | --- |
| alloc +0x43 | none (no call-site row) | personality terminates |
| key read +0xfd, identifier +0x1e7 | +0x45b | vec drop callee |
| value read +0x16c | +0x44c | drop the pending key (0x21d8eb0), then the vec drop callee |
| grow +0x1bc | +0x437 | drop the pending pair (0x21d6020), then the vec drop callee |
| missing/duplicate formatter, key drop after value Err | +0x435 | vec drop callee |
| key drop in the error loop +0x3df | +0x46e | drop that pair's value, then the remaining pairs (0x22faae0), then free |
| value drop in the error loop +0x3ec | +0x482 | the remaining pairs, then free |
| vec drop callee +0x296, free, handle_alloc_error, resume | row with no pad | unwinds out |
| any drop inside a landing pad | +0x446/+0x468/+0x47c/+0x4c8 | in-cleanup panic 0x1680cab (abort) |

## Implementation and comparison

The reconstruction is `Model` (about 200 lines) in
`tools/re010_tagged_content_visitor_115.py`. A Rust implementation is not yet
implemented. The original bytes are interpreted by a fixed-pattern x86-64 subset
decoder/interpreter: mov/movzx/lea/ALU/shl/cmov/movups/movaps/jcc/call/ret plus
multi-byte nop. The interpreter is the same subset used by the merged-path RE-010
packets, with `shl` and `nop` added.

Callee contracts are scripted by the case:

- The key reader returns the next event: a tag, end, a Content key with its value
  result, or a key Err. The Ok dword knob is 0 or 2.
- The identifier returns Ok with an index, or an Err blob.
- The formatter writes a SHA-256 stream keyed by the pieces address.
- Allocation can fail.
- Growth doubles (minimum 4) into a new heap block.
- Drops record what they are given: Content bytes, pair hashes, and vec cap/ptr/len.
- Any call ordinal can unwind. The unwinder uses the bytes' own LSDA call-site
  table and jumps to the landing pad with the exception object in `rax`.

The compared outcome is: how the run ended (`ret`, `resume`, `escape`, `terminate`,
`alloc_error`, `no_call_site`), the 64-byte `out`, the full callee sequence with
semantic arguments, the count left at `access+8`, and a hash of the buffered pairs
on Ok.

Cases (`cases.tsv`, one row each): 1,100 seeded map runs (count 0 / small /
0x4000 / 0x4001 / 2^31 / 2^32-1, name lengths 0/4/9, every key-head class, allocation
failure every 61st run), 240 seq runs (identifier indices including 0x5c, 0x5d
and 0xff, and rest-reader flags 0/1/0x80/0xff), an exception at every callee ordinal
of every 6th run plus up to two second exceptions inside the pads, and three runs with
16,386 entries (one tag, 16,385 pairs) that reach the grow path: a normal return, an
unwind out of grow, and a second exception in the grow pad, which ends in the in-cleanup abort.

## Results and limitations

`summary.json`:

| copy | form | instructions covered | jcc both ways | mismatches |
| --- | --- | --- | --- | --- |
| 0x1fb1750 | map | 258/260 | 14/16 | 0 |
| 0x3952ed0 | map | 258/260 | 14/16 | 0 |
| 0x5687260 | map | 258/260 | 14/16 | 0 |
| 0x1fb1d20 | seq | 74/74 | 4/4 | 0 |
| 0x39535e0 | seq | 74/74 | 4/4 | 0 |
| 0x5687730 | seq | 74/74 | 4/4 | 0 |

Outcome kinds over the 3,989 cases: alloc_error 17, escape 859, no_call_site 176, resume 756, ret 1,324, terminate 857.

Not executed in the anchor copies: 0x1fb17db, 0x1fb1917. Both are alignment nops (`0f 1f`) that the loop entry and the tag arm jump over.

- The two `jcc` that run one way only are the `test rsi,rsi; je` skip-free tests at
  +0x3ff (error exit) and +0x4ad (landing pad). They are never taken because these exits
  are reached only after a successful allocation, so `cap >= 1`. A capacity of 0 exists
  only when the count is 0, and that takes the missing-field path before any allocation.
  The model keeps the `cap != 0` test as written.
- Wrong models (`mutants.tsv`): 9/9 killed: capacity 0x8000, no
  count write-back, duplicate tag allowed, empty map read anyway, Err keeps the
  pairs, value Err keeps the key, landing pad skips the vec drop, seq treats 0x5c
  as a variant, padding bytes zeroed.
- Image mutants: one bit of every immediate (bit 8 for immediates of 0x100 or more,
  so `cmp $0x4000` becomes 0x4100 instead of the equivalent 0x4001) and the
  condition of every `jcc` in both anchor copies: killed 46, rejected_fault 10, rejected_static 2 of 58 (none survived).
- Limits: callees are contracts, not reconstructions. The key reader's result
  layout is known only as far as these functions read it (the dword-1 Err test and
  the 0x16/0x17 heads). The seven padding bytes in each Ok result are stack bytes,
  not part of the value. The name `type` comes from the visitor argument and is
  not read here. No progress gate is requested.

Next question: the key reader 0x1a7e1a0 (and its two copies) decides `TagOrContent`
by comparing the key with the visitor's name. Which byte comparison does it use, and
does its Content buffer share the value reader 0x17fb290's layout?
