# RE-015: node 115 write target 0x1680500 of the flag-group arguments block

```text
Task: RE-015
Function: 0x1680500
Topic: first read of the arguments block in the shared write target
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 flag-group-format packet established that
the format consumer `0x141e3a0` never dereferences its third argument
and forwards it verbatim as the fourth argument of a virtual write
call through slot `0x64df6f0`, bound to `0x1680500`, leaving what
this function does with the arguments pointer as its named next
question. The RE-014 field-adapter chain converges on the same
function: the table shim `0x168aa10` tail-jumps through the same
slot with the adapter table inserted as the second argument, and the
RE-014 byte-arm packet names how the shim's target uses the table it
is handed as an open question. This packet traces the shared target
and is filed under RE-015, whose chain posed the question first.

The answer: this function is the arguments block's first reader,
but only inside placeholder dispatch. Most of its work is a walk
over the template byte stream in the third argument: literal runs
are written through the table method at offset `+0x18`, and each
placeholder tag dispatches one 16-byte argument record — a value
word at `+0x0` and a formatter word at `+0x8` — by loading the value
word and calling through the formatter word with a 24-byte
descriptor built on the stack. The arguments pointer itself is
never dereferenced speculatively: on the scan path the template is
read first, and the block is touched only when a tag is dispatched
(or when a tag's indirection bits read a field out of a record).

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| write_target | `0x1680500..0x16806c0` | 448 | `1d04ea71bff68d24b04f11ccfc52b1341ef49aabea0b199d73e0c2f7edd43561` |

Measured denominator: one complete FDE, **448 bytes**, retained as
a disassembly export and pinned instruction by instruction. Cited
but not counted: the two chain tables' `+0x18` method words
(consumer table `0x63f3d50` → `0x141e8f0`; adapter table
`0x64078f8` → `0x1686bd0`, both FDE starts), and the single slot
binding. The target is reached only through slot `0x64df6f0` (the
sole relocation whose addend is its address): 0 direct calls or
jumps, 1,143 `call` sites through the slot in 626 distinct FDEs,
86 `jmp` sites through the slot, and no occurrence of its address
as data outside `.rela.dyn`. Sixteen further sites load the slot's
pointer into a register (`mov` at `0x1456774`, `0x16881a1`,
`0x5c4f2a3`, and thirteen more listed in `records.json`) — first-class
uses that still reach the target only through the slot. The
byte-pattern census was cross-checked against an objdump
instruction-boundary count, which agrees exactly (1,229 call/jump
references in total: 1,143 calls, 86 jumps, and the same 16 loads).
Exactly one call site is the RE-015 chain site inside the format
consumer (`0x141e4be`); exactly one jump site is the RE-014 shim's
tail jump (`0x168aa1d`).

## Trace stages

1. **Tagged fourth argument.** The target saves `rcx` to `rbx`,
   `rdx` (template) to `r13` and `rdi` (out) to `r14`, then tests
   bit 0 of the fourth argument (`0x168051a`). Odd takes the inline
   path (stage 6). Even selects the template scan with the word
   carried as the arguments-block pointer.
2. **Scan setup and literal runs.** A first template byte of zero
   returns success before the table is even saved (`0x1680523`).
   Otherwise the table is saved, the method word at table `+0x18`
   is cached (`0x1680534`), and the sequential argument index is
   zeroed (`0x168053c`). In the loop (`0x1680550`), a byte below
   `0x80` is a literal run: the cached method is called with
   `(out, payload, length)` (`0x1680575`); a byte of `0x80` is a
   wide literal run whose length is the following little-endian
   u16 (`0x16805b5`, call at `0x16805c4`). Any callee error byte
   aborts the walk with result 1; a zero byte ends it with
   result 0.
3. **Placeholder dispatch — the first read of the arguments
   block.** A tag byte (`>= 0x81`) builds a 24-byte descriptor on
   the stack: `{out, table, spec dword, field A u16, field B u16}`
   (stores at `0x1680647`..`0x168065a`). The function then reads
   the arguments block for the first time on this path: the
   selected record's value word is loaded into `rdi`
   (`0x168065e`) and the record's formatter word is called
   (`0x1680666`) with `rsi` pointing at the descriptor. An error
   byte aborts with result 1; on success the sequential index
   becomes the dispatched index plus one (`0x168066e`,
   `0x1680671`) and the walk continues.
4. **Tag field grammar.** The spec dword defaults to `0x60000020`.
   Payload bytes follow the tag in a fixed order, each present
   only when its bit is set: bit 0 replaces the spec with the
   little-endian u32 at the cursor (`0x16805e5`); bit 1 reads
   field A as a u16 (`0x168060d`); bit 2 reads field B as a u16
   (`0x16805fe`); bit 3 reads an explicit argument index as a u16
   (`0x1680624`), replacing the sequential counter for this
   dispatch. Bit 6 is never tested. Tag `0xc0` is a fast path:
   sequential index and the default spec block in one store
   (`0x16805a8`), no payload bytes.
5. **Indirection bits.** Bit 4 replaces field A with the u16 at
   `arguments[field A * 16 + 8]` (`0x1680680`); bit 5 replaces
   field B with the u16 at `arguments[field B * 16 + 8]`
   (`0x168063b`) — the low half of that record's formatter word.
   When set, these reads precede the value load of stage 3.
6. **Inline path and return contract.** On the odd path the
   length is the tagged word shifted right by one, and the target
   tail-calls the table method at `+0x18` with `(out, third
   argument, length)` (`0x168068b`..`0x16806a9`): here the third
   argument is a data pointer and the template grammar never runs.
   That method's `AL` is returned unchanged. On the scan path the
   result is a byte in `AL`: 0 iff the walk reaches the template
   terminator with no callee error, 1 on the first literal-write
   or dispatch error.

## Traced result

Both RE-015 chain calls arrive with an even fourth argument (an
aligned stack address), so both take the scan path over the
templates the flag-group-format packet decoded:

| Chain call | Template | Walk |
| --- | --- | --- |
| 1 (`0x43b857`) | `c0 00` | one dispatch: record 0, default spec block |
| 2 (`0x440e47`) | `c0 01 2f c0 01 2f c0 00` | dispatch record 0, write `/`, dispatch record 1, write `/`, dispatch record 2 |

For chain call 1 the arguments block is the callee's pair record at
`&[rsp+0x10]` (construction owned by the RE-015 derived-byte-callee
packet, cited not re-derived): record 0's value word is the
flag-group pointer itself and its formatter word is the pair's
global word `0x16035e0`, an FDE start. So the flag-group pointer
reaches this function as a record value, is loaded at `0x168065e`,
and is passed in `rdi` to that formatter — this function loads it
but still never dereferences it; its first dereference is inside
the formatter it dispatches to. For chain call 2 the block is the
callee's 48-byte constructed record — three records whose formatter
words are `0x1500960`, `0x1598e40` and `0x150ce90` (all FDE starts)
— and the two `/` runs are written through the consumer table's
`+0x18` method `0x141e8f0`. Through the RE-014 adapter table the
same function's `+0x18` method is `0x1686bd0`, which is the only
table word this function ever reads.

Reproduce from the repository root:

```bash
python3 -B tools/flag_group_write_static.py
python3 -m unittest tests.test_flag_group_write_static -v
```

Write target `0x1680500` only: the tagged fourth argument (odd is
an inline length for a single literal write of the third argument
through the table method at +0x18; even is the arguments-block
pointer), the template token scan over the third argument, the
16-byte argument records (value word at +0, formatter word at
+0x8), the tag field grammar and the two indirection bits, the
24-byte descriptor built for each formatter call, the sequential
argument counter rule, and the byte-sized error contract in AL.
What the table method at +0x18 computes, what any argument
formatter computes with the value word and the descriptor, what the
descriptor fields mean to a formatter, and the behaviour of the
other callers that reach this function through the same slot are
NOT established by these bytes. The flag-group arguments-block
construction is owned by the RE-015 derived-byte-callee packet, the
template and tagged-word forwarding by the RE-015 flag-group-format
packet, and the adapter-table shim tail call by the RE-014
field-adapter-table-shim packet; all three are cited here, not
re-derived. The next question is what the record-0 formatter
`0x16035e0` computes with the flag-group pointer it receives as its
value argument. No captured code executed, no runtime value,
indirect-call recovery, #94 correspondence, or reconstruction gate
is claimed.
