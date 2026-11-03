# RE-015: node 115 record-0 formatter 0x16035e0 of the flag-group chain

```text
Task: RE-015
Function: 0x16035e0
Topic: what the record-0 formatter does with the flag-group pointer value
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 flag-group-write-target packet established
that the write target `0x1680500` loads the flag-group pointer as
record 0's value word and passes it in `rdi` to this formatter,
leaving as its named next question what the formatter computes with
that value. This packet traces the formatter end to end.

The answer: it computes nothing with the value at all. The
formatter is a one-record adapter. It stores the value word on its
own stack without dereferencing it, builds a single argument
record whose value word is the *address of that stored word* and
whose formatter word is `0x15eadd0`, and re-enters the same write
target through slot `0x64df6f0` with the same two-byte template
(`c0 00`, at `0x43b857`) that the format consumer used for chain
call 1, forwarding the descriptor's out and table words unchanged.
The descriptor's spec dword and fields are never read. The
flag-group pointer therefore reaches the next formatter one
indirection deeper — as a pointer to the word holding it — and
its first dereference is deferred once more.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| record0_formatter | `0x16035e0..0x160361a` | 58 | `a764351ae22010d7b789b2e29e7cd777f9b08cd34c585b6a8062c073f1db36d5` |

Measured denominator: one complete FDE, **58 bytes**, retained as
a disassembly export and pinned instruction by instruction. Cited
but not counted: the two slot bindings (formatter slot
`0x64e1490` → `0x16035e0`; write-target slot `0x64df6f0` →
`0x1680500`), the two template bytes at `0x43b857`, and the next
formatter's FDE (`0x15eadd0..0x15eadff`, 47 bytes).

Reference census: the formatter's address is materialised exactly
once in the whole binary. `.rela.dyn` contains exactly one entry
whose addend is `0x16035e0` — the GOT slot `0x64e1490` — and no
static argument record in `.data.rel.ro` names it as a formatter
word. In `.text` exactly one instruction references that slot:
the load at `0x15ae459` inside the derived-byte callee
(`0x15ae430..0x15ae5ae`), which stores the loaded word at
`0x15ae460` as record 0's formatter word of the pair block it
constructs (construction owned by the RE-015 derived-byte-callee
packet, cited not re-derived). There are no direct `call`/`jmp`
instructions to the formatter, no indirect calls through its
slot, no `lea` computing its address, and no occurrence of its
address as data outside `.rela.dyn`. The formatter is reachable
only as record 0's formatter word in that one constructed block,
dispatched by the write target (`0x1680500`, owned by the RE-015
flag-group-write-target packet).

## Trace stages

1. **Frame and value store.** The function reserves 24 stack
   bytes (`0x16035e0`) and stores its first argument — the value
   word, the flag-group pointer on the chain call — at `[rsp]`
   (`0x16035e4`). That store is the only use of the value: no
   instruction in the body loads from the value as an address, so
   the flag-group pointer is not dereferenced here.
2. **One-record block.** It builds a single 16-byte argument
   record at `[rsp+0x8]`: the record's value word is `rsp` itself
   — the address of the stored value word (`0x16035e8`,
   `0x16035eb`) — and its formatter word is `0x15eadd0`,
   materialised by a rip-relative `lea` (`0x16035f0`) and stored
   (`0x16035f7`). No relocation slot binds `0x15eadd0`; the address
   exists only as this lea target.
3. **Descriptor reads.** From the descriptor pointer in `rsi` it
   reads exactly two words: `out` at `+0x0` into `rdi`
   (`0x16035fc`) and `table` at `+0x8` into `rsi` (`0x16035ff`).
   The spec dword at `+0x10` and the field A/B u16s at
   `+0x14`/`+0x16` are never read, so they cannot influence this
   formatter's behaviour; the nested dispatch re-derives its spec
   from the template's `0xc0` fast path (default spec block,
   per the write-target packet).
4. **Nested write-target call.** It loads the template pointer
   `0x43b857` into `rdx` (`0x1603603`) — the same two-byte stream
   `c0 00` (SHA-256 `e9aff84f…4998`) the flag-group-format packet
   decoded for chain call 1: one default-spec dispatch of record 0,
   then the terminator — and the block pointer `rsp+0x8` into
   `rcx` (`0x160360a`). The block pointer is even, so the write
   target takes its scan path. The call goes through slot
   `0x64df6f0` (`0x160360f`), bound to `0x1680500`.
5. **Return contract.** No instruction between the call and the
   return touches `rax`: the frame is released (`0x1603615`) and
   the function returns (`0x1603619`) with the nested call's `AL`
   unchanged — 0 iff the nested walk reached its terminator with
   no callee error, per the write target's contract. The formatter
   writes nothing to `out` itself; all output is produced by the
   nested walk.

## Traced result

Composing the chain: the write target dispatches record 0 of the
callee's pair block, passing the flag-group pointer to this
formatter as a plain value. This formatter wraps it once more —
the nested walk dispatches its single record, loading as the
record's value word the address of the stack slot that holds the
flag-group pointer, and calls the next formatter `0x15eadd0` with
that address in `rdi`. So after two formatter hops the value the
chain's formatters receive is a pointer *to* the flag-group
pointer, and no function traced so far — accessor, large consumer,
derived-byte callee, format consumer, write target, or this
formatter — has dereferenced the flag-group pointer itself. Which
word or bit of the flag group is read first is a property of
`0x15eadd0`, not of any function in the chain up to here.

Reproduce from the repository root:

```bash
python3 -B tools/record0_formatter_static.py
python3 -m unittest tests.test_record0_formatter_static -v
```

Record-0 formatter `0x16035e0` only: the 24-byte stack frame it
builds (the value word stored at +0x0 and the single argument
record at +0x8 whose value word is the address of that stored word
and whose formatter word is `0x15eadd0`), the two descriptor words
it reads (out at +0x0 and table at +0x8; the spec dword and field
A/B are never read), the single nested call it makes to the write
target `0x1680500` through slot `0x64df6f0` with the two-byte
template at `0x43b857`, and the byte-sized contract that the
nested call's AL is returned unchanged. What the next formatter
`0x15eadd0` computes with the pointer to the stored value word,
and what the write target does with the record, are NOT
established by these bytes: the write target is owned by the
RE-015 flag-group-write-target packet, the arguments-block
construction that pairs this formatter with the flag-group
pointer by the RE-015 derived-byte-callee packet, and the
template forwarding by the RE-015 flag-group-format packet; all
three are cited here, not re-derived. The next question is what
the formatter `0x15eadd0` (FDE `0x15eadd0..0x15eadff`) computes
with the pointer to the flag-group pointer it receives as its
value argument — in particular whether it finally dereferences
it, and which word or bit it reads first. No captured code
executed, no runtime value, indirect-call recovery, #94
correspondence, or reconstruction gate is claimed.
