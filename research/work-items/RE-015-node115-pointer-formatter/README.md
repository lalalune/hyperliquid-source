# RE-015: node 115 pointer formatter 0x15eadd0 of the flag-group chain

```text
Task: RE-015
Function: 0x15eadd0
Topic: what the pointer formatter does with the pointer to the flag-group pointer
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 record-0-formatter packet established
that the record-0 formatter `0x16035e0` never dereferences the
flag-group pointer: it stores the value word on its stack, builds
one record whose value word is the *address of that stored word*
and whose formatter word is `0x15eadd0`, and re-enters the write
target with template `c0 00`. This packet traces the formatter
that receives the value one indirection deeper — a pointer to
the word holding the flag-group pointer.

The answer: this is where the flag-group pointer is finally
dereferenced — exactly once, at its first byte. The formatter
loads the flag-group pointer from its value argument and reads
the byte at flag-group offset `+0x0`, then uses that byte as an
unchecked index into two `.rodata` tables — a qword length
table at `0x457fc0` and a relative-pointer table at `0x46a838` —
whose four established entries select a byte string:
`0 → "Error"` (5 bytes), `1 → "Warn"` (4), `2 → "Info"` (4),
`3 → "Debug"` (5). It reads only the descriptor's out and table
words, loads the method word at table `+0x18`, and tail-jumps to
that method with `(out, selected pointer, selected length)`. The
descriptor's spec dword and fields are never read. It builds no
record, dispatches no further formatter, and writes nothing to
out itself; the tail-called method performs the write and its
`AL` is the function's result.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| pointer_formatter | `0x15eadd0..0x15eadff` | 47 | `4e4d3a1a67401cbceb6f4bdb72d100eca0676a13fa66f9c82f73f1a6d8d8aec3` |

Measured denominator: one complete FDE, **47 bytes**, retained
as a disassembly export and pinned instruction by instruction.
Cited but not counted: the two lookup tables (length table at
`0x457fc0`, relative-pointer table at `0x46a838`) and the four
selected strings, each read and pinned at its selected length;
the chain's consumer table method binding (`.rela.dyn` slot
`0x63f3d68` → `0x141e8f0`), cited from the flag-group-write-target
packet.

Reference census: the formatter's address is materialised
exactly once in the whole binary, by the rip-relative `lea` at
`0x16035f0` inside the record-0 formatter
(`0x16035e0..0x160361a`), which stores it as the nested record's
formatter word (construction owned by the RE-015
record-0-formatter packet, cited not re-derived). No
`.rela.dyn` entry has `0x15eadd0` as its addend — no GOT slot
binds it; there are no direct `call`/`jmp` instructions to it,
no indirect calls through any slot, and no occurrence of its
address as data anywhere in the file. The formatter is reachable
only as that one record's formatter word, dispatched by the
write target (`0x1680500`, owned by the RE-015
flag-group-write-target packet).

## Trace stages

1. **Value load.** The first instruction loads the flag-group
   pointer from the value argument: `mov rax, [rdi]`
   (`0x15eadd0`). The value word the record-0 formatter stored on
   its stack is consumed here as an address for the first time
   in the chain.
2. **First byte load.** `movzx eax, byte [rax]` (`0x15eadd3`)
   reads the byte at flag-group offset `+0x0`. This is the first
   dereference of the flag-group pointer itself by any function
   in the chain — accessor, large consumer, derived-byte callee,
   format consumer, write target, and record-0 formatter all
   forwarded it without loading through it. Only this one byte
   is read; no other word or bit of the flag group is touched.
3. **Length lookup.** `lea rcx, [0x457fc0]` (`0x15eadd6`) and
   `mov rdx, [rcx+rax*8]` (`0x15eaddd`) load the qword length
   entry for the byte. The index is unchecked — no compare or
   bounds test exists anywhere in the body.
4. **Pointer lookup.** `lea rcx, [0x46a838]` (`0x15eade1`),
   `movsxd rax, [rcx+rax*4]` (`0x15eade8`) and `add rax, rcx`
   (`0x15eadec`) compute the selected string pointer as the
   table base plus the sign-extended dword entry for the byte.
5. **Established selection.** Reading both tables and the
   selected bytes at their selected lengths pins four entries:
   index 0 → pointer `0x46a5c4`, length 5, `"Error"`; index 1 →
   `0x459e50`, 4, `"Warn"`; index 2 → `0x45a19c`, 4, `"Info"`;
   index 3 → `0x46a5c9`, 5, `"Debug"`. Entries past index 3 are
   NOT established as part of either table: the length table's
   fifth qword is already the bytes of an unrelated string
   constant (`"RefCell already mutually borrowed…"`), and the
   pointer table's later dwords belong to adjacent data, so the
   tables' established extent is exactly four entries.
6. **Descriptor reads and tail call.** From the descriptor
   pointer in `rsi` it reads `out` at `+0x0` into `rdi`
   (`0x15eadef`) and `table` at `+0x8` into `rcx` (`0x15eadf2`),
   then loads the method word `rcx = [rcx+0x18]` (`0x15eadf6`) —
   the same table method slot the write target itself reads.
   The spec dword at `+0x10` and the field A/B u16s at
   `+0x14`/`+0x16` are never read. It moves the selected pointer
   into `rsi` (`0x15eadfa`) and tail-jumps through the method
   (`jmp rcx`, `0x15eadfd`) with `(rdi = out, rsi = selected
   pointer, rdx = selected length)`; the fourth argument
   register holds the method's own address at the jump, an
   artefact of loading the target through `rcx`. The function
   has no return instruction of its own: the method's `AL` is
   its result. For the chain's consumer table (`0x63f3d50`) the
   method word is bound by `.rela.dyn` slot `0x63f3d68` to
   `0x141e8f0` (cited from the write-target packet).

## Traced result

Composing the chain: the write target dispatches the record-0
formatter's single record, passing it a pointer to the stack
word that holds the flag-group pointer. This formatter performs
the chain's first and only dereference of the flag-group
pointer: it reads the flag group's first byte and emits, through
the descriptor table's write method, the one byte string that
byte selects — one of the four level names `"Error"`, `"Warn"`,
`"Info"`, `"Debug"` for byte values 0–3. No further formatter
follows; the chain's format walk for record 0 ends at this
selection. Which of the four names a given chain call emits is
decided entirely by that first byte — whose value on the chain
call is a property of whoever writes the block the pair record
points at, not of any formatter.

Reproduce from the repository root:

```bash
python3 -B tools/pointer_formatter_static.py
python3 -m unittest tests.test_pointer_formatter_static -v
```

Pointer formatter `0x15eadd0` only: the two loads that
dereference the pointer-to-pointer value argument (the
flag-group pointer loaded from [rdi] at `0x15eadd0` and the flag
group's first byte loaded at `0x15eadd3` — the first dereference
of the flag-group pointer itself in the chain), the unchecked
indexing of the two .rodata tables (the qword length table at
`0x457fc0` and the relative-pointer table at `0x46a838`) whose
four established entries select the byte strings
Error/Warn/Info/Debug, the two descriptor words it reads (out at
+0x0 and table at +0x8; the spec dword and field A/B are never
read), the method word it loads from table +0x18, and the tail
jump through that method with (out, selected pointer, selected
length). Which byte value the flag group's first byte actually
holds on the chain call — who writes that byte of the block the
derived-byte callee's pair record points at — and what the table
method at +0x18 computes are NOT established by these bytes: the
descriptor construction is owned by the RE-015
flag-group-write-target packet, the pair-block construction by
the RE-015 derived-byte-callee packet, and the method binding
for the chain's consumer table (slot `0x63f3d68` → `0x141e8f0`)
is cited from the write-target packet, not re-derived. Entries
of either table past index 3 are NOT established: the body
performs no bounds check, and the bytes that follow the length
table's fourth entry are an unrelated string constant. The next
question is what value the flag group's first byte takes on the
chain call — who writes that byte — and so which of the four
names the chain's record-0 dispatch emits; the table method at
+0x18 (`0x141e8f0` for the chain's consumer table) and its write
behaviour are the other open end. No captured code executed, no
runtime value, indirect-call recovery, #94 correspondence, or
reconstruction gate is claimed.
