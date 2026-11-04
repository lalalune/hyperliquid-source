# RE-015: node 115 format consumer 0x141e3a0 of the flag-group pointer

```text
Task: RE-015
Function: 0x141e3a0
Topic: flag-group pointer treatment in the format consumer
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 derived-byte-callee packet established that
callee `0x15ae430` hands the flag-group pointer onward twice through
slot `0x64df6e8` and left open what its target `0x141e3a0` does with
it. This packet traces exactly that question. The answer is a
non-read: the consumer never dereferences the pointer. The pointer
travels inside the third argument word, whose bit 0 the consumer
tests; the word is then forwarded verbatim as the fourth argument of
a virtual write call. What the consumer itself computes is the
capacity of a fresh 24-byte output triple, from a static template
byte stream passed as the second argument.

The "format consumer" name is an inference from three observations,
not a symbol claim: the panic message bytes at `0x456d84` read
`a formatting trait implementation returned an error when the
underlying stream did not` (86 bytes, the exact length the panic call
passes); the second argument is walked as a template of literal runs
and placeholder tags; and the write call passes a six-word table at
`0x63f3d50` whose first word is bound to a function and whose next
two words are the constants 24 and 8. The same slot binding is
recorded as a boundary by the RE-001 cache-suffix packet (which
explicitly does not establish the formatter's behaviour) and by open
RE-015 packets (as `formatter_boundary`); no merged or open packet
owns or traces this function.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| format_consumer | `0x141e3a0..0x141e538` | 408 | `aa4d4d0611c533e38c65e1577c0426b5163846c01225556743d4d4345cadd1fe` |

Measured denominator: one complete FDE, **408 bytes**, retained as a
disassembly export and pinned instruction by instruction. Cited but
not counted: three template streams in `.rodata` (2, 8 and 49 bytes,
each pinned by hash and by its decoded walk), six slot bindings, and
the six words of the table at `0x63f3d50`. The consumer is reached
only through slot `0x64df6e8` (bound to it by the single relocation
whose addend is its address): 0 direct calls, 840 `call` sites
through the slot in 586 distinct FDEs, 3 `jmp` sites through the
slot, and no occurrence of its address as data outside `.rela.dyn`.
The byte-pattern census was cross-checked against an objdump
instruction-boundary count, which agrees exactly (840 calls, 3
jumps). Exactly two of the call sites are the RE-015 chain sites
inside the derived-byte callee (`0x15ae476`, `0x15ae4f5`).

## Trace stages

1. **Tagged third argument.** The consumer saves `rdx` to `r14`,
   `rsi` (template) to `r15` and `rdi` (out) to `rbx`, then tests
   bit 0 of the third argument (`0x141e3b8`). Odd takes the inline
   path: `r12 = rdx >> 1` (`0x141e453`, `0x141e456`) joins the
   allocation stage directly, so an odd word is an inline length
   used verbatim as the capacity — no scan, no doubling. Even falls
   through to the template scan with the word carried untouched.
2. **Template scan.** A first template byte of zero takes the empty
   path (`0x141e3c2`..`0x141e3c8`). Otherwise the walk at
   `0x141e3e9` reads one token byte at a time; a zero byte ends it.
   A byte below `0x80` is a literal run: it adds its value to the
   literal length and skips that many payload bytes (`0x141e3f0`,
   `0x141e3e3`, `0x141e3e6`). The byte `0x80` is a wide literal run
   whose length is the following little-endian u16 (`0x141e3fe`).
   Any other byte (`0x81`..`0xff`) is a placeholder tag: it adds
   nothing, sets a flag iff the literal length so far is zero
   (`0x141e40d`..`0x141e414`), and skips
   `((b&1)<<2)|(b&2) + 2*(b&4 set) + 2*(b&8 set)` bytes (bit
   extraction at `0x141e417`..`0x141e445`, skips at
   `0x141e448`..`0x141e44e`).
3. **Initial-capacity rule.** At the end of the walk (`0x141e45b`):
   if the placeholder-at-zero flag is set and the literal length is
   below 16, the capacity is zeroed (`0x141e466`); otherwise the
   literal length is doubled (`0x141e46b`), and a doubled value that
   overflows into the sign bit takes the reserve-error path
   (`0x141e46e` to `0x141e50d`, error slot `0x64df498`, kind 0).
4. **Allocation and output triple.** Capacity zero skips the
   allocation and uses the pointer word 1 (`0x141e474`, `0x141e495`)
   — the dangling case. Otherwise the consumer allocates the
   capacity through slot `0x64df480` (bound to `0x6355830`,
   `0x141e47c`); a null result calls the same error slot as the
   reserve path, with kind 1 (`0x141e487`..`0x141e48f`). The triple
   `{capacity, pointer, 0}` is stored on the stack
   (`0x141e49d`..`0x141e4a5`).
5. **Virtual write call.** The consumer loads the table at
   `0x63f3d50` into `rsi` (`0x141e4ad`; words `0x141c960`, `0x18`,
   `0x8`, `0x141e8f0`, `0x141e7e0`, `0x141ed80`, function words via
   relocations), the triple address into `rdi`, the template pointer
   into `rdx`, and the saved third argument **verbatim** into `rcx`
   (`0x141e4bb`), then calls through slot `0x64df6f0` (bound to
   `0x1680500`, `0x141e4be`). On success (`al == 0`) the triple is
   copied to the out argument and returned in `rax`
   (`0x141e4c8`..`0x141e4d7`).
6. **Panic and cleanup.** A write error (`al != 0`) calls through
   slot `0x64df6a0` (bound to `0x1680c30`) with the 86-byte message
   at `0x456d84`, its length in `esi`, and location words
   `0x63f3ca0` / `0x63f3d80`, then traps (`ud2`, `0x141e50b`). The
   cleanup pad at `0x141e518` drops the local triple through slot
   `0x64df4a0` (bound to `0x635de30`) iff its first word is nonzero,
   then tail-calls `_Unwind_Resume` (`0x63f0a50`).

## Traced result

The pinned walk decodes the chain's two templates and the
template-shaped stream that immediately follows the first one's
terminator in `.rodata`:

| Template | Stream | Literal | Placeholder at zero | Capacity |
| --- | --- | ---: | --- | ---: |
| `0x43b857` (chain call 1) | `c0 00` | 0 | yes | 0 |
| `0x440e47` (chain call 2) | `c0 01 2f c0 01 2f c0 00` | 2 | yes | 0 |
| `0x43b859` (`.rodata` neighbour) | 49 bytes, `min > max, or either was NaN. min = ` + tag + `, max = ` + tag | 44 | no | 88 |

For both RE-015 chain calls the third argument is a stack address
from the callee (`&[rsp+0x10]`, `&[rsp+0x28]` in the sibling
packet): aligned, so bit 0 is clear and the scan path runs. Both
templates open with a placeholder tag, so the flag is set and both
calls build their output triple as `{0, 1, 0}` and leave all growth
to the write call. The flag-group pointer — word 1 of the first
call's arguments block, inside the 48-byte record of the second —
is forwarded untouched to `0x1680500`. **Its first actual reader is
inside the write target, not inside this consumer.** On the odd
path the same word would instead be consumed as a length, which no
chain call does.

Reproduce from the repository root:

```bash
python3 -B tools/flag_group_format_static.py
python3 -m unittest tests.test_flag_group_format_static -v
```

Format consumer `0x141e3a0` only: the tagged third argument (odd is
an inline length, even is an arguments-block pointer that is never
dereferenced here), the template literal-length scan over the second
argument, the initial-capacity rule, the allocation and dangling
cases, the virtual write call that receives the third argument
verbatim, the panic and cleanup paths, and the slot call census.
What the write target `0x1680500` computes with the arguments
pointer, what the rendered arguments mean, and the behaviour of the
other 585 FDEs that call through the same slot are NOT established
by these bytes. The flag-group pair construction is owned by the
RE-015 derived-byte-callee packet and is cited here, not re-derived.
The next question is what the write target `0x1680500` does with
the arguments pointer it receives from this consumer. No captured
code executed, no runtime value, indirect-call recovery, #94
correspondence, or reconstruction gate is claimed.
