# RE-015: node 115 descriptor table method 0x141e8f0 of the flag-group chain

```text
Task: RE-015
Function: 0x141e8f0
Topic: what the descriptor table method at +0x18 does with (out, string pointer, length)
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 pointer-formatter packet established
that the formatter `0x15eadd0` dereferences the flag-group
pointer, selects one of the four level names
(`"Error"`/`"Warn"`/`"Info"`/`"Debug"`) by the group's first
byte, and tail-jumps through the method word at its descriptor
table `+0x18` with `(out, selected pointer, selected length)` —
the write itself, and the formatter's result byte, belong to
that method. For the chain's consumer table the method is
`0x141e8f0`. This packet traces the method end to end and proves
the binding from data.

The answer: the method is a byte-append writer over a 24-byte
out header — capacity at `+0x0`, buffer pointer at `+0x8`,
length at `+0x10`. It compares the requested length against
`capacity - length`; on a fit it copies the bytes verbatim to
`buffer + length` through the `.got` slot bound to `memcpy`,
advances the stored length, and returns 0. When the bytes do
not fit it first calls a grow function with `(out, current
length, requested length)` — the string pointer is saved across
that call and never passed to it — then reloads the length word
and performs the same copy with no second capacity check. A
zero-length request skips the copy and still returns 0. The
body's only store to the out structure is the advanced length
at `+0x10`. So the level name the formatter selects is appended
at the out buffer's current end, and the formatter's result
byte is this method's 0.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| table_method | `0x141e8f0..0x141e951` | 97 | `cca62c47ceefd6b3d4ae5288e6a18da83949305483fcd284be4e52b1c701f712` |

Measured denominator: one complete FDE, **97 bytes**, retained
as a disassembly export and pinned instruction by instruction.
Cited but not counted: the consumer descriptor table at
`0x63f3d50` (32 bytes in `.data.rel.ro`, its four words read and
its two relocations pinned), the `memcpy` `.got` slot binding,
and two boundary FDEs — the grow callee `0x141c980..0x141c9f2`
(114 bytes) and the table's `+0x0` word target
`0x141c960..0x141c975` (21 bytes) — each hash-pinned in
`records.json` with its frame records.

The table binding, from data: the consumer table at
`0x63f3d50` holds four qwords. The `+0x8` and `+0x10` words are
link-time constants stored in the file (`0x18` and `8`, no
relocation). The `+0x0` and `+0x18` words are zero in the file
and are filled at load by `R_X86_64_RELATIVE` relocations whose
addends are `0x141c960` and `0x141e8f0` — the method word is the
relocation at slot `0x63f3d68` (table `+0x18`). No runtime code
initialises the table: across all of `.rela.dyn` exactly one
slot carries the method as its addend, and in `.text` the table
is referenced only by two `lea` instructions (at `0x141e4ad`,
inside the consumer `0x141e3a0`, and at `0x141ed86`, inside the
19-byte thunk `0x141ed80` that forwards to the write target
through slot `0x64df6f0`), both address loads; the method's own
address and its slot's address are referenced by no
rip-relative instruction, there are no direct `call`/`jmp`
instructions to the method, and its address occurs nowhere as
data outside the one relocation addend. The method is reached
only by loading the word at a descriptor's table `+0x18` — by
the write target for its literal writes and its formatter
dispatches, and by formatters such as `0x15eadd0` tail-jumping
through it.

## Trace stages

1. **Argument saves.** `mov rbx, rdx` (`0x141e8fb`) holds the
   requested length and `mov r14, rdi` (`0x141e8fe`) holds the
   out pointer in callee-saved registers for the whole body;
   the string pointer stays in `rsi`.
2. **Capacity check.** `mov rax, [rdi]` (`0x141e901`) loads the
   capacity word at out `+0x0` and `mov r15, [rdi+0x10]`
   (`0x141e904`) the length word at out `+0x10`;
   `sub rax, r15` (`0x141e908`) computes the remaining space
   and `cmp rdx, rax` / `ja 0x141e937` (`0x141e90b`/`0x141e90e`)
   diverts to the grow path exactly when the requested length
   exceeds the remaining space — an exact fit takes the fast
   path.
3. **Zero-length skip.** `test rbx, rbx` / `je 0x141e925`
   (`0x141e910`/`0x141e913`): a zero-length request performs no
   copy and falls into the length store with an unchanged
   length.
4. **The copy.** `mov rdi, [r14+0x8]` (`0x141e915`) loads the
   buffer pointer and `add rdi, r15` (`0x141e919`) forms the
   destination `buffer + length`; `mov rdx, rbx` (`0x141e91c`)
   restores the count. The string pointer in `rsi` has never
   been rewritten on this path, so the call
   `call qword ptr [rip + 0x50c0be3]` (`0x141e91f`) through
   `.got` slot `0x64df508` — bound by an `R_X86_64_GLOB_DAT`
   relocation to the dynamic symbol `memcpy` — receives
   `(buffer + length, string pointer, requested length)`: the
   selected bytes are copied verbatim to the buffer's current
   end, with no transformation, prefix or terminator.
5. **Length store and return.** `add r15, rbx` (`0x141e925`)
   advances the length and `mov [r14+0x10], r15` (`0x141e928`)
   stores it back — the body's only store to the out
   structure. `xor eax, eax` (`0x141e92c`) makes the return
   byte 0 on every path; the function then returns (`ret` at
   `0x141e936`). This 0 is the byte the pointer formatter's
   tail jump returns as its own result, and the 0 the write
   target's error contract treats as success.
6. **Grow path.** At `0x141e937`: `mov rdi, r14` (out),
   `mov r12, rsi` (`0x141e93a`) saves the string pointer,
   `mov rsi, r15` (`0x141e93d`) passes the current length and
   `mov rdx, rbx` (`0x141e940`) the requested length into the
   direct call `call 0x141c980` (`0x141e943`). The grow callee
   never receives the string pointer or its bytes. On return,
   `mov rsi, r12` (`0x141e948`) restores the string pointer,
   `mov r15, [r14+0x10]` (`0x141e94b`) reloads the length word,
   and `jmp 0x141e915` (`0x141e94f`) rejoins the copy — with no
   second capacity check, so the copy trusts the grow to have
   made room. The grow's own body (how it recomputes capacity
   and replaces the buffer) is a boundary: its FDE and body
   hash are pinned, its internals are not traced.

## Traced result

Composing the chain: the write target's table method — the
same function its inline path tail-jumps to for literal bytes
such as the `/` runs of the RE-015 flag-group-format packet —
is a plain append into a growable byte buffer. The pointer
formatter's selected level name therefore lands verbatim at
the current end of the descriptor's out buffer, the out
length advances by the name's length (5 for `"Error"` and
`"Debug"`, 4 for `"Warn"` and `"Info"`), and the dispatch's
result byte is 0. Nothing else is written: no separator, no
terminator, no record framing is added by this method, and no
further formatter or method follows it on this path — the
chain's format walk for record 0 ends with the name appended
to the out buffer. What the out buffer's owner does with the
accumulated bytes afterwards is outside this packet.

Reproduce from the repository root:

```bash
python3 -B tools/table_method_static.py
python3 -m unittest tests.test_table_method_static -v
```

Descriptor table method `0x141e8f0` only: the capacity/length
check against the out words (+0x0 capacity, +0x8 buffer
pointer, +0x10 length), the verbatim byte copy through the
`.got` memcpy slot (0x64df508), the single length store back to
out +0x10, the always-zero return byte, and the slow path that
saves the string pointer, calls the grow boundary (0x141c980)
with (out, current length, requested length) and rejoins the
copy without re-checking capacity; plus the consumer table
binding at 0x63f3d50, whose +0x18 word is zero in the file and
filled at load by the binary's only R_X86_64_RELATIVE
relocation carrying the method as addend (slot 0x63f3d68). The
grow callee's body, the table word +0x0 function (0x141c960),
the two lea sites' containing bodies, the out structure's
construction and lifetime, and every other descriptor table's
method are NOT traced: the grow is recorded as a boundary FDE
with its call site and argument registers only, since it never
receives the string pointer. No captured code executed, no
runtime value, indirect-call recovery beyond the pinned table
word, #94 correspondence, or reconstruction gate is claimed.
