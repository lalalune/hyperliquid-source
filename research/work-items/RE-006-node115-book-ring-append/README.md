# RE-006: node 115 book insert-path ring append

## Claim

The two 663-byte FDE bodies at `0x5911890` and `0x5911b30` are twin
instantiations of one insert-path helper. Each one:

1. sign-tests the order qword at `+0xb0` and panics with
   ``called `Result::unwrap()` on an `Err` value`` at
   `l1/src/book/level.rs:32:54` when the sign bit is set;
2. derives a signed key from that qword — negated when the order side
   byte at `+0xd2` is zero, unchanged when it is nonzero — and selects
   the 32-byte book half at `book + 0xa8 + side * 32`;
3. splits on the order dword at `+0xd8`. Only the `== 1` arm appends:
   it writes one 32-byte element into the level ring
   {capacity `+0x30`, buffer `+0x38`, head `+0x40`, length `+0x48`} at
   index `(head + length) mod capacity`, growing the ring first when
   `length == capacity`. The other arm never appends; it only calls
   the shared insert routine and, when the level byte at `+0x20` is
   clear, sets that byte and caches the routine result at `+0x28` —
   the same `+0x28` qword the append arm later writes as element
   field 0.

Both arms return the shared insert routine's result. The twins differ
only in rip-relative displacements and in three per-twin callees (key
construction, level lookup, shared routine); all 63 pinned exact
instruction sites and all branch targets are identical.

## Scope

| Owner | FDE range | Bytes | SHA-256 | Role |
| --- | --- | ---: | --- | --- |
| `ring_append_a` | `0x5911890..0x5911b27` | 663 | `08e8b4239e731ee50d74c945e5fe6ae3f8e18d12a5ee8c6ab8725363260558b6` | append/registration twin A |
| `ring_append_b` | `0x5911b30..0x5911dc7` | 663 | `cecc9282e700d4433aa077e63b65b50eaa287b16d6de32964b7bbb743f5b3223` | append/registration twin B |

The measured denominator is the two complete owner FDEs: 1,326 bytes.
The four caller FDEs below are the boundary: each contains exactly one
direct `E8` call site into one twin, a whole-`.text` census finds no
other callers, and no `R_X86_64_RELATIVE` relocation references any of
the six bodies.

| Caller | FDE range | Bytes | Call site | Calls |
| --- | --- | ---: | --- | --- |
| `insert_caller_1` | `0x5901dd0..0x5905ce9` | 16,153 | `0x5903fab` | `ring_append_a` |
| `insert_caller_2` | `0x5905cf0..0x5909b21` | 15,921 | `0x5908216` | `ring_append_b` |
| `insert_caller_3` | `0x5909b30..0x590da49` | 16,153 | `0x590bd0b` | `ring_append_a` |
| `insert_caller_4` | `0x590da50..0x5911881` | 15,921 | `0x590ff76` | `ring_append_b` |

## Method

`tools/book_ring_append_static.py` authenticates the whole node 115
capture by size and SHA-256 before generation. Analysis derives both owner
ranges and all four caller ranges from the FDE extents, re-derives
every body hash, scans the whole `.text` for direct `E8` callers,
confirms no relative relocation reaches any of the six bodies, parses
both `core::panic::Location` records from their relative relocations,
and pins 85 instruction sites per owner (63 exact instruction byte
strings plus 22 resolved branch/call/slot/lea targets), each validated
as a native instruction start during generation.

## Trace

1. **Entry guard.** `mov rax, [rsi+0xb0]; test rax, rax; js` reaches
   the panic block at owner `+0x259`, which loads the 43-byte message
   at `0x91f9eb`, the unnamed argument record at `0x64a35e0`, and the
   Location record at `0x64a3508`
   (`l1/src/book/level.rs`, line 32, column 54), then calls the panic
   format routine through slot `0x64df6a0` and traps with `ud2`.
2. **Signed key.** The byte at order `+0xd2` is loaded with `movzx`;
   `mov rdx, rax; neg rdx; test ecx, ecx; cmovne rdx, rax` yields the
   value itself for a nonzero side byte and its negation for a zero
   side byte. The same byte, shifted left by 5, selects the book half
   at `book + 0xa8 + side * 32`. The key construction callee
   (`0x4dc42f0` / twin `0x4dc52b0`) builds the lookup object on the
   stack, the lookup callee (`0x4da5f90` / `0x4da7010`) returns the
   level handle in `r14`, and the shared level operation `0x518e690`
   runs on it before the split.
3. **Arm split.** `cmp dword ptr [r12+0xd8], 1; jne` sends every
   non-1 value to the registration arm at owner `+0x108`.
4. **Registration arm (dword != 1).** The 0x110-byte order is copied
   through slot `0x64df508`, and the shared insert routine
   (`0x58df360` / `0x58df790`) is called on `book + 0x80` with a
   pushed zero as its extra stack argument. If the level byte at
   `+0x20` is nonzero the arm returns the routine result unchanged.
   Otherwise it stores 1 at `+0x20`, stores the result at `+0x28`,
   and returns it. This arm contains no ring store.
5. **Append arm (dword == 1).** A 0x20-byte tagged record
   {1, `[order+0xf0]`, `[order+0xdc]`, `[order+0xdc]`, 2} is built on
   the stack and passed to the derivation callees `0x4dce580` and
   `0x4e188f0`. The arm flag qword is 1 when the second callee returns
   nonzero, else the qword already at level `+0x20`. The order is
   copied again (0x110 bytes) and the shared routine is called with
   the cached qword at level `+0x28` and the flag qword as stack
   arguments. A `#[track_caller]` call to `0x4dbe910` follows with
   `level + 0x50`, the qword at order `+0xf0`, the dword at order
   `+0xdc`, and the routine result, attributed to
   `l1/src/book/book/impl_insert_order.rs:537:45`; its own result is
   discarded. The copied order bytes are patched at `+4` with the
   third argument's qword and at `+12` with its dword at `+8`.
6. **Ring append.** With `rcx = [level+0x30]` (capacity) and
   `rax = [level+0x48]` (length): when `rax == rcx` the grow helper
   behind slot `0x64e27a8` runs on the ring fields at `+0x30` first.
   Length is stored back incremented by one. The slot index is
   `head + length` reduced by one conditional subtraction of capacity
   (`cmovae`), i.e. `(head + length) mod capacity` under the ring
   invariant `head, length < capacity`. The 32-byte element written
   at `[level+0x38] + index * 32` is: the cached qword from level
   `+0x28` at `+0`, the dword from order `+0xdc` at `+8`, and the 16
   patched copy bytes at `+12`. The arm returns the shared routine
   result, forwarded in `rbx`.

## Boundary

The packet ends at the two owner bodies and their four pinned call
sites. The key construction, lookup, level operation, derivation,
track-caller, grow, and shared insert callees are recorded by address
only; their internals, the source-level order type distinguished by
the `+0xd8` dword, and the meaning of the unnamed panic argument
record at `0x64a35e0` are not established here. The caller FDEs are
themselves insert-order functions (their panic locations name
`l1/src/book/book/impl_insert_order.rs`) but their bodies are not
traced in this packet.

## Next question

What does the shared insert routine (`0x58df360` / `0x58df790`)
return, given that the registration arm caches that value at level
`+0x28` and the append arm later writes the cached value as element
field 0 of every appended record?

## Validation

```sh
python3 tools/book_ring_append_static.py
python3 -m unittest tests.test_book_ring_append_static
sha256sum -c MANIFEST.sha256  # run in this directory
```

The test regenerates the packet into a temporary directory and
requires byte identity with the retained files, checks the signed key
rule on both side-byte cases including the `i64::MIN` wrap, checks the
append index against `% capacity` for every
`head, length < capacity <= 200`, and mutates eight pinned bytes or
records — the guarded field displacement, the `cmovne` opcode, the
arm split immediate, the order copy size, the element size shift, the
panic message, the panic location line, and one caller `E8` opcode —
requiring `analyze` to reject each mutation.
