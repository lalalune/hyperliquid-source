# RE-006: node 115 twin callers' use of the forwarded slab slot index

## Claim

The RE-006 ring-append twins (`0x5911890` / `0x5911b30`) return the
shared insert routines' result -- the pre-insert slab head, i.e. the
index of the slab slot that received the order copy. A whole-`.text`
census finds exactly four direct `E8` call sites into the twins, one
in each of four insert-order FDE bodies. This packet traces what
each of the four callers does with the returned index, from the call
site to the capture register's first reassignment. In all four
callers the answer is the same:

1. **Capture.** The instruction after the call moves `rax` into a
   callee-saved register: `r15` in the two A-side callers, `r12` in
   the two B-side callers.
2. **Forward 1.** The `rax` copy is moved to `rcx` and passed as the
   fourth argument of a direct call to `0x4eeed90`, before anything
   else can clobber `rax`. The other arguments are a frame record
   pointer in `rdi`, a book-side pointer in `rsi`, and a frame qword
   in `rdx`.
3. **Forward 2.** After a preparatory call and a lookup call, the
   captured register is moved to `rsi` and passed as the second
   argument of a direct call to `0x51d1b00`, whose first argument is
   the lookup result plus `0x40`.
4. **No store.** Between the twin call and the reassignment, no
   instruction stores the value to memory -- neither to a heap
   structure nor to a frame slot -- and neither `rax` nor the
   capture register is ever pushed. A whole-window operand scan
   over each decoded body pins this: the only reads of `rax` are
   the capture and forward-1 moves, and the only reads of the
   capture register are the forward-2 move (plus, in the B-side
   callers, the excluded block below).
5. **Reassignment.** The capture register is then overwritten with
   an unrelated value (`mov r15, [rsp+0xc8]` in the A-side callers,
   `mov r12, r13` in the B-side callers) and holds other values for
   the rest of the body.

So at this level the forwarded index is **insert-path-local**: the
callers themselves turn it into no durable handle. Any durable use
would have to be created inside the two boundary callees.

**Excluded block (B-side callers only).** In address order the
B-side windows contain one more read of the capture register: a
`test r12, r12` / `jle` guard over a call through slot `0x64df4a0`
(bound to `0x635de30`) with `rdi = r13`, `rsi = r12`, `rdx = 0`.
That block is *not* a use of the returned index. Its only direct
branch predecessor inside the body is a conditional jump that
precedes the twin call site, and the instruction immediately
before the block is an unrelated unconditional jump, so there is
no fall-through entry and no path from the twin call into the
block. On that arm the register holds the arm's own size-like
guard operand for the slot call. The block, its predecessor, and
the slot binding are pinned so the exclusion is checked, not
assumed.

## Scope

| Owner | FDE range | Bytes | SHA-256 | Twin call site | Capture |
| --- | --- | ---: | --- | --- | --- |
| `caller_1` | `0x5901dd0..0x5905ce9` | 16,153 | `69712a6423044cdfd8b9a5ddf17ffa1a7c6346381471234df8aa587d04e4b2c6` | `0x5903fab` | `r15` |
| `caller_2` | `0x5905cf0..0x5909b21` | 15,921 | `41b6ea3b11ca2a035f22bfa7703cb11ca5a623eb0a3970740b0193580a649e84` | `0x5908216` | `r12` |
| `caller_3` | `0x5909b30..0x590da49` | 16,153 | `368701b152fa985ad4852bfa862db2edefb73b7c15f5c425be49a1e259f6ecc4` | `0x590bd0b` | `r15` |
| `caller_4` | `0x590da50..0x5911881` | 15,921 | `17d3fe719c2fc2a12be204c26a182231920e632f81aabf26844f48acf6374bd2` | `0x590ff76` | `r12` |

The measured denominator is the four complete caller FDEs: 64,148
bytes. Each caller body is pinned whole by SHA-256; the retained
disassembly exports cover the traced windows around the call site,
the second forward, and (B-side) the excluded block, since the full
bodies exceed the export bound. The twins are the boundary: their
bodies and return contract are established by the ring-append and
shared-insert-return packets and are cited here, not re-derived.
The forward callees (`0x4eeed90`, `0x51d1b00`), the preparatory
callees (`0x4dc5eb0` / `0x4dc18a0`), the lookup callees
(`0x4da81b0` / `0x4da7880`), and the excluded block's slot callee
(`0x635de30`) are recorded by address only.

## Method

`tools/twin_caller_index_use_static.py` authenticates the whole
node 115 capture by size and SHA-256 before generation. Analysis
derives all six FDE ranges from the FDE extents, re-derives every
body hash, scans the whole `.text` for direct `E8`/`E9` references
to the twins, confirms no relative relocation reaches any of the
six bodies or is held inside one, pins every flow instruction
byte-exactly (each validated as a native instruction start during
generation), and runs operand-level window scans over each decoded
caller body: the `rax` read set up to the first forward, the
capture-register read set and store/push absence up to the first
reassignment, the reassignment's first-write position, and -- for
the B-side callers -- the excluded block's complete direct
predecessor set.

## Trace

1. **Call and capture.** Each caller executes its single twin call
   (`caller_1`/`caller_3` to twin A, `caller_2`/`caller_4` to
   twin B) and captures `rax` in the next instruction.
2. **Forward 1.** Within five instructions, `mov rcx, rax` feeds a
   direct call to `0x4eeed90`. In the A-side callers the remaining
   arguments are set up after the twin call (`rdi` = frame record
   at `rsp+0x300`, `rsi` = `r12`, `rdx` = `[rsp+0x90]`); in the
   B-side callers likewise (`rdi` = frame record at `rsp+0x240`,
   `rsi` = `rbx`, `rdx` = `[rsp+0xa8]`).
3. **Forward 2.** A preparatory call (`0x4dc5eb0` A-side /
   `0x4dc18a0` B-side; it receives no index argument) and a lookup
   call (`0x4da81b0` A-side / `0x4da7880` B-side) run on the
   converged continuation. The lookup result is incremented by
   `0x40` into `rdi`, the captured index is moved into `rsi`, and
   `0x51d1b00` is called.
4. **Death of the value.** The capture register's next write is
   its reassignment (A-side `0x59041a2` / `0x590bf02`, B-side
   `0x59085aa` / `0x591030a`); after it, every read of the register
   in the body refers to the new value. The index is not returned
   to the caller's caller either: `rax` is clobbered by the first
   forward's call and is never reloaded from the capture register.
5. **Excluded B-side block.** See the Claim: pinned and excluded
   by its sole pre-call predecessor (`0x5907e88` in `caller_2`,
   `0x590fbe8` in `caller_4`).

## Boundary

The packet ends at the four caller bodies' flow windows and the
two forwards. What `0x4eeed90` does with the index it receives in
`rcx`, what `0x51d1b00` does with the index in `rsi`, the internals
of the preparatory and lookup callees, and the rest of each
caller's body (order parsing, error arms, drops) are not
established here. The twins' return contract is the
shared-insert-return packet's result, cited as a boundary.

## Next question

What do the two forward callees do with the index -- does either
of them write it into a durable structure (an order record field,
a level field, a map), making it a durable order handle one level
down, or is it consumed inside the insert path there too?

## Validation

```sh
python3 tools/twin_caller_index_use_static.py
python3 -m unittest tests.test_twin_caller_index_use_static
sha256sum -c MANIFEST.sha256  # run in this directory
```

The test regenerates the packet into a temporary directory and
requires byte identity with the retained files, checks the flow
facts for all four callers (capture registers, forward targets,
read sets, empty store set, verdicts, the B-side exclusions), the
classification model on its cases, and mutates eight pinned bytes
or records -- the capture move, the first forward's call
displacement, the second forward's move, a reassignment, a twin
call opcode (census), and the excluded block's predecessor
displacement -- requiring `analyze` to reject each mutation.
