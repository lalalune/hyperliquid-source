# RE-006: node 115 book-order slab unlink

## Claim

The two 860-byte FDE bodies at `0x58dfbc0` and `0x58dff20` are the
removal twins of the shared insert-return helpers. Each one:

1. returns after writing qword `2` to the output when the index is at
   or past the slab length, or when the element qword at `+0x0` is `2`;
2. otherwise marks that element vacant, links it to the previous head,
   saturating-decrements the slab counter, and stores the removed index
   as the new head;
3. appends one event record, subtracting element `+0xe0` from the u64
   behind `r9` (a borrow calls the `l1/src/qtys/impl_sz.rs:9:1` helper
   and stores 0 when that helper returns);
4. with a null level pointer, copies the pre-removal element and writes
   flag byte 0; with a negative element qword at `+0xb0`, panics at
   `l1/src/book/level.rs:32:54`;
5. otherwise may replace the level's cached 16-byte link at `+0x20`,
   and either calls `0x4de02d0` when element byte `+0xd8` is nonzero or,
   when that byte is zero, rewires the level links under
   `l1/src/book/book_orders.rs:137:44` and `:145:44`.

The measured owner denominator is the two FDEs: 1,720 bytes. Four
direct callers are the boundary only.

## Scope

| Owner | FDE range | Bytes | SHA-256 | Role |
| --- | --- | ---: | --- | --- |
| `unlink_a` | `0x58dfbc0..0x58dff1c` | 860 | `17ab611392e3211229944efe4c965d336f193010a8682d19934ece069e26007e` | event element `0x2c8` |
| `unlink_b` | `0x58dff20..0x58e027c` | 860 | `b23cb9f94a4440655d0649d0f7b9ccbdbfd1b16594a9e7f2fe83e675e98a3d86` | event element `0x2b8` |

| Caller | FDE range | Bytes | Call site | Calls |
| --- | --- | ---: | --- | --- |
| `caller_a1` | `0x58e1400..0x58e1f34` | 2,868 | `0x58e1a8c` | `unlink_a` |
| `caller_a2` | `0x58e1f40..0x58e2a74` | 2,868 | `0x58e25cc` | `unlink_a` |
| `caller_b1` | `0x58e2a80..0x58e36c0` | 3,136 | `0x58e3174` | `unlink_b` |
| `caller_b2` | `0x58e36c0..0x58e4300` | 3,136 | `0x58e3db4` | `unlink_b` |

A whole-`.text` direct-`E8` census finds no other caller. No
`R_X86_64_RELATIVE` relocation addresses either owner entry or lands
inside the six bodies.

## Method

`tools/book_order_unlink_static.py` authenticates the node #115 capture
by size and SHA-256 before interpretation. It checks each selected
range against the decoded FDE table, re-derives every body hash, pins
71 shared instruction sites and 24 classified twin differences, and
resolves their rip-relative targets. GNU objdump 2.42 and readelf are
used only while writing the retained disassembly and frame lines; the
byte checks do not trust mnemonic text. The executable model in that
tool and in `src/node115-book-order-unlink` follows the pinned stores.
It is not a source-built copy of the body.

## Trace

1. **Vacant gate.** `cmp r14, [rsi+0x10]; jae` and `cmp` of the element
   qword with `2` share the store of qword `2` at `[rdi]` and the
   epilogue jump.
2. **Free list.** The body copies `0x108` bytes from element `+0x8`,
   then stores qword `2` at `+0x0` and the old `[rsi+0x20]` head at
   `+0x8`. `[rsi+0x18]` is a saturating decrement (`cmp 1; adc -1`).
   The removed index becomes the head.
3. **Event.** Defined stores, relative to the appended record, are
   qword `2` at `+0x0`, qword `3` at `+0x8`, element `+0xb0` at
   `+0x20`, the original `rcx` at `+0x28`, element `+0xf0` at `+0x30`,
   16 bytes from element `+0xf8` at `+0x38`, the dword at element
   `+0x108` at `+0x48`, and the byte at element `+0xd2` at `+0x4c`.
   The copy length is `0x2c8` or `0x2b8`. Other copied bytes are not
   written by this body. Equal length and capacity call the per-twin
   grow slot first.
4. **External quantity.** Element `+0xe0` is subtracted from `[r9]`.
   The borrow arm zeros the register, calls slot `0x64e4ea8`
   (`l1/src/qtys/impl_sz.rs:9:1`), and stores that zero if the helper
   returns.
5. **Level.** A null stack argument copies the saved element and writes
   flag 0 at output `+0x110`. A negative `+0xb0` uses the 43-byte
   Result unwrap message, location `0x64a3508`, and `ud2`. When the
   level dword at `+0x20` is `1` and the qword at `+0x28` is the
   removed index, 16 bytes from element `+0x10` replace level `+0x20`.
   Nonzero element `+0xd8` calls `0x4de02d0` with `rdi = level+0x50`
   and argument pair `(element+0xf0, element dword +0xdc)`; stores
   after that call are not interpreted. On the zero-byte path, level
   `+0x70` is a saturating subtract and `+0x78` a saturating decrement.
6. **Relink.** The saved tag's low bit chooses the checked index. An
   index at or past the original length, or a live low dword of `2`,
   calls the Option unwrap helper at slot `0x64df830` and jumps to
   `ud2`. The locations are `book_orders.rs:137:44` and `:145:44`. A
   zero link word writes the saved tag and the other index into the
   level; a nonzero word writes them into the checked element. The
   output flag is 0 when level byte `+0x0` is nonzero, else level byte
   `+0x10` xor 1. The `0x110`-byte copy is the pre-removal element.

## Twin difference

Both routines share the 71 pinned instruction sites. Twenty-four
instructions differ, 42 bytes in total. The differences are the frame
size (`0x418` / `0x408`) and its two stack-argument displacements, the
event size immediate (`0x2c8` / `0x2b8`, two sites), rip-relative
displacements that resolve to the same slot or location, the event grow
slots (`0x64e4f88` → `0x5962310`, `0x64e5a28` → `0x59630a0`), and the
unwind destructors (`0x5948db0` / `0x5947550`).

## Boundary

The callee at `0x4de02d0` (613 bytes), the grow helpers, the quantity
helper, the copy slot `0x64df508`, and the four caller bodies beyond
the pinned setup are not interpreted. The callers pass the slab at
`base+0x80`, `rcx = [base+0x110]`, `r9 = base+0x118`, and a stack
argument that one immediate predecessor path zeros.

## Validation

```sh
python3 tools/book_order_unlink_static.py
python3 -m unittest tests.test_book_order_unlink_static
(cd research/work-items/RE-006-node115-book-order-unlink && sha256sum -c MANIFEST.sha256)
```

The unittest regenerates the packet, rejects a corrupted vacant-tag
immediate, checks the model boundaries, and compiles
`src/node115-book-order-unlink/lib.rs` with `rustc` 1.95.0 when that
compiler is present. No node or visor code is executed.

## Results and limitations

Owner denominator: 1,720 bytes across 2 FDEs. Direct-call boundary:
12,008 bytes across 4 FDEs. These are selected extents, not coverage
of the book component. The order-book acceptance gates stay false.
There is no whole-node, source-built, or byte-equivalence claim.

## Next question

Which of the four caller FDEs decides the level pointer, and does a
nonzero element byte at `+0xd8` change the level totals after
`0x4de02d0` returns?
