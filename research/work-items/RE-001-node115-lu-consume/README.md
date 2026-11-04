# RE-001: the node #115 lu consume helper — stamp, header, zeroed block

## Summary

Packet #235's next question: what the consume helper at `0x63ba600`
does with the allocator block and the cursor value it receives, and
how that explains the gate's `+0xe0`/`+0xe8` bookkeeping — does the
gate hand out arena slices, or merely register blocks against a
cursor?

It is a single FDE, `0x63ba600..0x63ba672` (114 bytes, single `ret`
at `0x63ba671`, zero `call` instructions, zero branches). It takes
a freshly allocated block and two words, and initializes the block
in place: it stamps the cursor value and the counter value into the
first two words, writes a fixed header (`0x100` at `+0x10`,
`0x200` at `+0x60` from a `.rodata` constant), zeroes the flag
words and the whole tail, and returns. It allocates nothing, calls
nothing, and moves no cursor itself.

The answer to #235's question is therefore the second option, with
a precision: the gate **registers** each fresh block against its
current cursor — the block's first word is the cursor value — but
the block itself is **not** an arena slice. The block comes from
the allocator thunk (`0x636b370`, called by the gate with
`(first-arg, [context+0xf0], 0xf8, 0x40)`), and the cursor value
is never passed to the allocator. All cursor arithmetic
(`+0x200000` advance, `+0xe0`/`+0xe8` update, drain zeroing)
happens in the gate around the call, not here. This helper only
stamps the block the gate already holds.

## Entry contract

Arguments: `rdi` = block pointer (the gate's fresh `0xf8`-byte
allocation), `rsi` = cursor value (`[context+0xe0]` at the call),
`rdx` = counter value (`[context+0xf8]`, the old value — the
gate stores `old + 1` back to `[context+0xf8]` before the call,
but `rdx` itself still holds the old value, so the block is
stamped with the pre-increment counter).

No return value is established by these bytes: `rax` is never
written in the FDE, and both gate call sites keep using the
registers they saved before the call (`rbp`/`rax` holding the
block pointer). The block pointer is an input, not an output.

## Block layout after the call

The block is `0xf8` bytes, exactly the gate's allocator size
argument. Every write in the FDE, in order:

| Offset | Value | How |
|---|---|---|
| `+0x00` | cursor (arg `rsi`) | `mov %rsi,(%rdi)` |
| `+0x08` | counter (arg `rdx`, old) | `mov %rdx,0x8(%rdi)` |
| `+0x10` | `0x100` (dword) | `movl $0x100,0x10(%rdi)` |
| `+0x14` | `0` (byte) | `movb $0x0,0x14(%rdi)` |
| `+0x18..+0x1f` | untouched | no store |
| `+0x20` | `0` (dword) | `movl $0x0,0x20(%rdi)` |
| `+0x24` | `0` (byte) | `movb $0x0,0x24(%rdi)` |
| `+0x28..+0x5f` | untouched | no store |
| `+0x60` | `0x200` (qword) | `movdqa` from `.rodata 0x453a60` |
| `+0x68` | `0` (qword) | second half of the same 16-byte constant |
| `+0x70..+0xaf` | `0` | `movups %xmm1` (`xmm1` zeroed by `pxor`) |
| `+0xb0` | `0` (qword) | explicit `movq $0x0,0xb0(%rdi)` |
| `+0xb8..+0xf7` | `0` | `movups %xmm1` |

Two details worth stating exactly. First, the `+0xb0` zero is
written explicitly because the `movups` run skips it: the run
covers `+0x60`, `+0x70`, `+0x80`, `+0x90`, `+0xa0`, then jumps
to `+0xb8` — `+0xb0` is the one 8-byte hole in the zeroed tail,
closed by its own store. Second, the `+0x60` constant is a
16-byte `.rodata` value at `0x453a60` (`00 02 00 00 ...`, i.e.
qwords `0x200` and `0`); the helper does not compute it.

## What this decides about the gate's bookkeeping

On the gate's main path, `[context+0xe0]` advances by
`0x200000` and `[context+0xe8]` retreats by the same amount
after this call, so consecutive blocks are stamped with cursor
values `c`, `c + 0x200000`, `c + 0x400000`, ... — a per-block
sequence number in cursor units, not a pointer into the block.
On the drain path (`[context+0xe8] == 0x200000` at entry) the
gate zeroes both words after the call, so the next call takes
the setup path again. None of that arithmetic is in this FDE:
the helper's only contribution to the bookkeeping is stamping
the current pair `(cursor, counter)` into the block header.

Whether `[context+0xe0]` is an address cursor or a byte count
is still not decided by these bytes — the helper stores it
verbatim either way — but the slice reading is now excluded:
the block's memory is allocator memory, addressed by the block
pointer, not by the cursor.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63ba600..0x63ba672`); the following bytes
  `0x63ba672..0x63ba680` are `int3` padding and the next
  function starts with `endbr64` at `0x63ba680`. Static
  analysis only; the binary was never executed.
- 3 exhibits, 114 bytes, 20 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `cs_entry` | `0x63ba600..0x63ba61e` | 30 | 6 | Entry, constant load, cursor/counter stores, `0x100` |
| `cs_flags` | `0x63ba61e..0x63ba638` | 26 | 4 | Flag zeros, `+0xb0` zero |
| `cs_zero` | `0x63ba638..0x63ba672` | 58 | 10 | `+0x60` constant store, zeroed tail, `ret` |

- Census: direct `E8` call sites to `0x63ba600`: 2. Direct `E9` jump
  sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63ba600`: 0 of 60,723 entries.
  E8: `0x63b86bc` (gate main path: `rdi` = alloc, `rsi` =
  `[context+0xe0]`, `rdx` = `[context+0xf8]` old),
  `0x63b87b9` (gate drain path: same arg shape). Internal calls
  within the FDE: 0. Internal jump targets: none (no branches).
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#235 and no other contributor's topic, addresses, or
  tables. The only `63ba6` mentions in the merged tree are
  citations of the neighbouring `0x63ba680` value-compute helper
  (packet #232, cited only) — a different function starting 16
  bytes after this FDE ends. The gate FDE, the driver FDE, the
  allocator thunk, and the resolver/release helpers are cited by
  address, not claimed here.

## Corrections to earlier packets

- **#235 confirmed and completed.** Its consume step is this FDE:
  the block argument is the gate's fresh `0xf8`-byte allocator
  block, the cursor argument is `[context+0xe0]`, and the
  counter argument is `[context+0xf8]` (old value). The gate's
  `+0xe0`/`+0xe8` bookkeeping is gate-side; this helper only
  stamps the block.
- **#234 confirmed.** The driver's gate call is the same gate
  whose two paths call this helper; the block the driver passes
  to `0x63d94b0` is the stamped block built here.
- **#233 confirmed.** The loop caller is not involved with this
  helper; the gate is called by the driver and the single-shot
  caller only.
- **#232 confirmed.** The single-shot caller reaches this helper
  only through the gate (site `0x63b8bdc` calls the gate, not
  this helper).
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this helper never calls it.

## Unresolved

- The meaning of the fixed header words (`+0x10 = 0x100`,
  `+0x60 = 0x200`): size, capacity, version, or tag — the bytes
  state the constants, not their semantics.
- What fills the untouched gaps (`+0x18`, `+0x28..+0x5f`) and
  when: later passes (the driver hands the block to `0x63d94b0`,
  cited only) may write them, but no writer is decoded here.
- Who reads `[block]` (cursor) and `[block+8]` (counter) after
  the gate returns the block, and what the counter orders.
- Whether `[context+0xe0]` is an address cursor or a byte
  count; only its `+= 0x200000` arithmetic (gate-side) and its
  verbatim stamp here are proven.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#237)

Decode `0x63d94b0` end to end: what it does with the gate block
it receives as second argument from the driver, and whether it
is an alternate entry of the `0x63d94a0` completion helper —
this decides what the stamped block built here becomes after the
driver passes it on.

## Verification

- `tools/node115_lu_consume.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, single `ret`, zero calls, zero branches, key stores
  and call rel32s, rodata constant, full census, neighbour
  disjointness, MANIFEST coverage (11 entries).
- `tests/test_node115_lu_consume.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7165 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
