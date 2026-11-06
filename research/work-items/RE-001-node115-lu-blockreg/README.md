# RE-001: the node #115 lu block register — count, flag, handoff

Packet #236's next question: what `0x63d94b0` does with the gate
block it receives as second argument from the driver, and whether
it is an alternate entry of the `0x63d94a0` completion helper.

Short answer: it is **not** an alternate entry — `0x63d94a0` is its
own 12-byte FDE, a getter for the list anchor — and `0x63d94b0`
itself **registers** the block: it counts the block into a table
entry chosen by a three-way dispatch on `[block+0x68]`, sets the
block's processed flag (`[block+0x24] := 1`), and hands the block
to a helper (`0x63d8790`, cited only) when the block's flag byte
says so. For a block exactly as the consume helper stamped it
(#236), the net effect is: zero-path counter bump, totals bump,
`0x63d8790` handoff, return. The block is not freed, not moved,
and not an arena slice.

## The two FDEs

- `0x63d94a0..0x63d94ac` (12 bytes, `.eh_frame`-confirmed): the
  anchor getter. `endbr64; mov 0x1498(%rdi),%rax; ret` — it
  returns `[first-arg+0x1498]`, the same anchor pointer the
  splice path below uses. It contains no jump into `0x63d94b0`,
  and `0x63d94b0` starts with its own `endbr64`. They are
  adjacent, separate functions — not two entries of one.
- `0x63d94b0..0x63d96db` (555 bytes, `.eh_frame`-confirmed,
  single `ret` at `0x63d95fe`, `int3` padding to `0x63d96e0`).
  Three internal calls (`0x63e8bf0`, `0x63d8790`, `0x63d88d0`,
  all cited only); every branch target lies inside the FDE.
  No return value is established by these bytes.

## Entry contract

- `rdi` = first-argument object (saved in `rbp`). At the driver
  call site it is `driver-context+0x140` (cited only); at the
  single-shot call site it is that caller's first argument
  (cited only).
- `rsi` = block pointer (saved in `rbx`): the gate's stamped
  block. At the driver site the value passed is `rbx` after a
  `sub` adjustment (cited only); it is dereferenced as a block
  throughout, so it is a block pointer, not a length.

## Entry and dispatch

1. `[block+0x24] := 1` (byte), immediately, on every path.
2. `rax = [block+0x68]`. If `0`, take the zero path (step 5).
   If `0x200`, take the `0x200` path (step 4). Otherwise take
   the main path (step 3).

## Main path

3. `rdi = [block+0x60] << 12`; call `0x63e8bf0` (cited only).
   If the result exceeds `0x7000000000000000`, the table slot
   is the fixed offset `0x2970` (overflow stub, verified by
   rel32, not exhibited). Otherwise a size-class index is
   computed from the result: bit position via `bsr`, clamped
   to a minimum of 14, with 2 bits extracted from the shifted
   value; the entry is at
   `first-arg + 0x420 + 48 * index + align`, where
   `align = (-[block+0x10] byte) & 0x18`. Then:
   - `[entry] += 1`
   - `[entry+8] += [block+0x68]`
   - `[entry+0x10] += [block+0xb0] - [block+0x68]`
   - `[first-arg+0x408] += 1`
   - `[first-arg+0x410] += [block+0x68]`
   - `[first-arg+0x418] += [block+0xb0] - [block+0x68]`
   (the `+0x418` store itself happens in the shared tail.)

## The 0x200 path

4. A 16-byte `.rodata` constant at `0x450b10` (qwords `1` and
   `2`) is added to the entry at `first-arg+0x1020+align` and
   to the `[first-arg+0x408]` pair, i.e. `[entry] += 1`,
   `[entry+8] += 2`, `[first-arg+0x408] += 1`,
   `[first-arg+0x410] += 2`. Then
   `[entry+0x10] += [block+0xb0] - 0x200` and
   `[first-arg+0x418] += [block+0xb0] - 0x200`. Control joins
   the shared tail at the `[block+0x11]` test.

## The zero path

5. Entry at `first-arg+0x1050+align`:
   `[entry] += 1`, `[entry+0x10] += [block+0xb0]`,
   `[first-arg+0x408] += 1`, `[first-arg+0x418] += [block+0xb0]`.
   No `[entry+8]` or `[first-arg+0x410]` write on this path.
   Control jumps to the shared tail.

## Shared tail

6. `[first-arg+0x418] := rsi` (the accumulated value from
   whichever path ran).
7. If `[block+0x11] != 0`, call `0x63d8790(first-arg, block)`
   (cited only). If `[block+0x13] != 0`, call
   `0x63d88d0(first-arg, block)` (cited only).
8. If `[block+0x14] == 0`, return. Otherwise splice the block
   into the doubly-linked list anchored at
   `[first-arg+0x1498]` via its `+0x50`/`+0x58` links
   (`[block+0x20] := 1` first; when the anchor is empty the
   block becomes the anchor, self-linked; otherwise the block
   is spliced after the anchor node and the anchor pointer is
   unchanged — the sentinel reading of the anchor is inference,
   the pointer writes are bytes). Then return.

## What this means for a consume-stamped block

For a block exactly as #236 stamped it (`[block+0x10]` dword
`0x100`, `[block+0x60] = 0x200`, `[block+0x68] = 0`,
`[block+0xb0] = 0`, flag bytes `+0x14`/`+0x24` zero):

- `[block+0x68] == 0` selects the zero path; the
  `[block+0x10]` byte is `0x00`, so `align = 0`; the entry is
  `first-arg+0x1050`, bumped by 1, with a `+0` sum add.
- `[first-arg+0x408] += 1`; `[first-arg+0x418] += 0`.
- `[block+0x11] = 0x01` (the second byte of the `0x100`
  dword), so `0x63d8790(first-arg, block)` **is** called.
- `[block+0x13] = 0x00`, so `0x63d88d0` is **not** called.
- `[block+0x14] = 0x00`, so the list splice is **not** taken.
- Plus the entry flag: `[block+0x24] := 1`.

So after the driver passes the gate block on, the block is
counted (one entry bump, one totals bump), marked processed,
and handed to `0x63d8790`. It is not freed, unlinked, or
converted into anything else here. The splice path and the
`0x63d88d0` call exist for blocks whose flag bytes other
writers have set — no such writer is decoded here.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d94a0..0x63d94ac` and `pc=0x63d94b0..0x63d96db`);
  `int3` padding `0x63d94ac..0x63d94b0` and
  `0x63d96db..0x63d96e0`. Static analysis only; the binary
  was never executed.
- 6 exhibits, 502 bytes, 112 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab + mnemonic;
  objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `cm_anchor` | `0x63d94a0..0x63d94ac` | 12 | 3 | Anchor getter: endbr64, mov, ret |
| `cm_entry` | `0x63d94b0..0x63d94dd` | 45 | 12 | Entry, arg saves, flag `:= 1`, dispatch |
| `cm_main` | `0x63d94dd..0x63d958b` | 174 | 40 | Size call, size-class index, bucket accounting |
| `cm_tail` | `0x63d958b..0x63d95ff` | 116 | 29 | Flag tests, list splice, epilogue, ret |
| `cm_200` | `0x63d9600..0x63d9664` | 100 | 18 | `0x200`-path pair add, sum add, tail join |
| `cm_zero` | `0x63d9690..0x63d96c7` | 55 | 10 | Zero-path counter bump, tail jump |

- The overflow stub (`0x63d96d0..0x63d96db`: `mov $0x2970`,
  `jmp 0x63d9548`) and the helper-call sites (`0x63d966a`,
  `0x63d967f`) are verified by rel32 in the static verifier,
  not exhibited, to keep the packet at 18 files.
- Census: direct `E8` call sites to `0x63d94b0`: 2. Direct
  `E9` jump sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63d94b0`: 0 of 60,723
  entries. E8: `0x63b8c1d` (single-shot caller FDE, #232;
  same arg shape, first-arg and block), `0x63b8f1a`
  (driver FDE, #234; `rdi` = driver-context+0x140).
  Internal calls within the FDE: 3 (`0x63e8bf0`,
  `0x63d8790`, `0x63d88d0`). Internal jump targets: all lie
  inside `0x63d94b0..0x63d96db`. Single `ret` at `0x63d95fe`.
  The anchor getter's own census: 9 direct `E8` sites (each
  confirmed by objdump/rel32), 0 `E9`, 0 `LEA`, 0 GOT.
- Disjointness: this FDE and the anchor getter overlap no
  claimed range from packets #183–#236 and no other
  contributor's topic, addresses, or tables. The driver, the
  single-shot caller, the gate, the allocator thunk, and the
  three helpers are cited by address, not claimed here.

## Corrections to earlier packets

- **#236 confirmed and completed.** Its consume step's block
  is this function's second argument; the gate's `+0xe0`/
  `+0xe8` bookkeeping stays gate-side, and this function only
  counts, flags, and hands the block on.
- **#235 confirmed and completed.** The gate is called by the
  driver and the single-shot caller, and both callers call
  this function too — the single-shot site `0x63b8c1d` is new
  here (it refines #235's caller picture for this function).
- **#234 confirmed and completed.** The driver's gate-block
  handoff is this FDE: the block is counted and flagged here,
  then passed to `0x63d8790`.
- **#233 confirmed.** The loop caller is not involved with
  this function; its callers are the driver and the
  single-shot caller only.
- **#232 confirmed and refined.** The single-shot caller
  reaches this function directly (site `0x63b8c1d`), not only
  through the gate.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- The identities and semantics of `0x63e8bf0` (size mapping),
  `0x63d8790` (the flag-gated handoff), and `0x63d88d0`
  (the second flag-gated handoff): what they do with
  (first-arg, block).
- What the table entries at `first-arg+0x420...`,
  `+0x1020`, `+0x1050`, and the totals at `+0x408`/`+0x410`/
  `+0x418` count in domain terms — the arithmetic is proven,
  the domain meaning is not.
- Which writers set `[block+0x68] = 0x200`, `[block+0x13]`,
  or `[block+0x14]` to nonzero, i.e. which blocks take the
  `0x200` path, the `0x63d88d0` call, or the list splice.
- Whether `[first-arg+0x1498]` is a sentinel node or a plain
  head pointer; only the pointer writes are proven.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.

## Next question (#238)

Decode `0x63d8790` end to end: what it does with the
(first-arg, block) pair it receives whenever `[block+0x11]`
is nonzero — which, for every consume-stamped block, is always
— and whether it consumes, queues, or further transforms the
counted block.

## Verification

- `tools/node115_lu_blockreg.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict
  counts, FDE bounds, single `ret`, key stores and call
  rel32s, rodata constant, full census (target and anchor
  getter), branch targets internal, neighbour disjointness,
  MANIFEST coverage (17 entries).
- `tests/test_node115_lu_blockreg.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
