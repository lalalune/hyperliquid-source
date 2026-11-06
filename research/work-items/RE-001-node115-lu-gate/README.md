# RE-001: the node #115 lu gate — lock, arena cursor, flag byte, block return

## Question

Packet #234's next question: what the gate at `0x63b85f0` checks in
`(first-arg, [context+0x38], size, flag-byte-ptr)`, why a zero return
stops the driver after round 2, and whether it can set the flag byte
itself — this decides what stands between the driver's second and
third tranches.

## Answer

The gate is a single FDE, `0x63b85f0..0x63b8820` (560 bytes, single
`ret` at `0x63b8709`). Under a lock on the context object it
maintains a (cursor, remaining) pair at `+0xe0`/`+0xe8`, hands out
one allocator block per call, and returns that block — or NULL on
any failure. It **can** set the flag byte: it writes `0` to it
after acquiring the lock, and `1` on every failure path, so a
caller that reads the byte sees `0` exactly when the gate
succeeded. The driver itself, however, branches only on the
return value: a NULL return jumps straight to its epilogue,
skipping the round-3 loop call, and the accumulated count is what
comes back.

One surprise: the gate **never reads its size argument**. The
incoming `rdx` is overwritten on both paths (`0xf8` on the main
path, `0x200000` on the setup path) before any use, so the size
the driver passes is dead on arrival here.

## Arguments

- `rdi` = first-argument object (saved in `rbp`; used for the
  `[context+0xa0]` identity compare and as the allocator's first
  argument).
- `rsi` = context object (`rbx`). The driver passes
  `[driver-context+0x38]`; the single-shot caller passes
  `[rbx+0x38]` — same shape, different object from the loop
  caller's context (note the lock at `+0xb0` and the contention
  argument at `+0x70`, versus `+0x80`/`+0x40` in #232/#233).
- `rdx` = size argument. Never read (see above).
- `rcx` = flag-byte pointer (saved in `r12`, never reassigned;
  the only stores through it in the FDE are the `0` at entry and
  the `1` on the fail path).

## Main path, in order

1. **Lock (exhibit `gt_entry`).** `pthread_mutex_trylock(context+0xb0)`.
   On failure the contention helper `0x63bf680(context+0x70)` runs,
   `[context+0xd8] := 1`, and the lock is retried.
2. **Accounting (exhibit `gt_entry`).** `[context+0xa8]++`. If
   `[context+0xa0] != first-arg`, then `[context+0x98]++` and
   `[context+0xa0] := first-arg`.
3. **Flag clear (exhibit `gt_entry`).** `*(flag-byte-ptr) := 0`.
   This happens on every lock-acquired path, before any work.
4. **Arena test (exhibit `gt_entry`).** If `[context+0xe0] == 0`,
   take the setup path (step 7). Otherwise continue.
5. **Allocate (exhibit `gt_main`).** With `rsi = [context+0xf0]`,
   `rdx = 0xf8`, `rcx = 0x40`, call the #216 allocator thunk
   `0x636b370(first-arg, [context+0xf0], 0xf8, 0x40)` — cited
   only. If `[context+0xe8] == 0x200000` at entry, the drain
   path (step 8) is taken instead. A NULL allocation diverts to
   the fail path (step 9).
6. **Consume (exhibit `gt_post`).** `r14 = [context+0xe0]`;
   `rdx = [context+0xf8]`; call `0x63ba600(alloc, r14, rdx)` —
   cited only. Then `[context+0xf8] := rdx + 1`,
   `[context+0xe0] += 0x200000`, `[context+0xe8] -= 0x200000`,
   `[context+0xd8] := 0`, unlock, return the block.
7. **Setup path (exhibit `gt_setup`).** Call the resolver
   `0x63c2130(0, 0x10000000, 0x200000, &stack-byte)` with the
   stack byte pre-set to `1` — cited only. A NULL result diverts
   to the fail path. Otherwise allocate as in step 5; a NULL
   allocation first calls `0x63c2450(resolver-result, 0x10000000)`
   — cited only — then diverts to the fail path. On success
   `[context+0xe0] := resolver-result`,
   `[context+0xe8] := 0x10000000`, and control joins the consume
   step at the `0x63ba600` call.
8. **Drain path (exhibit `gt_drain`).** Taken when
   `[context+0xe8] == 0x200000` at entry, i.e. exactly one
   `0x200000` chunk remains. Same allocate and consume calls,
   but the bookkeeping zeroes instead of advancing:
   `[context+0xe0] := 0`, `[context+0xe8] := 0`,
   `[context+0xd8] := 0`, unlock, return the block. Read as an
   exhaustion marker: with `[context+0xe0] == 0` the next call
   takes the setup path again. The zeroing itself is bytes; the
   "arena exhausted" reading is inference.
9. **Fail path (exhibit `gt_fail`).** `*(flag-byte-ptr) := 1`,
   `rbp := 0` (the return value), `[context+0xd8] := 0`,
   unlock, return NULL. Every failure in the FDE funnels here:
   resolver NULL, allocator NULL on either path, and the
   post-release failure on the setup path.

## The (cursor, remaining) pair, stated carefully

On the main path `[context+0xe0]` advances by `0x200000` while
`[context+0xe8]` retreats by the same amount, so their sum is
invariant across main-path calls. The setup path seeds them as
(resolver-result, `0x10000000`), i.e. 128 chunks of `0x200000`.
The drain path breaks the invariant deliberately by zeroing
both. What `0x63ba600` does with the block and the cursor value
is not decoded here (cited only) — so whether `+0xe0` is an
address cursor or a byte count is not proven by these bytes,
only the arithmetic is.

## Why a zero return stops the driver after round 2

At the driver's gate call site (`0x63b8ec2`, cited only) the
driver tests the return and jumps to its epilogue (`0x63b8f70`)
on zero: `[driver-context+0x118] := 0`, unlock, return the
accumulated count. The round-3 loop call site (`0x63b8f4d`,
cited only) is never reached. On a nonzero return the driver
instead passes the gate's block to `0x63d94b0(driver-context+0x140,
block)` — cited only — before round 3. Note this also refines
#234's open item: `0x63d94b0` takes the gate block as its
second argument; whether it is an alternate entry of the
`0x63d94a0` completion helper is still unresolved.

## The flag byte, answered

Yes, the gate sets it, twice over: `0` after lock acquisition
on every path, `1` on the fail path. A success therefore leaves
`0`, a failure leaves `1`. The driver does not test the byte
after the gate call — it tests only the return — so the byte's
reader is not the driver; who reads it is unresolved.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63b85f0..0x63b8820`); the next function starts with
  `endbr64` at `0x63b8820` (the single-shot caller, #232).
  Static analysis only; the binary was never executed.
- 6 exhibits, 389 bytes, 78 strict instructions (strict = mnemonic-line
  count: address + bytes field + tab + mnemonic; objdump
  byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `gt_entry` | `0x63b85f0..0x63b8661` | 113 | 26 | Entry, arg saves, trylock, accounting, flag `:= 0` |
| `gt_main` | `0x63b8667..0x63b869d` | 54 | 10 | Field loads, `e8 == 0x200000` branch, alloc call, NULL test |
| `gt_post` | `0x63b869d..0x63b86e6` | 73 | 12 | Consume call, `f8++`, `e0 += 2M`, `e8 -= 2M`, unlock |
| `gt_setup` | `0x63b8728..0x63b874f` | 39 | 9 | Resolver call, NULL test |
| `gt_drain` | `0x63b8790..0x63b87e3` | 83 | 15 | Drain alloc, consume, `e0 := 0`, `e8 := 0`, unlock |
| `gt_fail` | `0x63b8800..0x63b881b` | 27 | 6 | Flag `:= 1`, return NULL, unlock |

- Census: direct `E8` call sites to `0x63b85f0`: 2. Direct `E9` jump
  sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63b85f0`: 0 of 60,723 entries.
  E8: `0x63b8bdc` (single-shot caller FDE, #232; same arg shape,
  NULL-tested to its epilogue), `0x63b8ec2` (driver FDE, #234;
  NULL-tested to its epilogue, skipping round 3).
  Internal calls within the FDE: 13 sites (trylock, contention,
  allocator x3, consume x2, resolver, release, unlock x3,
  stack-check). Internal jump targets: all lie inside
  `0x63b85f0..0x63b8820`. Single `ret` at `0x63b8709`.
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#234 and no other contributor's topic, addresses, or
  tables; the driver, the single-shot caller, and all helpers
  are cited by address, not claimed here.

## Corrections to earlier packets

- **#234 confirmed and completed.** The gate is the check
  between the driver's second and third tranches: its zero
  return is exactly what stops the driver after round 2, and
  its nonzero return is passed to `0x63d94b0` before round 3.
  #234's `0x63d94b0` open item is refined (it takes the gate
  block as second argument) but not resolved.
- **#233 confirmed.** The loop caller is not involved in the
  gate; the gate is a separate FDE called by the driver and by
  the single-shot caller.
- **#232 confirmed.** The single-shot caller also calls this
  gate (site `0x63b8bdc`, same arg shape, NULL-tested); the
  surrounding path in that caller is cited, not decoded here.
- **#216 confirmed.** The allocator thunk `0x636b370` is called
  here with `(first-arg, [context+0xf0], 0xf8, 0x40)`.

## Unresolved

- The identities and semantics of `0x63c2130` (resolver),
  `0x63c2450` (release), and `0x63ba600` (consume): what the
  consume helper does with the block and the cursor value.
- Whether `[context+0xe0]` is an address cursor or a byte
  count; only its `+= 0x200000` arithmetic is proven.
- The meaning of `[context+0xf8]` (incremented once per
  successful consume) and of `[context+0xd8]` beyond its
  set-on-contention / cleared-before-unlock pattern.
- Who reads the flag byte the gate sets, since the driver
  tests only the return after the call.
- Why the gate ignores its size argument while the driver
  passes a size to it.

## Next question (#236)

Decode the consume helper `0x63ba600` end to end: what it does
with the allocator block and the cursor value it receives, and
how that explains the gate's `+0xe0`/`+0xe8` bookkeeping — this
decides whether the gate hands out arena slices or merely
registers blocks against a cursor.

## Verification

- `tools/node115_lu_gate.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, single `ret`, key call rel32s, flag/cursor stores,
  branch targets internal, full census, neighbour disjointness,
  MANIFEST coverage (17 entries).
- `tests/test_node115_lu_gate.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
