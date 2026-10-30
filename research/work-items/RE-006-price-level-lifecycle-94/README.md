# RE-006 — one resting-order price-level insertion/cancellation lifecycle, node #94

Status: **bounded evidence packet; no reconstruction or completion gate claimed.**

- Component: `orderbook`.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Independent upstream base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference lead: unlicensed `can1357/hl` pin
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. It was used only to choose
  search terms and candidate source paths. No reference implementation or
  comment is treated as evidence, copied, or claimed correct.
- Scope: one compiled family that allocates a resting `0xf8`-byte slot,
  appends it to a signed-price level, then removes the slot and repairs the
  linked level. Matching, external action dispatch, synchronization and a
  complete book implementation are excluded.

The target supports a doubly linked FIFO-shaped level: insertion copies the
old tail into the new slot's previous link, clears its next link, initializes
the head only for an empty level, repairs the old tail's next link, and always
sets the new tail. Removal performs the inverse previous/head and next/tail
updates and removes an empty level. The same route adds/removes an unsigned
64-bit slot quantity to/from a supplied aggregate and places deleted slots on
a LIFO free list for reuse.

## Reproduce

Static and offline; the captured binary is never executed.

```sh
make verify
python3 -I -B tools/order_book_lifecycle_94.py
python3 -I -B research/work-items/RE-006-price-level-lifecycle-94/verify.py
python3 -O -B research/work-items/RE-006-price-level-lifecycle-94/verify.py
python3 -m unittest tests.test_order_book_lifecycle_94 -v
make test
make catalogue-check
```

Recorded author environment: macOS 26.1 arm64, Apple LLVM/`llvm-objdump`
21.0.0, GNU Binutils 2.47.20260726, Apple Python 3.9.6, Git 2.56.0 and Git LFS
3.8.1. GNU Binutils was placed first in `PATH` for the repository-wide test
suite, whose existing cross-checks require GNU `objdump`/`readelf` rendering.
The evidence collector itself uses only Python's standard library and the
repository's ELF/FDE parsers. The retained disassembly is human-readable raw
output from `llvm-objdump -d`; the tool and tests do not parse its rendering.
Local paths are replaced with `<authenticated-node94>`.

`make doctor` reports `analysis_ready: false` here because Java/Ghidra and the
two future Rust toolchains are absent. This packet uses no Ghidra output and
makes no exact-rebuild claim. The authenticated ELF, internal section/FDE
parsers and an independent `llvm-objdump` instruction-boundary check are the
actual inputs.

## Anchoring and exact scope

All coordinates are linked ELF virtual addresses. In `.text`, file offset is
VA minus `0x1000`. FDEs are unwind-described ranges, not original symbol
boundaries. Descriptive labels below are ours.

| Inferred role | FDE, half-open | Bytes | Direct E8 hits to start |
| --- | --- | ---: | ---: |
| Resting insert body | `0x430d610..0x4311140` | 15,152 | 3 |
| Insert accounting/allocation | `0x42e85c0..0x42e870d` | 333 | 2 |
| `0xf8` slab insert monomorph | `0x45a4c90..0x45a4dc3` | 307 | 1 |
| Removal caller/unlink | `0x42f7890..0x42f8834` | 4,004 | 4 |
| `0xf8` slab remove/accounting | `0x42e8bf0..0x42e8f77` | 903 | 2 |

The five FDEs total 20,699 bytes. Exact body and block hashes are in
`evidence.json`; relevant raw instructions are in `objdump-excerpts.txt`.
The following direct edges bind the family:

```text
0x430d610 insertion body
  0x430fa06 -> 0x42e85c0 accounting/allocation
                    0x42e869d -> 0x45a4c90 slab append/reuse

0x42f7890 removal caller
  0x42f7de1 -> 0x42e8bf0 slab delete/accounting
  then 0x42f8590..0x42f8651 repairs neighbors/head/tail
```

Nine `R_X86_64_RELATIVE` Location records independently anchor the family to
the embedded target paths `l1/src/book/book/mod.rs`,
`l1/src/book/book/impl_insert_order.rs`, and `l1/src/slab/slab.rs`. The exact
slots, addends, lines and columns are retained in `evidence.json`. Particularly
useful anchors are `mod.rs:1286:56` / `1294:56` at the two invalid-neighbor
arms and `slab.rs:79:21` at the invalid reuse arm. Embedded path attribution
does not by itself prove a Rust function name.

## Observed insertion transition

At `0x430f84b..0x430f876`, a one-byte side selects both a tree and signed
64-bit key:

| Side byte | Tree relative to the book | Stored signed key | Ascending order |
| ---: | ---: | ---: | --- |
| `0` | `+0x80` | `-price` | larger numeric prices first |
| nonzero | `+0x98` | `+price` | smaller numeric prices first |

Those orderings are the mechanical bid/ask orderings, so this packet calls the
zero/negative-key side bid-shaped and the nonzero/positive-key side ask-shaped.
The original enum name/discriminant is not recovered.

At `0x430f970..0x430f98a`, the current level tail Option (16 bytes at level
`+0x10`) is copied into the new slot's previous Option; the next Option is
zeroed. After allocation returns the new `u64` key, `0x430fa0e..0x430fa79`:

1. writes `Some(new)` to level `+0/+8` only if the head is absent;
2. if the old tail is present, checks `tail < slab.entry_len`, scales it by
   `0xf8`, rejects vacant discriminator `2`, and writes `Some(new)` to that
   slot's next Option at `+0x10/+0x18`;
3. writes `Some(new)` unconditionally to level tail `+0x10/+0x18`.

This is an append relationship. A consumer that begins at the head and
follows next links observes insertion order. The packet proves the maintained
link shape; it has not closed every matching consumer of that list.

## Slab allocation, deletion and reuse

The slab-insert block `0x45a4cab..0x45a4d50` gives these exact widths and
fields for this monomorph:

| Slab/slot offset | Width | Observed use |
| --- | ---: | --- |
| slab `+0x08` | 8 | backing entry pointer |
| slab `+0x10` | 8 | raw entry count / append boundary |
| slab `+0x18` | 8 | occupied count, incremented with a `u64::MAX` ceiling |
| slab `+0x20` | 8 | next allocation/free-list head |
| slot `+0x00` | 4 tested, 8 written | vacant discriminator `2` |
| slot `+0x08` | 8 | next free key while vacant |
| slot stride | 8-byte immediate | `0xf8` (248 bytes) |

If the next key equals the raw entry count, the target grows when needed,
copies 248 bytes, increments the raw count, and sets the next key to the new
end. Otherwise it requires `key < entry_count` and discriminator `2`, loads
the following free key from slot `+8`, then overwrites the complete slot.
Other cases enter the `slab.rs:79:21` failure arm.

The removal helper checks the same boundary/discriminator at
`0x42e8c04..0x42e8c2b`. A missing or already-vacant key returns an absent
result with discriminant `2`. A live removal writes vacant `2`, writes the old
free head at slot `+8`, decrements the occupied count with a zero floor, and
sets the free head to the removed key (`0x42e8d3c..0x42e8d5e`). Consequently,
the next insertion reuses the most recently removed slot.

## Cancellation/unlink and accounting

The removed slot's two linked Options are represented by qwords:

- previous discriminant/key at slot `+0x00/+0x08`;
- next discriminant/key at slot `+0x10/+0x18`.

At `0x42f8590..0x42f85e4`, a present previous key is range-checked, scaled by
`0xf8`, checked against vacant `2`, then its next Option is replaced by the
removed slot's next Option. With no previous key, the level head is replaced.
At `0x42f85e4..0x42f863c`, the target symmetrically replaces a present next
slot's previous Option, or replaces the level tail when next is absent. If
both resulting level Options are absent, `0x42f8635..0x42f8651` calls the map
removal helper. Thus head, middle, tail and single-element cancellation have
distinct, observed target paths.

The qword at occupied slot `+0xc8` is loaded by both accounting helpers.
Insertion adds it to a supplied qword total; carry enters a diagnostic path
and stores `u64::MAX`. Removal subtracts it; borrow enters a diagnostic path
and stores zero. These are unsigned 64-bit operations. This establishes one
aggregate total, not a complete size/notional accounting system or a per-level
size field.

## Tests and adversarial controls

Fifteen test methods cover:

- exact target identity, five FDEs, three direct edges and nine relocated
  source Locations;
- every one of 15 local byte ranges, every call displacement and every
  Location line field under corruption;
- bid-shaped descending and ask-shaped ascending key order;
- first/second append, head/middle/tail/singleton removal, empty-level deletion;
- invalid-previous-neighbor fail-before-model-write behavior;
- LIFO slot reuse and aggregate overflow/underflow boundaries; and
- output stability under `PYTHONHASHSEED` 0, 1 and 4242.

The architectural model executes only independently authored Python over the
observed writes. It does not execute, emulate, lift, or import code from the
captured binary. An identical-byte control is the baseline; mutations bypass
only the whole-file digest so local obligations are actually exercised.

## Explicit unknowns and nonclaims

- **Duplicate orders:** the insert FDE constructs a value
  `0x8000000000000017`, but this packet did not close its predicate and return
  layout well enough to label it a duplicate-order result. Duplicate behavior
  therefore remains unknown; the reference lead's label is not adopted.
- The externally reachable action/transaction entrypoint that selects this
  monomorph is not established. Addresses above are target FDE/call sites, not
  public API names.
- The complete maker-consumption loop, partial fills, price-level aggregate
  size, order-id/user indexes, event emission, rollback and concurrency are
  not recovered here.
- No independently authored Rust is supplied: the surrounding ABI, ownership
  and failure contract are insufficiently closed for an honest replacement.
- No live node, exchange data, network call, signing, transaction, normalized
  match score or source-equivalence claim. No catalogue/component progress or
  completion gate changes.

The best next action is to close the predicate and output layout around the
`0x8000000000000017` arm, then trace the head-following match consumer into
the already pinned `+0x10/+0x18` next-link representation.
