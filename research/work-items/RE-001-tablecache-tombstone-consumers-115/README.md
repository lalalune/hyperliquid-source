# RE-001: pin node #115 TableCache's range-tombstone consultation: UpdateRangeTombstoneSeqnums and Get

Task ID: **RE-001** (node #115 function map). Bounded question: **how does
TableCache consult the fragmented range tombstones when serving a Get and
when refreshing cached seqnums?**

## Answer in one paragraph

Both consumers share one update. `TableCache::UpdateRangeTombstoneSeqnums`
(`0x5f3d4f0`, 346 B) loops over a level range and, for every level whose bit
is CLEAR in the combined mask, asks the fragmented iterator for the max
covering tombstone seqnum and raises the cached max. `TableCache::Get`
(`0x5f40070`, 2589 B) performs the same raise-and-refresh once, before the
table lookup, gated on the cached slot, the `+0x35` skip flag and the
slot-`0x18` canonical. The shared rule: let `m` be the value
`MaxCoveringTombstoneSeqnum` returns; if `m` is not strictly greater than
the cached max, nothing changes; otherwise the cached max is raised, the
covering-key string is replaced with the key-array Slice at the returned
seqnum's index, and the flag byte is set to 1. The iterator comes from
vtable slot `0x18` of the table reader, and the null-returning stub
`0x5eba930` is the canonical "this reader has no range tombstones" —
installed by `CuckooTableReader` and `PlainTableReader`, overridden by
`BlockBasedTable`. This resolves the open unknowns in #3900 ("the
no-catalogue-row MemTable lookup/Get and MergingIterator caller FDEs" is
partly answered: the two TableCache caller FDEs are pinned here; the
MemTable hosts were already pinned by the RE-014 packets) and in #3674
("consumer in FDE 0x5f3d4f0 / 0x5f40070 (exact use open)").

## The two hosts

### UpdateRangeTombstoneSeqnums — `0x5f3d4f0..0x5f3d64a` (346 B)

Signature (observed registers): `(rdi: ignored, rsi: passed through to
slot 0x18, rdx: the receiver, rcx: pointer to the level-range struct)`.

- **Iterator build** (`0x5f3d4f0..0x5f3d518`): load the receiver's vtable
  slot `0x18`; compare it against the GOT slot `0x64ed6e8` (RELATIVE
  target `0x5eba930`, the null stub). Equal → `ret` immediately, nothing
  is updated. Otherwise `call *%rax` with `rdi = receiver, rsi = arg2`;
  a null return → `ret` immediately.
- **Level loop**: the struct at `rcx` holds `+0x00` base, `+0x08` start
  index, `+0x10` end index, `+0x18`/`+0x20` mask words. For each level
  `i` in `[start, end)`, compute the mask
  `*(struct+0x18) | *(struct+0x20) | *(base+0xf08)`; a SET bit means
  **skip** the level (`bt` + `jb` to the advance step), a clear bit
  means process it.
- **Per level** (`0x5f3d58d..0x5f3d609`): `rsi = *(base + i*8 + 0xe00)`
  (the per-level record); `rax = *(rsi+0x98)` (the subobject);
  `r14 = *(rax+0x1b0)` (the cached-max cell pointer); call
  `MaxCoveringTombstoneSeqnum(iterator, key Slice at rsi+0x10)`.
  `cmp %rax,(%r14); jae skip` — raise only when strictly greater.
  On a raise: `rdi = *(rax+0x190)` (the covering-key string slot);
  when non-null, replace the whole string with the key-array Slice
  for the returned seqnum (see below) via `std::string::_M_replace`,
  then `movb $1, 0x198(%r14)`.
- **Release** (`0x5f3d620`): tail-jump through the iterator's vtable
  slot `0x8` (the deleting destructor).
- **Sole caller**: site `0x5f44279` in FDE `0x5f42f80..0x5f44309`
  (5001 B, a multi-level lookup; the level-range struct is filled at
  `0x5f4308f`/`0x5f4309d`). Cited by contract, not modelled.

### TableCache::Get — `0x5f40070..0x5f40a8d` (2589 B)

The tombstone consultation runs first (at `0x5f40176..0x5f405c2`); the
table lookup follows. The gate order is exactly:

1. `0x5f40176`: `r12 = *(r13+0x1b0)` — the cached-max cell pointer
   (`r13` is the first stack argument, the per-file record). Null →
   skip to the table Get (`0x5f40199`).
2. `0x5f4018f`: `cmpb $0, 0x35(%rdx)` where `rdx` is arg 3. Nonzero →
   skip to the table Get. (The same `+0x35` offset is tested by the
   MemTable iterator gate `0x5f0b050` on its second argument; the
   owner's identity is an open unknown — likely a ReadOptions field,
   not proven here.)
3. `0x5f40500..0x5f4050b`: `rdx = *(rax+0x18)` where `rax = *(r14)`,
   `r14 = *(arg5)`. Compare against GOT `0x64ed6e8` (`0x5eba930`).
   Equal → skip to the table Get.
4. `0x5f40511..0x5f40527`: `call *%rdx` with `rdi = r14, rsi = arg3`
   builds the iterator. Null → the status check at `0x5f405c2`.
5. `0x5f4052d..0x5f4055e`: build the user-key Slice on the stack from
   the internal key (`ptr = *(rcx), len = *(rcx+8) - 8` — the 8-byte
   seqnum/type trailer is stripped; `rcx` is the saved 6th argument);
   call `MaxCoveringTombstoneSeqnum`. `cmp %rax,(%r12); jae` — raise
   only when strictly greater.
6. On a raise (`0x5f40569..0x5f405ad`): store the max into `*(r12)`;
   `rdi = *(r13+0x190)`; when non-null, `_M_replace` the string with
   the key-array Slice and set `*(r13+0x198) = 1`.
7. `0x5f405b5`: release the iterator with a `call` through vtable
   slot `0x8`, then `0x5f405c2`: the Status code is still 0, so
   control falls through to the table Get at `0x5f40199`.
8. The table Get itself (`0x5f401db`, `call *0x58(%rax)`) and the
   rest of Get — the `+0x38`/`+0x40` cache chain-walks, the
   `0x5f3f6c0` null-reader fallback, the `0x5f3cd50`/`0x5f3d0d0`
   not-ready path, the `0x616fb90` tail marker — are cited by
   contract, not modelled (see "Cited, not modelled" below).
- **Sole caller**: site `0x5f738e8` in FDE `0x5f733c0..0x5f743d9`
  (4121 B). It passes the per-file record (`index * 0x3c8 +
  *(rdx+0x228)`) and the `+0x1118` struct as stack arguments. Cited
  by contract.
- **Exception cleanup**: the landing pads at `0x5f40a69`/`0x5f40a75`/
  `0x5f40a81` jump into the separate FDE `0x5f4000e..0x5f40070`
  (98 B, excerpted as `get_cleanup.txt`).

## The shared update and the fragment-index arithmetic

Cached state (on the subobject — `*(record+0x98)` in the refresh
loop, the directly-passed record in Get):

| offset | meaning |
|---|---|
| `+0x1b0` | a `u64*` cell holding the cached max covering seqnum |
| `+0x190` | a `std::string*` holding the cached covering key (null = no slot) |
| `+0x198` | a flag byte, set to 1 on a raise |

Fragment-index arithmetic (identical in both hosts): with `rdx =
*(iterator+0x68)` (the list) and `rax = *(iterator+0x90)` (the seq
pointer), `index = (rax - *(rdx+0x18)) >> 3`, and the entry is the
16-byte Slice at `*(rdx+0x30) + index * 16`. That Slice replaces the
`+0x190` string whole (`_M_replace` with pos 0, n = current length).

## The null stub and its installers

`0x5eba930..0x5eba937` (7 B): `endbr64; xor %eax,%eax; ret`. It is the
default slot-`0x18` implementation: a reader that installs it has no
range-tombstone iterator to hand out. RELATIVE evidence (`readelf -r`):

- GOT `0x64ed6e8 -> 0x5eba930` — the slot the two hosts compare against.
- `0x64d5ea8 -> 0x5eba930` — slot `0x18` of the `CuckooTableReader`
  vtable `0x64d5e90` (typeinfo `N7rocksdb17CuckooTableReaderE`,
  slot `0x00 = 0x615b1b0`).
- `0x64d6768 -> 0x5eba930` — slot `0x18` of the `PlainTableReader`
  vtable `0x64d6750` (typeinfo `N7rocksdb16PlainTableReaderE`,
  slot `0x00 = 0x61a3cc0`).

Typeinfo pointers resolve through their own RELATIVE records
(`0x64d5e88 -> 0x64d5e50`, `0x64d5e58 -> 0x97ba20`;
`0x64d6748 -> 0x64d6710`, `0x64d6718 -> 0x97c2f0`); the name strings
are read from the binary at the resolved addresses and checked by
`verify.py`.

## The MemTable-side gate (cited)

`0x5f0b050..0x5f0b073` (35 B, `iterator_gate.txt`): return null when
the `+0x35` byte of the second argument is nonzero, or when the
MemTable's `+0xa60` byte is nonzero; otherwise tail-jump to
`NewRangeTombstoneIteratorInternal 0x5f0a9c0` (#3674 ground). 11 direct
callers (see `callers.tsv`). The `+0x35` test is the same offset the
Get gate tests — the two gates agree on the flag's meaning (nonzero =
skip tombstones) while disagreeing on nothing else.

## The callee contract (re-shipped from #3900)

`MaxCoveringTombstoneSeqnum 0x5f32900..0x5f32a0a` (266 B,
`max_covering_seqnum.txt` re-shipped byte-identical from
`RE-001-fragmented-tombstone-iterator-115`): call
`SeekToCoveringTombstone`; Valid check; return 0 when invalid, when
`seq_ptr == fragment range end`, or when the fragment start key is
greater than the key; else return `*(+0x90)`. Exactly 4 direct callers
in the whole binary: the two MemTable lookup/Get paths (`0x5f0d1e5`,
`0x5f0e09c` — pinned by the RE-014 packets) and the two hosts pinned
here (`0x5f3d5aa`, `0x5f4055e`).

## Cited, not modelled

- `TableCache::Get`'s value lookup: the slot-`0x58` table Get
  (`0x5f401db`), the `+0x38`/`+0x40` chain-walks at `0x5f403c0`/
  `0x5f406ac` (8 levels unrolled, then a virtual call), the
  `0x5f3f6c0` null-reader fallback (10 callers), the `0x5f3cd50`/
  `0x5f3d0d0` not-ready path, the inlined small-memcpy at
  `0x5f409a0..0x5f40a5f`, and the `0x616fb90` tail marker (writes
  `+0x108 = 1`, clears the byte at `*(+0x1a0)`; 7 callers).
- The cache-chain canonicals resolve to cache-wrapper vtable slots:
  GOT `0x64ecd48 -> 0x5d42220` (slot `0x18`: `CacheWrapper`
  `0x64c8da0`, `CacheWithSecondaryAdapter` `0x64c8ea0`);
  GOT `0x64ecd18 -> 0x5d3f090` (slot `0x38`: same two vtables);
  GOT `0x64ece10 -> 0x5d420a0` (slot `0x40`: `CacheWrapper`,
  `ChargedCache` `0x64c9e00`). The chain resolution itself is not
  modelled here.
- The lazy static at `0x65046a0` (guard `0x6504690`, 0x30 bytes:
  `+0x00 = 0x5f3cb30` deleter, `+0x20 = 0xd`, `+0x28 = self`) behind
  the `+0x38`-chain object in Get, initialised once via
  `__cxa_guard_acquire` at `0x5f408d8`.
- The two hosts' sole callers (FDEs `0x5f42f80..0x5f44309` and
  `0x5f733c0..0x5f743d9`): only the call sites are pinned.
- `0x5f3cb30` (the 0x20-byte deleter) and `0x5f0a9c0`
  (`NewRangeTombstoneIteratorInternal`, #3674 ground).

## The model and tests

`tools/tablecache_tombstone_consumers_115.py` models the refresh loop,
the Get gate (in the binary's exact gate order), the raise-and-refresh
rule and the fragment-index arithmetic, with `MaxCoveringTombstoneSeqnum`
implemented by #3900's contract. `tests/test_tablecache_tombstone_consumers_115.py`
runs 448 checks, all passing, including: the max-covering rule
cross-checked against a brute-force linear scan on 200 seeded random
fragment sets; the gate matrix (null slot / skip flag / canonical stub /
null iterator / consult-and-raise / consult-no-raise); the loop mask
polarity and per-level keys; and 100 seeded random loop cases against a
direct reference.

## Verification

`verify.py` reports ALL CHECKS PASSED: digest vs provenance, manifest,
excerpt regeneration byte-for-byte (7 windows), 3 seeded-random gate
spots byte-for-byte against fresh objdump and the raw binary, frames,
census reproduction (59 caller rows, 7132 dispatch rows), RELATIVE
relocations (17 checks) and typeinfo names (5 checks), literals, and
the 448 model checks. The objdump command is recorded in
`export_excerpts.py`; `endbr64` and the other mnemonics in the excerpts
are genuine instructions present in the target binary, not
placeholders.

## Environment limits (honest)

This packet was built on a VM with no cargo/rustc, no git-lfs and no
Ghidra/Java, so `make verify test catalogue-check` could not be run
here; the packet's own `verify.py` (digest, manifest, excerpts,
gate spots, frames, census, relocations, model tests) was run instead
and passes. The value lookup inside `TableCache::Get` is cited, not
modelled — a maintainer with a tooled environment can run the repo
gates on the added files.

## Unknowns (kept separate from observations)

- The C++ names of the two hosts (described by behaviour).
- The semantic identity of the key-array Slice refreshed into `+0x190`
  (fragment start key vs end key vs timestamp key) — carried open
  from #3900.
- The exact roles of the three mask words in the refresh loop
  (`struct+0x18`, `struct+0x20`, `base+0xf08`) beyond the observed
  skip rule.
- The class behind the slot-`0x18` receiver in each host (the vtable
  is not named; only the canonical guard is pinned).
- The identity of the `+0x35` flag's owner struct (the same offset is
  tested by the MemTable gate `0x5f0b050` and by Get; likely a
  ReadOptions field, not proven here).
- The full value-lookup behaviour of `TableCache::Get` beyond the
  tombstone consultation (slot-`0x58` table Get, the `+0x38`/`+0x40`
  cache chain-walks, the `0x5f3f6c0` fallback and the not-ready path
  are cited, not modelled).
- The landing-pad / LSDA tables of both hosts.
