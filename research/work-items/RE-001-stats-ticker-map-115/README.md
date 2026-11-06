# RE-001: node #115 StatisticsImpl slot-0xf0 ticker-map fill and the four DB-family vtables behind rebuild slot 0x2d0

- Component ID: RE-001 (node #115 function map)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `artifacts/node/115/hl-node`; local copy
  `work/hl-node-115.bin` hashes exactly)
- Source commit / reference commit: upstream main `05bc2de30`
- Claim status: observation for everything below except the items listed
  under Unknowns, which are inference boundaries, not claims.

## Bounded question

#3362 left two things open: what the StatisticsImpl vtable slot-0xf0
routine `0x6076030` computes (the next slot after ToString at 0xe8),
and which classes own the four vtable slots that reach the DBImpl
rebuild `0x5d58720`.

## Answer, pinned to the target

### Part 1 — slot 0xf0 is the ticker-map fill

The StatisticsImpl vtable is `0x64d2d88` (typeinfo
`N7rocksdb14StatisticsImplE`, base `N7rocksdb10StatisticsE`, 32 slots).
Slot `0xe8` holds ToString `0x6070810` (#3362); slot `0xf0` holds
`0x6076030` (installed by the single RELATIVE record
`0x64d2e78 -> 0x6076030`), a 0x5e5-byte routine that fills a
caller-supplied `std::map<std::string, uint64_t>` with one
(ticker name -> shard-summed count) entry per entry of the BSS
ticker vector, and returns a bool. There are no direct calls to
it anywhere in the binary: it is reached only through the vtable.

`0x6076030` (`rdi=this`, `rsi=out map`) runs, in order:

1. **Null map.** A null `out` returns false (0) immediately, without
   taking the lock.
2. **Clear.** The old map contents are freed: the tree is walked
   from the root at `out+0x10`, each right subtree through the
   recursive `_Rb_tree::_M_erase` `0x60700d0`, each heap string
   buffer freed (skipped when the string pointer equals its own
   SSO buffer at `node+0x30`) with its length+1, each `0x48`-byte
   node freed. The header is then re-initialised: root
   `out+0x10 = 0`, left `out+0x18` and right `out+0x20` =
   `&header` (`out+0x08`), count `out+0x28 = 0`.
3. **Lock.** The mutex at `this+0x38` is locked via `0x60d5230`.
4. **Walk.** The BSS ticker vector at `0x6506260` (`{begin, end}`
   of `0x28`-byte entries: u32 ticker id at `+0x00`, name pointer
   at `+0x08`) is walked in vector order. An empty vector jumps
   straight to unlock.
5. **Sum.** Per entry the count comes from the ticker getter
   `0x6070430(this, id)` (re-shipped from #3362): the sum over
   `2**(u8 at this+0x68)` shards of the u64 at
   `*(this+0x60) + shard*0xce40 + id*8`. The getter has exactly
   three direct callers: `0x60704ae` (FDE `0x6070490..0x60704d2`),
   `0x6070895` (ToString), and `0x6076133` (here).
6. **Key.** The name is built into a `std::string` temporary:
   inline SSO buffer for length <= 15, heap buffer via
   `_M_create` above that, null-terminated at `buf[len]`. A null
   name throws `logic_error` with the message at `0x963298`:
   `basic_string: construction from null is not valid`.
7. **Insert.** The pair goes through the inlined RB-tree
   lower_bound (memcmp on the shared prefix, then the length
   difference against the `0x80000000` bound) plus
   `_Rb_tree_insert_and_rebalance` for a new `0x48`-byte node
   (the key string is copied into the node, length+1 bytes
   including the terminator). A key already present keeps its
   node and takes the new summed value at `node+0x40`, so the
   last duplicate wins. Node layout: colour/parent/left/right
   at `+0x00/+0x08/+0x10/+0x18`, string key at `+0x20`
   (pointer `+0x20`, length `+0x28`, SSO buffer `+0x30`), u64
   value at `+0x40`.
8. **Unlock and return.** The mutex is unlocked via `0x60d52f0`
   and the routine returns true (1), including for an empty
   ticker vector.
9. **Exception path.** The landing pads funnel into the shared
   cleanup fragment `0x6075ff6..0x607602a` (its own FDE), which
   disposes the temp string, unlocks the mutex, checks the
   stack canary and resumes unwinding. The mutex is therefore
   never left held on an exception.

The neighbouring routine at FDE `0x6075bc0..0x6075ff5` is not
examined; only the cleanup fragment it shares with this routine
is pinned (see Unknowns).

### Part 2 — the four DB-family vtables behind rebuild

Rebuild `0x5d58720` (#3362: locks `db+0x700` via the instrumented
acquire `0x606ca40`, builds a temp via `0x60c2e20`, copies the
statistics shared_ptr into `DB+0x548`, unlocks) has no direct
callers. It is installed at vtable slot `0x2d0` of four 151-slot
DB-family vtables, identified from their typeinfo pointers
(vtable `-0x08`) and base chains:

| class | vtable | typeinfo | base |
| --- | --- | --- | --- |
| DBImpl | `0x64c9368` | `N7rocksdb6DBImplE` | `N7rocksdb2DBE` |
| DBImplReadOnly | `0x64cb0e0` | `N7rocksdb14DBImplReadOnlyE` | `N7rocksdb6DBImplE` |
| CompactedDBImpl | `0x64cb5c0` | `N7rocksdb15CompactedDBImplE` | `N7rocksdb6DBImplE` |
| DBImplSecondary | `0x64cbbc0` | `N7rocksdb15DBImplSecondaryE` | `N7rocksdb6DBImplE` |

Each vtable starts at `gap+0x10` where the gap holds
offset-to-top `0` (no relocation). All four hold `0x5d58720` at
slot `0x2d0`: **no subclass overrides the rebuild method**.
The full 151-slot tables are in `vtables.tsv` (re-derived from
`relocations.txt` by `verify.py`). 121 of the 151 slots are
identical in all four vtables; the override counts are
DBImplReadOnly 22, CompactedDBImpl 20, DBImplSecondary 27
(the differing slots are listed in `records.json` and in
`tools/stats_ticker_map_115.py`).

Note on the earlier record: #3362 described the four slots only
as "four vtable slots (0x64c9638, 0x64cb3b0, 0x64cb890, 0x64cbe90)
whose classes are unidentified". Those addresses are the slot
addresses themselves (vtable + `0x2d0`); the owning vtables and
classes are identified here. #3362's "virtual slot 0x30" phrasing
does not describe this slot: the slot offset within each vtable
is `0x2d0`.

## Evidence packet

- `slotf0.txt`, `cleanup_fragment.txt`, `tree_erase.txt`,
  `rebuild.txt`: whole-function verbatim objdump excerpts
  (FDE ranges), generated by `export_excerpts.py`.
- `ticker_getter.txt`, `mutex_lock.txt`, `mutex_unlock.txt`:
  re-shipped byte-identical from #3362.
- `frames.txt`: the 7 FDE lines for the excerpted windows.
- `relocations.txt`: 654 RELATIVE records — the StatisticsImpl
  vtable (typeinfo pointer + 32 slots), the typeinfo name/base
  records, and the four DB vtables in full (typeinfo pointer +
  151 slots each).
- `vtables.tsv`: the four 151-slot tables, one row per slot.
- `callers.tsv`: 841 rows from `census.py` (one objdump pass
  over the executable segment). Census summary: rebuild has
  0 direct calls / 0 tail jumps / 0 leas and 4 RELATIVE
  records; the slot-0xf0 routine has 0 direct calls and 1
  RELATIVE record; the ticker getter has 3 direct calls;
  the tree erase has 2 (one self-recursion, one from the
  slot-0xf0 routine); the mutex lock has 157 calls + 1 tail
  jump and the unlock 669 calls + 5 tail jumps; ToString has
  0 direct calls and 1 RELATIVE record; the sibling `0x6075bc0`
  has 1 lea reference (from `0x607788d`) and no direct calls.
- `records.json`: semantic records only (routine contracts,
  vtable/override tables, literals, census). Instruction-level
  detail lives only in the excerpt text files. The mnemonics
  in the excerpts (including `endbr64`) are genuine instructions
  present in the target binary, not placeholders.
- `verify.py`, `census.py`, `export_excerpts.py`: the packet's
  own runnable checks, as in the earlier RE-001 packets.

## Model and tests

`tools/stats_ticker_map_115.py` models the ticker-map fill
(clear, lock, per-ticker shard sum, insert with last-duplicate
wins, null-map false, null-name logic_error, exception-path
unlock) and the DB vtable override maps.
`tests/test_stats_ticker_map_115.py` checks it (shard sums,
fill/clear/duplicate/null cases, the 151-slot tables, the
override counts 22/20/27 and the 121 identical slots).

## Verification

`python3 research/work-items/RE-001-stats-ticker-map-115/verify.py`
must print ALL CHECKS PASSED: binary digest, manifest, excerpt
regeneration byte-for-byte from fresh objdump, every excerpt
line byte-for-byte against the raw binary, fixed + 3 seeded
random gate spots (`random.seed(20261106)`), FDE ranges,
relocation set, literals, census reproduction, vtable slots
re-derived from relocations.txt, model tests.

## Unknowns

- The public C++ name of the slot-0xf0 routine is not
  established from the stripped binary; it is described by its
  observed behaviour (ticker-map fill) and its vtable slot, not
  by a source-level name.
- The RocksDB source-level name of the DB virtual method at
  slot `0x2d0` (rebuild `0x5d58720`) is not established; only
  its binary behaviour (#3362) and its four owning classes are
  pinned.
- The neighbouring routine at FDE `0x6075bc0..0x6075ff5` (one lea
  reference from `0x607788d`, no direct calls) is not examined;
  its role is open.
- The routine at FDE `0x6070490..0x60704d2`, the third direct
  caller of the ticker getter, is not mapped; only its call
  site `0x60704ae` is recorded.
- The deeper base of the Statistics typeinfo (`0x64d34a0`,
  pointed to by `0x64d2ce0+0x10`) is not resolved.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify` / `make test` / `make catalogue-check` cannot run
here; the packet's own `verify.py` and the model tests are the
checks that were run. `pytest` is not installed; the model
tests run directly with `python3`.
