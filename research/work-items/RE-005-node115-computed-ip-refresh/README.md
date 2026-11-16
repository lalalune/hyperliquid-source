# Node 115 computed-IP view refresh

This packet establishes the selected execution-side refresh of the 104-byte
computed-IP view: where the candidate comes from, how the caller decides to
retain or replace the view, and the order of old-view retirement and new-view
installation. It advances the peer-state provenance needed by RE-005/RE-008;
it does not establish a complete network node or change a component gate.

## Target and method

- Target: `artifacts/node/115/hl-node`, 105896032 bytes.
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Static ELF/FDE inspection and x86-64 decoding with Capstone 5.0.7 and
  pyelftools 0.32. The captured executable was neither executed nor emulated.
- All addresses are native virtual addresses. `records.json` retains six
  instruction windows, their bytes and digests, FDE bounds, two ELF relocation
  bindings and the native `check_computed_ips` / `update_computed_ips` labels.

## Prior work and precise addition

- [#5407](https://github.com/lalalune/hyperliquid-source/pull/5407),
  `RE-008-node115-peer-address-admission`, closes the keyed lookup at
  `0x2a59160` and listener gate. Its owner+`0x6b0` map producer/freshness remain
  outside that contract.
- [#2520](https://github.com/lalalune/hyperliquid-source/pull/2520),
  `RE-001-node115-node-ip-filter`, already covers
  `0x5b2b150 -> 0x5b7bc60` under its stated query-result premises. This packet
  reuses that boundary; it does not reconstruct the filter again.
- [#4945](https://github.com/lalalune/hyperliquid-source/pull/4945) and
  [#5585](https://github.com/lalalune/hyperliquid-source/pull/5585) cover
  execution-row selection and the later compact publication/queue send.
  The refresh here precedes the `0x2af6580` call in the same caller and uses
  `0x29c5860 -> 0x2a5d6a0`, not the later compact-Arc swap or result queue.

The new result is the caller-to-owner refresh relation and the lifetime of the
old versus candidate view. Overlap screening includes all 6,976 available
open/closed PR title/body records and targeted current-main evidence/source
searches at base `a8a165e65d53abc1c996bcc9b609749529cfc41a`. Addresses in broad
xref or lock-location inventories are not claimed as new discoveries.

## Selected call and data flow

In `0x2af7150`, byte `owner+0x260 == 1` bypasses this refresh branch.
Otherwise the caller copies the 20 bytes at `owner+0x261` into a local
optional-key value. It obtains a byte at `(*execution_arg)+0xb9a` and passes
`(*execution_arg)+0xd88`, that byte and the optional-key value to the producer
at `0x5b2aa70`. The call at `0x2af7272` resolves through ELF relocation
`0x64e5bf0`; this is a real producer binding, not an inferred function name.
The produced view is then passed through `0x5b2b150` at `0x2af728c`, via
relocation `0x64e7408` (the filter already studied in #2520).

The destination allocation is loaded from `owner+0x290` at `0x2af7292`.
The same `allocation+0x10` value is used in both closures below:

| Boundary | Captured object/value | Result |
| --- | --- | --- |
| `0x2af72f4 -> 0x29be600 -> 0x2a5ac50` | closure+0: allocation+0x10; closure+8: candidate address | Four short-circuited comparison-helper results determine the returned byte. |
| zero result at `0x2af72fb` | Candidate remains locally owned | `0x2af73f6` drops the candidate through `0x2ab8410`; no replacement call occurs on this arm. |
| nonzero result at `0x2af73b9 -> 0x29c5860 -> 0x2a5d6a0` | closure+0..0x67: candidate; closure+0x68: the same allocation+0x10 | Retire the old view and install all 104 candidate bytes. |

Both instrumentation wrappers have a direct tail route and an instrumented
call route to the same respective operation. Their TLS records are not an
additional peer-state cache.

## Comparison and replacement ordering

Let `S = allocation+0x10`. The comparison operation acquires the lock at
`S+0x6a8`. Its fast reader route adds `0x10` to the lock word; it checks
`S+0x6b0` against candidate+0 through `0x2e3bd90`, then the regions
`S+0x6d0`, `S+0x6e8` and `S+0x700` against candidate+`0x20`, +`0x38`,
and +`0x50` through `0x246d490`.

The first helper returning zero short-circuits to returned byte 1. If all four
return one, the final `xor r15b,1` produces zero. This is the precise helper
composition; no arbitrary malformed-container or pointer-equality contract is
asserted for the helpers. The comparison releases its reader ownership before
returning. The timing-enabled copy performs the same four operations.

The replacement captures `S` from closure+`0x68` and copies all 104 incoming
bytes to stack storage. It separately acquires `S+0x6a8` for writing (fast
route compares zero and writes 8). On the normal acquired path:

1. `0x2a5d894` calls `0x29ee000` on **old** `S+0x6b0`.
2. Stores at `0x2a5d8a1..0x2a5d8ec` install offsets `0x60`, `0x50`,
   `0x40`, `0x30`, `0x20`, `0x10`, `0`, covering exactly `[0,0x68)`.
3. `0x2a5d8f8` releases the write ownership; the contended-release path also
   comes after the copy. Subsequent timing/reporting work does not move the
   copy ahead of old-view retirement.

The old-view helper dispatches the first 32-byte container between its tree
release and 24-byte-row allocation release; it then visits the regions at
`+0x20`, `+0x38`, and tail-calls the final release at `+0x50`. This proves
retirement is of the entire old view, not merely its first map descriptor.
It does not claim all nested allocator failure or unwind behavior is closed.

**The comparison and replacement are separate lock acquisitions.** This is not
a compare-and-swap publication or a proved atomic read/compare/replace
transaction. The selected code supplies no version check between the two
operations. Whether another writer can actually interleave requires an owner
and scheduling proof beyond this packet.

## Remaining boundaries

- `0x5b2aa70` is a bound producer dependency, not a complete recovered builder.
  The semantic identity/authentication of its input tables remains open.
- This packet proves the same destination object across comparison and update.
  Matching the listener's separately captured allocation to this allocation is
  **not** established solely by the shared `+0x6b0` offset. Thus no full
  writer-to-listener freshness, authority, or stale-peer rejection claim is made.
- The filter and comparison helpers retain their prior or opaque input-domain
  requirements. No fake source implementation with supplied acceptance results
  is presented as a working peer-state subsystem.
- Panic, cancellation, concurrent scheduling, persistence and complete startup
  reachability remain open. No network, consensus or full-scope completion gate
  is advanced.

## Reproduction

With the pinned dependencies installed in a Python environment:

```sh
python3 research/work-items/RE-005-node115-computed-ip-refresh/verify.py \
  --target artifacts/node/115/hl-node
make catalogue-check
```

The verifier checks exact target identity, retained bytes, FDE bounds, all
instruction rows, 62 selected instruction witnesses, both relocations and
both native labels. Six negative controls reject a wrong target, swapped call,
inverted caller gate, wrong owner slot, missing final field copy, or retirement
replaced by a store. These are static-evidence controls, not emulated execution
or independently observed runtime behavior. Catalogue validation must be run
again after the new files and generated catalogue are committed.
