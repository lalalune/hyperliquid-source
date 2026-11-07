# RE-001: the remaining per-thread LCG-seed consumers (node #115)

## Task and bounded question

Task **RE-001**. Open PR #3613 (RE-001-statistics-shard-record-115)
established the 17-site census of the per-thread LCG seed
(`0x61c4080`): 3 sites in the StatisticsImpl record slots and 14
elsewhere. Seven of those 14 were pinned by later packets. This
work item pins the **remaining 10 sites in 9 host routines** and
what each host does with the advanced seed value, completing the
census. The bounded question: for each of the nine still-unpinned
hosts, what is the exact derivation of the advanced seed (mask,
modulus, comparison) and where does the derived value land?

Artifact: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

## Windows

All excerpts are whole-function verbatim `objdump -d` output
(`objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`), re-shipped from #3613 where noted.
`frames.txt` holds the `.eh_frame` first column for each window,
verified against a fresh `objdump --dwarf=frames` dump.

| window | FDE range | frame prefix | seed sites |
| --- | --- | --- | --- |
| picker 0x60d5cd0 (re-shipped from #3613) | 0x60d5cd0..0x60d5cf0 | 0036ca90 | — (CPUID picker, 6 call sites) |
| thread seed 0x61c4080 (re-shipped from #3613) | 0x61c4080..0x61c4117 | 0076c098 | — (the getter itself) |
| oneshot builder 0x5f6b000 | 0x5f6b000..0x5f6b516 | 00748d10 | 0x5f6b06a, 0x5f6b11a |
| oneshot lookup 0x5f999d0 | 0x5f999d0..0x5f9a478 | 0074a920 | 0x5f9a116 |
| flag wait 0x5fca940 | 0x5fca940..0x5fcabdc | 0074d9b8 | 0x5fcaa75 |
| SkipListRep slot 0 (height draw) 0x6063150 | 0x6063150..0x6063229 | 00368248 | 0x6063165 |
| randomised descent 0x6066b80 | 0x6066b80..0x6066d61 | 0075a9f4 | 0x6066bc9 |
| SkipListRep slot 14 (sampler) 0x6066f20 | 0x6066f20..0x6067450 | 0075aa88 | 0x60671b1 |
| ZSTD gate 0x60e5610 | 0x60e5610..0x60e5a39 | 00761810 | 0x60e56f5 |
| bitmap-node ctor 0x60f4a00 | 0x60f4a00..0x60f4cb5 | 0076253c | 0x60f4b2a |
| sample-flag ctor 0x616f960 | 0x616f960..0x616fb83 | 00767ab8 | 0x616fb33 |

The census (`census.py`, output saved as `callers.tsv`) was
re-run fresh this cycle and reproduces #3613 exactly: the seed
`0x61c4080` has the same 17 direct calls, no tail jumps, no qword
hits and no RELATIVE slots; the picker `0x60d5cd0` has the same 6
direct calls. Two qword hits in the host-caller census
(`0x11ba50`, `0x11bba0`) are the RELATIVE addend fields of the
SkipListRep vtable slots 0 and 14, not code references.

## Observations (read from the binary)

* **The shared advance.** Every site inlines the same fold:
  `seed = seed * 0x41a7`, then `(seed & 0x7fffffff) + (seed >> 31)`,
  minus `0x7fffffff` once when the 32-bit sum sets the sign flag
  (the `cmovs` after the `add`; `lea` does not touch flags). The
  result is always in `[0, 0x7fffffff]`. The seed getter first use
  computes `_Hash_bytes(&pthread_self, 8, 0xc70f6907) & 0x7fffffff`,
  or 1 when that is 0 (pinned in #3613).
* **0x5f6b000 / 0x5f999d0 — LevelIterator builders.** Both build the
  same 0x118-byte record (vtable `0x64cce30`, 24 slots; typeinfo
  `*N7rocksdb12_GLOBAL__N_113LevelIteratorE`). Record `+0x90` is
  `((seed & 0x3ff) == 0x133)` (1-in-1024). In 0x5f6b000 the first
  advance also gates, on the index-0 path only, a `lock addq $0x400`
  to `+0x70` of every node in the list at `*(this+0xad8)`. The
  record layout (offsets `+0x00`..`+0x110`) is in `records.json`.
* **0x5fca940 — flag wait.** Spins at most 200 times on the flag
  byte at `(rsi+0x51) & arg-mask`, then the slow path. The seed
  advance gives the skip flag `((seed & 0xff) == 0)` (1-in-256);
  skip selects the slow timed-wait adjustment path (`±0x20000` to
  `*(arg3+0x08)` with a 1024-rounded decrement).
* **0x6063150 — SkipListRep slot 0 (vtable base `0x64d26e8`).**
  Geometric height draw by rejection sampling: tries start at 1,
  each try advances once and stops at the first seed `< this+0x14`;
  height is the try number, capped at `min(count, 32)` where count
  is the u16 at `this+0x10`; `count <= 1` never advances and gives
  height 1. The node is allocated via vtable slot 0x18 on
  `*(this+0x18)` with size `(height-1)*8 + arg2 + 8`; the height is
  stored at `buffer+(height-1)*8`.
* **0x6066b80 — randomised descent.** Once per level: advance once,
  `index = seed % n` where `n = (array_end - array_base) / 8` over
  the stack-collected forward-pointer array (filled by helper
  `0x60669f0`), step to `array[index]`; levels run from
  `count-1` down (`count = this+0x20`, head `this+0x18`).
* **0x6066f20 — SkipListRep slot 14.** Hash-index build with a sqrt
  split, then a seed phase: per iteration advance once,
  `index = seed % remaining_nodes`; if `index < remaining_count`,
  hash-look the sampled node up (bucket `key % bucket_count`) and
  decrement `remaining_count` on a hit; loop while
  `remaining_count != 0`. The deterministic phase calls
  `0x6066b80` up to 5 times first.
* **0x60e5610 — ZSTD gate.** Gated on `flag arg + *(arg2+0x20) != 0`;
  advance once; the heavy ZSTD CCtx setup runs only when
  `(seed % N) == 0` with `N = *(arg2+0x20)` (u32); otherwise the
  fast path is taken.
* **0x60f4a00 — bitmap-node ctor.** Builds a 0x28-byte node
  (descriptor qword from `0x459a38`: low u32 4, high u32 32);
  `node+0x20 = seed % count` (count = rdx arg); `node+0x10 =
  floor(log2(count >> 1)) + 1` when `count >= 2`, else 0; the bitmap
  is `(quotient+1)` u32s where `quotient = ((*(this+0x30)-1) >>
  node+0x10) / 32`; then calls `*(arg+0x18)`'s vtable slot 0xb0
  with id `0x57`.
* **0x616f960 — sample-flag ctor.** Zeroes `0x00..0xe0`, stores the
  args, then `this+0x1e0 = ((seed & 0x3ff) == 0x133)`.

## Inferences (named, not observed)

* The 1-in-1024 and 1-in-256 flags are sampling / probabilistic
  throttles: the same magic `0x133` appears in both LevelIterator
  builders and the 0x200-byte ctor, which suggests a shared
  sampling convention, but no shared helper exists in the binary
  (each site inlines the fold).
* The `0x6063150` draw is a geometric distribution with success
  probability `bound / 0x7fffffff` per try; the 32-cap and the
  count-exhaustion path make it a truncated geometric.
* The `0x6066f20` sampler is a random-without-replacement sweep
  over the skiplist nodes, used to build the hash index.

## Unknowns (open)

* **Oneshot path pointer.** The stored pointer is `0x4376fd`;
  the byte at `0x4376fd` is `0x00` and the path string
  `/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs`
  begins at `0x4376fe`. Whether the consumer reads from `+1` or
  the field is a tagged/length-prefixed pointer is not established;
  the packet records the pointer and the string as observed.
* The host caller sets are census facts (see `records.json` /
  `callers.tsv`); the *meaning* of several callers (e.g. the
  TableCache multi-level lookup area around `0x5f736ae`, the
  `0x60e656f` ZSTD caller, the nine `0x60f4a00` callers) is not
  pinned here.
* The `0x5fca940` slow path's perf-level TLS (`fs:-0x10b0`) and
  per-thread perf counter (`fs:-0x350+0x1b0`) semantics are read as
  addresses only.

## Cited, not re-pinned

Seven of the 17 census sites are pinned elsewhere and are cited
only (see `records.json` `cited_not_pinned`): the StatisticsImpl
record slots `0x606fba0` / `0x606fef0` / `0x606ffd0` (#3613);
`0x5f0a9c0` (merged RE-001-range-tombstone-cache-115);
`0x605e170` (merged RE-001-shard-refresh-605e170-115);
`0x605f340` (merged RE-001-chain-histogram-snapshot-115 /
RE-001-hashlinklist-insert-115); `0x61c1e10` (merged
RE-001-zstd-decompress-cache-115). No excerpt in this packet
duplicates a merged packet's window.

## Model and tests

`tools/other_seed_consumers_115.py` models the shared advance, the
height draw, the descent pick, both sample flags, the sampler step,
the ZSTD gate, the bitmap-node fields and the LevelIterator record
construction. `tests/test_other_seed_consumers_115.py` has 25
tests: seeded random inputs drive every derivation end to end, the
height draw is cross-checked against an independent transcription
of the disassembly loop, and the boundary cases are covered
(`count <= 1` skips the seed, the 32-cap, exhaustion, `N = 1`
always runs the ZSTD setup, `count = 1` start index is 0).

## Notes

* Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders;
  the excerpts are verbatim `objdump -d` output.
* The evidence JSON carries semantic records only (census,
  derivations, vtables, literals, layout); instruction-level
  detail lives only in the raw excerpts.
* Re-shipped from #3613: `picker-60d5cd0.objdump.txt` and
  `thread-seed-61c4080.objdump.txt` (byte-identical).
* Environment limits: this VM has no cargo/rustc, no git-lfs and
  no Ghidra/Java; all evidence is static disassembly of the
  digest-verified work binary. The `make verify` / `make test`
  catalogue checks that need the Rust toolchain cannot run here;
  the packet's own `verify.py` and the model tests were run
  instead (see below).

## Verification

```
python3 research/work-items/RE-001-other-picker-seed-consumers-115/verify.py
# ALL CHECKS PASSED
python3 -m pytest tests/test_other_seed_consumers_115.py -q
# 25 passed
```
