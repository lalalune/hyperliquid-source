# RE-001: map node #115 db-stats consumer 0x5ef97b0 with its counter registry, decimal conversion and db.uptime entry

Task: RE-001. Bounded question: what does the third stats-snapshot
consumer 0x5ef97b0 write into the out map, where do its nine counter
names come from, how does it compute `db.uptime`, and who calls it?

Artifact: `artifacts/node/115/hl-node`, node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound in `provenance/artifacts.json`; check 1 of verify.py).

## What the routine does

`f(owner, ctx)` — owner carries nine u64 counters at +0x00..+0x40, a
handler chain at +0x780 and a last timestamp at +0x790; ctx holds a
`std::map<std::string, std::string>` at +0x08.

1. **Nine counters.** For i in 0..8 it writes
   `out[REGISTRY[i]] = decimal(counters[i])`, where the name comes from
   the global `std::map<int, std::string>` at 0x65039c8 via
   `map::at(i)` (a miss throws `__throw_out_of_range("map::at")`). The
   value string is fetched with `map_find_insert` 0x5ef40a0
   (`std::map::operator[]`) and move-assigned. The decimal conversion
   is inlined (see below).
2. **Chain walk and secs.** It walks the handler chain from
   `*(owner+0x780)` (links at +0x20, slot at +0x98) and calls the first
   link whose slot differs from the walker 0x5d4d490; if the first four
   links all carry the walker slot, it calls the fifth link's slot.
   Then `secs = (u64)(slot_now - last) / 1e6` as a double, formatted
   with `fmt_pct` 0x5eec680 (`"%f"`).
3. **`db.uptime` entry.** It assigns `"db.uptime"` to a stack string,
   lower-bounds the ctx map with it, inserts with `map_insert`
   0x5ef3c80 if absent, and move-assigns the formatted secs string
   into the node's value. Both stack strings are then disposed.

The sole caller is the 23-byte forwarding thunk at 0x5ef9f80, which
passes its arguments through, calls the consumer at 0x5ef9f88 and
returns 1. The thunk has no stored qwords and no RELATIVE relocations,
so its own caller is not determinable from the file.

## The counter registry (0x65039c8)

The static initializer 0x5efbd80..0x5effdbb builds a 9-entry
`{int, string}` stack array (stride 0x28) and range-inserts it via
`range_insert` 0x5ef11e0. `derive_names.py` in this packet parses the
initializer disassembly mechanically (string_assign literals + `movl`
keys in construction order, with the array-stride assertions) and
reproduces all nine pairs; verify.py checks `records.json` against it.

| key | name |
|----:|------|
| 0 | `db.wal_bytes_written` |
| 1 | `db.wal_syncs` |
| 2 | `db.user_bytes_written` |
| 3 | `db.user_keys_written` |
| 4 | `db.user_writes_by_other` |
| 5 | `db.user_writes_by_self` |
| 6 | `db.user_writes_with_wal` |
| 7 | `db.user_write_stall_micros` |
| 8 | `write-buffer-manager-limit-stops` |

Key 8 is not a literal: `name_join` 0x5fca2d0 builds
`lookup1(4) + "-" + lookup2(1)` = `"write-buffer-manager-limit" +
"-" + "stops"`. The same initializer first builds the 21-entry pair
map at 0x6503a00 (RocksDB-style compaction-stats column headers:
NumFiles/Files, Score/Score, ReadGB/Read(GB), ...), which this routine
does not read; it is recorded in `records.json` for context.

## The decimal conversion (inlined)

The digit-count dispatch uses thresholds 9 / 99 / 999 / 9999 and then
repeated divide-by-10000 steps (magic 0x346dc5d63886594b, `>> 75`),
adding 4 digits per step with the 999999 / 9999999 / 99999999 cut-offs.
The main loop divides by 100 with magic 0x28f5c28f5c28f5c3
(`hi = ((v >> 2) * magic) >> 64; q = hi >> 2; rem = v - 20 * ((hi & ~3)
+ (hi >> 2))`) and writes digit pairs from a 200-byte table built on
the stack from thirteen .rodata chunks; placed at their actual store
offsets (0, 16, ..., 176, and the 13th chunk at offset 185 via
`movups` at rsp+0x129, overlapping the 12th chunk's tail with
identical bytes) the chunks assemble to `"00".."99"` in order
(verify.py check 9 parses the build block for the (source, store
offset) pairs and checks both builds in the routine). The loop index starts at
length-1 (`lea -0x1(%rax),%esi` at 0x5ef98dc), pairs are written at
`buffer[idx]` and `buffer[idx-1]`, `idx -= 2`, and the leading one or
two digits are written at `buffer[0]` / `buffer[0..1]`. The model in
`tools/snapshot_consumer_97b0_115.py` emulates this literally and is
tested against Python's `str()` on 200,000 random u64 values plus the
dispatch boundaries.

The `secs` computation uses floating-point division (`secs = diff /
1e6`, divisor double at 0x4599a0 = 1000000.0); the sibling consumers
#3082/#3133 compute secs with an integer divide-by-1e6 magic instead.
The u64-to-double conversion is plain `cvtsi2sd` when the difference
is non-negative and the standard `(v >> 1) | (v & 1)` fixup when it is
negative (the `js` branch at 0x5ef9b6a); the fixup is exact only for
`v >= 2**63`, which is exactly its branch domain.

## Evidence

- `records.json` — semantic records only (branch site→target pairs,
  registry and pair tables, chain walk, census site lists, model spot
  check). No per-instruction mnemonic list: instruction-level detail
  lives only in the raw disassembly excerpts below.
- Verbatim objdump excerpts (whole functions, unmodified), regenerated
  with `export_excerpts.py`:
  `main.txt` (0x5ef97b0..0x5ef9f7f), `cleanup.txt` (0x5ef977e..0x5ef97b0),
  `thunk.txt` (0x5ef9f80..0x5ef9f97), `thunk_cleanup.txt`
  (0x5ef9f98..0x5efa001), `fmt_pct.txt`, `map_find_insert.txt`,
  `map_insert.txt`, `map_node_create.txt`, `string_compare.txt`,
  `string_move_assign.txt`, `string_assign.txt`, `range_insert.txt`,
  `pair_range_insert.txt`, `name_join.txt`, `name_lookup1.txt`,
  `name_lookup2.txt`, `walker.txt`, `initializer.txt`
  (0x5efbd80..0x5effdbb, 3031 lines). The `fmt_pct`,
  `map_find_insert`, `map_insert`, `map_node_create`,
  `string_compare`, `string_move_assign` excerpts are re-shipped
  verbatim from PR #3133 and `walker.txt` from PR #3082; each was
  regenerated with the same objdump command and diffed byte-for-byte
  against the source packet before committing.
- `census.py` / `callers.tsv` / `relocations.txt` — exhaustive E8/E9
  scan of the executable PT_LOAD segments (FDE-confirmed) plus stored
  qwords and RELATIVE relocations for the pinned addresses.
- `frames.txt` — the FDE lines for the 18 pinned windows.
- `derive_names.py` — mechanical derivation of the registry and pair
  table from the initializer disassembly.
- `verify.py` — the self-check; run it from the repository root:
  `python3 research/work-items/RE-001-snapshot-consumer-97b0-115/verify.py`

Objdump command (every excerpt):
`objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
with no post-processing. Mnemonics such as `endbr64` in the excerpts
are genuine instructions present in the target binary, not
placeholders.

## Model and tests

- `tools/snapshot_consumer_97b0_115.py` — `build_map(counters,
  slot_now, last)` (the whole consumer behaviour), the literal
  `to_decimal` / `digit_count` / `div100` / `u64_to_double`
  emulations, the five-link `select_slot_now` walk, `map_at`
  (throws on a missing key), and `insert_or_assign`.
- `tests/test_snapshot_consumer_97b0_115.py` — run directly
  (`python3 tests/test_snapshot_consumer_97b0_115.py`; pytest is not
  installed on this VM): 11 checks, including the 200,000-value
  random comparisons for `to_decimal` and `u64_to_double`, the
  `"%f"` cross-check against the C library's `snprintf`, the
  five-link walk cases, and the full `build_map` render.

## Observations, inferences, unknowns

Observations:
- This is the third stats-snapshot consumer in the
  0x5ef8000..0x5efb000 family (#3082 maps 0x5efda00, #3133 maps
  0x5ef8360). It shares `fmt_pct`, `map_find_insert` and `map_insert`
  with #3133, but differs in three ways: it does NOT clear the map
  first, it computes secs with floating-point division instead of the
  integer divide-by-1e6 magic, and its chain walk tests five links
  instead of three or four.
- The decimal conversion is inline here, while the sibling consumers
  call the standalone `to_string` helper 0x5d4f970 for the same job.
  The inlined copy uses the same table chunks and the same magic
  constants.
- The nine counter names are RocksDB `db.*` property names plus the
  composed `write-buffer-manager-limit-stops`; both tables are built
  by one static initializer and both are global; only the 9-entry map
  is read by this routine.

Inferences:
- A is an owner object whose first nine qwords are the nine db
  counters in registry order.
- B is a context struct holding a `std::map<std::string, std::string>`
  at +0x08.
- The thunk at 0x5ef9f80 is reached through a virtual call or a
  function pointer.

Unknowns:
- A's exact type and B's exact type (concrete class names not pinned).
- Who calls the thunk 0x5ef9f80 (no reference to it in the file).
- What the chain links' +0x98 slots return beyond a timestamp.
- Whether the pair map at 0x6503a00 is consumed by a sibling routine.

## Not claimed

`make verify` / `make test` / `make catalogue-check` were not run in a
tooled environment on this VM (no cargo/rustc, no git-lfs, no
Ghidra/Java); the packet's own `verify.py` and the model tests are the
verification performed here. No hosted CI result is claimed.
