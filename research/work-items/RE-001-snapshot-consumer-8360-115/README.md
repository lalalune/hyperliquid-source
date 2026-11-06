# RE-001: map the node #115 stats-snapshot map consumer 0x5ef8360

**Task:** RE-001 (node #115).
**Bounded question:** what does the sibling consumer `0x5ef8360` do with a
published stats snapshot, and how does its map output differ from the twin
text-dump consumer `0x5eefda0` (open PR #3082)?
**Artifact:** `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes).

## What the routine does

The routine fills a `std::map<std::string, std::string>` held at `ctx+0x08`
with 46 entries from a 312-byte stats snapshot. It is the sibling of the
twin consumer `0x5eefda0`, which renders the same snapshot as an
ostringstream text dump; this one instead stores every number under a
string key. It is called exactly once, from the twin caller `0x5ef9520`
(open PR #3049) at `0x5ef96db`, with the snapshot copy in `rdi`, the ctx
in `rsi` and the chain head in `rdx`.

It first destroys the map's old tree and resets the header (root 0,
leftmost = rightmost = &header, count 0), then writes, in order:

| key | value |
| --- | --- |
| `di` | snapshot name (the `name@0x<ptr>#<pid>` string) |
| `capacity` | decimal of snapshot+0x00 |
| `secs_for_last_collection` | `"%f"` of `elapsed(snapshot) / 1e6` |
| `secs_since_last_collection` | decimal of `(slot_now - snapshot+0x130) / 1e6` |

then, for all 14 slots `i = 0..13`, three entries each:
`count.<role>` (decimal of snapshot+0xb0[i]), `bytes.<role>` (decimal of
snapshot+0x40[i]), `percent.<role>` (`"%f"` of
`value * 100.0 / capacity`). Every slot produces all three entries,
including zero counts — unlike the twin's text dump, which skips zero
counts. The role names are lowercase-hyphen strings from the table at
`0x6503c00` (`data-block`, `filter-block`, `filter-meta-block`,
`deprecated-filter-block`, `index-block`, `other-block`, `write-buffer`,
`compression-dictionary-building-buffer`, `filter-construction`,
`block-based-table-reader`, `file-metadata`, `blob-value`, `blob-cache`,
`misc`).

The chain is NOT walked: the routine calls the chain head's vtable slot
`+0x98` once, directly, and uses the return only as `slot_now` for
`secs_since_last_collection`. `secs_since` is the unsigned wrap-around
difference divided by 1,000,000 by the magic multiply
`0x431bde82d7b634db` (high word, shift 18), verified equal to unsigned
`// 1_000_000` on 200,010 values.

The map operations are the libstdc++ `_Rb_tree` shapes, pinned whole:
`map_find_insert` 0x5ef40a0 (the `operator[]` shape used for the four
header keys), `map_insert` 0x5ef3c80 (the per-slot inserts),
`map_insert_pos` 0x5ef3ac0, `map_node_create` 0x5ef3ed0,
`tree_destroy` 0x5eec590 (the clear), `string_compare` 0x5eeb970 and
`string_move_assign` 0x5eebb20. The key strings are built by
function-local static accessors (one call each, all from this routine)
and three prefix builders (`count.` / `bytes.` / `percent.` + role name).
The u64-to-decimal conversion is the same digit-pair algorithm as the
standalone helper `0x5d4f970`, inlined three times per slot; the
`"%f"` formatting is the helper `0x5eec680`.

## Correction to open PR #3082

#3082's `elapsed_ns` model and its tests are **wrong on the else
branch**. The binary code at `0x5eee580` is `mov $0x0,%edx; cmovae
%rdx,%rax` (`elapsed.txt` 0x5eee59b/0x5eee5a0): `rdx` was just zeroed,
so the else branch returns **0**, not `last`. #3082's model returns
`last_value` in that case and its tests assert
`elapsed_ns(30, 100) == 30` and `elapsed_ns(50, 50) == 50`. The
correct rule is **hi − lo when lo < hi, else 0** (unsigned 64-bit),
and this packet's model implements it, with tests asserting 0 for both
cases. See `records.json` `corrections`.

## Evidence

Every excerpt is the raw output of
`objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
with no post-processing; `export_excerpts.py` regenerates them and
`verify.py` checks them byte-for-byte against fresh objdump output and
against the raw binary. The `endbr64` instructions in the excerpts are
genuine instructions present in the target binary, not placeholders.

- `main.txt` — the consumer 0x5ef8360..0x5ef94ee (4,494 bytes)
- `cleanup.txt` — the shared cleanup fragment 0x5ef823c..0x5ef835a
- `caller_5ef9520.txt`, `site-5ef96db.txt` — the twin caller and the
  call site (re-shipped verbatim from open PR #3049)
- `elapsed.txt`, `fmt_pct.txt`, `to_string.txt`, `tree_destroy.txt`,
  `map_find_insert.txt`, `map_insert.txt`, `map_insert_pos.txt`,
  `map_node_create.txt`, `string_compare.txt`, `string_move_assign.txt`
  — the helpers, whole-function
- `key_di.txt`, `key_capacity.txt`, `key_secs_for_last.txt`,
  `key_secs_since_last.txt`, `key_count.txt`, `key_bytes.txt`,
  `key_percent.txt`, `role_name.txt` — the key builders, whole-function
- `initializer.txt`, `initializer_cleanup.txt`, `string_init.txt`,
  `string_fini.txt` — the role-name table initializer (re-shipped
  verbatim from open PR #3082)
- `frames.txt` — the readelf FDE lines for all 25 pinned routines
- `callers.tsv`, `relocations.txt` — the exhaustive census (E8/E9 scan
  of every executable segment, confirmed by disassembly; stored qwords
  and RELATIVE relocations), reproducible with `census.py`
- `records.json` — semantic records only: routine, snapshot fields,
  header entries, entry loop, name table, helpers, chain, cleanup,
  callers, census summary, corrections, not-claimed, and the model
  spot-check render
- `verify.py` — the self-check; run it from the repo root and expect
  `ALL CHECKS PASSED`

## Model and tests

- `tools/snapshot_consumer_8360_115.py` — the model: `build_map`
  (the 46-entry map), plus `to_string_u64`, `u64_to_f64`,
  `elapsed_ns` (corrected else-0), `divide_by_1e6`, `format_pct`
- `tests/test_snapshot_consumer_8360_115.py` — 16 tests, run with
  `python3 tests/test_snapshot_consumer_8360_115.py` (pytest is not
  installed on this VM). The spot render, the divide-by-1e6 magic and
  the to-string conversion are checked against `// 1_000_000` and
  `str()` on 200,000 random values each; the `"%f"` values are
  cross-checked against C `printf("%f")` (500.000000, 0.195312,
  100.000000, 0.000000, 0.333333, 0.666667, inf, -nan).

## Not claimed

- What ctx is, who allocates it, what its +0x00 field holds, and who
  calls the twin caller `0x5ef9520` (its only entries are the two
  indirect thunks at `0x5ef9760`/`0x5ef9770`, which have no direct
  callers and no stored qwords or RELATIVE records).
- What the slot `+0x98` handler computes (its return is treated here
  only as a counter/timestamp value), and what the slot
  `+0x70`/`+0x78`/`+0x80`/`+0x88` producers compute.
- The exact throw-site mapping of the nine landing pads (they jump
  into the shared cleanup fragment; the exception table was not
  decoded).
- The third map-building consumer in FDE `0x5ef97b0..0x5ef9f7f` (it
  calls the same map helpers: `string_compare`, `string_move_assign`,
  `fmt_pct`, `map_find_insert`, `map_insert`) — an open lead.
- Behaviour on a null chain link, a null ctx map, or a snapshot whose
  capacity is zero with a nonzero value (the model prints `inf`; the
  binary's stream would print `inf` the same way, but no binary run
  confirms it).

## Environment

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify` / `make test` / `make catalogue-check` were not run in a
tooled environment; the packet's own `verify.py` (artifact digest,
excerpt regeneration, byte checks, FDE lines, census reproduction,
records + model spot check, model tests) passes here.
