# RE-004: reconstruct the node #115 keyed lookups and saturating totals behind the order value gate

This packet rebuilds, as executable pure-Python rules proved against the real instruction bytes, the seven
functions that the merged order value gate packet (`RE-004-order-value-gate-115`) had to stub: the record-kind
lookup `0x2a8a770` (zero rows, one row, many rows, shared default record, Once slow path), its stand-alone twin
`0x4ef4480`, the two default-returning wrappers `0x55e8c30` / `0x55e8cb0`, the structurally identical total readers
`0x2d35520` / `0x2d357d0` (two containers, deque or B-tree, saturating sum) and the ring binary search
`0x24c55a0` that the totals call. The rules reproduce 15000 generated cases with 0 mismatches against the bytes,
and 136 negative controls (104 byte mutants, 21 wrong rules, 11 damaged inputs) are all detected. A Rust port can
now take the exact key layout (20 bytes at row +0x48, 0x60-byte rows, returned pointer = row +8), the
one-row 20-byte compare, the unconditional trust in the bucket probe with a bounds panic at index >= row count,
the default-record fallback and the order of the Once check, the 0x38-byte ring rows and 0x20-byte-stride B-tree
nodes, and the saturation rule from `tools/order_value_lookups_115.py` instead of re-reading 2,621 bytes of code.

- Component ID: RE-004 (quantities and rounding); no other component
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: 0781ce04826eeefd89fe336cb8ea073be0c1de30 / references/can1357-hl (labels were not used)
- Claim status: observation for the control flow, field offsets, constants, comparison widths and saturation
  under the stated host model; inference for every role name; unresolved: the hash function, the bucket probe,
  the Once helper, the panic helper and the compare symbol (all stubbed)
- Scope included: the seven bodies above (2,621 bytes of FDE extent, 693 instructions), their field reads and host
  calls. Scope excluded: the bodies behind the stubs (`0x2b6e540`, `0x26fe6d0`, `0x4ef4560`, `0x4eff000` are owned
  by `RE-017-abci-keyed-result-115`), what the returned record means, the writers that fill these maps, and every
  progress gate. No gate is requested.

## Reproduce

Working directory: repository root. The tool reads the binary as bytes and never executes it; it needs only
the standard library and the shared evaluator `tools/decimal_scaled_u64.py`.

```
python3 tools/order_value_lookups_115.py --out research/work-items/RE-004-order-value-lookups-115
python3 -m unittest tests.test_order_value_lookups_115
```

The first command rewrites every generated file in this folder (all but `README.md` and `MANIFEST.sha256`)
byte for byte; it was run twice with different hash seeds and time zones with identical output, in about
45 s and 221 MB resident. Input check: the binary's SHA-256 must equal the value above or the tool stops.
`MANIFEST.sha256` lists every file of the folder. Test result at packet time: 41 tests, 0 failures, 0 skips, 18 s.

## Evidence

Coordinates are virtual addresses of node #115.

| Body | VA range | Bytes | Insns | Role (inferred) |
|---|---|---|---|---|
| `state_lookup` | 0x2a8a770-0x2a8a8df | 367 | 89 | row lookup in the map at state+0x968 (fields at +0x970/+0x978/+0x980/+0x9a0/+0x9a8), default when absent |
| `map_get` | 0x4ef4480-0x4ef4555 | 213 | 61 | the same lookup on a map object (rows +0x8, count +0x10, table +0x18, hasher words +0x38/+0x40), null when absent |
| `state_map_a` / `_b` | 0x55e8c30 / 0x55e8cb0 | 117 each | 33 | `map_get(state+0x968)` / `map_get(state+0x14d8)` plus default record and Once check |
| `total_a` / `total_b` | 0x2d35520 / 0x2d357d0 | 676 each | 170 | value of a key in two containers, summed, saturating at u64 max |
| `ring_search` | 0x24c55a0-0x24c5767 | 455 | 137 | binary search of a deque of 0x38-byte rows by 20-byte key |

`functions.tsv` has the extents (from the `.eh_frame_hdr` table through the shared evaluator) and the SHA-256 of
each body; `sites.tsv` lists every instruction as raw bytes (693 rows); `slots.tsv` the five slots and four stubbed
helpers. The two total readers differ only in rip-relative displacements and branch offsets; the two wrappers differ
in the `add $imm32,%rdi` (0x968 vs 0x14d8) and in the rip-relative operands.

**Lookup rule** (`state_lookup`, `map_get`, wrappers):
- row count 0: miss; no host call.
- row count 1: one 16-byte SSE compare plus one 4-byte compare against the row key at row +0x48; no hash. Cases
  that flip one bit in each of the 20 key positions all miss (`tests`, `damage.tsv`, `cases.tsv`).
- row count >= 2: the hash helper gets the two hasher words and the key; the bucket probe gets the table pointer,
  the hash and a 24-byte frame `{key pointer, rows pointer, row count}` on the stack (the frame is checked in every
  run: `probe` rows of `hook-sequences.tsv`). A null answer is a miss. Otherwise the word at answer-8 is the row
  index: index >= row count calls the panic helper with `(index, count, location)`; else the result is
  `rows + 0x60 * index + 8`. The key is not compared again after the probe (the `last` and `zero` probe modes
  return a row for a different key).
- default forms only: a miss returns the pointer stored in slot 0x64e71a8 (record at 0x64fd9b0). Before returning,
  the word at default+0x40 is tested; if non-zero the Once helper (slot 0x64df9f0) is called with
  `(default+0x40, 1, closure info, location)` on every path, hit or miss. In the file that word is 3, so the
  slow path is the one the bytes start in (what 3 means is not established).
- The record body (row +8..) is never read; the only row bytes read are +0x48..+0x5b (`field-reads.tsv`).

**Total rule** (`total_a`, `total_b`): each of the two containers (at set +0x18 and +0x38) is either a deque
`(cap, ptr, head, len)` or, when `cap == 0x8000000000000000`, a B-tree `(root, height)`. A deque row is 0x38 bytes
with the key first and a u64 value at +0x30, found through `ring_search` over the logical order `(head + i) mod cap`;
an index >= len counts as absent. A B-tree node holds up to 11 keys of 20 bytes at +0x168, a u16 key count at +0x246,
u64 values at +0x18 + 0x20 * i and child pointers at +0x248 + 8 * i; the search compares keys with the 20-byte
compare, descends while the height counter allows, and an absent key or a null root counts 0. The result is the
sum of the two values, replaced by 0xffffffffffffffff when the sum carries (the `cmovae` pair at the end).
Cases cover empty, deque (wrapped and not), B-tree of height 0, 1 and 2, and sums at 2^64-1 and 2^64.

**Ring rule** (`ring_search`): returns `(0, index)` for a present key and `(1, insertion point)` otherwise, over
the rotated layout, with the compare result only used by sign.

Raw tables: `cases.tsv` (310 case classes with counts), `hook-sequences.tsv` (host-call name sequences), `field-reads.tsv`
(every modelled-memory read by region and offset), `mutants.tsv`, `spec-flaws.tsv`, `damage.tsv`.
Analysis was complete for the seven bodies (linear sweep of each FDE extent ends exactly at the extent end).

## Implementation and comparison

`tools/order_value_lookups_115.py` runs each body's real bytes on the concrete evaluator in
`tools/decimal_scaled_u64.py` (extended in the tool with `cltq`, call through a register and the `movd`, `pcmpeqb`, `pand`,
`pmovmskb` forms). Memory the model did not write reads as unknown, so an unexpected read fails the run. The hash,
probe, Once helper, panic helper and compare are recorded host calls; the compare returns the first byte difference.
Each case is built from a seeded generator (one seed per body derived from its name), run, and compared with the
pure rule: result, outcome (return or panic) and the full ordered host-call log with arguments.

| Body | Cases |
|---|---|
| `state_lookup`, `map_get` | 2200 each |
| `state_map_a`, `state_map_b` | 1800 each |
| `total_a`, `total_b` | 2400 each |
| `ring_search` | 2200 |
| total | 15000, 0 mismatches |

Controls (all counted in `measure.json`): 104 byte mutants (every conditional branch flipped and every imm8 of
`imul`/shift/ALU instructions not aimed at `rsp` incremented, each checked against the first 140 cases of its body;
104 killed, 0 survived); 21 wrong rules (single-byte compare width, `>` for `>=` on the bounds check, missing
default, missing Once call, key re-check after the probe, hash on one row, wrapping instead of saturating sum,
late insertion point); 11 damaged inputs (flipped binary byte changes the digest, seven mid-function starts refused,
key pointer outside modelled memory refused, unpopulated containers refused).
This is not a Rust port: no Rust is written and no equivalence to the original source is claimed.

## Results and limitations

- `measure.json`: cases 15000, negative_controls 136, negative_detected 136 (mismatches 0, mutants killed 104,
  survived 0, spec flaws 21, damage controls 11).
- The hash, the bucket probe (so that the table really finds the right row), the Once helper, the panic helper and the
  compare symbol are stubs: the packet proves what these functions do with the answers, not the answers. The probe model
  can return rows for the wrong key (that is how the unconditional trust is shown); real tables are consistent.
- B-trees are generated only as complete trees of height 0-2 with at most 3 separators per inner node, and deques
  only sorted with distinct keys; unsorted input is outside the model.
- Role names (kind lookup, total, ring) are mine. The meaning of the returned record, of the Once word and of the
  keys (the 20 bytes are address-sized) is not established. The merged gate packet's question about the byte at record
  +0x3c is narrowed only to this: that byte lies 4 bytes before the key (row +0x44) and no lookup in this packet reads it.
- Next question: the writers behind `state+0x968` and the sets read by `total_a`/`total_b` (who inserts rows, in what
  order, and what lives in the record that the gate later reads at +0x3c).
