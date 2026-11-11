# fees: reconstruct the node #115 open order cap threshold (0x5495210 / 0x5495680)

- Component ID: fees (order admission cap; the mapped sibling 0x2a82220 sits under RE-001)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; the #94 packet `fees-open-order-cap-94` (git history) is a clue only
- Claim status: observation (bytes run by the evaluator) and inference (names of the two result heads)
- Scope included and excluded: the two threshold functions end to end, with the count lookup, the book and second-map volume lookups, the hashbrown probes and the address predicate running as real bytes. Excluded: the callers (order insert paths), the key hashers, the Once call, the overflow recorder and the panic slots (stubbed), the third sibling 0x2a82220.

With this packet the open order cap of node #115 can be rebuilt as a pure function: the threshold is `1000 + min(scaled_volume / 500,000,000, 4000)` (flat `10000` for eight fixed addresses), the order passes when the user's open count is strictly below it, and the all-ones key, a nonzero byte +0xb8 of the kind-1 object, and a count under 1000 pass early. The Python model in `tools/open_order_threshold_115.py` agrees with the real bytes on 12,400 generated cases in both copies, and 166 negative controls (wrong readings, flipped branches and constants, corrupted bytes, out-of-domain inputs) are all detected.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/open_order_threshold_115.py --out research/work-items/fees-open-order-threshold-115
python3 -m unittest tests.test_open_order_threshold_115
```

Python 3 standard library only; section and FDE parsing come from `tools/elf_index.py` and `tools/fde_extents.py`; no objdump or readelf runs and the node is never executed. The tool checks the SHA-256 of `artifacts/node/115/hl-node` first. Generated files and their hashes are in `MANIFEST.sha256`; the tool was run twice (different hash seed and time zone) and the outputs compared byte for byte. Coordinates are virtual addresses; in `.rodata` they equal file offsets.

## Evidence

Two complete FDEs, 1,121 bytes and 245 instructions each: `0x5495210` and `0x5495680`. They differ in exactly three displacements (`copy-diff.tsv`): the count map at state +0x968 / +0x14d8, the books vector length at +0x7d0 / +0x1340 and its pointer at +0x7c8 / +0x1338. Everything else is identical byte for byte once rip-relative targets are resolved. Shared callees (all decoded to their FDE ends, `instructions.tsv`):

| role | address | notes |
| --- | --- | --- |
| count lookup | 0x4ef4480 (FDE 213 B) | index map, entry stride 0x60, key +0x48, row = entry + 8; count word row +0x20 |
| book lookup | 0x4716be0 (214 B) | stride 0x98, key +0x80; words +0x50 and +0x58 |
| second lookup | 0x4716cc0 (205 B) | stride 0x70, key +0x58; words +0x40 and +0x48 |
| probes | 0x4eff000, 0x3ee6740, 0x3ee69c0 | hashbrown group probe, run as real bytes |
| predicate | 0x421a520 (347 B) via slot 0x64e5ae8 | eight 20-byte addresses, `addresses.tsv` |
| hashers | 0x4ef4560, 0x4717440 | stubbed (return the case hash) |
| Once call | slot 0x64df9f0 | stubbed; fills the lazy default and clears the flag |
| overflow recorder | slot 0x64e4ea8 | stubbed; Locations 0x6493948, 0x6492e68, 0x6483fe0 |

The three lazy defaults (count 0x64fd9b0 via slot 0x64e71a8, books 0x64fda80, second 0x64fd958) are found through RELATIVE relocations; their constructors run as bytes and all produce zero words (`evidence.json`, `lazies`). The eight predicate addresses equal, in value and order, the list of the #94 gate 0x37e4fb0 (`fees-open-order-cap-94`), found here as `.rodata` constants at 0x454410, 0x454420, 0x456c10, 0x450d30, 0x4513d0, 0x453d70, 0x455be0, 0x454100, which is the cross-check of that #94 clue against #115 bytes; the #94 gate was inlined into six order functions, the #115 form is a standalone function returning a result head. The head `0x8000000000000018` is the reject side and `0x800000000000001b` the pass side (head + 3); the names pass/reject are inferred from the #94 tag 0xc3 ("Too many open orders") and are not proved here.

Reading, as the model implements it (`model()` in the tool):

1. Look the 20-byte key up in the count map (key inline at descriptor +1, or at object +0xc8 when the descriptor byte is 1). A missing key uses the lazy default count (0). Run the Once call first if the default is not initialised.
2. Count < 1000: pass. Otherwise, for descriptor byte 1: object byte +0xb8 nonzero passes. The all-ones key passes. Descriptor byte 2 rejects. Byte 1 with object byte +0xa0 nonzero rejects. Other bytes reject when order byte +0x31 is nonzero or order byte +0x19 is not 2.
3. Limit: 10000 if the key is one of the eight addresses; otherwise sum words +0x50 and +0x58 over every book (saturating, overflow reported to the recorder), add word +0x40 of the second row, saturating; the second row +0x48 overflow is only reported. Limit = 1000 + min(scaled / 500,000,000, 4000), the division being `(x >> 8) * 0x44b82fa09b5a53 >> 75`, proved equal to floor(x / 5e8) for every u64 (`evidence.json`, `division_proof`).
4. Pass when count < limit, else reject. The input state is never written.

## Implementation and comparison

`tools/open_order_threshold_115.py` holds the table decoder (must land on every FDE end), a strict-memory evaluator (reading an unset byte faults), and the model. Each case builds the state with real swiss-table index maps (matching, decoy, missing, multi-entry, corrupted-index panic), lazy-default combinations, book vectors of 0 to 4 maps, near-overflow volume words, and counts placed on the edge of the limit the same input produces. The machine result must equal the model on the result head, the ordered event list (hash, Once, overflow records), the returned pointer and an unchanged input state. Nothing is implemented in Rust yet.

- Cases: 12,400 (6,200 per copy), 0 mismatches. Outcomes (`evidence.json`): A:panic 26, A:pass 3745, A:reject 2429, B:panic 24, B:pass 3832, B:reject 2344.
- Both copies run to the `ret`; the only instructions never executed are listed in `unreached.tsv` (dead saturating re-checks after a certain overflow, the panic arms behind the probe's own bounds check, the table-full exits of the probes, which valid tables cannot reach).
- Negative controls: 166 detected out of 166 counted (byte corruption 3, instruction 135, out of domain 7, wrong reading 21); 16 further mutants survived and are listed in `mutations.tsv` as survived, not counted:
- instruction: A 0x5495210 0x54952a2 low bound `cmp rbx,0x3e8`
- instruction: A 0x5495210 0x5495436 kind one `mov rsi:32,0x1`
- instruction: A 0x5495210 0x54954ac branch `jb 0x54953f8`
- instruction: A 0x5495210 0x5495593 kind one `mov rsi:32,0x1`
- instruction: A 0x5495210 0x549561b kind one `mov rsi:32,0x1`
- instruction: A 0x4eff000 0x4eff0e0 branch `je 0x4eff12f`
- instruction: A 0x4eff000 0x4eff0e9 branch `jae 0x4eff036`
- instruction: A 0x3ee6740 0x3ee6820 branch `je 0x3ee686f`
- instruction: A 0x3ee6740 0x3ee6829 branch `jae 0x3ee6776`
- instruction: A 0x3ee69c0 0x3ee6a90 branch `je 0x3ee6adf`
- instruction: A 0x3ee69c0 0x3ee6a99 branch `jae 0x3ee69f6`
- instruction: B 0x5495680 0x5495712 low bound `cmp rbx,0x3e8`
- instruction: B 0x5495680 0x54958a6 kind one `mov rsi:32,0x1`
- instruction: B 0x5495680 0x549591c branch `jb 0x5495868`
- instruction: B 0x5495680 0x5495a03 kind one `mov rsi:32,0x1`
- instruction: B 0x5495680 0x5495a8b kind one `mov rsi:32,0x1`
  The survivors are default-count compares that can never see a nonzero default, `Once` argument constants the stub ignores, dead re-checks, and probe exits that need a full hash table.

## Results and limitations

`measure.json`: cases 12400, negative_controls 166, negative_detected 166. Peak resident set of a full generation: 409 MB (cases are generated, run and dropped one by one); a full run takes about three minutes. The data share of the packet is above the 0.6 target (0.74) because the 6,000-line floor is met with the instruction listing and the sampled case table, not with more code.

Limits: hashers, Once, recorder and panic slots are stubs, so hashing and the exact Location semantics are not reconstructed; the meaning of the two result heads and of the book/second-map owners (the callers pass the state of an order book and a user table) is inferred, not proved; callers are not modelled. The sibling 0x2a82220 (914 bytes, mapped in `RE-001-node115-raw-volume-tag-threshold`) is a third form of the same test and is not re-owned here. The Location edges at 0x5495657 and 0x5495ac7 inside these functions belong to the merged RE-001 edge packets; this packet only runs the functions. No component gate is requested.

Next question: the callers of 0x5495210 / 0x5495680 (`0x58fc770`, `0x58fe4d0`, `0x5901dd0`, `0x5905cf0`, `0x5919fc0` and their twins) to see how the head is turned into the status tag, and the key hashers 0x4ef4560 / 0x4717440.
