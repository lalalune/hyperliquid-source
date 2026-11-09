# vaults: reconstruct the node #115 vault amount helper 0x44a9430 with its two index-map lookups, SipHash-1-3 hasher and two deque searches

This packet makes it possible to reimplement the vault amount helper at `0x44a9430` (a `base + (stored + extra) / 100` value with
saturation at both ends) and everything it calls inside the node: the two index-map lookups `0x4716be0` / `0x4716cc0`, the SipHash-1-3
key hasher `0x4717440` with its `Hasher::write` body `0x45927a0`, and the two `VecDeque::binary_search` bodies `0x45584b0` / `0x455b7b0`.
All seven bodies run as real bytes in a small x86-64 evaluator and are compared with a separately written rule list (including an
independent SipHash-1-3) on 11,047 cases; the five callees that are not run as bytes (base conversion, third-store lookup, extra term,
lazy initialiser, overflow event) are named with their relocation targets as the open boundary of the reconstruction.

- Component ID: vaults (docs/COMPONENTS.md vaults row); related task RE-007 (risk) is only context, no TASKS row exists for vaults
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was copied
  (labels in references/can1357-hl were not used)
- Claim status: observation (byte-level behaviour of the seven bodies, checked); inference (the roles "amount helper", "base", "extra
  term" are names given here); unresolved (the five modelled callees, listed below)
- Scope included and excluded: included - control flow, arithmetic, saturation, layouts and error paths of the seven bodies for every
  reachable branch; excluded - the bodies behind the five stub boundaries, the callers `0x44a97b0` / `0x44af2f0`, any Rust source claim,
  any execution of the node

## Reproduce

Working directory: repository root. Requires only Python 3 standard library and the pinned binary; no binutils, no network, the node is
never executed.

```
python3 tools/artifacts.py verify
python3 tools/vault_amount_helper115.py --out research/work-items/vaults-amount-helper-115
python3 -m unittest tests.test_vault_amount_helper115
(cd research/work-items/vaults-amount-helper-115 && sha256sum -c MANIFEST.sha256)
```

The tool refuses a binary whose SHA-256 differs from the pinned value, reads the ELF only through `tools/elf_index.py`
(`sections`) and `tools/fde_extents.py` (`eh_frame_records`), skips SHT_NOBITS sections, and writes every file deterministically
(no time, no randomness beyond a fixed LCG seed, no absolute paths). Regeneration takes about 95 seconds and 320 MB resident; the
unit tests (41) take about 70 seconds. The evaluator in the first third of the tool is the one used by `tools/funding_rate115.py`
(copied, with `rol` added) so that the packet stands alone.

## Evidence

Coordinates are virtual addresses of node #115; file offsets are derived only through the section table (`Image.offset`).

| body | VA | FDE size | role |
| --- | --- | --- | --- |
| amount helper | `0x44a9430` | `0x37f` | subject |
| first index-map lookup | `0x4716be0` | `0xd6` | entry stride `0x98`, key at entry `+0x80` |
| second index-map lookup | `0x4716cc0` | `0xcd` | entry stride `0x70`, key at entry `+0x58` |
| key hasher | `0x4717440` | `0x16b` | SipHash-1-3 over 20 bytes |
| hasher write | `0x45927a0` | `0x1d7` | std `SipHasher13::write` |
| deque search, 32 byte entries | `0x45584b0` | `0x121` | `VecDeque::binary_search`, target key 0 |
| deque search, 40 byte entries | `0x455b7b0` | `0x11c` | same, third store |

What the bytes establish (all reproduced by `tools/vault_amount_helper115.py`):

1. `0x44a9430(ctx, key20)`: `ctx` holds three object pointers at `+0`, `+8`, `+0x10`. The 20 byte key is copied to the stack three
   times (once per lookup) and passed by pointer.
2. Lookup 1 (`ctx[0] + 0x60`, index map `0x4716be0`) returns an entry pointer or null. A lazy-state word at `0x64fdaf8` (file value 3,
   so "not initialised") is tested first; non-zero runs the initialiser slot `0x64df9f0` and continues. The entry (or the default cell
   `0x64fda80` when null) goes to the base conversion slot `0x64e6d20` with `edx = ecx = 1`, `r9 = ctx[0] + 0x148` and `ctx[0]` as the
   first stack argument; its result is the signed base amount.
3. Lookup 2 (`ctx[1] + 0x370`, index map `0x4716cc0`) returns a store header or null (default header `0x64fd958`, lazy word
   `0x64fd9a8`, same initialiser slot with a different payload pair). Word 0 of the header selects the layout: `0x8000000000000000`
   is a B-tree (root `+8`, height `+0x10`; node length `u16` at `+0x16a`, keys at `+8`, first-word values at `+0x60` stride 24,
   children at `+0x170`), anything else is a VecDeque (capacity, buffer, head, length) of 32 byte entries searched by `0x45584b0` for
   key 0 (constant at `0x459348`, bytes `00`x8). A hit yields the entry word at `+8`, a miss or an empty root yields 0.
4. Lookup 3 goes through the pointer slot `0x64e6498` with `ctx[2]`. Its answer is a keyed set (deque of 40 byte entries searched by
   `0x455b7b0`, or a B-tree whose node length is at `+0x1c2`, keys at `+0x168`, children at `+0x1c8`). Only when key 0 is present does
   the body call `0x3694920(out, store, 0, 0, ctx[2] + 0x58)`; bit 0 of the first output byte means "none", otherwise the second
   output word is added to the stored value.
5. The sum saturates at `2^64-1` (the event slot `0x64e4ea8` is called with location `0x6487460`), is divided by 100 as
   `((sum >> 2) * 0x28f5c28f5c28f5c3 >> 64) >> 2`, and added to the base with signed overflow saturating at `2^63-1`
   (event location `0x648ba50`). `divisor-check.tsv` shows the error term `e = 25 * M - 2^66 = 11`, which makes the sequence exact for
   every `x >> 2 < 2^62` (`e * 2^62 < 2^66`), plus 652 boundary points with 0 mismatches.
6. The index-map lookups have three arms: length 0 -> null; length 1 -> a 20 byte `pcmpeqb` compare of the single entry; length >= 2
   -> SipHash-1-3 of the key under the two hasher words at `map + 0x38` / `map + 0x40`, then a raw-table probe (`0x3ee6740` /
   `0x3ee69c0`, modelled) whose answer is an index checked against the length (failure -> slice index panic slot `0x64df620`).

Branch and failure table of `0x44a9430` (every row was reached by at least one case; `cases_reaching` in `function-rows.tsv`):

| branch at | taken when | effect |
| --- | --- | --- |
| `0x44a946c` `jne 0x44a96d9` | lazy word `0x64fdaf8` non-zero | call initialiser slot `0x64df9f0` with payload (`0x64fda80`), resume at `0x44a9472` |
| `0x44a947c` `cmovne` | lookup 1 returned an entry | use the entry instead of the default cell `0x64fda80` |
| `0x44a94d7` `jne 0x44a971f` | lazy word `0x64fd9a8` non-zero | initialiser slot with payload (`0x64fd958`), resume at `0x44a94dd` |
| `0x44a94fe` `jno 0x44a9573` | header word 0 is not `0x8000000000000000` | VecDeque layout for store 1, else B-tree walk at `0x44a9500` |
| `0x44a9507` `je 0x44a95bc` | tree root is null | held value 0 |
| `0x44a9536` `je 0x44a9560` | node has no keys | descend into child 0 |
| `0x44a9558` `je 0x44a95b0` | first key equals 0 | held value = first word of value slot |
| `0x44a9567` `jb 0x44a95bf` | height counter exhausted | miss, held value 0 |
| `0x44a9587` / `0x44a958d` | search missed / index >= length | held value 0 |
| `0x44a95e6` `jne 0x44a9653` | store 3 header word 0 is not the niche | deque layout, search with `0x455b7b0` |
| `0x44a95ef` `je 0x44a9667` | key-set root is null | key 0 absent, no extra term |
| `0x44a9638` `je 0x44a9671` | key set has key 0 as first key | extra term path |
| `0x44a9662` `je 0x44a9671` | deque search reported a hit | extra term path |
| `0x44a968c` `jne 0x44a9698` | extra output byte bit 0 set | extra term 0 (the word at `+0x28` is not read) |
| `0x44a96a3` `jb 0x44a978d` | `stored + extra` carries | event slot with location `0x6487460`, sum becomes `2^64-1`, resume at `0x44a96a9` |
| `0x44a96c4` `jo 0x44a9765` | `base + quotient` overflows signed | event slot with location `0x648ba50`, result `2^63-1`, jump to the epilogue `0x44a96ca` |

The event slot returns in both overflow rows (the body continues after it), so the node's behaviour after a checked-arithmetic event
depends on the body behind `0x64e4ea8 -> 0x4524e40`, which is outside this packet; the saturated results above are what the helper itself
computes after the call returns.

Raw tables: `constants.tsv` (bytes read from the ELF), `call-sites.tsv` (every call of the seven bodies; indirect calls with the
pointer slot and the relocation read from `.rela.dyn`: `0x64e6d20 -> 0x3beb980`, `0x64e6498 -> 0x369a210`, `0x64df9f0 -> 0x5c87d50`,
`0x64e4ea8 -> 0x4524e40`, `0x64df620 -> 0x1680cbf`), `object-fields.tsv`, `function-rows.tsv` (per instruction: how many cases
reached it; 620 distinct instructions reached), `outcomes.tsv`, `cases-sample.tsv` (every 5th case), `layout-facts.tsv` (33 claims about offsets, strides and constants, each
read from the decoded instruction bytes of its function with an exact minimum count and the matching sites; all hold).

The reconstructed behaviour in one place (this is `spec()` of the tool, condensed; `u64` and `i64` are the machine widths):

```
def helper(ctx, key):                                   # 0x44a9430
    cell   = map1_lookup(ctx.self.map1, key)            # 0x4716be0: None or an entry
    base   = base_conversion(cell or DEFAULT_CELL)      # slot 0x64e6d20, signed result (modelled)
    header = map2_lookup(ctx.obj2.map2, key)            # 0x4716cc0: None or a store header
    store  = header or DEFAULT_STORE                    # lazy words are cleared by the initialiser slot first
    stored = 0
    if store.word0 == NICHE:                            # B-tree: leftmost path only, key 0 is the smallest u64
        node = store.root
        for _ in range(store.height + 1):
            if node is None: break
            if node.len > 0 and node.keys[0] == 0: stored = node.values[0].word0; break
            node = node.children[0] if node.children else None
    else:                                               # ring of 32 byte entries
        hit = ring_search32(store, 0)                   # 0x45584b0
        if hit is not None and hit < store.len: stored = store.entry(hit).value
    members = lookup3(ctx.obj3, key)                    # slot 0x64e6498: a ring of 40 byte entries or a key set
    extra = 0
    if members.contains(0):                             # 0x455b7b0 / key-set walk
        flag, term = extra_term(members, ctx.obj3)      # 0x3694920
        extra = 0 if flag & 1 else term
    total = stored + extra
    if total >= 2**64: event(0x6487460); total = 2**64 - 1
    quotient = total // 100                             # multiply-shift, exact for every u64
    result = base + quotient
    if result > 2**63 - 1: event(0x648ba50); result = 2**63 - 1
    return result
```

An index-map lookup (`0x4716be0` / `0x4716cc0`) is: no entries -> miss; one entry -> compare all 20 key bytes; more -> hash the key
with SipHash-1-3 under the map's two key words, probe, bounds-check the index against the entry count (panic otherwise), return the
entry address.

Layouts the helper and its callees read (offsets in bytes; every offset is a row of `layout-facts.tsv` or `object-fields.tsv`):

| object | offset | meaning | read by |
| --- | --- | --- | --- |
| context | `+0` | first object (`self`) | `0x44a9444` |
| context | `+8` | second object (map 2 at `+0x370`) | `0x44a94b2` |
| context | `+0x10` | third object (lookup 3 argument, extra-term argument `+0x58`) | `0x44a95bf` |
| `self` | `+0x60` | first index map | `0x44a9456` |
| `self` | `+0x148` | argument of the base conversion slot | `0x44a9484` |
| index map | `+8` / `+0x10` | entries pointer / entry count | `0x4716bfe`, `0x4716beb` |
| index map | `+0x18` | raw table handed to the probe | `0x4716c69` |
| index map | `+0x38` / `+0x40` | the two SipHash key words | `0x4716c3b`, `0x4716c3f` |
| map 1 entry | `+0` / `+0x80` | looked-up cell word / 20 byte key | passed on at `0x44a949d`, `0x4716c06` |
| map 2 entry | `+0` / `+0x58` | store header / 20 byte key | `0x44a94f5`, `0x4716ce6` |
| store header | `+0` | capacity, or `0x8000000000000000` for a B-tree | `0x44a94f5`, `0x44a95e3` |
| store header | `+8` / `+0x10` / `+0x18` | buffer or root / head or height / length | `0x44a958f`, `0x44a9589` |
| ring entry (store 1) | `+0` / `+8` | key / value word, 32 bytes per entry | `0x4558523`, `0x44a95aa` |
| ring entry (store 3) | `+0` | key, 40 bytes per entry | `0x455b820` |
| tree node (store 1) | `+8`, `+0x60`, `+0x16a`, `+0x170` | keys, values (24 byte stride), length, children | `0x44a9538`, `0x44a95b3`, `0x44a9514`, `0x44a9569` |
| tree node (store 3) | `+0x168`, `+0x1c2`, `+0x1c8` | keys, length, children | `0x44a9615`, `0x44a95f7`, `0x44a9649` |
| hasher state | `+0` to `+0x18`, `+0x30`, `+0x38`, `+0x40` | v0 v2 v1 v3 words, byte count, tail word, tail length | `0x45927a1` and following |

The map-1 and map-2 entries start with the looked-up words, so the lookup result is the entry address itself and no separate value
pointer exists.

## Implementation and comparison

`tools/vault_amount_helper115.py` contains: the evaluator, `Harness` (builds a heap image per case: three objects, two index maps with
decoy entries whose keys differ in a chosen byte lane, deque rings with wrap, B-trees of height 0 to 3, lazy words and default
stores), the rule list `spec()` (with `siphash13`, `deque_find` as `VecDeque::binary_search`, `tree_find`, `lookup_rows`), the
case generators, 23 named wrong readings, the byte-edit mutants and the structural controls.

- Stubs (recording, with their contract checked on every call): raw table probes `0x3ee6740` / `0x3ee69c0`, base conversion slot,
  third-store slot, extra term `0x3694920`, lazy initialiser (checks its payload words and installs the default store), overflow
  event (returns), bounds panic slot (raises). Every stub verifies its arguments (key bytes, table words, hash equal to the independent
  SipHash, closure words), so a wrong call shape stops the case.
- Real bytes: the seven bodies above. The evaluator also checks that the callee-saved registers and stack pointer are restored and
  that the heap image is unchanged by the body.
- Cases: 11,047 (47 named, the rest from a fixed LCG): all combinations of {absent store, deque, B-tree} x {deque, B-tree}, map sizes
  0/1/2/3/5, probe answering out of range, lazy words set or clear, base and sums at 0, 99, 100, 101, `2^63-1`, `2^64-1`.
  Result: 0 mismatches of result and call log.
- Negative controls: 302 made, 286 detected, 16 equivalent. 23 named wrong readings (no division, divide by 128, ceiling, round half
  up, wrapping instead of saturating, unsigned base, extra without key 0, extra doubled, flag bit 1, inverted presence, default store
  ignored, last deque entry, lookup order swapped, ...) are each refused by at least two cases; 29 structural controls (wrong digest,
  mid-function address, NOBITS address, truncated ELF, every stub removed, every real body demoted to a stub, int3 at each entry,
  flipped hash bit, off-by-one key pointer, tampered divisor, and an edited multiplier byte and an edited stride byte that the layout
  fact table must notice); 250 byte edits (a reached conditional jump flipped, an immediate
  bit flipped, a structure displacement changed) of which 234 change the result on at least one of 1,000 sampled cases.
- The 16 surviving edits are listed in `equivalent-mutants.tsv` with the reason each cannot change an observable result (for
  example the key tail copy lands in a slot already holding the same bytes; `adc` immediates only change the insertion index of a
  miss; hasher tail masks differ in a bit that a 20 byte key never has). The tool fails if a surviving edit is not listed or a listed
  edit is killed.
- Rust: not yet implemented. No Cargo graph, no build comparison is claimed.

## Results and limitations

Machine-readable counts are in `measure.json`: cases 11,047; negative controls 302; detected 286; equivalent 16; mismatches 0.

- The seven bodies agree with the rule list on every case; the reconstruction of the amount rule is therefore complete for this
  helper up to the five modelled boundaries.
- Unresolved: the semantics of the base conversion slot (`0x3beb980`), the third-store lookup (`0x369a210`), the extra term
  (`0x3694920`), the lazy initialiser (`0x5c87d50`), the checked-arithmetic event (`0x4524e40`) and the raw table probes; the packet
  models only their calling contract (the base conversion is modelled as the identity on the first cell word, which is an assumption,
  not an observation).
- B-tree search with key 0 follows the leftmost path only (key 0 is the smallest unsigned key); the written rule states that and the
  mutants confirm the code does the same, but a tree whose smallest key is not in the leftmost leaf is outside real data.
- The reconstruction does not name the quantity (which vault amount `base`, `stored` and `extra` are); no gate is requested.
- Not claimed: equivalence of the whole node, Rust source, the callers of this helper.

Next question: reconstruct the base conversion body `0x3beb980` (the slot `0x64e6d20` target), which fixes the meaning of `base`, and
then the two callers `0x44a97b0` and `0x44af2f0` that call the helper six times.
