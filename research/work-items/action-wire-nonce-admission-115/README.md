# action-wire: reconstruct the node #115 order-nonce admission path (account lookup, three front ends, wrapper 0x4228310, check 0x4228080, insertion, callees)

This packet makes the nonce admission rule of node #115 reconstructible as an executable function. For a
sorted nonce ring, a candidate nonce, the node clock (a packed calendar date word plus seconds and
nanoseconds), two flag bytes and an optional second container of pending nonces, a pure-Python model now
predicts the exact 24-byte answer record of the original machine code: the rule order (ring floor `0xcb`,
upper bound `0xcc`, lower bound `0xcb`, duplicate `0xcd`, pending-eviction `0x61`, success `0x1a2`), the three
time bounds in milliseconds (`now + 86,400,000`, or `+ 86,280,000` with the flag; `now - 172,800,000`, or
`- 172,680,000` with the flag; ring floor `ring[len - 100]`, or `ring[len - 400]` with the other flag), the
calendar-to-milliseconds arithmetic with its clamp at 0, the insertion position of a success, and the
eviction fold that rejects a nonce when one of the oldest `len + 1 - limit` ring entries is still in the pending
container. The wrapper above it (`0x4228310`) is reconstructed too: the 400-versus-100 window is selected by whether the
signing address is one of 19 fixed 20-byte addresses read from the binary, and a success inserts the nonce into the ring and
trims the oldest entries to the window. The three callers of the wrapper are now found and reconstructed as well: the wrapper is reached only through the function-pointer slot `0x64e7ef0`, and three 233-byte front ends (`0x2c766e0`, `0x560dbb0`, `0x560dca0`) call it after resolving the per-account container through slot `0x64e7ee8`, which is the account lookup `0x3be7e80` (SipHash-1-3 of the 20-byte address, a 16-wide SwissTable of entry indices, 64-byte entries whose first 32 bytes are the nonce ring header, append of an empty entry on a miss). With that, the path from an address and a clock to a stored nonce is executable end to end except the clock source and the grow arms. It answers the first task's open question "which check raises which tag, and in what order" for
the three replay tags 203/204/205 and the new tag 97, which the error-display packet could only name.

- Component ID: `action-wire` (task: recover tags, signing domains, replay checks and error precedence).
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `a8616af94`. No reference source was used; every constant,
  offset and branch comes from the function bytes. Tag texts are read from the Display table of
  `action-wire-error-display-115` (0x46ef710), whose arm addresses this tool re-derives from the rel32 table.
- Claim status:
  - Observation: the five function bodies, every comparison, constant and store they make, and the
    equality of the model with the machine code in all 29,600 cases (12,000 check-level, 6,000 callee-level, 4,000 wrapper-level, 4,500 front-end, 2,500 account-lookup, 600 hasher).
  - Inference: that the record tags are error tags of the Display table (they equal its slot numbers and slots
    97/203/204/205 carry these texts); that `0x1a2` (418, one past the 418-slot table) is the success value;
    the readings "nonce ring", "pending container" and "evict fold" for the data structures.
  - Unresolved: the callers of the three front ends (the 2,239-byte functions `0x54848e0` and `0x54851a0` also call the wrapper slot, with the lookup slot, and are not reconstructed here), the origin of the context clock; which flag byte is
    which mode (named `flag_a`/`flag_b` after their offsets 0x1c/0x1d); what the second container holds
    (24-byte entries whose first word is the nonce, or a B-tree of u64 keys, selected by the niche value
    `0x8000000000000000` in its first word); the Rust type names.
- Scope included (all extents from `.eh_frame` FDEs through `tools/fde_extents.py`):
  - wrapper `0x4228310..0x4228578` (616 bytes), run for real: window flag, call of the check, insertion, trim
  - address-set tests `0x421a520..0x421a67b` and `0x421a3c0..0x421a51b` (347 bytes each), run for real
  - ring insertion `0x454b8c0..0x454bde5` (1,317 bytes), run for real with a memmove contract (see Limits)
  - ring grow fix-up `0x4560af0..0x4560b7a` (138 bytes, slot `0x64e2620`), run for real when the ring is full; the RawVec step behind slot `0x64ea7b8` is a contract (capacity `max(2 * cap, 4)`)
  - admission body `0x4228080..0x4228309` (649 bytes, 174 instructions)
  - ring search `0x4551530..0x4551640` (272 bytes, 84 instructions), run for real
  - evict fold `0x450c430..0x450c75c` (812 bytes, 236 instructions), run for real
  - 24-byte ring search `0x4555f40..0x455605c` (284 bytes, 90 instructions), run for real
  - B-tree search `0x35bd8a0..0x35bd932` (146 bytes, 39 instructions), run for real
  - Display arms of tags 97, 203, 204, 205 (table `0x7d8c1c`), read for their texts
  - front ends `0x2c766e0`, `0x560dbb0`, `0x560dca0` (233 bytes each), run for real; context offsets are read from their bytes
  - account lookup `0x3be7e80` (313 bytes), SipHash-1-3 of the address `0x4717440` (363) and its write `0x45927a0` (471), table find `0x3ee6e80` (300),
    table insert `0x3ec72b0` (1,041), all run for real
- Scope excluded: the callers of the front ends, the entry-vector grow call (GOT `0x64e6288`), the SHA/EIP-712
  signing path, tags 93/96 (`Nonce already used.` / `Nonce mismatch.`), and the sibling copies of the body (a byte scan
  for 16-bit store immediates of the tags 203/204/205 found no other function).

## Reproduce

From the repository root, with Python 3 and the standard library only (no binutils, the binary is never run):

```
python3 tools/action_wire_nonce_admission_115.py --out research/work-items/action-wire-nonce-admission-115
python3 -m unittest tests.test_action_wire_nonce_admission_115
```

The tool checks the SHA-256 of `artifacts/node/115/hl-node` first, reads the five bodies through
`tools/fde_extents.py` and `tools/elf_index.py`, and interprets their bytes with an x86-64 subset interpreter that
is embedded in the tool (the shared offline interpreter skeleton, extended by nothing but the cases below).
Case generation is seeded (`CASE_SEED = 115`), so two runs write identical bytes. A run takes about three minutes
and well under 1 GB.

## Evidence

All files are written by the tool; `MANIFEST.sha256` lists their hashes.

| File | Content |
| --- | --- |
| `body.tsv` | every instruction of the seventeen functions: function, VA, length, operation, executed in the corpus |
| `coverage.tsv` | per function: bytes, instruction count, instructions the corpus executed |
| `special-addresses.tsv` | the 19 fixed 20-byte addresses (8 + 8 in the two set tests, 3 in the wrapper) read from the instruction operands |
| `tags.tsv` | the Display arm, kind and text of tags 97, 203, 204, 205 read from the table at `0x7d8c1c` |
| `cases-sample.tsv` | the first 40 check-level cases and the first case of each (tag, container, fold) class |
| `kinds.tsv` | the 16 (tag, container kind, fold ran) classes with their case counts |
| `controls.tsv` | the 265 detected negative controls and the first case that exposes each |
| `equivalent-mutants.tsv` | the 43 undetected mutations and why (or: that no case separates them) |
| `summary.json`, `measure.json` | counts (summary also holds the three front-end context layouts) |

The record, as the check `0x4228080` writes it (`rdi` = output, `rsi` = nonce ring, `rdx` = argument block):

```
args:  +0x00 nonce u64      +0x08 pointer to the pending container (0 = none)
       +0x10 u32 date word  (year << 13 | ordinal << 4 | flags, year signed)
       +0x14 u32 seconds of day   +0x18 u32 nanoseconds   +0x1c u8 flag_a   +0x1d u8 flag_b
ring:  +0x00 capacity +0x08 buffer +0x10 head +0x18 length   (u64 entries, strictly ascending)
out:   +0x00 u16 tag, +0x08 word1, +0x10 word2
```

Rules of the check, in the order the machine code runs them (each early exit writes the tag and its two words):

1. `limit = 400` if `flag_a != 0` else `100`. If `len >= limit` and `nonce < ring[len - limit]`: tag `0xcb`, words
   `(nonce, ring[len - limit])` (the ring floor; the logical entry is read through the head and one wrap subtraction).
2. `now` = milliseconds from the date word: `days = ordinal + floor((y-1)*1461/4) - (y-1)/100 + (y-1)/400 - 719163`
   (a 400-year cycle shift when `year <= 0`), `now = max(0, (days*86400 + seconds)*1000 + nanos/1,000,000)`.
3. `upper = now + 86,400,000` (`- 120,000` when `flag_b`). If `nonce > upper`: tag `0xcc`, `(nonce, upper)`.
4. `lower = max(0, now - 172,800,000)` (`172,680,000` when `flag_b`). If `nonce < lower`: tag `0xcb`, `(nonce, lower)`.
5. Binary search of the ring; present: tag `0xcd`, word1 `nonce`.
6. With no pending container, or `len + 1 <= limit`: tag `0x1a2`, word1 `1`, word2 = insertion position.
7. Otherwise the fold `0x450c430` takes the oldest `len + 1 - limit` ring entries and asks the container whether
   any is present (ring variant by `0x4555f40`, B-tree variant by `0x35bd8a0`); a hit gives tag `0x61`
   (`Too many pending nonces`), no hit gives tag `0x1a2` as in rule 6.

The wrapper `0x4228310(out, ring, &time{date, secs, nanos}, &address20, nonce, pending)`:

1. `flag_a = 1` when the 20-byte address is in the 8-address set tested by `0x421a520`, or in the 8-address set tested by
   `0x421a3c0`, or equals any of three fixed addresses it compares itself; otherwise 0. `flag_b` is always 0.
   (`0x421a3c0` and `0x421a520` compare the address, 16 bytes plus 4 bytes, with constants whose upper 12 tail bytes are 0.)
2. It calls the check. On any tag but `0x1a2` it copies the 16 result bytes (and padding) to the caller and the ring is unchanged.
3. On `0x1a2` with word1 `1`: `ring.insert(word2, nonce)` (`0x454b8c0`, a `VecDeque::insert`), then, when the length
   exceeds the window (400 if `flag_a` else 100), the oldest entries are dropped from the front so the length equals the window.
   It then writes only the tag `0x1a2`.

## Implementation and comparison

The model is `admit()`, `clock_ms()` and `wrap_model()` in the tool; `two_slices()` and `build_tree()` rebuild the memory images the
machine code reads. No Rust path is part of this packet ("not yet implemented"); the model is Python and is meant as
the executable specification a Rust port can be checked against.

Comparison (all counts were computed by the tool and are in `measure.json` / `summary.json`):

- 12,000 check-level cases: sorted rings of 0..440 entries with random capacity and head (including heads that make the
  ring wrap, so the fold crosses from the front to the back slice), years -900..3000 plus edge years (0, 1, -1, +-400,
  1969, 1970, 2000, 2100, 2400, 1900, 1600, +-262144), nonces at each bound +-1, equal to a ring entry, at the ring floor
  +-1, 0, 1, 2^63 and 2^64-1, and the three container kinds (none, 24-byte ring, B-tree of one or two levels, each
  possibly empty). The model equals the record for all 12,000. Tag counts: `0x1a2` 7,229, `0xcb` 1,919, `0xcc` 1,230,
  `0xcd` 1,009, `0x61` 613; the fold ran in 1,556 cases.
- 6,000 callee-level cases run the four callees alone against `bisect` and set-membership models (1,000 each for the u64
  ring search, the 24-byte ring search and the tree search, 3,000 for the fold, whose return code must be 0, 1 or 2 with bit 0
  equal to "an item is present").
- 4,000 wrapper-level cases run `0x4228310` with the real set tests, check, fold, searches and insertion (only `memmove` is a
  contract: it copies `n` bytes with overlap safety). Each compares the record tag/words and the complete ring contents (and its
  capacity) afterwards. Outcomes: `0x1a2` 2,683 (each with an insertion and, for full rings, a trim), `0xcb` 509, `0xcc` 326,
  `0xcd` 291, `0x61` 191. Addresses are drawn from the 19 fixed addresses and from random bytes.
- 4,500 front-end cases (1,500 per front end) run each 233-byte body for real with the real wrapper, check, fold, searches and insertion;
  the lookup slot `0x64e7ee8` is a contract that records `(map address, key pointer)` and returns the ring header, and the `memmove` slot is
  the same copy contract. The model predicts record tag/words, the ring after the call, the two saturating counters of the context (initial values drawn
  from 0, 1, 2, 2^32-2, 2^64-2, 2^64-1 and random) and the lookup arguments. Outcomes: `0x1a2` 3,193, `0xcb` 628, `0xcc` 337, `0xcd` 342.
  Rules: counter 1 (`+0xb40`, or `+0x16b0` in the second copy) is incremented before the lookup, saturating at 2^64-1; the lookup receives the map at the
  context offset `+0x3af0` (`+0x4660`) and the caller's key pointer; the clock words come from context `+0x60` (date and seconds) and `+0x68`
  (nanoseconds); the wrapper is called with no second container; counter 2 (`+0xb48`, `+0x16b8`) is incremented, saturating, only on success.
- 2,500 account-lookup cases (`0x3be7e80` with the callees and the reserve arm real) build tables of 4..128 buckets from a Python SwissTable with the
  SipHash-1-3 keys drawn at random, with tombstones, with clustered hash positions that force probing across groups, and with present and absent
  addresses. The model returns the entry index and the complete table state afterwards (control bytes with mirror, bucket indices, growth left,
  item count, appended entry with hash and key) and equals the machine in all cases. 600 further cases run the hasher alone against `siphash13()`.
- Instruction coverage (`coverage.tsv`): 1,129 of 1,235 instructions of the first nine functions executed, 99 unexecuted in the insertion, 2 in the wrapper and 1 in the
  tree search; the new functions: front ends 59/59 each, lookup 71/77, hasher 91/91, hasher write 57/141 (only the 20-byte path), table find 67/76, table insert 111/253
  (the panic arms are outside the cases); the new grow arm: reserve-and-rehash 353/455 and table drop 34/44.
- The grow arm of the lookup (new in this revision, `LOOKUP_CASES` unchanged at 2,500, 449 of them reach it): when the table has no growth left and the insert
  slot is EMPTY, the inserter calls slot `0x64e6290` = `0x3ee0ed0` (1,953 bytes, run for real) with the table, one extra item and the entry vector. It computes the
  capacity of the mask (`mask` below 8 buckets, else buckets/8*7). When the live items plus one are at most half of it, it rehashes in place (full -> DELETED,
  special -> EMPTY, mirror copy, then each DELETED bucket re-inserted by the hash held in its entry: same probe group keeps the slot, an EMPTY target takes the
  bucket, a DELETED target swaps and the displaced bucket is placed in turn); 300 cases. Otherwise it allocates a table of `next_pow2(max(items + 1, cap + 1) * 8 / 7)`
  buckets (4 or 8 below 8), fills control bytes with 0xff, re-inserts the full buckets in old index order and drops the old allocation through
  `0x3ddd030`; 149 cases, every one a doubling. The allocator (bump, 16-byte aligned), `memset`, `memmove` and the free slot are contracts; the hash of a bucket is
  read from the entry vector (hash at +0x20, 64-byte stride). The packed in-place cases (12% of the cases: 64/128 buckets, live items just under half the capacity,
  a probe that lands on an EMPTY slot) are what makes the swap chain observable. Table cells of EMPTY or DELETED slots hold allocator garbage in the new table and
  are blanked on both sides before comparing. One decoder addition was needed (`pcmpgtb`, signed byte compare) and four slot entries: `0x64e6290` (the real reserve),
  `0x64df480`, `0x64df750` and `0x64df4a0` (contracts).
- Negative controls (308 built, 265 detected, 43 reported as equivalent, 0 unexplained). Of them, the 165 of the first part were: 36 model mutants of the check (30 detected,
  6 equivalent), 9 model mutants of the wrapper (9 detected), and 120 byte corruptions of the nine functions (107 detected, 13 equivalent).
  A byte corruption inverts one conditional jump (every conditional jump of the ten wrapper-side bodies) or bumps one 16-bit tag
  immediate in the check (all six tag stores); it counts as detected when the patched bytes disagree with the unmodified model, or crash, on a
  patch corpus of 1,000 check-level, 1,500 callee-level and 500 wrapper cases. The 13 undetected byte corruptions are 8 in the advance-only
  loop that the fold runs for an empty B-tree (all exits return 0 or 2, the caller tests bit 0), 1 in the wrapper's trim loop and 4 in the
  insertion's shift-direction choices; for those 5 the reason column says only that no case in the patch corpus separates them. They are
  reported as undetected-equivalent in the gate sense and not argued further here.

## Results and limitations

- Results: 29,600 cases, 0 disagreements; 308 negative controls, 265 detected, 43 reported as equivalent. The 143 controls added after the first part (2 are byte corruptions of the grow fix-up) are 10 front-end
  model mutants, 23 lookup model mutants (9 of them for the grow arm: never in place, in-place at full capacity, reversed re-insertion, growth off by one, no mirror after resize,
  no swap chain, no probe-group test, no rehash after the conversion, halved buckets) (probe stride, mirror bytes, SipHash round counts, tombstone handling, index and fresh-entry values) and 52 byte corruptions
  (every conditional jump of the front ends, the lookup, the hasher write, the table find, insert, reserve and drop; tag immediates of the front ends). The undetected byte corruptions
  of the new functions are in arms the cases never reach (panic exits, overflow exits of the size computation, hasher write lengths other than 20); they are listed with that reason's
  generic text in `equivalent-mutants.tsv` and are not claimed to be behaviour-neutral.
- The model covers sorted rings (the invariant `RE-001-node115-nonce-ordering` established). An unsorted ring is outside
  the contract and is not modelled.
- The fold's count-0 case is outside the contract (the machine code would loop); the check never calls it with 0.
- In 20% of the wrapper and front-end cases the ring is full (`capacity == length`), so a success calls the real grow fix-up `0x4560af0` and the expected capacity afterwards is `max(2 * cap, 4)` through the RawVec contract; the RawVec allocation itself and the panic exits are not run from bytes. The `memmove` slot `0x64df568` is a copy contract, not run from its bytes.
- Only one-level and two-level B-trees are built (up to 143 keys); a deeper tree reuses the same search loop.
- The clock is read as given. Where the date word, seconds and nanoseconds come from is not recovered here.
- The meaning of the 19 addresses (for example an operator or market-maker list) is not established; they are recorded as bytes.
- No gate is requested: the packet covers one admission path, not the whole `action-wire` component.
- The entry-vector grow call (GOT `0x64e6288`) is not modelled: the lookup keeps spare entry capacity. The reserve call (GOT `0x64e6290`) is now run for real, with the allocator as a contract.
  Hash keys are taken from the map as given; where they are seeded is not recovered.
- Next question: the two 2,239-byte functions `0x54848e0` and `0x54851a0` that call both slots (the action-level callers that supply the address, nonce and clock),
  and tags 93/96 that the Display table pairs with this check.
