# RE-006: resting-order index growth and tracker handoff on node 94

This packet establishes that a resting-order insertion can grow its order-ID-to-slot index before it knows whether the key already exists, while its subsequent per-user tracker searches before growing, so a reconstruction can preserve both update order and the different full-table behavior.

- Component ID: `orderbook`, task RE-006, resting-order insertion bookkeeping.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no reference implementation was copied.
- Claim status: exact bytes, FDE extents, selected instructions, direct call operands, relocation addends, data bytes and branch destinations are observations. Book, order-ID and tracker roles rely on earlier packets and are inferences. The test projections are synthetic, not executions of the captured program.
- Scope included and excluded: the selected 16-byte-pair insertion counterpart, its common index growth body and the subsequent tracker-entry constructor. The previously researched insertion and level link, and the referenced book-map insertion copies, user-slot set, tracker probe/counter, shared allocator and calendar helper, are bounded context or external edges; they are not selected FDEs. Complete insertion, all other paths through the map, the allocator, time helper internals, unwind and rollback, other releases, and live execution are excluded.

## Reproduce

Run from the repository root with the authenticated artifact available. Recorded environment: Linux x86-64, CPython 3.12.3 and GNU objdump 2.42. Objdump was used solely for manual instruction-boundary inspection; its rendering is not input to the generator or tests. The generator first verifies the whole input SHA-256, then imports the shared `tools/elf_index.py` and `tools/fde_extents.py` parsers. It reads no NOBITS bytes, requires unique file-backed mappings, invokes no external program, and does not run the node or visor.

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_rest_index_growth94
python3 tools/catalogue.py --check
python3 tools/rest_index_growth94.py --out '<tmp-dir>/a'
diff -r -x README.md -x MANIFEST.sha256 '<tmp-dir>/a' research/work-items/RE-006-rest-index-growth-94
(cd research/work-items/RE-006-rest-index-growth-94 && sha256sum -c MANIFEST.sha256)
```

Replace `<tmp-dir>` with a writable relative directory. To check independence from hash seed and time zone, use two distinct outputs:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/rest_index_growth94.py --out '<tmp-dir>/a'
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/rest_index_growth94.py --out '<tmp-dir>/b'
diff -r '<tmp-dir>/a' '<tmp-dir>/b'
```

`functions.json`, `witnesses.tsv`, `constants.tsv`, `tracker-stores.tsv`, `branches.tsv`, `calls.tsv`, `relocations.tsv`, `context-copies.tsv`, `copy-operands.tsv`, `literals.tsv`, `capacity-projections.tsv`, `hash-projections.tsv`, `counter-projections.tsv`, `logical-projections.tsv`, `rehash-projections.tsv` and `tracker-projections.tsv` are generated. `MANIFEST.sha256` covers those files and this README. No host path, clock time or tool-rendered disassembly is written to generated evidence.

## Evidence

All addresses are linked ELF virtual addresses and ends are exclusive. For the selected `.text` windows, file offset is VA minus `0x1000`; the generator derives and records the actual offsets from ELF sections. Each selected FDE and both comparison-context FDEs are checked against their `.eh_frame_hdr` entry for both start and record address. An FDE is an unwind-described range, not by itself proof of a source-language function boundary. Full original bytes and hashes for each selected range are in `functions.json`.

| Selected body and role | FDE extent | FDE record VA | Bytes |
| --- | --- | --- | ---: |
| Pair-map put counterpart | `0x379d360..0x379d4ee` | `0xe5e4a4` | 398 |
| Pair-map growth and rehash | `0x357a6d0..0x357ab95` | `0xe31cb8` | 1221 |
| User tracker entry construction | `0x3597020..0x3597192` | `0xe32d9c` | 370 |

These three selected FDEs total 1,989 bytes. The earlier `RE-006-perp-order-insert-94`, `RE-006-price-level-lifecycle-94` and `RE-006-cancel-item-path-94` packets establish the insertion and book context. Their functions are not newly selected here. The counterpart is independently located and shares the book put bodies' complete byte shape under the narrowly defined comparison below.

### One resting-order handoff

The bounded perp insertion windows record this order on the normal continuation:

| Order | Byte-backed action | Bounded consequence |
| --- | --- | --- |
| 1 | The slab insertion call returns a slot key; the code tests the former tail's tag and, if present, checks its index against book `+0x10` and rejects a slot with low dword tag 2. | The selected caller's invalid-tail edge reaches `0x4314a17`; the meaning and effects of its failure handler are outside this packet. |
| 2 | `0x4312f93` writes the level tail tag and slot key, then `0x4312fad` calls the pair-map put with book `+0x28`, the order key and the returned slot key. | The tail writes precede any growth required by that put. |
| 3 | A saved flag controls an optional client-ID index call through `0x5774810`; the following calls get the book user entry and insert the slot in its `+0x20` set. | The client-ID map and set internals are prior/pending work, not reanalyzed here. |
| 4 | `0x4313078` calls through `0x5774850` to the tracker counter wrapper. Earlier bytes save the caller's state pointer plus `0x11c0`; the call passes that saved pointer and a copied 20-byte key. | The wrapper calls selected `0x3597020` and increments the returned row's `+0x20` qword with saturation. |

The order-ID and 20-byte user names come from the earlier book packets. The saved state pointer's provenance is inherited from that caller analysis. The bounded windows show instruction order but do not prove that later error handling cannot roll earlier writes back. The caller's other gates and all intervening helpers are outside this packet.

### Put, lookup and capacity

`0x379d360` takes a table header in `rdi`, a qword key in `rsi` and a qword value in `rdx`. It reads the available-growth qword at table `+0x10` **before** probing; if it is zero, it calls the growth body and resumes the probe only after normal return. Thus even a key that would subsequently be found takes the growth path. This is a machine-level branch ordering, not a claim that duplicate order IDs are admitted by the enclosing insertion gates.

The target's key hash is a wrapping 64-bit product by `0xf1357aea2e62a9c5`, rotated left by 20. It uses the high seven bits as the control fingerprint and masks the hash with the table's bucket mask to choose the first group. The probe examines groups of 16 control bytes, tests the full qword key on a fingerprint hit, and advances through groups. A found key replaces the associated qword, returns tag 1 and the previous qword. On a miss, the selected negative control byte's low bit is subtracted from the growth allowance, the live count increases, and the key and value are stored in a 16-byte bucket; the return tag is 0. The selected control byte and its mirror are both written. The all-ones control tests and the `0x80` marker support the conventional empty/deleted interpretation, but no arbitrary malformed table state is claimed valid.

The selected counterpart's 398 bytes compare with each previously referenced book put copy at `0x488da60` and `0x27ca640`. Exactly two four-byte PC-relative operands are masked, at relative offsets `0x116` and `0x164`: eight bytes in each body. Across the two context copies, zero are raw-equal, two are normalized-only and zero are unmatched under that mask. Their complete original bytes, hashes and differences are retained in `context-copies.tsv`. `copy-operands.tsv` resolves the first operand of each body to the same `0x203480` 16-byte data literal; `calls.tsv` resolves the second to the same relocation slot `0x5773758` and growth target `0x357a6d0`. The FDE of each context copy is also checked. This comparison binds the selected counterpart's local instruction shape to both book call sites; it does not claim whole-program identity or equality of any unexamined external callees.

For the growth body, let `m` be a valid bucket mask and let `required = items + additional`, with addition checked for unsigned 64-bit carry. For a valid power-of-two bucket count `m + 1`, the capacity is `m` when `m < 8`; otherwise it is `(m + 1) - ((m + 1) >> 3)`. When `required <= floor(capacity / 2)`, the branch selects the in-place path; otherwise it calls the shared allocator with a 16-byte element size and request `max(capacity + 1, required)`. The allocator and its detailed failure contract are not reimplemented here. The book put passes additional count 1 and error mode byte 1.

| Example valid mask | Capacity | Existing items | Additional | Selected growth route |
| ---: | ---: | ---: | ---: | --- |
| 15 | 14 | 6 | 1 | in-place rehash |
| 15 | 14 | 7 | 1 | allocation |
| 31 | 28 | 13 | 1 | in-place rehash |
| 31 | 28 | 14 | 1 | allocation |

These are synthetic boundary projections from `capacity-projections.tsv`. In actual insertion the growth body is reached only when the allowance is zero; a sparse table can meet that condition after deleted controls accumulate. The selected code alone does not prove the examples are reachable in a valid book.

### Rehash details and failure edges

On the allocation path, `0x357a738` calls the shared allocator and `0x357a74f` tests the returned leading word. With a usable result it scans live old controls, hashes each qword key with the same multiplier and rotation, copies each complete 16-byte pair into a selected new bucket and writes the mirrored fingerprint. After redistribution, the selected instructions install the new control pointer, mask and growth allowance; the live count is retained. A nonzero old mask leads toward release of the old backing allocation. The exact allocator, release and exception effects remain external.

On the in-place path, the SIMD loop at `0x357a8e0` changes nonnegative controls to `0x80` and negative controls to `0xff`, using the 16-byte literal in `literals.tsv`. The later loop recomputes each live key's hash. Its masked distance comparison at `0x357a9ca` keeps a pair when source and destination are in the same 16-byte probe group. Otherwise the code moves the pair when the selected destination control was `0xff`, or swaps two 16-byte pairs and continues rehashing the displaced one. Mirror control stores occur on both routes. This is a local interpretation of the selected operations under a well-formed table, not a validated layout for every corrupted control array.

| Condition | Selected edge | Observation and limit |
| --- | --- | --- |
| `items + additional` carries | `0x357a6e5 -> 0x357ab6a` | Error mode zero returns a zero word; nonzero calls slot `0x576e098`, whose relative addend is `0x157b810`. The book put supplies mode 1. The passed 57-byte data span begins `Hash table capacity overflow`; it includes adjacent bytes and is not asserted to be a complete rendered message. |
| Allocator result's leading word is zero | `0x357a74f -> 0x357a8b1` | This body reaches its return without installing the proposed new header on that branch; allocator side effects and outer handling are not established. |
| New tracker row's date helper returns zero | `0x3597068 -> 0x3597185` | Before the new tracker row is stored, the code calls slot `0x576e470`, whose relative addend is `0x157a9f0`. The earlier tracker lookup may already have grown its table. |
| Former level-tail index is out of range or has tag 2 | `0x4312f64` / `0x4312f7e -> 0x4314a17` | The book put has not yet been called on these selected edges. Earlier slab and level writes are not assumed rolled back. |

No failure handler, landing-pad effect or transaction rollback is proved. A failure after the level tail write can occur after a prior state write in this local sequence; this observation alone does not determine the final state after unwinding.

### Tracker lookup and counter

The tracker probe context at `0x379a110` checks a 20-byte key. On a match it returns the existing row immediately. Only after the search reaches an empty control does it check table `+0x10` and, when zero, call the previously recorded growth target through `0x57737c0`. This is different from the put's pre-probe growth check. For a vacant entry, selected `0x3597020` calls the calendar helper through `0x576e890` with day value 719163. A nonzero result is copied into the new row together with zero-initialized fields and the 20-byte key; the 0x58-byte bucket contains 20 key bytes, four bytes whose value is not established here, and a 0x40-byte value. The old tracker evidence associates the date with the epoch; the complete helper is not analyzed here.

The selected stores distinguish the following ranges in a new bucket; `tracker-stores.tsv` derives each store's bucket-relative interval from its pinned displacement and the stride immediate. These are offsets in the observed storage, not a recovered Rust ABI:

| Offset | Width | Observed write |
| --- | ---: | --- |
| bucket `+0x00` | 20 | Key copied from the selected vacant-entry result. |
| bucket `+0x14` | 4 | Copied from stack scratch; their value is not interpreted here. |
| value `+0x00` | 48 | Copied from zeroed stack scratch after the control-byte writes. |
| value `+0x30` | 4 | Calendar helper's nonzero result. |
| value `+0x34` | 10 | Zeroed by a qword and a word store. |
| value `+0x3e` | 2 | No write is shown in this new-entry sequence. |

On normal return, the existing counter wrapper loads row `+0x20`, adds one, and selects `u64::MAX` when that increment wraps. Thus a new row's zero counter becomes one; a preexisting maximum stays maximum. `tracker-projections.tsv` enumerates selected found/vacant, capacity and external success/failure choices. A failure-labelled row is conditional on the supplied external outcome; it does not establish production reachability or cleanup behavior.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, target ABI claim, compiled-code comparison, relocation/vtable closure or whole-ELF comparison is made. The only normalization is the two four-byte operands in the context-copy comparison; all three newly selected original FDE byte strings remain unmasked in `functions.json`.

The focused suite contains 38 tests and does not skip when the artifact is absent. It checks whole-input identity, actual FDEs and unwind-header membership, the 29 pinned byte windows, 18 decoded operands, the three selected data spans, ten tracker store intervals, direct and relocation-bound calls, the comparison mask, selected branch decoding, capacity and counter boundaries, and deterministic regeneration against the retained files. Corruption controls alter the digest, a selected unwind extent, the header-to-FDE binding, every witness, decoded operand and tracker-store displacement in turn, branch conditions, instruction and displacement bytes, relocation data, masks, and file mappings, including NOBITS, out-of-range and ambiguous sections. The unwind corruption test deliberately bypasses only the digest guard to exercise the later extent guard.

The synthetic structural index checks collisions, replacement, the full-table duplicate path and tombstone-triggered rebuilds against independent dictionary expectations. Sixteen deterministic 64-bucket cases exercise the in-place group, move and swap choices; the first model case takes them 19, 4 and 4 times respectively. The model omits control-byte mirror storage, stale payload bytes in deleted buckets, small tables and allocator behavior, so these are **not** target execution or differential runtime fixtures. Synthetic control and pair corruption is rejected by the model's invariant checks. The tracker rows and capacity cases are branch projections with supplied external outcomes, not observations from a running node.

## Results and limitations

The bounded denominator is three FDE ranges, 1,989 raw bytes, 38 selected conditional branches, 17 call sites, eight relocation records, 29 byte windows and two context-copy comparisons. Those counts are not RE-006 or whole-node function coverage. The generated projections include 28 capacity rows, eight hash examples, four counter cases, four logical scenarios, 16 rehash cases and 16 tracker routes. The 38 focused tests pass with no skips; independent regeneration and repository checks are reported in the draft.

The copied insertion bodies are compared only under the explicitly listed eight-byte mask. The position and key identities derive from earlier packet context, not recovered symbols. No dynamic target execution, complete CFG proof, malformed-table contract, helper closure, allocator guarantee, unwind/rollback model, independent Rust implementation, or node equivalence is claimed. No component completion gate is requested.

Next question: establish the enclosing insertion caller's failure and cleanup behavior after the level link has been written but before both index and tracker updates complete, without assuming atomic rollback.
