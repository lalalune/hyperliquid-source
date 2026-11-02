# RE-006: cancellation-candidate collection and short ordering on node #94

A reconstruction can now collect a user's live, owner-matching order slots into cancellation candidates, rank lists of up to 20 records using the observed position and product rules, and apply the observed cancellation-loop stop condition in that order.

- Component ID: `orderbook`, task RE-006.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only for search leads.
- Claim status: instruction bytes, operands, FDE extents, selected branches and relocations are observations; the state-machine descriptions below are static interpretations. Names such as order, side, position and asset rely partly on earlier book evidence and are identified as inferences.
- Scope included and excluded: the three selected helper FDEs and bounded context linking the already known cancellation hosts through collection, sorting of 0–20 candidates, the removal call and its stop/exit paths. The already researched hosts, the accessor, removal and flush bodies, the 21-or-more sorting body, allocator and error routines, runtime execution, rollback and a full book implementation are excluded.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the standard library. The collector authenticates the target first, imports `tools/elf_index.py` and `tools/fde_extents.py`, reads file-backed ELF bytes, and never starts another program or executes the target. Manual reading used GNU objdump 2.42; its rendering is not an input or generated evidence.

```sh
python3 tools/artifacts.py verify
python3 tools/book_cancel_short_order94.py --out research/work-items/RE-006-cancel-candidate-rank-94
python3 -m unittest tests.test_book_cancel_short_order94
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/book_cancel_short_order94.py --out <tmp-dir-a>
PYTHONHASHSEED=987 TZ=Pacific/Honolulu python3 tools/book_cancel_short_order94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
(cd research/work-items/RE-006-cancel-candidate-rank-94 && sha256sum -c MANIFEST.sha256)
```

The generator creates `evidence.json`, `windows.tsv`, `branches.tsv`, `calls.tsv`, `indirect.tsv`, `locations.tsv`, `lookup-cases.tsv`, `tree-cases.tsv`, `sort-cases.tsv`, `rank-cases.tsv`, `gap-cases.tsv`, `transition-cases.tsv` and `pipeline-cases.tsv`. `MANIFEST.sha256` covers those files and this README. The two output directories must be distinct and initially empty. The environment variables alter neither target bytes nor output. All fixture rows are synthetic; no user data is used.

## Evidence

All addresses are linked ELF virtual addresses; file offsets and complete selected FDE bytes and hashes are in `evidence.json`. For these executable-section ranges, the file offset is the VA minus `0x1000`. FDEs describe unwind ranges and do not establish a complete function census or source-function boundaries. The selected ranges are:

| Descriptive role | FDE range, half-open | Length | FDE VA |
| --- | --- | ---: | --- |
| Temporary set iterator step | `0x42bb100..0x42bb246` | 326 | `0xebec04` |
| Key to validated slab slot | `0x4339fe0..0x433a11b` | 315 | `0xec4de0` |
| Short-list insertion step | `0x490d700..0x490dd30` | 1,584 | `0x12a6a70` |

The following is a bounded path through the earlier host, not a claim to recover that entire host. Both host copies have the first three corresponding direct call sites in `calls.tsv`:

```text
positive entry gap
  -> prior filtered-key builder, one book at a time (call 0x4cdd722)
  -> temporary-set iterator step               (call 0x4cdd868)
  -> key-to-slot and owner validation          (call 0x4cdd8bc)
  -> append one 0x28-byte candidate
  -> for 2..20 candidates: insertion step       (call 0x4cddd5e)
  -> for each ordered candidate: removal edge   (call 0x4cddf47)
  -> stop test, candidate-buffer cleanup and flush edge
```

The earlier `RE-006-user-book-cancel-94` packet identifies the filtered-key builder and its book/user inputs. That packet does not describe this candidate ranking and cancellation loop. `RE-004-order-pair-rank-94` describes a different, separately researched two-record sorting function. This packet selects neither of those earlier functions. For 21 or more candidates the host takes the indirect edge recorded in `indirect.tsv`; its body and general long-list order are outside this packet.

### Entry, candidate lookup and row construction

The contextual entry computes a signed saturating subtraction of the accessor's returned word from the requested word and clamps the result below at zero. If the result is not positive, it returns before building this candidate list. On signed overflow it chooses the appropriate signed endpoint and calls the diagnostic edge before continuing. Earlier `bridge-withdraw-fee-route-94` research interprets the accessor as a withdrawable amount; this packet checks the call and arithmetic but does not re-establish that accessor's implementation. `gap-cases.tsv` includes both signed overflow directions as illustrative inputs.

The temporary-set step reads a node pointer, a height and an index, tests its 16-bit length at node `+0x62`, and advances or ascends when an index reaches that length. While ascending exhausted nodes it passes sizes `0x68` or `0xc8` to the recorded indirect edge according to the height. If no parent remains, it returns an absent pointer. The edge is consistent with freeing the consumed temporary tree; its callee is not reconstructed here. This packet does not claim all tree shapes or allocation behavior have been tested.

The slot lookup performs the following observed steps:

1. A zero table count at book `+0x40` returns null. Otherwise it multiplies the supplied key by `0xf1357aea2e62a9c5`, rotates the low 64 bits left 20 and uses the high seven bits as a fingerprint.
2. It probes 16 control bytes at a time using the pointer at book `+0x28` and mask at `+0x30`. Candidate buckets have a 16-byte reverse stride; matching fingerprints are checked against the full qword key. A group containing `0xff` ends an unsuccessful search. A fingerprint collision alone does not establish a match.
3. A matching bucket supplies a slab index. The index must be below book `+0x10`; slots start at book `+0x08`, have stride `0xf8`, and a low dword of `2` is vacant. A missing key, out-of-range index or vacant slot returns null.
4. The slot's 20 bytes at `+0xe0` are compared with the 20 supplied bytes. A mismatch returns null; equality returns the slot pointer. The host skips null results.

On a non-null result, the contextual caller appends the following 33 defined bytes in a `0x28`-byte record. The last seven bytes are not initialized in this window and are not assigned a semantic value.

| Candidate offset | Width | Copied from |
| --- | ---: | --- |
| `+0x00` | 8 | slot `+0xa0` |
| `+0x08` | 8 | book `+0xb0` |
| `+0x10` | 8 | slot `+0xc8` |
| `+0x18` | 8 | slot `+0xd8` |
| `+0x20` | 1 | slot `+0xc2` |

Prior book evidence supports interpreting these as price, packed asset, remaining size, order ID and side respectively. The collector calls a separate growth edge if the candidate vector is full; its allocation behavior is not modeled. The fields are not copied from the unlicensed reference.

### Short-list ordering

A length below 2 bypasses sorting. Lengths 2 through 20 invoke the selected insertion step once for each record after the first; length 21 and above take the distinct indirect edge. The selected step compares adjacent records and shifts complete 40-byte records, including opaque padding. Equal keys retain their input order.

For each record, let `price`, `asset`, `size`, and `side` be the words/byte at the offsets above. The step calls an external user accessor and searches the returned tree by unsigned asset. Its root and height are at accessor result `+0x08` and `+0x10`. The node's key array begins at `+0x2c8`, count is a 16-bit field at `+0x322`, children start at `+0x328`, and values have stride `0x40` beginning at `+0x10`. A missing root or exhausted leaf gives signed position `p = 0`; the accessor's body is an external edge.

The following ordering is a static lift of the selected instruction and branch bytes:

```text
R = (size <= unsigned_magnitude(p)) and ((side == 0) xor (p > 0))
P = unsigned_full_product(price, size)
V = P <= 0x7ffffffffffffffe
sort key = (R, V, P if V else 0), in ascending order
```

The signed-minimum position has unsigned magnitude `2^63`; all nonzero side bytes take the same branch. A product equal to the limit is valid; a product above it or with a nonzero high 64-bit half is invalid. Invalid products precede valid products when `R` is equal. Two invalid products, or two equal valid products with equal `R`, do not move past each other. The field names and product units remain inferences; the arithmetic rule is stated independently of their names.

The FDE also contains a block that restores the saved 40-byte record into the current hole before the unwind-resume edge. The LSDA pointer is retained, but this packet does not decode the landing-pad table or establish every allocation and exception path.

### Cancellation and stop conditions

Before the cancellation loop, the caller obtains a baseline qword from a user-keyed table. An external predicate, empty table or absent user yields zero. A matching entry supplies the word at value `+0x48` in an `0x50`-byte bucket. The direct hash and predicate edges are recorded; the meaning of that qword is not established independently here.

The loop stops immediately on candidate side byte `2`. Otherwise it computes the packed asset modulo 10,000, requires that local index to be below the book count, selects a book at stride `0xd8`, and passes the candidate's `+0x18` qword to the removal edge with reason word `7`. An out-of-range local index takes the error edge with `l1/src/books.rs:19:47`. If the removal returns a nonzero low byte, the loop proceeds to the next candidate without the metric comparison. On a zero low byte, the caller selects a row using the book's packed asset divided by 10,000, obtains a current user-table word, computes `max(baseline - current, 0)` as an unsigned subtraction, and stops when that decrease is at least the positive entry gap. The baseline is taken before the loop; the current word can be looked up in the row selected for the current book. No claim is made that the two words have the same meaning across all markets.

On loop exit, the bounded context calls the separate buffer-release and row-flush edges. A candidate vector length of zero makes no removal call. Iterator failure edges use the relocated `collections/btree/navigate.rs` records at lines 600 and 198; the exact error-helper behavior is outside scope. `locations.tsv` records only relative path suffixes, with relocation coordinates and numeric fields read directly from ELF bytes.

| Condition in this bounded route | Observed next action |
| --- | --- |
| Signed saturated entry difference is zero or negative | Return before candidate collection |
| Iterator has no remaining entries | Finish collection for that iterator |
| Remaining count is nonzero but iterator tag is invalid, or its next result is absent | Call the corresponding iterator error edge |
| Key missing, slot index invalid, slot vacant, or owner differs | Skip this candidate |
| Candidate vector is full | Call the vector-growth edge before the append |
| Candidate count is 0 or 1 | Bypass the sort |
| Candidate count is 2 through 20 | Run the selected insertion step for each subsequent row |
| Candidate count is 21 or greater | Call the separate long-sort edge |
| Candidate side byte is 2 | End the removal loop |
| Local book index is out of range | Call the `books.rs:19:47` error edge |
| Removal returns nonzero | Continue without re-reading the metric |
| Removal returns zero, and selected market row is out of range | Call the `dex_registry/clearinghouses.rs:11:29` error edge |
| Removal returns zero, and the floored decrease reaches the entry gap | End the removal loop |
| Removal returns zero, and the floored decrease is smaller than the entry gap | Continue to the next candidate |

A short human-reading excerpt, not an input to the collector:

```text
4cddd2b  cmp    r12,0x2
4cddd31  cmp    r12,0x15
4cddd5e  call   490d700
4cddf41  mov    r9d,0x7
4cddf47  call   42f7420
4cddf50  test   al,al
```

### Inferences

The slot fields and earlier price-level and cancellation packets support the order, side and asset names. The previous withdraw-fee packet supports calling the entry accessor withdrawable. The raw `7` argument matches a status value elsewhere, but this packet does not follow it through removal to a status serializer and does not assign it a status name. The user-table word's financial meaning, the circumstances invoking this host and the validity of synthetic malformed states remain unresolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build flags, two-build result, raw and normalized target comparison, helper closure and whole-ELF comparison are **not yet measured**. There is no execution of the captured node or of a machine-code evaluator.

The Python fixture models are static lifts of selected conditions. They use an independently expressed tuple key to cross-check the insertion-sort lift, and separately compose synthetic lookup, row construction, short sorting and supplied removal outcomes. For one composed fixture, four inputs produce two live owner-matching rows, one owner mismatch and one out-of-range slot; the two rows reverse order, both removal calls occur, and the supplied metric reaches the threshold. This demonstrates the model's bookkeeping, not a target execution. The threshold-zero and malformed-state tests are controls, not reachability claims.

## Results and limitations

The generated evidence records 3 selected FDEs, 16 contextual windows, 18 direct-call sites, 14 RIP-relative indirect sites, 4 relocated location records and 43 selected branches. Fixture tables contain 8 lookup cases, 18 tree cases, 6 short-sort sequences, 144 abstract flag combinations, 7 entry-gap cases, 9 stop cases and 1 composed case. These are selected evidence and model counts, not function coverage or runtime coverage.

The focused unittest module contains 33 passing tests without skips, including changed digest and byte witnesses, non-executable and NOBITS addresses, duplicate relocation records, absent and colliding keys, owner mismatch, stale and vacant slots, signed minimum, exact product ceiling, equal-key stability, 20/21 length boundary and cancellation-loop controls. The generator accepts no unverified target digest. The selected branch list is not a complete CFG, and a malformed in-memory table may not terminate; the synthetic probe rejects such a fixture rather than predicting a target result.

The removal, accessor, sort-for-21-or-more, flush and allocator bodies remain external. The source-level meanings of the baseline and current words, any cross-market invariants, exception routing, an independent Rust implementation and target behavior are not closed. No component progress gate or binary-equivalence claim is requested.

Next question: establish the baseline and post-removal user-table word's units and cross-market invariants, then connect that result to the long-list sort and the actual removal/status implementation.
