# RE-006: client-ID index update during a resting-order insertion

This packet establishes how node #94 updates both directions of a per-user order-ID/client-ID index, including replacement, collisions, control-byte deletion, table rehash and allocation boundaries, so a reconstruction can preserve the index when an order rests or a client ID is reassigned.

- Component ID: `orderbook`, task RE-006, resting-order insertion bookkeeping.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / unlicensed `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a search lead, not implementation evidence or code copied here.
- Claim status: the selected raw bytes, FDE extents, relative-call operands, ELF relative relocations, branch destinations, immediate operands and data literals are observations. Identification as order IDs, client IDs and a book follows the already recorded call-site context; the logical map projection below is an inference from the selected instructions. No captured instruction has been executed.
- Scope included and excluded: eight previously unrecorded FDEs cover user entry lookup/insertion, both inner table puts, their three growth paths and their shared allocation-layout helper. The already researched insertion body and bimap coordinator are used only as bounded context. Their complete bodies, external hash functions, allocator internals, rollback and whole-book execution are excluded.

## Reproduce

From the repository root with Python 3.12.3 on Linux x86-64:

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_book_client_bimap94
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_client_bimap94.py --out work/client-bimap-a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_client_bimap94.py --out work/client-bimap-b
diff -r work/client-bimap-a work/client-bimap-b
diff -r -x README.md -x MANIFEST.sha256 work/client-bimap-a research/work-items/RE-006-client-id-bimap-94
python3 tools/catalogue.py --check
```

The collector checks the full binary SHA-256 before parsing. It reads only ELF bytes using Python's standard library and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`; it rejects NOBITS and ambiguous file mappings. It invokes no disassembler or external process and does not execute either captured program. GNU objdump 2.42 was used for manual inspection of the listed instruction boundaries, not as generator input. `functions.json`, `calls.tsv`, `branches.tsv`, `witnesses.tsv`, `constants.tsv`, `copy-operands.tsv`, `literals.tsv`, `locations.tsv` and `summary.json` are generated. `MANIFEST.sha256` covers this README and those files. The source path of the one relocated diagnostic is intentionally retained only as a relative suffix.

## Evidence

All addresses below are linked ELF virtual addresses; ends are exclusive. On these `.text` windows the file offset is VA minus `0x1000`. An FDE is an unwind-described extent, not proof of a source-level function boundary. All eight extents are authenticated and their complete raw bytes and hashes are in `functions.json`.

| Descriptive role | FDE extent | Bytes |
| --- | --- | ---: |
| User entry | `0x3596b30..0x3596d97` | 615 |
| User entry probe | `0x3799e90..0x3799fce` | 318 |
| Order ID to client ID put | `0x379f580..0x379f72d` | 429 |
| Client ID to order ID put | `0x379d4f0..0x379d685` | 405 |
| Outer user table growth | `0x357c210..0x357c859` | 1609 |
| Order-ID table growth | `0x357da80..0x357df8c` | 1292 |
| Client-ID table growth | `0x35781f0..0x35786fc` | 1292 |
| Shared table layout/allocation | `0x3577160..0x3577309` | 425 |

### Handoff and update order

The previously documented perp insertion body reaches this path after its order-ID-to-slot update. At `0x4312fb2` it tests a saved byte; zero bypasses the index call. Otherwise it forms `book + 0x48`, supplies a copied 20-byte user and the order and client values, and calls through slot `0x5774810` at `0x4312ff3`. The ELF `R_X86_64_RELATIVE` addend for that slot is coordinator `0x342aa50`. The slot establishes the static link; the runtime loader and any patching are not examined. The body of the insertion function is not claimed here. The inference that the saved flag means a client ID is present follows `RE-006-perp-order-insert-94`; the saved byte itself is observed here.

The coordinator first calls `0x3596b30` with the outer table and the 20-byte key. The returned per-user object contains two tables. It calls `0x379f580` to put `(order ID -> client ID)`, uses that result, then calls `0x379d4f0` to put `(client ID -> order ID)`. `calls.tsv` records the caller and helper edges. The ordered branch table is:

| Earlier order-ID entry | Prior client for this order | Prior order for new client | Observed coordinator action |
| --- | --- | --- | --- |
| Absent | none | absent | Write both directions. |
| Present | equal to new client | not read | Return after the first put; the reverse table is not checked. |
| Present | different | absent | Delete the old client's reverse entry if found, then write the new reverse entry. |
| Either | absent or different | present | Write the new reverse entry and delete the displaced order's forward entry if found. |

The old-client comparison at `0x342aa8e` covers all 16 bytes. The return tags come from the two selected put helpers: the first returns a byte tag and, when present, a 16-byte old value; the second returns an `al` tag and an old qword in `rdx`. The coordinator's lookups can miss and simply continue or return. Removal of an old reverse entry is by its 16-byte key; removal of a displaced forward entry is by its qword key. Neither removal compares the associated value first. The table above assumes normal return and no aliases among input and table storage; it does not claim behavior for every malformed state.

A repeated pair is logically unchanged, but is not necessarily physically untouched: each put tests its table's available-growth word before probing, so a full table can rehash or allocate before the coordinator discovers the same pair. A failure of the later put can occur after the earlier put and deletion instructions. This evidence does not establish whether an enclosing caller rolls anything back.

### Layout and probing

For the outer user table, `0x3799e90` hashes and compares a full 20-byte key. A bucket has stride `0x78`. The returned nested object starts `0x18` bytes into its bucket: `0x3596b30` turns the probe result into that pointer on both the existing and inserted routes. Within this object:

| Offset | Use in selected instructions |
| --- | --- |
| `+0x00` | Order-ID to client-ID hash-table header. |
| `+0x30` | Client-ID to order-ID hash-table header. |
| Table `+0x00`, `+0x08` | Control-byte pointer and bucket mask. |
| Table `+0x10`, `+0x18` | Remaining growth allowance and item count. |
| Table `+0x20` | Two qwords passed to the corresponding hash helper. |

Both inner buckets occupy `0x18` bytes. The first holds an 8-byte order key followed by a 16-byte value; the second holds a 16-byte client key followed by an 8-byte value. The control pointer lies after the backwards-indexed bucket storage. Both puts compare fingerprints from `hash >> 57` in groups of 16 bytes, check the complete key on a fingerprint match, and advance through groups until a matching key or an empty control is seen. The fixed immediates and data are in `constants.tsv` and `literals.tsv`; the hash algorithms themselves are outside this packet.

On insertion, the low bit of the previous negative control byte is subtracted from the growth allowance and the item count increases by one. The fingerprint is written both to the selected control byte and to the mirrored control area. The data at `0x203480` supplies the two qword lanes used by that update. On a found deletion the coordinator tests neighboring empty controls: the selected control is set to `0xff` and growth allowance increases when the combined distance is at most 15; otherwise it becomes `0x80`. Both control copies are written and the item count decreases. Calling `0xff` empty and `0x80` deleted is an inference supported by these tests and the probe behavior, not a claim about all possible control bytes.

### Growth and failure boundaries

The three growth helpers take the same broad decisions for their different bucket widths. They first add the requested extra count to the current item count and branch on unsigned overflow. For bucket mask `m`, their effective capacity is `m` when `m < 8`, otherwise `(m + 1) - (m + 1) / 8` using integer division. If the required count is at most half that capacity they rebuild controls in place; otherwise they request a new table for the larger of required count and capacity plus one. The in-place path marks controls, rehashes live entries, and either moves or swaps a 24-byte inner bucket; the allocating path rehashes into new storage and installs its pointer and mask. The outer path uses the same allocation helper with `0x78`-byte buckets. These statements are bounded to the observed code and well-formed table inputs.

For requested element count `n`, the shared helper chooses 4 buckets for `n < 4`, 8 for `4 <= n < 8`, 16 for `8 <= n < 15`, and for `n >= 15` the next power of two at least `floor(8*n/7)`. Before allocation it checks the multiply, 16-byte rounding, additions, and the total layout ceiling `0x7ffffffffffffff0`; a large `n` also has a shift overflow guard. Its selected failure arm references the literal `Hash table capacity overflow` and the relocated source-location suffix `src/raw/mod.rs:37:40`. The callers pass a nonzero error-mode byte; the selected instructions then call the external failure handler on overflow or allocation failure. The handler, unwind actions and allocation side effects are not analyzed.

The two inner growth FDEs are each 1292 bytes. Exactly 10 explicitly enumerated four-byte PC-relative operands are masked for the comparison, 40 bytes in total. Every other byte agrees. `copy-operands.tsv` gives each original operand and decoded target; the two hash-call operands point to different helpers, while the other eight targets agree. This does not claim that the different hash helpers, all reachable callees, relocation effects or the complete ELF are equivalent.

### Inferences and unresolved questions

The bimap interpretation follows the per-user call context, key widths, paired writes and cleanup branches. The order-ID and client-ID names use existing `RE-006-cancel-item-path-94` and `RE-006-perp-order-insert-94` evidence, not a recovered symbol. A consistent bimap stays consistent under the four ordinary cases above; a same-pair fast return does not repair an already inconsistent reverse table. No runtime reachability proof, transaction rollback, concurrent mutation semantics or behavior of malformed table metadata follows from these bytes. The initial per-user seed initialization uses thread-local state and static data; its source and randomness properties are not determined.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. The focused tests exercise static byte admission and separately written synthetic projections; those projections do not execute target code and are not differential behavior fixtures. A 20-method suite covers authenticated input and FDEs, direct and relocated calls, branch decoding, all full-body hashes, an altered instruction, altered call and branch operands, duplicate and truncated RELA records, NOBITS and ambiguous mappings, four logical reassignment cases, inconsistent-map behavior, growth thresholds, bucket-size boundaries and layout overflow. Synthetic fixtures establish consequences of the stated interpretation, not target-runtime behavior.

No Rust build, two-build comparison, target ABI comparison, relocation/vtable closure or whole-ELF match has been made. The only comparison mask is the 40-byte growth-copy mask stated above; all complete original bytes remain in `functions.json`.

## Results and limitations

The selected denominator is eight FDEs totaling 6385 bytes, with 13 direct calls, four relocation-bound indirect calls, 36 selected conditional branches, 17 fixed instruction witnesses, eight extracted immediates, three data literals, one relocated diagnostic and 10 compared operands. These are bounded evidence counts, not function coverage of RE-006. Twenty focused tests pass without skips. The import-pin check initially could not write Git LFS temporary data in the read-only submodule Git directory; with a temporary external LFS storage override it verified 38 imported files and all source pins. No component progress gate is requested.

Remaining gaps include the full coordinator and caller control-flow closure, the allocator and hash implementations, actual exception/rollback behavior, deletion after cancel or fill, live execution and independent Rust reconstruction. Next question: trace the client-ID removal path after an order is canceled or fully filled, including whether both directions are removed on every successful branch.
