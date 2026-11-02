# RE-006: fill-user set insertion and split propagation on node 94

A reconstruction of the fill and resting-order paths can now preserve the user-set duplicate rule, its 20-byte key ordering, and the exact 11-key split and root-publication decisions, including distinct local failure routes.

- Component ID: `orderbook` (RE-006).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a search lead only; no reference code is copied or taken as evidence.
- Claim status: byte-level observations and explicitly labeled inferences below; static fixture projections are not target execution.
- Scope included and excluded: two newly selected unwind extents for an insertion counterpart and its shared split helper; the previously studied fill entry and small caller windows are context only. Full matching, user-set traversal after insertion, allocation and panic implementations, rollback, and Rust reconstruction are excluded.

## Reproduce

Run from the repository root with Python 3 and the authenticated target. Author environment: Linux x86-64, Python 3.12.3. The collector imports the repository ELF, FDE and ULEB readers, reads only the target file, excludes `SHT_NOBITS` from address resolution and does not invoke another program or execute captured code. The raw disassembly was inspected with GNU objdump 2.42 only as an aid to selecting fixed byte windows; its output is not a collector input or generated artifact.

```sh
python3 tools/artifacts.py verify
python3 tools/book_fill_user_set94.py --out work/fill-user-set-a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_fill_user_set94.py --out work/fill-user-set-b
diff -r work/fill-user-set-a work/fill-user-set-b
diff -r -x README.md -x MANIFEST.sha256 work/fill-user-set-a research/work-items/RE-006-fill-user-set-splits-94
python3 -m unittest tests.test_book_fill_user_set94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-fill-user-set-splits-94 && sha256sum -c MANIFEST.sha256)
```

The generated files are `functions.tsv`, `windows.tsv`, `branches.tsv`, `calls.tsv`, `operand-comparison.tsv`, `comparison-bytes.tsv`, `comparison-differences.tsv`, `relocations.tsv`, `locations.tsv`, `diagnostics.tsv`, `exception-sites.tsv`, `failures.tsv`, `split-parameters.tsv`, `split-cases.tsv` and `evidence.json`. The manifest includes this README and those generated files. Selected windows are bounded byte ranges and do not constitute a complete instruction listing. Addresses are linked ELF virtual addresses; FDE ends are exclusive. The collector authenticates the complete input before parsing it.

## Evidence

### Binding the path

| Role | Unwind extent | File offset of start | Status |
| --- | --- | --- | --- |
| Insertion counterpart | `0x492d640..0x492d863` | `0x492c640` | Selected |
| Split and upward propagation | `0x41fb1d0..0x41fbb7a` | `0x41fa1d0` | Selected |
| Fill-path insertion entry | `0x4941fe0..0x4942203` | `0x4940fe0` | Previously studied context |

The established perp insertion body calls the prior fill-pair builder at `0x4312339`. Its returned pair is copied into two 20-byte temporary keys. The dword at stack `+0x100` is compared with 1; equality reaches the two successive calls at `0x4312395` and `0x43123aa`, both passing the same set at stack `+0x108` and a different key. Another condition, a dword at stack `+0x270` equal to 1, reaches a single set call at `0x43130e1` after the queue call at `0x43130c0`. The previously reviewed insertion packet identifies these as the fill users and the touched-user bookkeeping. The precise runtime meaning of both local flag words and alias freedom are not independently proven here.

The two 547-byte entry extents differ at 21 raw byte positions. Zeroing seven explicitly listed four-byte PC-relative fields yields equal 547-byte bodies; the unmodified operands independently resolve to the same seven targets, including the shared split helper. The mask is exactly the 28 bytes in `operand-comparison.tsv`, including call and RIP-relative operands; it does not mask other bytes. This is a target-to-target comparison of one selected counterpart and one context entry: zero raw-equal, one normalized-only, zero unmatched, with a denominator of one pair. It is not a Rust-to-target comparison or a whole-node coverage measure. The complete entry and split hashes, FDE records, coordinates and raw bytes of the selected windows are retained.

### Search, insertion and splits

The entry reads the set root at header `+0`, height at `+8`, and count at `+0x10`. It searches each node using an indirect comparison of 20-byte input and key slices; the slot's dynamic relocation names `memcmp`. Keys start at node `+0x08` with stride `0x14`; the 16-bit key count is at `+0xe6`, and child pointers begin at `+0xe8`. A comparison equal to zero returns low byte 1 without entering the new-key path. A missing key that is inserted returns low byte 0 and increments header `+0x10` after its selected insertion helper returns. An empty root allocates `0xe8` bytes, initializes the node count and header height to zero, stores the key and increments the count. Allocation and invalid-count destinations are in `branches.tsv` and `calls.tsv`.

At the split helper, a node with fewer than 11 keys shifts the suffix when required and inserts the 20-byte key. A full leaf selects an old key for promotion before inserting the new key; a full parent uses the same position decisions. The 12 position rows retain the old pivot and the destination index, using immediates extracted from the leaf and parent instructions:

| Insertion position among 11 old keys | Old pivot index | Destination for new key |
| --- | ---: | --- |
| 0 through 4 | 4 | left, at the original position |
| 5 | 5 | left, at index 5 |
| 6 | 5 | right, at index 0 |
| 7 through 11 | 6 | right, at index `position - 7` |

The leaf split allocates `0xe8` bytes; the internal split and new root allocate `0x148`. Internal children have their parent pointer at `+0` and 16-bit parent-edge index at `+0xe4` rewritten as edges move. A split propagates until a parent has room or a new root is made. The selector and destination rows are a static projection of the listed instruction bytes; the tests check ordered synthetic examples rather than execute the target.

### Failures and publication order

The helper's FDE points to the exception table at `0xb2264c`. Its omitted-base, omitted-type, ULEB call-site table contains 10 decoded rows. Twelve selected calls in diagnostic arms are joined to these rows in `failures.tsv`; a blank landing means that the row has no **local** landing, not that no outer cleanup exists. Action values are recorded without interpreting the personality routine.

On the root-growth route, the newly allocated node first receives the old-root pointer at `+0xe8`. The height increment is then checked for wrapping before the old node's parent pointer and the header's root/height are stored. A later height-disagreement check occurs after those header stores. The wrap-error call at `0x41fbb05` has local landing `0x41fbb3f`, whose bytes pass the `0x148` allocation and pointer to the release-shaped slot and then reach `ud2`. The published-height mismatch call at `0x41fbb20` has no local landing. These are static unwind records: their execution depends on the error handler and exception mechanism. The split may already have modified a node before a later diagnostic; no caller-level rollback claim follows.

The leaf right-count error and selected internal edge/count errors have different local landing addresses and allocation widths. Four diagnostic strings and nine relocation-backed source-location records are retained, with compiler path prefixes removed and only the source suffix printed. They corroborate local bounds, copy-length and height checks; they do not establish source function boundaries.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lock, build flags, target ABI, helper closure and raw or normalized Rust-to-target comparisons are **not yet measured**. The two target entry copies above are compared only to connect the previously studied fill site to the newly selected split helper. Dynamic allocation, `memcmp`, `memmove`, panic handlers and unwind behavior are not reconstructed.

The focused suite checks the authenticated artifact, exact FDE extents and function hashes, every selected branch and call with opcode and displacement corruption, every pinned window with a corrupted byte, all seven comparison operands and an unmasked byte, file-backed range and NOBITS rejection, relocation and location corruption, and the exception table. It also exercises all 12 split-position cases. A separate synthetic B-tree model inserts 600 unique keys in ascending, descending and deterministic shuffled order, repeats 55 existing keys per sequence, and checks sorted membership, equal leaf depth, child cardinality, duplicate handling and the non-root key bounds. These fixtures validate the projection's consistency, not live target behavior.

## Results and limitations

The collector records 2 selected extents, 1 context extent, 37 selected branches, 21 selected calls, 18 byte windows, 9 relevant dynamic relocations, 9 source locations, 4 diagnostic strings, 10 exception call-site rows, 12 failure calls 13 decoded split immediates and 12 split-position projections. Thirteen focused unittest methods passed without skips. The two target entry bodies compare as one normalized-only pair under the stated 28-byte mask; no engineering or component coverage percentage is inferred.

FDE ranges describe unwinding and need not equal original source-function boundaries. The selected branches are not a complete CFG, and the result depends on normal helper return and well-formed objects unless otherwise stated. The reachability of corrupted states, behavior of allocation and panic handlers, unwind side effects, aliasing, outer rollback, consumers of the sets, and all other book transitions remain unresolved. No RE-006 progress gate is requested.

Next question: follow the completed touched-user set into the reduce-only queue sweep and establish ownership and ordering across the set iterator and the subsequent removals, without reselecting previously mapped functions.
