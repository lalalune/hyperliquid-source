# RE-021: callback bundle and account-cache preparation on node 94

The selected four-pair callback bundle joins the previously identified precompile provider to preparation methods whose 20-byte address set and 208-byte account cache can feed a distinct account-access and journal path when given the same context, allowing these structures to be reconstructed separately from the precompile registry.

- Component ID: `evm`, RE-021 extension.
- Target release and full SHA-256: node #94 Linux x86-64, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference submodule `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference names and comments are not used as proof.
- Claim status: static observations from the authenticated ELF; inferred roles and unresolved runtime conditions are identified below.
- Scope included and excluded: one constructor, three descriptor methods, an address-set insert and membership probe, one preparation walker, an account entry probe and reserve path, and one account-access/journal decision path. The earlier 0x09 registry lookup, its handler, the 104-byte storage-table reserve helper, execution, database behavior and other releases are outside this packet.

## Reproduce

Run from the repository root with Python 3.12.3 or a compatible Python 3 with the standard library. The target artifact must exist at `artifacts/node/94/hl-node`. The extractor imports the repository's `tools/elf_index.py` and `tools/fde_extents.py`; it uses no binutils output or external programs. It checks the complete input SHA-256 before parsing, requires unique FDEs and file-backed sections, verifies each selected body hash, and writes eleven evidence files. No target instructions are executed. `MANIFEST.sha256` records the hashes of all files in this evidence directory other than the manifest.

```sh
python3 tools/re21_account_cache94.py --out research/work-items/RE-021-account-cache-preparation-94
python3 -m unittest tests.test_re21_account_cache94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/re21_account_cache94.py --out work/re21-account-cache-check/first
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_account_cache94.py --out work/re21-account-cache-check/second
diff -r work/re21-account-cache-check/first work/re21-account-cache-check/second
```

A reviewer may inspect the instruction interpretations with their own disassembler, but the extractor's numbers and files do not depend on its text. The original target digest and complete selected function bytes are in `summary.json` and `function-bytes.json`; `functions.tsv` provides VAs, file offsets and body hashes. `unwind.json` preserves the selected `.eh_frame_hdr`, FDE, CIE and LSDA header bytes, and `exceptions.tsv` preserves decoded LSDA call-site entries. `windows.tsv`, `branches.tsv`, `indirect-calls.tsv` and `relocations.tsv` retain the raw bytes behind the observations. The window and transfer lists are deliberately selected, not exhaustive.

## Evidence

All code and data coordinates in this section are link-time virtual addresses unless called a file offset. FDE ends are exclusive. Ten selected FDE intervals total 6,433 file bytes; `functions.tsv` has the individual offsets and digests. The FDE interval identifies an unwind-covered region; raw bytes and selected control transfers support the stated local interpretation, not a whole-program reachability or equivalence claim.

| Selected FDE | Static role inferred from its bytes | Principal evidence |
| --- | --- | --- |
| `0x4e77920..0x4e77ad6` | Four-pair constructor | Four 16-byte allocations; stores descriptor `0x574be78` at output `+0x08`, descriptor `0x574bea8` at `+0x18`, and two more pairs. Four null-allocation branches and cleanup landing pads are retained. |
| `0x4e76b20..0x4e76bb8` | Preparation method at descriptor `+0x28` | Context marker, two address-set calls, walker call, result-byte branch and copy. |
| `0x4e76c20..0x4e76cb8` | Preparation method at descriptor `+0x20` | Same body shape after the stated displacement mask. |
| `0x4e76d40..0x4e76dd8` | Preparation method at descriptor `+0x18` | Same body shape after the stated displacement mask. |
| `0x4e8c640..0x4e8c827` | 20-byte address-set insertion | Fingerprint candidates and full-key comparison; hit, insertion and reserve paths. |
| `0x4e8c420..0x4e8c52f` | Address-set membership probe | Empty count and control, full-key hit, and boolean result without table stores. |
| `0x4e77060..0x4e7738c` | Account access and journal decision | Account hit or miss, membership-dependent journal path, flag clearing, and failure/cleanup boundaries. |
| `0x4e77390..0x4e77914` | Address and slot preparation walker | Reads rows, probes the account map, constructs missing accounts and handles nested slot hits and misses. |
| `0x4e8c100..0x4e8c286` | Account entry probe | Hash, grouped controls, full 20-byte equality, hit/miss result and account reserve call. |
| `0x4e758a0..0x4e76117` | Account-map reserve and rehash | Checked capacity sizing, in-place rehash or allocation, row movement, publication and failure boundaries. |

### Bundle and preparation methods

The provider descriptor has RELA slot `0x574bea0` at `+0x28`, with addend `0x4e76bc0`; prior PR #1373 associates that method with the mode-5 provider containing the 0x09 registry. The preparation descriptor has slots `0x574bec0`, `0x574bec8` and `0x574bed0` at `+0x18`, `+0x20` and `+0x28`; their respective RELA addends are the three selected preparation methods. `bindings.json` records constructor RIP-relative descriptor references and these relationships are independently backed by `relocations.tsv`. This proves composition of the returned bundle when the constructor succeeds, not that any specific transaction chooses a particular callback or that the callbacks execute in a given order.

Each preparation body is 152 bytes. The three full body hashes differ; their byte strings are identical only after masking four 4-byte PC-relative displacement fields at method offsets `0x43`, `0x4a`, `0x61` and `0x6c`. The extractor checks the three call destinations and constant-data RIP target for each body separately. This is an intra-target shape comparison, not comparison with compiled Rust.

The methods write `0xff` to context `+0xb0`, then call `0x4e8c640` for the 20 bytes at the environment pointer's `+0xd0` and for the fixed 20-byte value `25a219378dad9b3503c8268c9ca836a52427a4fb`. They then call `0x4e77390`. The first 16 constant bytes are file data at `0x7c360c`; the remaining four are an immediate in each method. Both calls are insertion attempts: an already-present set entry follows the hit path. The set checks its growth field and calls its reserve boundary before it searches for a duplicate; in contrast, the account-entry probe checks reserve only after a miss. The set returns a low byte of 1 for an existing key and 0 after a new insertion. These calls precede the walker's empty-row check. The callback propagates a result byte of 5 and has a separate non-5 path copying 32 bytes; the selected walker's normal return writes 5.

### Walk and state changes

The walker reads the environment pointer at context `+0xd8`. It uses the row pointer and count at environment `+0x1f0` and `+0x1f8`. A row is 48 bytes: the 20-byte address starts at `+24`, and the nested slot pointer and count are at `+8` and `+16`. Slot inputs advance by 32 bytes, with four byte swaps forming the key used by the nested probe. The account map begins at context `+0x30`; the address set begins at context `+0x80`. `layout.json` derives the selected immediate operands from their exact instruction-byte predicates.

| Condition | Observed local transition |
| --- | --- |
| Address-set growth is zero | `0x4e8c692` reaches its distinct reserve boundary before testing for a full-key hit; after reserve it performs the search. |
| Outer count is zero | `0x4e773bc` branches to the normal byte-5 return. The callback's two address-set attempts have already occurred. |
| Account key hits | `0x4e8c100` writes zero to result word 0 and a bucket-end pointer to word 1; `0x4e7744b` bypasses missing-account construction. A zero slot count advances to the next row. |
| Account key misses | The result carries the table pointer, hash and key. If the growth field is zero, `0x4e8c100` first calls reserve with additional count 1 and mode 1. The walker calls the external default-record boundary, finds a free control, writes its fingerprint and mirror, stores the 20-byte key, copies 172 prepared record bytes, stores a nested-table seed and byte 8, and increments the account count. |
| Slot key hits | Full 32-byte key equality branches to the next slot or row without the new-slot writes. |
| Slot key misses | If needed, control reaches the previously studied 104-byte slot reserve boundary `0x4e742e0`. The insertion stores the normalized key, four consecutive 16-byte zero values and a zero byte, then increments the nested count. No persisted-state or database conclusion follows from these writes alone. |
| Constructor allocation returns null | Four distinct branches lead to failure/cleanup code. LSDA entries preserve cleanup landing coordinates; behavior of called failure and cleanup helpers remains a boundary. |
| Account allocation or size check fails | The caller uses reserve mode 1. Checked overflow reaches the capacity-failure slot; a null allocation reaches the allocation-failure slot. Other mode values have separate return paths. Helper behavior and unwind/rollback outcomes are not established. |

The walker has an LSDA call-site interval `0x4e77476..0x4e7747f` landing at `0x4e778f9` for the default-record boundary, and `0x4e7789c..0x4e778a1` landing at `0x4e778d7` for seed initialization. `exceptions.tsv` lists all 20 selected call-site rows across the selected FDEs. Action indices are retained; action and type tables are not decoded as an exception taxonomy.

### Account access and journal decision

The separately selected `0x4e77060` accepts a context in `rsi` and a 20-byte key in `rdx`, calls `0x4e8c100` with context `+0x30`, and on an account miss calls `0x4e8c420` with context `+0x80` and the same key. The latter is a read-only membership probe: an empty set count or an empty control yields low byte 0, and full 20-byte equality yields low byte 1. This is a conditional composition with the preparation path: the static bytes do not show that a live request passes the same context or chooses this account-access routine.

| Account-access condition | Observed transition, assuming called helpers return normally |
| --- | --- |
| Account hit, flag bit `0x10` clear | Return result tag 5, bucket pointer at `+24`, and result byte 0. No membership lookup or journal append is taken on this branch. |
| Account hit, flag bit `0x10` set | Clear that bit, then enter the journal append path. After a successful append the result byte is 1. |
| Account miss and address-set hit | Construct and insert an account record; skip the journal append and return result byte 0. |
| Account miss and address-set miss | Construct and insert an account record, append a journal record and return result byte 1. |
| Journal frame absent | The path reaches the external failure boundary at slot `0x576e470`; no claim is made about its behavior or recovery. |
| Journal record vector full | The path calls the external reserve boundary at slot `0x5773270` before writing the entry. |

The append uses the last 24-byte frame selected from context `+0x20/+0x28`. It stores tag byte 0 and the 20-byte key starting at entry `+1` in an 88-byte-stride record, then increments the record count. These are local writes, not a proof of rollback semantics or durable database state. The access routine has an LSDA interval `0x4e7717f..0x4e7718b` landing at `0x4e7736e`, and an initialization interval `0x4e77330..0x4e77335` landing at `0x4e77352`; actions and cleanup helpers remain external boundaries.

### Account probe and reserve

At `0x4e8c100`, four overlapping 8-byte little-endian loads cover the 20-byte key. Two process seed words come through RELA slot `0x576e3e0`, whose addend points into a `SHT_NOBITS` section; the live values cannot be read from the ELF. Another seed is at table `+0x20`. The 64-bit multiplication folds high and low halves with XOR; the high seven hash bits are the control fingerprint. A probe checks 16 controls and compares all 20 key bytes for candidates before treating `0xff` as empty; the deleted marker `0x80` does not itself terminate lookup. Subsequent group starts advance by 16, then 32, then 48, under the mask.

For logical index `i`, the selected instructions address the 208-byte bucket beginning at `controls - 208*(i+1)`. The hit result points to `controls - 208*i`, the bucket end. The selected insertion writes the key at bucket `+0`, 172 bytes at `+20`, a seed at `+192`, and byte 8 at `+200`. The set probe addresses 20-byte buckets, while the account probe addresses 208-byte buckets and the prior precompile registry uses 48-byte buckets. An address in one table does not establish membership in either of the others.

For a well-formed mask one less than a power of two, reserve computes capacity as the mask when it is below 8, otherwise `(mask+1) - ((mask+1) >> 3)`. After a checked `count + additional`, a request at most half that capacity enters in-place reclassification and rehash. Otherwise it requests the greater of `capacity+1` and the needed count, chooses 4, 8 or 16 buckets for requests below 15, or uses checked scaling by 8/7 and a power-of-two bucket count. For `n` new buckets, the selected allocation-size arithmetic is `208*n + n + 16`; control bytes are initialized to `0xff`. The body rehashes and copies 208-byte buckets, publishes the new control pointer, mask and growth field, and conditionally releases the old allocation. The raw branches and indirect slots are retained; any semantic assumptions about external allocation, filling, copying or freeing remain explicit boundaries.

## Implementation and comparison

Independent Rust implementation, build scope, compiler comparison, whole-ELF comparison and runtime behavior: **not yet implemented/measured**. The only normalization is the four displacement fields for the three methods described above. No relocation, call-target, vtable/data, helper, compiled-code or whole-ELF equivalence is claimed.

The tool includes small synthetic projections of the observed hash, grouped key probe and reserve sizing solely for corruption and boundary tests. These are not target execution or an independent proof of the complete target semantics; the probe projection requires power-of-two tables of at least 16 controls. Tests compare the hash projection with separate shift/add multiplication and reserve sizing with a capacity oracle, change each of the 160 key bits, exercise deleted controls, wraparound, a third triangular group, the distinct set/account reserve ordering, account hit/miss and journal-branch byte predicates, malformed ranges and overflow, and corrupt the input digest, body bytes, instruction predicate, RELA records and LSDA data. The full target is never executed.

## Results and limitations

The reproducible selected evidence comprises 10 FDEs / 6,433 body bytes, 44 manually selected byte windows, 50 selected direct transfers, 16 selected indirect calls, 17 RELA slots, 3 compared method shapes and 20 exception call-site rows. These are the selection sizes, not a node or component coverage denominator. `MANIFEST.sha256` records the resulting file hashes. Targeted unittest and independent-output checks are reported in the accompanying draft.

The earlier work on the 0x09 object, registry lookup and 104-byte storage-table reserve remains separate. The prior revision-9 read-builder analysis in PR #1867 observes an initially zero outer-row count before callback boundaries, subject to later mutation or aliasing; it does not establish that this descriptor is selected. The nonempty walk in this packet remains conditional on both selection and suitable inputs. The descriptor composition is conditional on this constructor and runtime callback selection is unresolved. Exact types, live seeds, external helper effects, callback reachability, database interactions, failure rollback, behavior on malformed runtime tables and execution equivalence remain open. Node #115 and visor are separate targets. No component milestone gate is requested; `evm` remains at 0/4.

Next question: which previously unowned caller and control state choose this preparation descriptor and account-access path for a concrete transaction, and how does the resulting state cross the already mapped 0x09 dispatch boundary?
