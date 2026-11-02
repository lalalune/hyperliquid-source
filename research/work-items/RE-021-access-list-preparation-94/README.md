# RE-021: revision-9 storage-key cache before precompile lookup

The common precompile-preparation walker now has a 15-descriptor revision map and a reconstructible account/storage-key cache path, including key order, duplicate handling, resize decisions and the revision-9 read route's empty-list limitation.

- Component ID: `evm`; RE-021 is a continuation of the unresolved runtime-wiring question in `RE-021-blake2b-compress-94`, not an official TASKS row.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`; no reference code was copied. The bounded instruction-length decoder is adapted from this repository's MIT-licensed `tools/evm_kvs_inventory.py`.
- Claim status: observations are file bytes, ELF virtual addresses, FDE ranges, relocations, decoded branch destinations and operands; names such as access list, account and storage key are interpretations. Runtime inputs, actual dispatch, gas effects, database semantics, atomicity and source-level Rust types remain unresolved.
- Scope included and excluded: 45 methods in 15 descriptor groups, their common list walker, its slot-table reserve/rehash helper, and selected normal and exceptional edges. The earlier address-09 record, registry lookup, execution driver, backing database, address-set helper and private revision-18 sibling are boundaries, not newly claimed function bodies. Node #115 and visor are separate targets.

## Reproduce

From the repository root, with the authenticated artifact present and Python 3.12 (verified with 3.12.3) on Linux x86-64:

```sh
python3 tools/re21_access_list94.py --out research/work-items/RE-021-access-list-preparation-94
python3 -m unittest tests.test_re21_access_list94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/re21_access_list94.py --out work/re21-first
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/re21_access_list94.py --out work/re21-second
diff -r work/re21-first work/re21-second
```

The generator hashes the input before parsing; a different digest fails. It reads ELF, unwind and instruction bytes using Python's standard library and the repository's shared ELF/FDE parsers. It does not start binutils or execute the target. Its restricted instruction-length decoder fails on unsupported forms; it is not a general disassembler. Outputs are the 15 generated evidence files; `MANIFEST.sha256` also covers this README. The test models use explicit synthetic inputs and are not captured node executions.

## Evidence

All code addresses are node #94 ELF virtual addresses; file offsets and raw bytes are in the generated records. Ends in `functions.tsv` and windows are exclusive. Five selected FDE extents on the detailed revision-9 route are:

| FDE start | Exclusive end | Bytes | Selected role |
| --- | --- | ---: | --- |
| `0x276fa70` | `0x276fab5` | 69 | descriptor method at `+0x28` |
| `0x27712d0` | `0x2771315` | 69 | descriptor method at `+0x20` |
| `0x2776950` | `0x2776995` | 69 | descriptor method at `+0x18` |
| `0x278ed50` | `0x278f91f` | 3023 | account and slot list walker |
| `0x4e742e0` | `0x4e74a50` | 1904 | slot-table reserve and rehash |

`functions.tsv` gives all 47 selected FDEs and their hashes. `unwind.json` retains the index, FDE and CIE bytes. FDE extents are selected unwind ranges, not a whole-binary function inventory or a proof that all possible entry points have been found. `instructions.tsv` is a sequential decoding of these ranges; `control-flow.tsv` records direct transfers, indirect transfers, traps and returns without claiming all indirect targets. `calls.tsv` lists call sites, relocation-resolved targets and unresolved boundaries. `semantic-windows.tsv` contains the raw windows used below, and `decisions.tsv` records 29 reviewed conditional edges in the detailed walker and reserve helper. The condition-code nibble, selected flag-setting bytes and branch destination are checked; the English interpretation is still a reviewable inference.

### Revision descriptor family

The generator searches `.text` for direct-call byte candidates to `0x278ed50`, matches candidates to FDEs, and checks that the call starts at a decoded instruction. It then reads each wrapper's context-byte store and the relative relocation to that wrapper, grouping contiguous descriptor slots at `+0x18/+0x20/+0x28`. `revision-descriptors.tsv` and `revision-methods.tsv` retain all resulting addresses and file coordinates. This is a bounded FDE-indexed direct-call scan, not a proof of all indirect callers, alternate entries or live callback selection. The 45 methods belong to one shared call family, not 45 independently reconstructed subsystems.

To compare the three methods in each descriptor, the extractor masks only the four displacement bytes of direct relative calls and the four displacement bytes of the selected RIP-relative key-address instruction; it separately checks the decoded call and key-address targets. All other bytes must agree. `revision-methods.tsv` retains both the raw-body SHA-256 and masked-shape SHA-256 for each method; the original unmasked bodies, instructions and relocations remain in the evidence files. This is an intra-family byte-shape check, not a rebuilt-binary comparison.

| Context byte stored by methods | Descriptor VA | Calls to the address-set boundary before the walker |
| ---: | --- | ---: |
| 0 | `0x56beab0` | 0 |
| 2 | `0x56bf5f0` | 0 |
| 4 | `0x56bedb0` | 0 |
| 5 | `0x56bf9b0` | 0 |
| 6 | `0x56bf830` | 0 |
| 8 | `0x56beb70` | 0 |
| 9 | `0x56becf0` | 0 |
| 11 | `0x56be7b0` | 0 |
| 12 | `0x56bf170` | 0 |
| 15 | `0x56bf6b0` | 0 |
| 16 | `0x56be3f0` | 1 |
| 17 | `0x56bf2f0` | 1 |
| 18 | `0x56be870` | 2 |
| 19 | `0x56bf3b0` | 2 |
| 255 | `0x56be630` | 2 |

In the one-call and two-call families the first call passes a 20-byte value loaded from environment `+0xd0` to the previously studied set helper `0x27c7e10`, with context `+0x80` as the other argument. In the two-call family the second call passes 20 file bytes at `0x3f040f`: `25a219378dad9b3503c8268c9ca836a52427a4fb`. The helper's interpretation as an address-set insertion is supported by prior work and remains a boundary here. The byte values above are observed stores, not inferred historical fork names. PR #1540's revision selector separately maps multiple raw inputs to some of these canonical values; it does not imply every descriptor is installed in every engine. In particular, PR #1563's private revision-18 sibling uses a different descriptor and walker; this table alone does not establish private-fork selection.

### Placement before the registry

`descriptor.tsv` and `relocations.tsv` show symbol-free relative relocations for descriptor `0x56becf0`: slots `+0x18`, `+0x20`, and `+0x28` resolve respectively to `0x2776950`, `0x27712d0`, and `0x276fa70`. The file contents at those slots are zero before relocation. Each method stores byte 9 at context `+0xb0`, calls `0x278ed50`, and either returns tag 5 or copies the non-five result's 32 bytes. The revision byte 9 is distinct from the precompile address 09.

The connection to precompile dispatch depends on earlier pending work. PR #1540 records revision inputs 9 and 10 reaching the same constructor and retains its instructions: the load at `0x2790e93` and stores at `0x2790f07`/`0x2790f0b` put `0x56becf0` in the second returned pair; the copy at `0x246349c`/`0x24634b4` puts that pair at handler `+0x58/+0x60`. Using that PR's handler-to-engine offset, the existing executor reads the pair at engine `+0x168/+0x170` and calls its `+0x28` method at `0x2513530` before registry installation. PR #1373 traces a constructed registry containing the address-09 record through lookup to the wrapper. PR #1563 examines a revision-18 sibling; this packet instead pins the revision-9/10 slot-key probe and resize decisions in distinct FDEs. Previously selected parent and registry function bodies are not included here.

The earlier evidence also permits a conditional input-to-key composition. PR #1540 records the read builder copying 20 bytes from its incoming `rdx` address to environment `+0x295`, and its executor passing environment `+0x158` to the frame-constructor slot. PR #1563 analyzes that slot's resolved constructor: under normal clone/allocation/copy behavior it places those environment bytes at frame `+0x60` and sets the scheme byte to zero. If the 20 bytes are nineteen zeros followed by `09`, are retained until that constructor call, callback pairs remain installed, and the previously recorded account, value, registry and dispatch guards allow lookup, the revision-9 route has the address-09 frame key. This composition relies on the pending results and external-call/alias assumptions; it does not establish that a live request selects this route or that preparation is atomic.

The nonempty-list branch needs a further reachability qualification. In PR #1540's retained builder instructions, zeroing at `0x2446d62` and `0x2446e1e`, followed by the moves at `0x2446e80`, `0x2446e88`, `0x2446fe4` and `0x2446fe9`, initializes environment `+0x1f8` to zero before the intervening callback boundaries. If those calls do not change or alias that field, this builder reaches the walker's immediate tag-5 return; the nonempty account and slot branches below are then not taken. Other callers, callback mutations and live reachability have not been established.

### Input and account branches

The walker loads an environment pointer from context `+0xd8`, then a pointer/count from environment `+0x1f0/+0x1f8`. The count advances over 48-byte rows. Each row supplies 20 bytes at `+0x18` and a slot pointer/count at `+0x08/+0x10`; the inner input advances 32 bytes. Those shapes motivate the account/access-list names but do not independently prove source types. `layout.tsv` derives the offsets and strides from the pinned operands.

| Condition at site | Observed continuation |
| --- | --- |
| `0x278ed7f`: outer count zero | Go to the normal tag-5 return. |
| `0x278ee49`: external probe returns first word zero | Use the returned entry; with zero slot count, advance to the next row. |
| `0x278ee49`: nonzero first word | Call the external account getter, construct a record and insert a bucket with stride 208; insertion precedes the zero-slot-count test. |
| `0x278eec5`, `0x278ef91` | Distinguish account-getter word equal to one, and later a zero low byte; different temporary representations and cleanup paths follow. The source-level variants are unresolved. |

The account probe and getters are external boundaries here. They may fail or unwind; the evidence does not establish a complete account database contract or transactional rollback.

### Slot probe and state writes

At `0x278f735..0x278f76d`, four loaded 64-bit words are byte-swapped and written in reverse word order. The resulting 32 bytes equal the input bytes reversed. The slot hash folds two 64-by-64 products and a third product using XORs of their high and low halves; its inputs include a table word and two runtime words. The runtime words are behind relocation `0x576e3e0` to NOBITS state, so their values and resulting bucket positions cannot be read from this file.

For little-endian 64-bit words `q0..q3` of that reversed key, table word `s`, and runtime words `k0` and `k1`, the instruction-derived expression is:

```text
fold(x, y) = low64(x * y) XOR high64(x * y)
h = fold(fold(q3 XOR k0, q1 XOR k1) XOR
         fold(q0 XOR s, q2 XOR k0) XOR 4, k0)
```

The probe compares 16 control bytes at a time using the high seven hash bits. Candidate fingerprints are followed by comparison of all 32 key bytes. A full match at `0x278f46d` skips insertion and advances the slot cursor. Only after considering the group's matching fingerprints does the code test for an empty control byte; without one it advances by 16, then 32, then 48, with the table mask. Deleted controls do not terminate this lookup. These statements describe the selected instructions and assume valid table and control representations.

For a missing key, zero growth budget branches to `0x278f808`, which requests one additional entry through relocation slot `0x5773780` to the selected reserve helper. After reserve returns normally, the walker calls the backing-account boundary. A zero result word bypasses the storage getter and chooses 32 zero bytes; a nonzero word calls the storage-getter boundary, whose zero result byte also chooses zeros and whose nonzero arm copies its 32-byte payload. No name for these getter result variants is asserted.

The insertion window at `0x278f667..0x278f71c` updates the control byte and its mirror, the growth budget and the entry count. A slot bucket has stride 104: the normalized 32-byte key occupies `+0x00..+0x1f`, followed by two copies of the selected 32-byte value at `+0x20..+0x3f` and `+0x40..+0x5f`, and byte zero at `+0x60`. Padding and the source-level interpretation of the byte are unresolved. A prior matching key follows the bypass path; this packet does not claim that every input list is reachable.

### Reserve and exceptional edges

For a well-formed table mask, the selected helper computes capacity as the mask for masks below 8 and otherwise `(mask + 1) - ((mask + 1) >> 3)`. It detects carry in `count + additional`. If the needed count is at most half the current capacity, it takes its in-place control reclassification and rehash path. Otherwise it selects a new bucket count from `max(capacity + 1, needed)`: 4, 8 or 16 below request 15, and for larger requests the next power of two at least `floor(8 * request / 7)`. The allocation length is `align_up(104 * buckets, 16) + buckets + 16`, subject to the recorded size/overflow checks. The new-table path copies 104-byte rows, publishes the new table fields and then follows the old-allocation cleanup boundary. The in-place path moves or swaps the same-sized rows.

The selected caller passes additional count 1 and a nonzero mode. Size/carry overflow and null allocation reach separate failure-call sites when that mode is nonzero. The helper also contains nonfatal-mode returns, but the selected caller does not use that mode. The specific behavior of the external failure helpers is not inferred. `exceptions.json` records all 12 LSDA call-site rows for the walker, including 7 nonzero landing entries; actions, cleanup helper internals and unwinds through external code are not fully resolved. The walker's sole decoded normal return writes tag 5. This is not a claim that state is rolled back on failure or that a transaction succeeds.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo.lock, compiler/linker flags, independent rebuilds, target execution, native comparison, rebuild-comparison masks and whole-ELF equivalence: **not yet implemented/measured**. External account/database helpers, allocator behavior, dynamic dispatch beyond the listed relocation slots and their complete transitive closure remain outside this packet.

The focused Python suite uses negative controls for corrupt digest and instruction bytes, changed revision-family grouping or method shape, reversed branch conditions, invalid and NOBITS ranges, ambiguous mappings, missing or duplicate relocations, unsupported/truncated instructions, and corrupt exception metadata. Synthetic tests separately compare the storage-key hash against an independent 32-bit-limb multiplication, test all 256 single-bit key changes, exercise full-key/deleted/empty group handling, and compare reserve sizing against a minimum-capacity oracle. The probe model covers valid synthetic tables of at least 16 controls; the sizing model also covers smaller capacities. These tests check the stated static interpretation and regeneration, not target execution or Rust equivalence. The focused run passed 28 tests with zero skips under an empty executable-search PATH. Two empty-PATH generations with different hash seeds and timezones compared byte-for-byte equal.

## Results and limitations

`summary.json` reports 47 selected FDEs, 8,935 selected bytes, 2,223 sequentially decoded instructions, 332 recorded transfers, 99 call sites, 29 annotated conditional edges, 36 semantic windows and 56 selected relocation records. Forty-six call sites resolve to selected extents; seven have no resolved target address, including imported symbols. These are bounded corpus counts, not a node-wide coverage denominator. `exceptions.json` gives the walker's selected LSDA rows and raw encodings; other exception action chains are not decoded. The normal-return path and selected failure edges are mapped; arbitrary pointer corruption, all external helper behavior and all runtime branches are not validated.

In the summary, `descriptor_method_count` refers to the three slots of the separately detailed revision-9 descriptor; `revision_method_count` covers the 45 methods across all 15 groups.

This is a partial EVM result: the component gates remain 0/4, and the first COMPONENTS task covering reth/revm private-fork boundaries and all state-transition inputs is not complete. No progress or catalogue file is changed. The prior source record at `0x574f0c0` is included only as an authenticated identity boundary; its existing wrapper/compression evidence is not reclaimed.

Next question: which binary-backed producer populates this revision-9 environment's outer list, and how are its error and unwind effects reconciled with the caller's later registry installation? Establish its distinct FDEs and live input provenance without re-owning pending PR functions.
