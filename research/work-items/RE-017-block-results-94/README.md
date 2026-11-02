# RE-017: secondary block result collection and receiver-map update

For the secondary worker lane, this packet establishes how input metadata and per-item outputs are assembled into a 56-byte-per-entry return vector and how a separate later result updates a receiver map, including the selected sentinel, replacement, allocation and cleanup branches.

- Component ID: `abci`, RE-017.
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only to formulate questions.
- Claim status: the bytes, relative transfers, FDE ranges and selected decisions are static observations; working role names and the application meaning of the receiver are inferences. Loader-to-worker object identity is unresolved.
- Scope included and excluded: 21 selected, previously unclaimed FDE extents; selected context windows in already-studied worker and apply FDEs; direct and indirect transfers; 18 exception tables. The loader, its established GOT slots and call sites, the worker dispatcher, zip adapter, action handlers and root builder are boundaries, not newly owned bodies. #115 and visor are excluded.

## Reproduce

From the repository root on Linux x86-64, using Python 3.12.3 and the standard library:

```sh
python3 tools/abci_block_results94.py --out research/work-items/RE-017-block-results-94
python3 -m unittest tests.test_abci_block_results94 -v
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_block_results94.py --out work/re017-block-results-a
PYTHONHASHSEED=91 TZ=Asia/Seoul python3 tools/abci_block_results94.py --out work/re017-block-results-b
diff -r work/re017-block-results-a work/re017-block-results-b
diff -r --exclude=README.md --exclude=MANIFEST.sha256 research/work-items/RE-017-block-results-94 work/re017-block-results-a
```

Use initially empty output directories. The producer checks the full target digest before section parsing; imports the shared `elf_index` and `fde_extents` readers, including their ULEB decoder; excludes NOBITS from file-byte mappings; interprets only selected fixed x86-64 encodings; and never invokes the node, binutils, a subprocess or network. GNU objdump 2.42 was used for human inspection only. `MANIFEST.sha256` covers every file in this work item except itself.

## Evidence

Addresses are link-time ELF virtual addresses; output files also give file offsets. Ends are exclusive. A decoded FDE is an unwind-described range, not a proof of a complete function boundary or whole-program coverage. `functions.tsv` preserves each selected FDE body as raw hex, its hash, index entry and FDE address; `windows.tsv` preserves selected explanatory slices. `branches.tsv` and `decisions.tsv` contain selected branches and their adjacent guard bytes, not an exhaustive disassembly. `transfers.tsv`, `indirect.tsv`, `indirect-tails.tsv`, `operands.tsv`, `literals.tsv`, the dispatch tables and the LSDA files bind the remaining claims. Labels are working descriptions, not recovered Rust symbols.

### Entry and selected path

Earlier `RE-017-abci-state-link-94` binds the `state.rs` Location-bearing loader, while the open `RE-017-abci-slow-worker-94` packet follows a possible slow-worker handoff. Its selected dispatcher calls boundary `0x4677fd0`; that worker calls the already-studied apply boundary `0x42e5d40`. Those bodies and the original loader sites are not re-owned here. The route is conditional, and the evidence does **not** establish that the same object returned by the original loader is the worker input.

```text
prior worker 0x4677fd0 -> prior apply 0x42e5d40
  returned range -> 0x47f60d0 -> first result header
  40-byte input rows -> 40-byte metadata + 8-byte pointer list
    0x446d810 -> 0x47f9220 -> 0x4a13850 -> 0x476a320
      selected serial arm 0x4552020 -> 0x47f9770 -> 0x4a12960
      -> 32-byte descriptors containing nested 112-byte results
    0x454da60 -> 24-byte headers -> prior zip adapter 0x471e100
    64-byte rows -> 0x49367c0 / 0x420b7f0 -> temporary keyed map
      -> 0x4951230 / 0x4870700 -> second result header
  later prior boundary 0x446f130 -> 64-byte rows
    -> 0x47bd580 -> 0x4929e10 / 0x425ac80 -> receiver +0x3b10 map
  selected normal return copies both result headers and later boundary output
```

The worker's selected epilogue copies 40 bytes from its own stack slice to its output and later drops the two returned vector headers. Those observations do not by themselves identify the 40-byte record with either vector or prove what the protected handoff ultimately represents.

| Selected FDE start | Bounded observed role |
| --- | --- |
| `0x47f60d0` | Convert a `0x148`-stride input range into a header for a `0x168`-stride output allocation; call a prior fill boundary. |
| `0x446d810`, `0x47f9220`, `0x4a13850` | Prepare the descriptor collection, tail-transfer to reserve, and check capacity and returned count. |
| `0x476a320`, `0x4552020` | Select partition or serial work; in the selected serial arm, form `0x20`-byte descriptors and stop at a sentinel. |
| `0x47f9770`, `0x4a12960` | Tail-transfer to a nested reserve/collection with `0x70`-byte result stride and a separate returned-count check. |
| `0x4a0e3e0`, `0x47e2440`, `0x4a0df60` | Clean a `0x20`-stride descriptor list and its nested `0x70`-stride records, including selected unwind continuations. |
| `0x47e3940` | Dispatch the nested-record status word through two top-level and five nested relative-offset tables. |
| `0x454da60` | Invoke a prior processing boundary and construct a `0x18`-stride output header, with a conditional resize. |
| `0x49367c0`, `0x420b7f0` | Search, insert or replace in the temporary `u64`-keyed map; enter the nonempty insertion helper. |
| `0x44c71f0`, `0x4870700`, `0x4951230` | Drop unconsumed input rows and materialize selected map entries through a destructive iterator. |
| `0x47bd580`, `0x4929e10`, `0x425ac80` | Traverse a second `0x40`-stride row list and insert or replace 56-byte values in the receiver map. |

### Input, collection, and result layout

At the boundary, the input loop advances by `0x28` bytes, appends the sequential index and 32 copied bytes to a separate `0x28`-byte metadata row, and builds an eight-byte pointer list. The previously documented call at `0x42e60a8` returns a word tested against `0x186` at `0x42e60ad`: equality bypasses the selected cleanup at `0x42e610e`, while inequality calls it. This observation alone does not assign success or error meaning to `0x186`.

`0x446d810` supplies that pointer list and count to the descriptor collector. The serial branch at `0x4552020` visits each pointer, calls the nested reserve path, and either stops on a first output word of `0x8000000000000000` or writes the address of the current pointer-list slot and the returned three-word header as one `0x20`-byte descriptor. The nested reserve uses a `0x70`-byte result stride; it rejects insufficient capacity and a returned count unequal to its requested count. The parallel-side scheduler is a prior boundary, so the complete production of each 112-byte row is not claimed.

`0x454da60` passes the descriptors to prior boundary `0x444d5c0` and constructs a three-word header for `0x18`-byte elements. Earlier `bridge-signed-action-admission-94` relates that boundary to partitioning `0x70`-byte rows; it did not establish the present caller or returned-header connection. The prior `RE-001-zipped-record-layout-94` adapter requires equal counts and joins each 40-byte metadata row with one 24-byte header. In the resulting 64-byte row, the selected caller reads the first eight bytes as a map key and the remaining 56 as the value. A word at row `+0x28` equal to `0x8000000000000000` stops this insertion loop; the remaining zip input is then passed to `0x44c71f0`.

Both map insert paths use the same unsigned `cmp`/`seta`/`sbb` decision bytes, 56-byte value stride and 11-entry node threshold. A matching key returns the old 56-byte value and copies the replacement; an absent key increments the map length after insertion. For the temporary map, the absent result places the signed-minimum word at result `+0x20`; a non-sentinel old value takes a cleanup path. The second map uses an explicit zero/nonzero returned first word for absence/presence. Full internal split mechanics and allocator behavior remain outside this claim.

`0x4870700` allocates at most `0x249249249249249` entries at 56 bytes each, asks `0x4951230` for successive node/index pairs, and copies the 32-byte prefix plus a 24-byte header. A null iterator result or the signed-minimum word in that header stops output. The iterator also contains node-release paths, but no assertion here covers every possible malformed tree or proves source-level ordering independently of its caller.

### Selected decisions and failure paths

| Guard / branch | Taken and fall-through observations |
| --- | --- |
| `0x47f60f3`, `0x47f611a`, `0x47f6128` | Reject an input byte range above `0x749f49f49f49f498`, use pointer word 8 for zero allocation size, or reach the allocation-failure continuation on a null result. |
| `0x4a13879`, `0x4a13882`, `0x4a1388b`, `0x4a13930` | Grow when requested count exceeds remaining capacity; separate underflow, insufficient-capacity and mismatched-count branches reach failure helpers. |
| `0x476a353`, `0x476a3c5`, `0x476a3ea` | Compare half the input count with the threshold, then test the flag and budget before selecting the serial or alternate path. |
| `0x45520c7`, `0x45520d9`, `0x4a12a58` | Stop serial collection on signed-minimum sentinel, take a capacity failure if the output is full, or take a nested count-mismatch failure. |
| `0x47e2498`, `0x4a0dfb8` | For the two nested-record cleanup copies, the 16-bit word at each record `+0x10` equal to `0x186` skips the item cleanup helper; other values call it. The record stride is `0x70`. |
| `0x493681d`, `0x4936826`, `0x425aca7` | Continue unsigned key search, replace an equal key, or enter the nonfull insertion arm; full-node handling remains a separate helper path. |
| `0x4870729`, `0x487073e`, `0x4870869` | Check the 56-byte allocation limit, take the empty allocation arm, or stop at the signed-minimum header word. |
| `0x47bd627`, `0x47bd634`, `0x47bd6e6` | Distinguish an empty nested field, reject the selected nonempty field with zero first header word, or skip old-value cleanup when insertion returns zero. |
| `0x42e6409`, `0x42e642a` | If receiver dword `+0x3ae8` is not 2, continue toward the map update. If it is 2, atomically increment the word reached through `+0x3b88`; equality with receiver `+0x28` bypasses that update, otherwise a failure helper is called. |

The nested rows for `0x47bd580` come from the separate prior boundary `0x446f130`; their exact source-level type and the receiver map's role are not recovered. The previously documented root builder occurs later on another selected condition, but this packet does not establish that the `+0x3b10` map is included in that root or that this update executes for a particular block.

### Status-drop dispatch

Both selected `0x70`-stride record destructors call `0x47e3940` for non-`0x186` tags. The callee loads a 16-bit word and uses a first table for `0x3a..0xfa` and a second for `0x14b..0x172`; a value outside both ranges reaches the local return at `0x47e3b10`. Thus `0x186` would also reach that return if the callee were called directly, but the observed outer callers bypass the call first.

The two top-level tables contain 193 and 40 entries. Of these, 172 and 36 respectively point directly to the return; other entries reach different cleanup or nested-dispatch paths. Five further selected nested tables contain 32, 14, 7, 5 and 5 entries. `dispatch-entries.tsv` lists all 296 encoded signed displacements and resolved targets; `dispatch-targets.tsv` gives per-table target counts. Every listed target lies in this FDE, while table selection and out-of-range branches are bound to fixed instruction bytes. For example, top-level tag `0xbb` reaches the seven-entry nested table, and tag `0x14b` reaches the 32-entry table. These rows identify control-flow destinations only: they neither name source variants nor establish the behavior of all indirect cleanup functions reached by the destinations.

The selected destinations also distinguish several cleanup shapes without assigning variant names:

| Destination | Observation on the selected arm |
| --- | --- |
| `0x47e3963` | A zero word at `+0x08` returns; a nonzero word and pointer at `+0x10` reach the shared indirect tail slot. |
| `0x47e3a15` | A negative or zero word at `+0x08` returns; a positive word reaches that same tail. |
| `0x47e3a2d` | A pointer at `+0x08` is dereferenced and the first loaded pointer is used for an indirect tail jump; its target is unresolved. |
| `0x47e3a3b` | Two separate nonzero-word tests govern a call for the `+0x10` pointer and a tail for the `+0x28` pointer; the second size is shifted by four. |
| `0x47e3ad3` | A zero word at `+0x10` returns; otherwise the `+0x18` pointer reaches the shared tail. |

The shared slot is a runtime boundary, not an assertion that every dynamic cleanup target has been recovered. Nested tables and selected failure/unwind branches are included, but arbitrary malformed objects and full indirect-target closure remain open.

### Unwind evidence

`lsda-headers.tsv` and `lsda-rows.tsv` parse the selected omitted-LPStart, ULEB call-site tables from the FDE-linked LSDA locations. The next referenced LSDA is only an upper bound; action tables and personalities are not decoded. `lsda-calls.tsv` relates selected call instructions to covering rows. For example, the call at `0x446d868` has landing `0x446d8ee`, which calls `0x4a0e3e0` to drop descriptor records. The nested call at `0x45520aa` has landing `0x4552154`, which calls `0x4a0df60`; the item cleanup call at `0x47e249e` has landing `0x47e24d9`, whose selected continuation visits remaining `0x70`-stride records, conditionally releases their allocation and resumes unwinding. These are conditional landing-pad observations, not proof of which personality path runs or of transactional rollback.

## Implementation and comparison

Not yet implemented. No Rust component, Cargo lock, two-build comparison, normalization mask, complete helper/relocation closure, state-root comparison or whole-ELF comparison is claimed. The small test models are synthetic translations of pinned comparisons, byte strides, count limits and selected local branches; they do not execute the target or model arbitrary pointers, scheduler interleavings or full tree splits.

## Results and limitations

`summary.json` records 21 selected FDE extents, 44 byte windows, 95 conditional branches, 53 adjacent guards, 37 direct transfers, 25 indirect call sites, four indirect tail sites, 26 immediate operands, three literals, 18 LSDA tables, 127 LSDA call-site rows, 50 selected call/LSDA associations, and seven jump tables with 296 entries. These are selected evidence counts, not denominators for the component or function coverage.

The focused suite has 31 tests and zero skips. It checks that a missing or wrong target produces no output and corrupts the input digest, FDE extent, unwind index, every body/window, every selected branch opcode and displacement, every guard, direct and indirect calls and tails, operands, literal references, all jump-table references, bounds and data, and LSDA headers/rows; it also rejects the actual `.bss`, synthetic NOBITS, ambiguous and out-of-range file mappings. Synthetic controls include all 65,536 unsigned 16-bit top-level tag classifications and exercise unsigned key boundaries, duplicate replacement, full-node routing, allocation limits, sentinel versus capacity, tag neighbors, and the wrapping counter branch. Two independent hash-seed/time-zone regenerations under a Python-only PATH compared byte-for-byte; artifact and catalogue checks also passed.

No node or visor execution, public networking, hosted CI or component completion gate is claimed. The existing `abci` gate stays 0/4. The exact loader-result identity, full begin/action/end semantics, helper closure, all exception actions and state-root membership remain unresolved. Next question: connect the loader return to the worker's receiver under the actual scheduling and pointer ownership conditions without re-owning either earlier packet.
