# staking: insert a new withdrawal time into the queue tree

This packet recovers the previously stubbed vacant-time insertion, including its split pivots, vector-descriptor movement, returned cursor and selected unwind cleanup paths, so a reconstruction can preserve queued withdrawal lists while a full time-index node splits and the split propagates to a new root.

- Component ID: `staking`, withdrawal queue and stake accounting.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is a lead only, and no code is copied from it.
- Claim status: the ELF bytes, FDE, context calls and observed execution within the stated interpreter are observations. Identification of the tree as the pending-withdrawal time queue joins the context to the earlier binary-backed queue and drain packets. Other lifecycle behavior, target execution and arbitrary trees remain unresolved.
- Scope included and excluded: the selected FDE is the previously unreported insertion helper at `0x2f504e0`, including its LSDA call-site records and selected landing pads. The enqueue and vacant-entry callers are context byte pins only: both belong to existing packets and are not selected functions. Queue admission, time arithmetic, searches, equal-key appends, vector growth, draining and allocator internals are outside the interpreted subject. The result does not cover node #115.

## Reproduce

Run from the repository root with Python 3.12 and the authenticated artifact. The generator verifies the full digest before analysis, imports `tools/elf_index.py` and `tools/fde_extents.py`, and reads ELF sections, relocation records, FDEs and code bytes directly. It invokes no external program and does not launch the captured binary. The bounded decoder and interpreter are adapted from the repository's MIT-licensed `tools/staking_stake_accounting.py`; the license is included in the generator. The short disassembly excerpt below was checked with GNU objdump 2.42; no tool parses it.

```sh
python3 tools/artifacts.py verify
python3 tools/staking_withdraw_time_insert94.py --out research/work-items/staking-withdraw-time-insert-94
python3 -m unittest tests.test_staking_withdraw_time_insert94
(cd research/work-items/staking-withdraw-time-insert-94 && sha256sum -c MANIFEST.sha256)
python3 tools/catalogue.py --check
```

For two independent regenerations, replace each placeholder with a distinct writable relative directory:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/staking_withdraw_time_insert94.py --out <tmp-dir-1>
PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/staking_withdraw_time_insert94.py --out <tmp-dir-2>
diff -r <tmp-dir-1> <tmp-dir-2>
```

`function.tsv` provides the full unmasked subject hash, byte count, ELF virtual address, file offset and FDE/CIE coordinates; `anchors.tsv` binds the context and selected instruction bytes. `instructions.tsv` and `branches.tsv` are decoded directly from the pinned bytes, not binutils output. `cases.tsv`, `sequences.tsv`, `key-boundaries.tsv`, `controls.tsv`, `failure-landings.tsv`, `cleanup-cases.tsv` and `branch-mutations.tsv` preserve the fixture results. `lsda-call-sites.tsv` gives the raw exception call-site records. `relocations.tsv` describes the hooked external slots; `unwind-symbol.tsv` resolves the final direct call through its PLT entry and dynamic relocation to `_Unwind_Resume`. `summary.json` holds the counts and digest. `MANIFEST.sha256` covers this README and every generated evidence file.

## Evidence

Addresses are linked ELF virtual addresses. The exclusive unwind-described extent is `0x2f504e0..0x2f513c5`; `function.tsv` gives file offset `0x2f4f4e0`, 3,813 bytes, FDE and CIE. An FDE is an unwind extent, not a complete function census. The tool checks that selected direct branches within this extent land on decoded instruction starts.

The earlier `RE-004-cwithdraw-queue-94` packet established a time-keyed pending queue and stubbed the vacant insert. `staking-withdrawal-drain-94` identified the same map as 12-byte `(date, seconds, nanos)` keys with 24-byte vector descriptors for 32-byte `(amount, user, padding)` rows. Context pins connect that enqueue path to the selected helper:

1. The prior enqueue code compares a signed date, then unsigned seconds and nanoseconds. At a matching key, its pinned branch goes to the append site. Its vacant path initializes an empty three-word vector, then calls the vacant-entry adapter at `0x3c13327`.
2. The adapter calls the selected helper at `0x33bffcd`; after normal return, its pinned instruction at `0x33c006a` increments map length. A null-root setup in the adapter and the whole caller are not interpreted here.
3. At the append site the caller checks vector length against capacity, takes the growth branch when equal, writes the amount and 20-byte user into a 32-byte row, then increments length. These are caller-context observations, not a new claim over the pre-existing caller or its growth helper.

The context and input/output relationship is therefore:

```text
pre-existing enqueue search: existing time -> append boundary
                             vacant time -> pre-existing entry adapter
                                               -> selected insertion helper
                                               <- node, height, slot cursor
                             -> adapter increments map length -> append boundary
```

The helper takes a **vacant cursor** supplied by its caller. It does not itself search or compare time keys. The fixtures supply ordered valid trees and independently compute the vacant cursor; duplicate keys are rejected by the fixture rather than attributed to this helper. The selected function preserves the caller's map-length word, and the tested synthetic adapter step advances it once after successful return.

### Node and split decisions

| Item | Value established by selected bytes and fixtures |
| --- | --- |
| Key and value | 12-byte time key and 24-byte value, including all three vector descriptor words |
| Node count / parent edge | `+0x196` / `+0x194`; child pointers begin at `+0x198` |
| Leaf / internal allocation | `0x198` / `0x1f8` bytes |
| Full node | 11 keys |
| Root and cursor | A cascading split can allocate an internal root; the returned cursor names the inserted key/value, including after promotion |

For a full node, the gap is the insertion position among the existing 11 keys. The promoted item below is an **old** item, not the new one:

| Gap | Promoted old index | Left / right key counts after insertion |
| --- | --- | --- |
| 0 through 4 | 4 | 5 / 6 |
| 5 | 5 | 6 / 5 |
| 6 | 5 | 5 / 6 |
| 7 through 11 | 6 | 6 / 5 |

An abbreviated human-readable excerpt, also bound by `anchors.tsv`:

```text
2f504fe: 450fb7ba96010000  movzx r15d, word ptr [r10+0x196]
2f50506: 4983ff0b          cmp   r15, 0xb
2f50521: 4c8b6610          mov   r12, qword ptr [rsi+0x10]
2f50525: 4983fc05          cmp   r12, 0x5
2f506e0: bf98010000        mov   edi, 0x198
```

The evaluator compares every final key and all 24 descriptor bytes to an independent ordered-tree model, checks parent and edge backlinks, root height, allocation sizes, returned cursor and exact resulting shape. Descriptor pointers are synthetic tokens and are not dereferenced: their preservation is established, not ownership of live vector allocations. Most fixtures use a fixed date and second with varying nanoseconds. An additional 16-key sequence varies all three encoded components, including signed-date and unsigned-word extremes, across a split; some bit patterns are intentionally synthetic and are not asserted to be valid calendar times. The fixture computes the order itself and does not test the caller's calendar search. The three longer sequence fixtures insert 180 distinct vacant times each, checking the tree after every call and explicitly applying the separately pinned caller count increment.

### Failure boundaries and mutation controls

`controls.tsv` records four injected allocation failures: leaf allocation, internal propagation, new root, and a later cascading root. The evaluator stops at the corresponding modeled failure call. Six malformed cursor, root, occupancy or height descriptors likewise reach failure boundaries in the bounded model. Some have already performed earlier modeled writes.

The FDE's LSDA uses the supported omitted-base, omitted-type-table and ULEB call-site encodings. Its 13 records, raw bytes and addresses are in `lsda-call-sites.tsv`. `failure-landings.tsv` connects each modeled failure call to its LSDA landing address. The landing instructions are then interpreted **separately** with explicitly supplied synthetic registers and stack words; this is not an automatic unwind from the earlier failure fixtures. `cleanup-cases.tsv` records 40 combinations, using zero and nonzero descriptor capacities:

| Landing | Conditional cleanup observed in the explicit synthetic state |
| --- | --- |
| `0x2f51332` | If the extra capacity is nonzero, call the free hook for `extra_capacity * 32` bytes; then free a `0x198`-byte node; if the main capacity is nonzero, free `main_capacity * 32` bytes; resume the supplied exception. |
| `0x2f51365`, `0x2f51374` | The same conditional descriptor-size pattern surrounds a `0x1f8`-byte node free; resume the supplied exception. |
| `0x2f51312`, `0x2f51321`, `0x2f51323`, `0x2f5135c`, `0x2f5136f` | A nonzero main capacity leads to one `capacity * 32` free, then the supplied exception is resumed; the selected pointer source differs by entry. |
| `0x2f512fe`, `0x2f51310` | The modeled instruction path reaches `ud2`; the first entry calls the free hook for a `0x1f8`-byte node first. |

For example, the leaf-allocation failure call at `0x2f51292` belongs to the LSDA range targeting `0x2f51321`, while the modeled new-root failure call at `0x2f512b3` maps to `0x2f51310`. The latter's `ud2` is an instruction observation conditional on that landing being entered, not a claim that a real allocator failure unwinds there. The fixture hooks record addresses and sizes rather than freeing memory. They do not prove register values at an actual unwind, the behavior of the allocation-failure routine, complete ownership or rollback.

Four targeted byte changes affect capacity, a split pivot, a key-tail load and the full-node branch. Each is detected by an output or structural assertion. A separate branch leaving the selected FDE is rejected by the interpreter. `branch-mutations.tsv` inverts each conditional and tests up to two witnesses per previously observed edge: 23 produce a model difference, 14 reach a modeled failure boundary, five produce an interpreter fault, and four have no normal witness. A fault or a modeled boundary is not a claim about a modified target process.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No target binary execution, compiled-code comparison, normalization mask, helper equivalence, whole-ELF identity or node #115 result is claimed. The decoder and interpreter run on synthetic memory with modeled allocation, copy, free, resume and failure boundaries. The sorted-tree model is independent of the decoded instructions but shares the intentionally bounded fixture domain.

## Results and limitations

- The single selected FDE has 792 decoded instruction starts; 671 are reached by the 974 independent insertion fixtures. Both edges are observed for 22 of 46 conditional instructions, and four conditional instructions have neither edge reached. These are selected-window fixture counts, not component coverage.
- All 974 independent leaf and multilevel insertion cases and all 540 sequential insertions across three orders and 16 additional mixed-component insertions match the model. The sequences reach height 2; separately constructed cases include selected deeper cascades. The focused suite passes 30 tests with no skips.
- The 15 generator controls cover 10 modeled failure boundaries, four mutations and the out-of-FDE jump. The LSDA table has 13 records, and 40 separate landing fixtures check conditional free ordering and terminal behavior. Hash, body, context, address, NOBITS, exception-metadata, PLT and further mutation controls are also in the focused suite. Two regenerations under different hash seeds and time zones are byte-identical with binutils absent from PATH.
- The function assumes a valid vacant cursor and takes ownership of a descriptor supplied by its caller. Search correctness, equal-time append and vector growth, real allocation and unwind cleanup from actual call-site state, arbitrary malformed trees, real-chain reachability and independent Rust behavior are not established. No component completion gate is requested.

Next question: establish the actual register, stack and ownership state passed from each allocation-failure call into its landing pad, and compare an independent implementation with an authorized target-grounded harness.
