# RE-017: Resolve the result-ring lookup and 64-row conversion

For a selected loader-fed result path in node #115, a sorted ring's existing key is replaced without growing the ring, while an absent key at count 64 triggers conversion whose sorter recognizes the existing ordered rows as one run, under the pointer and representation assumptions stated below.

- Component ID: `abci`; RE-017, related to RE-009 state/snapshot and root validation.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no source is copied.
- Claim status: the bytes, relocations, FDE ranges and selected transfers are observations; the pointer joins, search invariant, sorted-run consequences and synthetic models are conditional inferences. Runtime reachability and complete state-root behavior remain unresolved.
- Scope included and excluded: eight newly selected #115 FDE ranges covering lookup, long-sort dispatch, run detection, merge, selected partition/small-sort branches, pivot and cleanup; previously proposed loader, block, accumulator, converter, reducer and their calls are context only. This is not a complete begin/action/end-block implementation, complete sort proof, or component gate.

## Reproduce

From the repository root on Linux x86-64, Python 3.12.3 and the authenticated node artifact are sufficient. The generator imports the repository ELF/FDE readers and uses only Python's standard library. It verifies the entire target digest before parsing or writing, never executes the target, and invokes no external program. GNU objdump 2.42 was used only for the human inspection reflected in this README; its text is not an input to the generator or tests.

Choose an empty writable directory for `TMPDIR`; the example uses a repository-relative, ignored location:

```sh
mkdir -p work/re017-sort-repro
export TMPDIR=work/re017-sort-repro
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_abci_result_sort115
PYTHONHASHSEED=1 TZ=Etc/UTC python3 tools/abci_result_sort115.py --out "$TMPDIR/first"
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_result_sort115.py --out "$TMPDIR/second"
diff -r "$TMPDIR/first" "$TMPDIR/second"
diff -r -x README.md -x MANIFEST.sha256 "$TMPDIR/first" research/work-items/RE-017-abci-result-sort-115
(cd research/work-items/RE-017-abci-result-sort-115 && sha256sum -c MANIFEST.sha256)
```

If the separately obtained historical artifact is available, this optional command independently authenticates and checks its old Location, selected FDEs, call-slot relocation and instructions; its generated #115 files are identical to the ordinary output:

```sh
python3 tools/abci_result_sort115.py --historical-node references/can1357-hl/bin/hl-node-mainnet-new --out "$TMPDIR/historical"
diff -r "$TMPDIR/first" "$TMPDIR/historical"
```

`MANIFEST.sha256` binds the README and every generated file. The tool is read-only except for the chosen output directory. Tests and generators also passed with a Python-only executable search path.

## Evidence

Coordinates are linked ELF virtual addresses before rebasing; generated tables include file offsets, exact bytes, relocation records and body hashes. The tool checks each selected FDE against the unwind header, its actual decoded end, and other FDE ranges. An FDE is an unwind-described range, not proof of a complete source function. The 83 transfer records and 65 fixed windows are selected instruction-aligned observations, not an exhaustive disassembly or component coverage denominator. All mapped bytes come from allocated, file-backed sections; NOBITS sections are rejected.

### Previously proposed route and scope of the join

The following entries are context from pending #115 proposals, not newly claimed functions or GOT/call sites. Their selected conditions, indirect bindings and helper effects remain prerequisites for the end-to-end interpretation.

| Stage | Conditional context |
| --- | --- |
| Startup and loader | PR #2047 relates upper continuation `0x2cb6500`, parent `0x2cbbbe0`, shared stage `0x2b41b70`, loader `0x3c12800` and Location wrapper `0x3c13520`. The latter references #115 Location `0x64767a8`, `state.rs:123:37`. The context windows also pin the selected loader writes at state `+0x10`, `+0x18` and `+0x10e8`. |
| Expanded owner and block | PRs #2047, #2107 and #2243 conditionally join the constructed owner to worker `0x5a6e1e0`, adapter `0x4fcb590`, and engine `0x5a06600`. The engine's context slot `+0x450` and owner `+0xb00` coincide only after the separately established owner/context adjustment; matching offsets do not prove runtime allocation identity or alias stability. |
| Begin, item and end | The selected begin at `0x5483f50` saturating-increments state `+0x28` and makes the recorded stores; a guarded item at `0x560dbb0` saturating-increments `+0x16b0`, and increments `+0x16b8` on its `0x1a2` result branch. PR #2107's end selector `0x5a08720` has separate early, failure and root-input paths. Those operations and their complete helper effects are not re-owned here. |
| Result rows | The engine initializes an index at `0x5a0692e`, advances it at `0x5a06984`, and writes it at `0x5a06a1a` on the previously selected non-sentinel path. PR #2352 follows the resulting 64-byte keyed rows through the accumulator `0x4dd0010`, ring-to-tree converter `0x515f660`, reducer `0x4d5f920`, collector `0x5b785d0` and a later fingerprint-input boundary. This packet checks selected context windows and examines the previously unresolved lookup and long-sort bodies. |

Each arrow in this composite map assumes the earlier proposals' path conditions, normal ABI-conforming returns, the relevant scheduler invocation, stable pointers and no conflicting alias writes. The loader's original allocation and its later expanded object are not asserted identical. A key in this packet is the observed leading qword of a result row, not a proved state root.

### New unwind ranges

| Start .. exclusive end | Selected role |
| --- | --- |
| `0x57f8cd0..0x57f8df1` | Search a one- or two-segment ring by its leading unsigned qword and return tag plus logical position. |
| `0x4f40550..0x4f40696` | Choose stack or heap scratch for 64-byte rows and call the run driver. |
| `0x4f73c60..0x4f742ee` | Detect monotone runs, reverse strictly descending runs, select and merge runs. |
| `0x4eb7970..0x4eb7f38` | Partition/recursive dispatch, small-run call and selected fallback/error branches. |
| `0x5417a80..0x5418198` | Small-run network, insertion and merge; check scratch capacity. |
| `0x4e66e70..0x4e66f1a` | Selected recursive pivot-choice comparisons. |
| `0x4f304e0..0x4f30536` | Selected cleanup and unwind-resume boundary. |
| `0x5b4f1c0..0x5b4f23e` | Selected nested row cleanup loop. |

The existing converter's indirect long-sort call at `0x515f7cd` and slot `0x64e5978` are context. Its relative relocation has addend `0x4f40550`. The driver's distinct dispatch slot `0x64eb8c8` has relative addend `0x4eb7970`. The merge copy slot has a `memcpy` dynamic-symbol relocation; the runtime binding and contract are assumptions, not newly owned GOT entries or proof of loader behavior.

### Lookup, replacement and conversion

For a well-formed ring, let `C` be the capacity at `+0`, the element pointer be at `+8`, `H` the head at `+0x10`, and `N` the count at `+0x18`. Assume `0 <= H < C`, `0 <= N <= C`, that the `N` logical keys are unsigned and nondecreasing, and that the backing storage and both segment bounds are valid. The local instructions do not validate all of these preconditions.

| Situation | Byte-backed decision and conditional result |
| --- | --- |
| `N == 0` | Return `rax = 1`, `rdx = 0` without a key load. |
| No wrap | Search the one selected segment. A match returns `rax = 0`; a miss returns `rax = 1`. `rdx` is the logical matched position or insertion position. |
| Wrap and query equals the first key in the wrapped segment | Return tag 0 and the size of the initial segment as the logical position. |
| Wrap and boundary key is below the query | Binary-search the wrapped segment and add the initial segment's length to its position. |
| Wrap and boundary key exceeds the query | Binary-search the initial segment and use its logical position. |

The segment choice follows from the stated ordering: when a wrapped segment exists, every initial-segment key is at most its first key. Thus a smaller query can only be in the initial segment, a larger query is searched in the wrapped segment, and equality can return the boundary position directly. The selected midpoint comparisons advance the candidate when a key is at most the query; the final comparison supplies the found tag and, for a miss, the insertion position. This reasoning requires the stated ring bounds and ordering; the instructions do not independently establish them.

The binary-search comparisons use the first eight bytes at 64-byte stride and unsigned conditions. At the wrapped boundary, the observed compare, `seta` and `sbb` sequence gives byte `0xff`, `0`, or `1` when the boundary key is below, equal to, or above the query; `synthetic-compare.tsv` records these three modeled cases. With **strictly increasing** keys, the reported missing-key position is the usual insertion point; with duplicates a hit need not be the first equal element. `synthetic-lookup.tsv` contains 77 derived examples. The focused test additionally checks 3,964 synthetic combinations of capacities, heads, lengths and queries, plus 8,256 full-ring head/query combinations, against an independent binary-search oracle. Another 11,550 duplicate-containing cases check hit positions and missing-key insertion positions; 1,225 merge inputs are checked against a stable-sort oracle.

A human-readable selection of the byte-pinned instructions is:

```text
57f8cd7  0f 84 97 00 00 00  je    57f8d74    # zero count
57f8cfa  76 7e              jbe   57f8d7a    # one segment
57f8d13  0f 84 c3 00 00 00  je    57f8ddc    # wrapped boundary equals query
57f8dcf  75 04              jne   57f8dd5    # first-segment candidate differs
57f8dd1  31 c0              xor   %eax,%eax  # equality tag
```

As a synthetic wrapped full-ring example, capacity 64, head 63 and logical keys 0 through 63 produce `(tag, position) = (0, 63)` for key 63 and `(1, 64)` for key 64. The first selects replacement and the second selects conversion under the accumulator conditions. These are modeled inputs, not captured runtime values.

The prior accumulator calls this new lookup. A zero return at count 64 bypasses conversion; after the existing bounds check it addresses the row's `+8`, copies its old 56-byte value to the caller's output, and overwrites those 56 bytes from the incoming value. A nonzero return below 64 takes the prior insertion boundary; a nonzero return at or above 64 moves the ring descriptor to a temporary, clears the original descriptor, and calls the prior converter. `synthetic-threshold.tsv` enumerates the selected 63/64/65 count decisions for both lookup tags. The insertion routine's complete movement/growth correctness remains prior work and is not independently proved here. Consequently, preservation of a sorted, unique ring across all updates is an explicit invariant to prove, not a runtime finding. If that invariant holds and no alias changes the rows, equal-key updates do not add another ring entry.

### Sorting the converted rows

For a hypothetical direct sorter input count `n`, the adapter computes `b = max(min(n, 125000), ceil(n / 2))`. It selects 64 stack scratch elements when `b < 65`; otherwise it checks the 64-byte product and uses the allocation boundary. In the existing converter, the long sorter is reached only at count at least 21. These buffer cases do **not** imply that the enclosing conversion is allocation-free: the earlier drain allocates its row copy, and the later builder separately allocates tree nodes.

| Selected synthetic count | Computed `b` | Sort scratch | Driver minimum run |
| --- | --- | --- | --- |
| 64 | 64 | stack, 64 rows | 32 |
| 65 | 65 | heap request, 4,160 bytes | 33 |
| 125,001 | 125,000 | heap request, 8,000,000 bytes | 372 |
| 250,001 | 125,001 | heap request, 8,000,064 bytes | 500 |

The complete selected boundary table, including overflow controls and the larger-count minimum-run formula, is generated in `buffer-cases.tsv`. A heap request is not evidence that allocation succeeds. The adapter checks the product against `0x7ffffffffffffff8` and tests a shifted high part before the allocation boundary; `buffer-cases.tsv` retains the wrapped arithmetic and size-error result.

The run scanner continues a nondecreasing run through equal keys, but stops a descending run at equality. It reverses only the selected strict descending run. If the prior drain presents 64 already nondecreasing rows and preserves their order, the driver sees one 64-row run, marks it complete and returns without entering the partition or merge bodies. `synthetic-fast-path.tsv` records the selected conditions and the modeled values; it is not an execution trace. The separate drain and tree allocations still apply.

The pinned forward selection is particularly sensitive to the unsigned condition:

```text
4f74223  49 8b 4d 00  mov    0(%r13),%rcx  # right key
4f7422b  48 3b 0a     cmp    (%rdx),%rcx    # right key minus left key
4f74235  48 89 d7     mov    %rdx,%rdi      # default to left row
4f74238  49 0f 42 fd  cmovb  %r13,%rdi      # select right only if below
```

If a merge is required, the forward loop compares the right key with the left key and selects the right row only when it is strictly smaller; equality selects the left row. The backward loop fills from the end and selects the right row on equality. Both choices preserve left-before-right order **at that merge boundary**, assuming sorted input runs and the recorded copy behavior; the three comparison cases are in `synthetic-merge-truth.tsv`. The small-run and larger partition algorithms have additional branches; global stability for every possible input is not claimed.

For a deliberately synthetic, globally unsorted 64-row array, the two 32-row runs in `synthetic-input.tsv` exercise the selected forward merge and contain 31 duplicate keys. The model places the earlier run's equal row first, then the existing reducer's last-per-key rule yields the 33 rows in `synthetic-survivors.tsv`. This is a corruption/branch control, not evidence that duplicate or unsorted rings can be produced by a valid node. A deliberately reversed tie choice changes the surviving identity and is rejected by the focused test. The model preserves the row identity as a stand-in for the other 56 bytes; it does not execute target instructions.

### Selected failure and cleanup boundaries

| Condition | Observed boundary and unresolved effect |
| --- | --- |
| Existing-key logical index is outside the ring count | The prior accumulator reaches a diagnostic call followed by `ud2` if that call returns. No successful replacement follows that selected branch. |
| Conversion begins | The old descriptor is saved and the original ring descriptor is cleared before the converter call. The later unwind windows include field stores and cleanup calls; they do not establish complete restoration or rollback. |
| Row-drain or tree-node allocation fails | Existing contextual paths take distinct allocation failure boundaries. No successful conversion is inferred from merely reaching those calls. |
| Sort scratch size overflows or allocation is null | The adapter reaches its selected failure boundary. Its bytes do not justify assuming that the boundary returns, or that all earlier state is rolled back. |
| Partition scratch is shorter than its selected count | The branch reaches `ud2` at `0x4eb7f07`. For `n >= 2`, the small-run helper has a distinct `n + 16` scratch guard ending at `ud2` at `0x541817a`. Neither synthetic invalid input is asserted reachable through the normal adapter. |
| Selected sort/cleanup unwinds | `0x4f304e0` calls the nested-row drop loop and conditionally reaches a release boundary before the unwind-resume call. FDE LSDA addresses are recorded, but call-site action chains and complete cleanup effects are not decoded. |

### Historical control

The retired RE-017 lead is node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: caller `0x32725d0`, call `0x3272785`, slot `0x57755a8`, target `0x3273810`, and Location `0x56dfbf8` at `state.rs:107:37`. Its selected comparison is against 2. The optional historical control independently authenticates those bytes and FDE records. The #115 extractor separately checks Location `0x64767a8` at `state.rs:123:37` and the comparison against 1 at `0x3c1353b`. This is a cross-release navigation check, not an assertion that old and new offsets, tags, layouts or behavior are equivalent.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler/linker flags, two-build comparison, raw/normalized masks, helper and dynamic-binding closure, relocation/vtable closure, behavior against captured executions, and whole-ELF comparison: not yet implemented/measured. The target was never executed. The static model and its synthetic inputs are not captured node fixtures.

## Results and limitations

The packet records 8 selected FDE ranges, 65 fixed windows including 23 prior-context windows, 83 selected transfers, 7 relocation records, 20 synthetic buffer cases and 77 synthetic lookup cases. The focused suite passed 35 tests with no skips, including byte-window, transfer opcode/displacement, hash, relocation, FDE-range, invalid-section and NOBITS controls, lookup-oracle comparisons, boundary cases and a reversed-tie mutant. Two regenerations with different hash seeds and time zones, plus the separately authenticated #94 control, produced byte-identical #115 outputs under a Python-only search path.

The selected path does not prove the sorted/unique ring invariant across every mutation, the absence of aliases, all sorter partition branches, all result variants, root serialization, scheduler reachability, exception safety or live persistence. No progress gate is requested. Next question: independently prove that ring insertion and every representation transition preserve sorted unique keys, including growth and unwinding, before treating the single-run case as guaranteed on the loader-fed path.
