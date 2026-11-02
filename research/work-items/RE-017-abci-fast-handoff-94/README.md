# RE-017: loader-derived fast-worker handoff and guarded updates

This packet fixes the placement of a loader-dependent worker object in an assembled parent and maps the conditional compare, replacement, and unwind paths associated with the same layout, giving a reconstruction concrete layout and cleanup rules while leaving a copied handoff and scheduling as conditions.

- Component ID: `abci` / RE-017, a partial state-loader result-handoff question.
- Target release and full SHA-256: Linux x86-64 node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: project `966865f1637a29ce75b019e1bf11d5529cc6f519`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; the observations and labels below come from the authenticated ELF, not copied source.
- Claim status: observations are explicit byte, relocation, FDE and exception-table facts. Names and runtime implications marked **Inference** are not observations. Open questions are in Results and limitations.
- Scope included and excluded: nine newly selected FDE extents, 35 short connection windows, 74 selected conditional branches and 21 selected calls. The earlier Location-bearing loader, its GOT/call sites, two already inventoried caller targets, and previously owned function bodies remain prior-work boundaries. This is a conditional handoff path, not the full block-application or state-root task.

## Reproduce

From the repository root, with Python 3.10 or newer and the authenticated node #94 file present:

```sh
python3 tools/artifacts.py verify
python3 tools/abci_fast_handoff94.py --out research/work-items/RE-017-abci-fast-handoff-94
python3 -m unittest tests.test_abci_fast_handoff94 -v
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_fast_handoff94.py --out work/abci-fast-a
PYTHONHASHSEED=917 TZ=Pacific/Honolulu python3 tools/abci_fast_handoff94.py --out work/abci-fast-b
diff -r work/abci-fast-a work/abci-fast-b
(cd research/work-items/RE-017-abci-fast-handoff-94 && sha256sum -c MANIFEST.sha256)
```

Python 3.12.3 on Linux x86-64 was used. The producer checks the full digest before parsing and uses the shared `tools/elf_index.py` and `tools/fde_extents.py`; it parses the observed LSDA call-site encoding with the shared ULEB decoder. It rejects unsupported encodings, ambiguous or NOBITS address mappings, FDE/index disagreements, changed code windows, changed LSDA headers/tables, and changed literal bytes. It reads files and writes the requested output directory; it executes neither the capture nor any external program. The test uses a private copy-on-write mapping for corruption controls. The producer needs no binutils and its outputs contain no clock, environment value or local absolute path.

For human cross-reading only, GNU objdump 2.42 was used with `-d -M intel` and explicit start and stop addresses. Neither producer nor tests parse that output.

The ten generated files are `fdes.tsv`, `boundaries.tsv`, `branches.tsv`, `calls.tsv`, `relocations.tsv`, `labels.tsv`, `lsda.tsv`, `lsda-headers.tsv`, `comparison-paths.tsv`, and `summary.json`. The manifest also covers this README. `fdes.tsv` contains complete bytes of the nine selected FDE extents; `boundaries.tsv` contains only the selected connecting windows in previously inventoried FDEs. The call and branch tables are curated instruction starts, not a whole-program census. All VAs are link-time ELF virtual addresses, without runtime rebasing; file offsets are independently resolved against file-backed sections and are not assumed equal to VAs. FDE ends and LSDA call-site ends are exclusive.

## Evidence

### Where the new work joins prior work

The [original state-link packet](../RE-017-abci-state-link-94/README.md) identifies the `state.rs` Location-bearing materializer path, and the [round-clock packet](../staking-round-clock-94/README.md) follows the reload into the local-state host. The [node inventory](../node-inventory-94/inventory.json) already records the outer startup FDE and the calls from it into the launch bridge and from the fast loop into the read guard. Those existing call instructions are not regenerated here. The [consensus-config packet](../consensus-config-94/README.md) owns the config builder, and the [firewall-cycle packet](../firewall-update-cycle-94/README.md) expressly excludes the separately addressed twin considered as a boundary below.

The selected FDEs and their exclusive ends are:

| New FDE | Extent | Observed role |
| --- | --- | --- |
| `0x4b31790` | `0x4b31790..0x4b31a67` | extract two words through two tree-shaped structures |
| `0x4548b40` | `0x4548b40..0x4548cb6` | construct the worker object and its cleanup path |
| `0x1f85740` | `0x1f85740..0x1f85d71` | build and submit the closure descriptor |
| `0x1f9a9f0` | `0x1f9a9f0..0x1f9ac00` | closure entry and argument reconstruction |
| `0x432f5f0` | `0x432f5f0..0x432f679` | adapter into the previously inventoried fast loop |
| `0x45292b0` | `0x45292b0..0x45294ca` | guarded call to a refresh helper |
| `0x4526490` | `0x4526490..0x45266fd` | compare three protected fields |
| `0x4523e00` | `0x4523e00..0x452422b` | replace the three fields, including unwind handling |
| `0x4527d40` | `0x4527d40..0x4527f5f` | replace a separately guarded 32-byte value |

FDE membership supplies unwind extents, not proof of complete source-function boundaries. The short windows in the already inventoried launch bridge and read guard only establish the argument chain; they do not claim either entire FDE. In particular, the inventory's two existing direct call sites are not reproduced as new call records.

### From state result to a worker object

In the continuation of the prior host, `0x226c9b8` copies `0x3ae8` bytes from the returned stack area to the parent at `+0xb48`. The already inventoried call at `0x226cd98` reaches the existing config builder; the immediately preceding new window passes that address as input and parent `+0x4658` as output. The next selected indirect call at `0x226d1fd` resolves through a type-8, symbol-zero relocation to `0x4b31790` and receives the config output at `+0xa0`. The next new indirect call, `0x226d275`, resolves to `0x4548b40`; the preceding moves pass the two returned words in `rdx` and `rcx`, with destination parent `+0x4798`.

`0x4b31790` reads root/depth/count triples at argument offsets `+0x28/+0x30/+0x38` and `+0x08/+0x10/+0x18`. For either triple, a zero root or count yields a zero result word. Otherwise the code descends through entries indexed by a 16-bit field, walks parent links when needed, and loads a final word. A missing parent on either walk calls the same resolved failure helper and reaches `ud2`; a zero computed address also produces zero. The first and second words return in `rax` and `rdx`. **Inference:** the shapes and traversal resemble two ordered-tree last-key queries; the keys' application meaning and validity invariants are not established.

The constructor stores those words at object `+0x2d0` and `+0x2d8`; it initializes the byte at `+0x260` to zero, copies a 20-byte input to `+0x261`, stores IEEE-754 bits `0x403e000000000000` (30.0) at `+0x278`, and stores a zero 32-bit marker at `+0x280`. It also retains reference arguments at `+0x2c8`, `+0x290`, and `+0x298`. Its LSDA maps an exception in the initialization call range to `0x4548c53`, which decrements the three captured reference counts and resumes unwinding, with conditional drop calls when a count reaches zero.

The selected copy windows show the state body of `0x3ae0` bytes and the `0x2e0`-byte worker object adjacent in a `0x3dc0`-byte aggregate. After the intervening aggregate copies, the worker tail is copied to stack `+0x19c0`, which is `+0x260` within the parent beginning at stack `+0x1760`. The prior [node-inventory instruction transcript](../node-inventory-94/instructions.json), in FDE `0x226c2d0` at offsets `0x3007..0x301f`, records the subsequent `0x698`-byte transfer from that stack parent to stack `+0x10a20`; the separately established [import binding](../foundation-reserve-grow-94/README.md) identifies the copy slot. These are prior-work citations, not new pins or a fresh claim of those call sites. Conditional on that copy and its control flow, the later selected window transfers the parent prefix into the caller's result buffer. On the non-2 return arm, the outer FDE copies `0x698` result bytes into its own `+0xe8` slot, and a later selected window copies from that same slot before the previously inventoried launch-bridge call. Tag value 2 takes the other branch; its source-language meaning is unresolved.

### Closure handoff and possible fast-worker route

The boundary window in the previously inventoried launch bridge passes a `0x6f0`-byte input to `0x1f85740`. The builder copies it after a `0x28`-byte closure prefix and uses a `0x718`-byte allocation. Its descriptor at `0x56924a8` records size `0x718`, alignment 8, and a symbol-zero RELATIVE relocation at descriptor `+0x18` to `0x1f9a9f0`. The callback reconstructs the first `0x10` bytes and the remaining `0x6e0` bytes before calling `0x432f5f0`; that adapter forwards to the inventoried fast loop. `labels.tsv` binds the outer launch label `node handle client blocks` and fast-loop guard label `run_node_send_execution_state` to their actual pointer/length setup.

Within the previously inventoried fast loop, a selected window forms the address of the parent at `+0x260`; another forwards that address as the guard's third argument. The read-guard connection window saves this argument and passes it as the first argument at `0x452725e` to the already mentioned twin update FDE. The worker offset matches at construction and use across the listed transfers, conditional on the prior-work copy and control flow. The closure descriptor is evidence of a possible indirect callback, not proof that the scheduler selects it, that every intervening branch runs, or that no unexamined write changes the bytes.

The builder has explicit null-allocation, reference-count and launch-result branches in `branches.tsv`. Its ELF string `RUST_MIN_STACK` is an input name in a conditional path; the recorded code supplies a `0x200000` fallback in the relevant branches. This is a static observation about the binary, not a read of the analyst's environment. The callback and adapter have LSDA call-site ranges in `lsda.tsv`, including their unwind targets; action-table contents are not decoded.

### Guarded refresh, comparison and publication

The update-boundary windows identify the labels `firewall_ips_maybe_update`, `check_computed_ips`, and `update_computed_ips` from actual ELF pointer/length pairs. The nonzero object tag branches past this particular refresh-and-compare block. With a zero tag, a zero 32-bit marker at `+0x280` enters refresh; otherwise the floating comparison's `be` branch reaches the no-refresh arm, including the x86 unordered case. The guarded refresh call reaches `0x45292b0`, which acquires a lock at argument-base `+0x568`, calls `0x47202c0` on `+0x570`, and releases the lock. The helper's internals remain outside scope.

On the selected compare path, `0x4526490` uses a reader-style lock at `base+0x568`. Its fast acquire is attempted only when bit 3 of the old word is clear and the unsigned word is below `0xfffffffffffffff0`; otherwise, or after a failed compare-exchange, control goes to the slow helper. It invokes three helpers on stored fields at `base+0x570`, `+0x588`, and `+0x5a0` against candidate offsets `0`, `0x18`, and `0x30`. A zero result from either first helper short-circuits to byte 1; otherwise the low byte of the third result is XORed with 1. The released-lock path stores that byte at result `+0x10`. The six rows in `comparison-paths.tsv` explicitly include non-Boolean third-return examples; treating every helper as a canonical equality predicate is an **inference**, not a proved precondition.

The boundary tests the returned byte: zero branches around the replacement call; nonzero reaches `0x4523e00` using the same base. The comparison's read lock is released before the replacement acquires its write-style lock; no atomic compare-and-swap of the aggregate is established. The replacement attempts `0 -> 8` at `base+0x568`, calls slow acquire on failure, walks/drops old field contents, and stores 72 input bytes at `base+0x570` using one 8-byte and four 16-byte stores. It then attempts `8 -> 0`, with a slow release on failure. The generated branch and call tables retain those sites and the corresponding helper boundaries.

The LSDA call-site table connects exceptions from the first, second and third old-field walks to landing pads `0x45241ad`, `0x45241a8`, and `0x45241a3`, respectively. On these landing paths the code performs the applicable remaining cleanup, executes the same 72-byte replacement stores, releases the lock, and resumes unwinding. An earlier protected call has a different landing pad that releases the lock and handles the incoming value. This describes the inspected landing code and call-site records; it does not claim every possible failure reaches those paths or decode nonzero LSDA action selectors.

A later selected loop copies four bytes plus one byte per item, advancing its source by `0x50` and destination by 5. It calls `0x4527d40` with a separate shared object. That helper locks a byte at `base+0x2a0`, conditionally calls a helper with the old pointer and five times the old leading word, copies a 32-byte input to `base+0x2a8`, and releases the byte lock. Its LSDA includes separate cleanup and unlock paths. The item type, ownership allocator, and reachability of this later branch are not fully resolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency scope, compiler/linker flags, two-build result, binary comparison, normalization masks, and helper/data/relocation closure: **not yet measured**. The six comparison rows are conditional instruction models, not observations of live node execution or target-equivalence tests. No node or visor was executed, and no target network traffic, keys, chain actions, or captured user state were used.

## Results and limitations

The producer retains 9 selected FDE extents, 35 boundary windows, 74 branch rows, 21 call rows, 9 relocation records, 7 pointer/length labels, 9 LSDA headers with 71 call-site rows, and 6 comparison examples. These denominators are the explicitly selected scope, not node coverage. The focused suite has 28 passing tests and no skips, including bad digest before output, altered owned and boundary bytes, invalid branch/call encodings, out-of-range and NOBITS mappings, ambiguous sections, altered/missing relocations, FDE/index changes, LSDA encoding and action-byte tampering, literal corruption, and byte-for-byte regeneration.

The state loader's earlier call sites and two inventoried call targets remain prior-work boundaries, not new function claims. The aggregate copy previously recorded elsewhere is also a dependency rather than a duplicated pin. Exact Rust types, helper comparison semantics, the scheduler's dynamic dispatch, all intervening reachability and aliasing, complete allocator/unwind closure, begin/action/end-block paths, and state-root inputs remain unresolved. Node #115 and visor are separate targets. No `abci` milestone gate is requested; the component remains 0/4.

Next question: follow the dispatch provider and the intervening state-machine edges with independent non-overlapping evidence, then establish whether the same initialized object actually reaches this callback and what the three comparison helpers compare.
