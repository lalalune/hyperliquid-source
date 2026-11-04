# RE-017: loader key to callback result representations

This packet follows a loader-parent key through twelve bounded copies into a callback allocation and identifies how the downstream row pipeline selects compact or tree representations, including their selected failure paths.

- Component ID: `abci`; RE-017, with the state-root handoff question connected to RE-009.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no license grant and no source text is incorporated.
- Claim status: observations are checked against the identified ELF; field roles, control-flow relationships and copy propagation are bounded inferences; runtime dispatch, aliases, complete state mutation and root semantics are unresolved.
- Scope included and excluded: selected #115 parent-to-callback copies, one forward cursor, two row representation families, selected unwind and failure branches. Previously documented loader, parent, collector and callback functions supply boundary context only. This is not a complete begin/action/end-block or state-root implementation.

## Reproduce

Run from the repository root with Python 3.12 and the pinned node artifact. The extractor reads ELF bytes; it does not run either node, call an external executable, contact a network, or modify the input. It uses the repository's `elf_index` and `fde_extents` modules for ELF and FDE/CIE interpretation, and validates the entire input digest before writing. VA-to-file mapping excludes `SHT_NOBITS`. Outputs are deterministic UTF-8 with no timestamps or host paths. The observations cover selected instruction starts and full selected FDE byte ranges; they are not a whole-program disassembly. GNU objdump 2.42 was used separately to inspect candidate instructions, but its output is neither parsed nor part of generated evidence.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_abci_row_repr115
python3 tools/abci_row_repr115.py --out work/abci-result-a
python3 tools/abci_row_repr115.py --out work/abci-result-b
diff -r work/abci-result-a work/abci-result-b
for f in work/abci-result-a/*; do cmp "$f" "research/work-items/RE-017-abci-result-repr-115/${f##*/}"; done
(cd research/work-items/RE-017-abci-result-repr-115 && sha256sum -c MANIFEST.sha256)
```

To repeat the portability check with only Python on `PATH`:

```sh
mkdir -p work/abci-python-only
python_bin=$(command -v python3)
ln -sf "$python_bin" work/abci-python-only/python3
PYTHONHASHSEED=1 TZ=Etc/UTC PATH=work/abci-python-only python3 tools/abci_row_repr115.py --out work/abci-result-seed-a
PYTHONHASHSEED=789 TZ=Pacific/Honolulu PATH=work/abci-python-only python3 tools/abci_row_repr115.py --out work/abci-result-seed-b
diff -r work/abci-result-seed-a work/abci-result-seed-b
PATH=work/abci-python-only python3 -m unittest tests.test_abci_row_repr115
```

An optional release-separated historical cross-check is available when the #94 reference binary is present:

```sh
python3 tools/abci_row_repr115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out work/abci-result-with-94
diff -r work/abci-result-a work/abci-result-with-94
```

The optional check verifies #94 independently and does not change the #115 output. `MANIFEST.sha256` supplies the evidence and README output hashes. See `summary.json` for input identity and machine-readable counts.

## Evidence

Coordinates below are ELF virtual addresses unless called file offsets; end addresses in `functions.tsv` are exclusive. `functions.tsv` contains each selected full FDE byte range and hash. An FDE is an unwind range, not by itself proof of a complete semantic function or a census of all code. `windows.tsv` records the selected byte windows, `transfers.tsv` the explicitly checked x86 relative branches and RIP-relative slot references, `operands.tsv` fixed-opcode operands, and `relocations.tsv` the selected ELF relocation records. Instruction starts were selected by inspection, not by a whole-section byte scan. The checked ranges, decoder forms and input identity are pinned in the extractor.

### Release-separated loader lead

The prior RE-017 packet concerns #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its FDE `0x32725d0..0x3272b3a` has the call at `0x3272785` through slot `0x57755a8`, whose relocation addend is `0x3273810`; the latter FDE is `0x3273810..0x327396c`. Its Location at `0x56dfbf8` ends in `l1/src/abci/state.rs:107:37` and its selected comparison is against `2` at `0x3273871`. The optional historical check independently validates these bytes, intervals, relocations and digest.

For #115, `location.json` records a distinct Location at `0x64767a8` (file offset `0x64747a8`), suffix `l1/src/abci/state.rs:123:37`; the selected RIP-relative reference at `0x3c1352f` and comparison against `1` at `0x3c1353b` are in context windows. The changed coordinates, line and immediate are observations, not a claim of source or semantic equivalence between releases. The prior #115 loader and parent mappings remain owned by their existing packets.

### Selected map and key transport

| Stage | Selected #115 FDE starts | Observation |
| --- | --- | --- |
| Constructor | `0x4dfe550` | Two previously mapped parents call slot `0x64e7478`, whose RELATIVE relocation addend is this FDE. The sixth argument supplies 20 bytes stored at output `+0x261`; output `+0x260` is set to zero. |
| Source cursor | `0x5135c50` | A count is tested and decremented; selected tag, parent, descent and exhaustion branches are recorded. |
| Representation entries | `0x51695e0`, `0x5160b30` | Separate row families drain, sort where selected, allocate a leaf, and invoke a builder. |
| Compact handling | `0x58027b0`, `0x58046d0` | Capacity and length decide no-op, resize or zero-length release-style paths. |
| Drain | `0x5ad6460`, `0x5ad6780` | Selected equality and half-capacity comparisons select buffer reuse or a fresh-buffer path. |
| Tree construction and guards | `0x4cb4ec0`, `0x4cd7440`, `0x57bc780`, `0x57bcd30` | Two builders consume lookahead iterators, populate nodes and have distinct unwind guards. |
| Adjacent-key grouping | `0x4d57b60`, `0x4d5a620` | Both compare the first 16 and following 4 key bytes; their zero-value stop conditions differ. |
| Sort | `0x53e5db0`, `0x4f42430`, `0x4f3e930`, `0x4f774c0`, `0x4f627e0`, `0x4eb18b0`, `0x4e7be10` | A selected short sorter and two long wrapper/driver/partition families are recorded, including relocation slots, scratch choices and failure edges. |

The map is a set of selected FDEs, not a claim that every edge and helper inside them is closed. `transfers.tsv` links recorded direct calls or slot references to the addresses shown; relocation results do not prove the runtime values of mutable slots.

In previously mapped parent B, the input bytes at parent `+0x158..+0x16b` are copied to a temporary beginning at `+0x540` and passed to the new constructor. Its selected stores put the key at constructed object `+0x261` and zero the byte at `+0x260`. Parent A has an independently pinned matching argument setup. In parent B, the second repack is on the `r15 != 2` arm; the direct jump at `0x2cbeb8e` reaches `0x2cbc52d`, and the final result copy requires the selected validation call to return zero. `key-flow.tsv` then projects both the 20-byte key and its flag through twelve explicitly bounded copies along the selected parent B path:

| Boundary | Key offset | Flag offset |
| --- | --- | --- |
| Constructed object | `+0x261` | `+0x260` |
| Parent result | `+0x261` | `+0x260` |
| Upper caller's enclosing object | `+0x699` | `+0x698` |
| Callback allocation | `+0x501` | `+0x500` |

The upper caller stages the enclosing object from `+0x198`, allocates `0x718` bytes and copies the staged data into that allocation. The prior callback worker context computes allocation `+0x2a0`; therefore its subobject offsets `+0x261` and `+0x260` address the projected key and flag. Previously documented callback/collector edges supply the further connection to the row pipeline. This join is conditional on the selected control-flow paths, ordinary calling conventions and the indicated `memcpy` binding, successful allocation, the callback receiving the constructed allocation, and no relevant intervening writes through aliases. The static windows do not prove those runtime conditions, scheduling, or a complete absence of aliasing. In particular, the offset calculation alone is not proof that a live state update occurred.

### Layouts and selected branches

| Question | First family | Second family |
| --- | --- | --- |
| Input row | 32 bytes: 20 key bytes, 4 auxiliary bytes, pointer at `+24` | 32 bytes: 20 key bytes, dword at `+20`, qword at `+24` |
| Grouping termination | Zero pointer stops the iterator | Zero dword stops the iterator |
| Adjacent duplicates | Compare 20 key bytes and retain the last complete row within an adjacent run | Same selected 20-byte comparison and adjacent-run selection |
| Builder output | Key at node `+0x60 + 20*i`, pointer at `+8 + 8*i`; the 4 auxiliary bytes are not written by this selected store | Key at node `+8 + 20*i`, 12-byte value at `+0xe4 + 12*i` |
| Node fields | Count at `+0x13e`; capacity 11; initial leaf request `0x140`, internal request `0x1a0` | Count at `+0x16a`; capacity 11; initial leaf request `0x170`, internal request `0x1d0` |
| Empty compact sentinel after release-style call | `8` | `4` |

These are layout and control-flow inferences from the recorded stores and comparisons. The stop cases are also exercised as synthetic negative controls; they are not assertions that the preceding collectors produce zero payloads on normal input. Nonadjacent equal keys are not combined by the lookahead alone. Sort tie stability and the original input row retained after long sorting remain unresolved.

The previously mapped caller selects compact handling at count at most 64 and the tree entry above 64. On the selected compact path, initial head and request are zero. If capacity equals length, the selected shrink path returns without a resize; if capacity exceeds a nonzero length, it calls the resize slot and stores its returned pointer. A null return selects a failure call followed by `ud2` if that call returns. For zero length and nonzero capacity, it makes a release-style call and writes zero capacity and the family sentinel. These names describe inferred roles, not proven allocator ABI or all side effects. A pointer returned by resize can differ from the input pointer.

For the selected tree route, the initial drain descriptor has equal start and current pointers, so the observed reuse edge avoids the drain copy, subject to the same ordinary call and alias assumptions. Its count is above 64, so the later count-at-least-21 branch selects a long-sort wrapper. The wrapper computes scratch rows as `max(min(n, 250000), ceil(n/2))`; on this route 65 through 128 use the 128-row stack area and 129 or more select an allocation-style path, requesting `32 * scratch_rows` bytes after a size guard. The drivers compare 20-byte keys through the recorded `memcmp` slot and reverse complete 32-byte strictly decreasing runs; equality stops the decreasing run. This does not establish full long-sort correctness or equal-key ordering.

The cursor returns an empty result when the remaining count is zero; otherwise its selected bytes decrement the count before checking tag `1`. A bad tag and a missing parent lead to error-slot calls followed by `ud2` if those calls return. Given a valid finite tree and the recorded parent/index invariants, its selected successor/descent operations are consistent with in-order traversal; those invariants and complete input construction are not proven. Builders and wrappers contain selected null-allocation and parent-full branches; `unwind.tsv` records LSDA call-site rows, and `unwind-links.tsv` joins selected calls to those rows where available. Action chains, all cleanup effects and recovery behavior remain unresolved. The constructor's landing path and guard calls are recorded rather than interpreted as a complete rollback protocol.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler and linker flags, two-build comparison, fixture comparison, normalization masks, relocation closure and whole-ELF equivalence: **not yet measured**. No reconstructed source was compared with the node. `family-differences.json` contains six unmasked raw byte comparisons of paired #115 FDEs, not a normalized or equivalence score. Calls to indirect helper slots are reported as static relocations; dynamic bindings, data/vtable closure, allocator behavior and complete failure semantics are open.

## Results and limitations

The generated evidence contains 21 selected FDE ranges (15,334 bytes), 76 owned byte windows, 36 boundary-context windows, 134 selected transfers, 85 selected operands, 15 selected relocations, six raw family comparisons, 12 key-copy projections and 51 LSDA call-site rows. Of 49 selected owned calls joined against unwind data, 39 match recorded LSDA ranges; the other 10 belong to selected owners without parsed LSDA. These counts describe this bounded selection only, with no whole-node denominator. `functions.tsv` and the raw windows retain the bytes underlying the claims; actions and indirect call destinations beyond selected relocation records are not exhaustively decoded.

The focused suite passed 33 tests with no skips, including altered digest and body bytes, changed operands and branches, invalid or ambiguous mappings, relocation and malformed LSDA controls, copy range failures, synthetic row grouping, cursor and scratch boundaries, and compact-path pointer/sentinel models. Synthetic tests exercise the extracted model; they are not executions of the node and do not independently prove the model. Two outputs produced with different hash seeds and timezones under a Python-only `PATH` were byte-identical; the separately authenticated #94 option produced the same #115 output. Artifact verification and the catalogue check passed. No component gate is advanced: begin/action/end-block coverage, resulting state mutations, the final state-root input and runtime equivalence remain open.

Next question: establish the callback binding and alias invariants across the selected handoff, then follow each representation into the actual state-root input and resolve long-sort ties and the failure cleanup chain.
