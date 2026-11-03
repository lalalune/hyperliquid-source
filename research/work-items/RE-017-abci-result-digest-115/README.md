# RE-017: loader-linked post-block collection and result fingerprint

On one loader-linked block callback, two state-derived collection cursors can advance before a separately serialized result vector is fingerprinted at heights divisible by 11 and handed to a record consumer.

- Component ID: `abci`; this bounded RE-017 question also informs RE-009 state and snapshot work.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a navigation lead only and no reference code was copied.
- Claim status: file bytes, FDE metadata, selected operands, relative transfers, and RELA entries are observations; the cross-function identities, role names and fingerprint algorithm are conditional inferences; actual runtime scheduling and helper effects remain unresolved.
- Scope included and excluded: the selected direct callback lane, two post-block collection paths, their cursor updates, the periodic result-vector serialization and sponge path, selected error branches and the sink handoff. Previously studied loader, block engine, callback, formatter and sink functions are context only, not newly owned functions. This is not the full begin/action/end-block task or a state-root implementation.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3, `artifacts/node/115/hl-node`, `tools/elf_index.py` and `tools/fde_extents.py` available, run the following. The two work directories must initially be absent or empty. The generator authenticates the complete target first, reads file bytes only, and calls no external program or node process. The restricted `PATH` checks that binutils is not required.

```sh
python3 tools/abci_result_digest115.py --out research/work-items/RE-017-abci-result-digest-115
python3 -m unittest tests.test_abci_result_digest115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
mkdir -p work/re017-python-only
ln -sf "$(command -v python3)" work/re017-python-only/python3
PYTHONHASHSEED=1 TZ=Etc/UTC PATH=work/re017-python-only python3 tools/abci_result_digest115.py --out work/re017-digest-a
PYTHONHASHSEED=314159 TZ=Pacific/Honolulu PATH=work/re017-python-only python3 tools/abci_result_digest115.py --out work/re017-digest-b
diff -r work/re017-digest-a work/re017-digest-b
diff -r -x README.md -x MANIFEST.sha256 work/re017-digest-a research/work-items/RE-017-abci-result-digest-115
(cd research/work-items/RE-017-abci-result-digest-115 && sha256sum -c MANIFEST.sha256)
```

For the optional separately authenticated historical cross-check, if the retired artifact is available at its reference location, run `python3 tools/abci_result_digest115.py --historical-node references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-historical`. This additional input does not change the generated #115 evidence. Output file hashes are in `MANIFEST.sha256`; inputs and tool/test contents are bound by the target hash and this source change. `functions.tsv` preserves full bytes for the selected FDE extents, `windows.tsv` preserves selected instruction-aligned windows, and the remaining files record decoded operands or data. No generated file is based on disassembler text.

## Evidence

All addresses below are linked ELF virtual addresses. `functions.tsv`, `windows.tsv`, `transfers.tsv`, `branches.tsv`, `relocations.tsv`, `literals.tsv`, and `round-constants.tsv` also give file offsets where applicable. Ends are exclusive. The shared ELF/FDE readers supply section, unwind-index and FDE/CIE data; this tool requires agreement between the unwind start and FDE start and checks the selected extents against each other. A selected FDE is a bounded unwind record, not a claim that the index enumerates every function. The indirect call targets below assume the checked static `R_X86_64_RELATIVE` relocations are applied and are not subsequently replaced.

### Entry and state handoff

The #115 Location record at `0x64767a8` names `l1/src/abci/state.rs:123:37`; an instruction at `0x3c1352f` references it and `0x3c1353b` compares a returned word with 1. This is a context anchor, not a newly claimed loader call. The earlier loader-handoff and expanded-result investigations connect this loader to the callback worker `0x5a6e1e0` through selected constructor and owner transfers. They are prior, conditional context; this packet does not re-own their functions or existing GOT call sites. In the selected worker lane, the block adapter is called at `0x5a6ea10`, after which the post-block dispatcher is called at `0x5a6ead6`. The earlier block-root proposal (PR #2107, open when checked) maps selected begin, item and end stages and some separate root-related state descriptors; the expanded-result proposal (PR #2243, also open) supplies the conditional callback-to-block join. Those proposals are not incorporated or treated as accepted here. Their root-related output is not established to be this packet's downstream result fingerprint.

At the prior block-result boundary `0x4fcb590`, a load reads owner `+0xb00`, then expanded state `+0x28`; selected copies put that value into the output record at `+0x18`. The worker saves the output vector triple and loads the word at output `+0x18` before the periodic predicate. The join assumes the same live object, normal helper returns, the selected branches and no conflicting alias writes; it is not an observed runtime execution.

On the selected post-block lane, the worker passes a pair containing the owner body and callback subobject. A direct dispatcher arm reaches `0x4fc5d70`; its selected calls at `0x4fc5e73` and `0x4fc5fcf` both pass the callback subobject and the address of owner `+0xb00` to `0x4dfe6d0`. The two calls arise on different paths through a guard of owner word `+0x128` against `0x3b9aca00`; the guard's source-level meaning is unresolved. The worker-derived callback subobject is at callback `+0x2a0`.

### New function map

Names below describe local roles only; the precise ranges, hashes and original bytes are in `functions.tsv`.

| Selected FDE start | Role in the selected path |
| --- | --- |
| `0x4f1ec10`, `0x4fc5d70`, `0x4dfe6d0` | Direct dispatch, owner adapter, two collection/update loops. |
| `0x53d7b00`, `0x53d7bf0` | Comparators used when the collected arrays contain multiple records. |
| `0x4e36af0` | Serialize the returned vector, invoke the sponge, return a 32-byte value. |
| `0x531bff0`, `0x531e200`, `0x53228f0`, `0x54835f0` | Outer vector, outer row, 32-byte identifier and nested response encoders. |
| `0x57ceba0`, `0x5306e90` | Selected array-header and array-finish handling. |
| `0x5cda910`, `0x5cdad40`, `0x5cda380` | Selected absorb, squeeze and permutation extents reached through relocation-backed slots. |

### Collection and branches

The table describes the selected loops after subobject byte `+0x260` equals 1 and the state slot is dereferenced. A `row` means the row pointer returned by the selected iterator path; it does not assert a source-language collection type or global ordering.

| Source in expanded state | Reverse step in initial contiguous segment | Collected stride | Old/new word in subobject | Selected rule |
| --- | --- | --- | --- | --- |
| `+0x1a48` | 32 bytes | 32 bytes | `+0x2d0` | Stop when the next first word is unsigned `<=` the old word; otherwise collect it. |
| `+0x1940` | 80 bytes | 64 bytes | `+0x2d8` | Apply the same stop rule; if row `+0x30` is null, skip that row and continue the iterator. |

When a collected array is nonempty, the corresponding comparison loop selects a record with the greatest first unsigned word and stores that word at the same offset; the comparator tie-break logic is not fully identified. Empty arrays do not reach those stores. With the callback subobject offset above, these stores project to callback `+0x570` and `+0x578`. The first nonqualifying row stops the selected iterator; nothing here proves later rows are ordered or absent. The iterator helpers, object mutation by callees and the alternate subobject-byte route are open boundaries.

| Site or decision | Observed selected branch or outcome |
| --- | --- |
| `0x4f1ec2d` | Dispatcher byte `+0x20` equal to zero takes the direct adapter; the other dispatcher route is not closed. |
| `0x4fc5e63`, `0x4fc5f58` | Word `+0x128` comparisons direct the two owner paths; the calls above converge on the collector. |
| `0x4dfe71c` | Subobject byte `+0x260` equal to 1 dereferences the owner state slot; the other route is not characterized. |
| `0x4dfebb0`, `0x4dfee4b` | A null iterator row terminates the respective selected loop. |
| `0x4dfebbc`, `0x4dfee5c` | Unsigned `<=` the saved cursor terminates the respective selected row loop. |
| `0x4dfee67` | Null second-stream row field branches to iteration, not to the cursor store. |
| `0x4dff4d4`, `0x4dff84b` | A helper result with status word 1 reaches a slot call and then `ud2` if that call returns. The helper and complete unwind behavior remain unresolved. |
| `0x5a6ec82` | The unsigned periodic comparison selects fingerprinting; the other path sets a local tag to 2. |
| `0x531c063`, `0x531c1d6`, `0x4e36b62` | Array-header and row failures propagate toward the caller; a serializer status other than `0x8000000000000004` enters the fingerprint error arm. |
| `0x4e36c5e` | The selected error arm conditionally releases storage, passes an `unwrap` diagnostic to a helper, and reaches `ud2` if it returns. |
| `0x5483690` | Nested response user byte `+0x28` equal to 1 selects the present-value path; the alternate selected encoding uses byte `c0`. |
| `0x5a6f8d2` | Callback byte `+0x6b8` determines which record payload lane is copied before the existing consumer call. |

The worker multiplies the saved output word modulo `2^64` by `0x2e8ba2e8ba2e8ba3` and branches when the unsigned result is at most `0x1745d1745d1745d1`. These are respectively the inverse of 11 modulo `2^64` and `floor((2^64 - 1) / 11)`. Thus this particular predicate is equivalent for every `u64` value to divisibility by 11, including zero. This arithmetic statement does not establish a block schedule or the word's source-level type.

### Serialization, fingerprint and delivery

The fingerprint input is the worker's saved vector triple: its pointer and count occupy offsets `+8` and `+16`. On selected successful paths the outer serializer visits 56-byte rows, writes an array header, and writes each row as a two-element array (`92`): a 32-byte input rendered as 66 ASCII bytes with the `0x` prefix and lowercase hex alphabet, followed by a nested vector at row offsets `+0x28`/`+0x30` with 64-byte elements. The old formatter and string writer are context, with a checked slot and byte windows. The nested response encoder selects keys `user` and `res`; the `res` value writer remains a boundary.

The selected array-header writer uses `90 | n` for `n < 16`, marker `dc` with a two-byte big-endian count for `16 <= n < 65536`, and marker `dd` with a four-byte big-endian count for larger counts representable in `u32`. The empty outer-vector preimage is the single byte `90`, assuming successful helper returns. Tests construct a synthetic single-row vector with an empty nested array; those bytes and independent known hash vectors are model controls, not captured node outputs.

The selected sponge initializes a 200-byte state, uses rate 136, domain byte 1 and requests 32 output bytes. Its checked permutation table begins at VA and file offset `0x94c518` and contains 24 eight-byte constants. Those facts and the independent constant-generation test are consistent with Keccak-256; the complete permutation instruction sequence has not been proved equivalent to a reference implementation. At `0x5a6edc4` the worker copies the returned 32 bytes into a local payload and writes tag 1. Under the later `+0x6b8 != 1` lane, selected instructions transfer that tag and the 32-byte payload into the record beginning at worker stack `+0x290`, with the first tag byte at record `+0x58` and payload at `+0x59`; `0x5a6f991` calls the prior consumer `0x595a6b0`. The final payload byte is carried by a later overlapping qword copy. This conclusion assumes intervening calls do not alter the saved locals. The other lane writes a different tag and is not decoded here; no persistence or state-root identity is asserted.

### Historical clue and release separation

The prior node #94 packet is bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its original caller `0x32725d0` uses call `0x3272785` through slot `0x57755a8` to `0x3273810`; the old Location is `0x56dfbf8`, `l1/src/abci/state.rs:107:37`, and the old comparison at `0x3273871` is against 2. The optional check authenticates that separate input and directly validates its slot relocation, call operand, Location bytes and comparison. The independent #115 Location and comparison above are different coordinates and values. Similar topology is a navigation clue, not evidence of equivalent releases, layouts or tags.

### Inferences and unresolved joins

The cursor roles, block-height label, same-owner join, record meaning and Keccak-256 label are interpretations conditioned on the preceding byte observations and assumptions. There is no proof that the 32-byte result fingerprint is a state root. The slot's construction and the loader-to-callback connection rely on the earlier separate packets; this packet pins only the contextual windows at its downstream entry. Helper side effects, iterator traversal across segments, all serialization variants and all indirect runtime bindings remain unresolved.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, lockfile, compiler and linker options, two-build comparison, byte normalization masks, call-target and relocation/vtable/data closure, and whole-ELF comparison: **not yet measured**. The generator extracts target bytes as evidence only; it does not transplant them into an implementation. No node or visor was executed, and no keys, chain access or network requests were used for target analysis.

## Results and limitations

`summary.json` reports 15 selected FDEs, 61 fixed windows (21 contextual), 25 recorded transfers (13 contextual), 17 recorded branches (2 contextual), 5 relocation records, 3 literals and 24 round constants. These are selected-record counts, not coverage rates or a function census. The focused suite has 25 passing tests and zero skips, including bad target digest, individual window and body corruption, wrong FDE bounds, duplicate/invalid relocations, out-of-range and NOBITS mappings, modified branch/call bytes, arithmetic and header boundaries, row-filter mutations, and synthetic hash controls. Deterministic regeneration under different hash seeds and time zones is checked separately.

Neither all begin/action/end-block behavior, state-root inputs, snapshot compatibility, all failure/unwind paths nor runtime behavior is established. No component gate is requested. Next question: close the iterator helpers and nested `res` value writer, then independently compare the selected serializer and sponge output against authorized #115 fixtures when such fixtures become available.
