# RE-009: ExchangeMisc state-hash codec in node #94

This packet identifies the previously unnamed hash job at state offset `+0x3a70` as the one-field `ExchangeMisc` serialization path, with `uta` entries carrying a 20-byte key, a u64 and a `technical` or `treasury` role; a reconstruction can now preserve its field, entry and role order when rebuilding this part of the app-hash input.

- Component ID: RE-009 (storage and state roots)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is a lead only; no reference implementation is copied.
- Claim status: ELF bytes, FDEs, selected instruction windows, direct call and conditional-branch targets are observations. The data model and traversal order below are inferences from those observations; node execution and a complete end-to-end hash fixture remain unresolved.
- Scope included and excluded: 25 selected FDE ranges listed in `functions.tsv`; the writer, tree collector, integer and role writers, binary struct and collection readers, related text-shaped entry/value readers and tree insertion. The pre-existing app-hash builder and closure are referenced only at their capture, vtable and serializer-call sites as context. Shared address-text and collection-header helpers are call targets only. This is not an inventory of every caller, schema version or state root.

## Reproduce

From the repository root on Linux x86-64, with Python 3 (tested with 3.12.3) and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/exchange_misc_root94.py --out research/work-items/RE-009-exchange-misc-root-94
python3 -m unittest tests.test_exchange_misc_root94
(cd research/work-items/RE-009-exchange-misc-root-94 && sha256sum -c MANIFEST.sha256)
python3 tools/exchange_misc_root94.py --out <tmp-dir>/first
python3 tools/exchange_misc_root94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
```

The generator checks the input SHA-256 before parsing and never runs the node, invokes an external program, or reads chain data. `evidence.json`, `functions.tsv` and `windows.tsv` are generated solely from ELF bytes, shared section/FDE parsers and fixed instruction patterns. `functions.tsv` records file offsets, exclusive FDE ends, FDE addresses and whole-range SHA-256s; windows preserve raw bytes rather than disassembler text. Selected calls and branches are fixed sites, not a claim of exhaustive disassembly. The independent integer boundary model is explicitly labelled as a model in the output. `MANIFEST.sha256` covers the generated files and this README.

## Evidence

All addresses are node #94 ELF virtual addresses; file offsets are in the generated TSVs. Each selected extent agrees between `.eh_frame_hdr` and its FDE and is read entirely from a file-backed executable section. `SHT_NOBITS` is excluded. Ranges, call/branch targets, relocation types, dynamic-symbol names and literal lengths are checked against the target digest.

### Hash capture and struct identity

| Step | Target observation |
| --- | --- |
| Capture | `0x275695c` takes the state-relative address `+0x3a70` into a one-pointer box. At `0x2756f5d`, that box is paired with vtable `0x56bded8`. The pair occupies job-list offsets `+0x250` and `+0x258`. |
| Closure | The vtable method relocation targets thunk `0x21e3210`, which calls `0x2815ba0`; its call at `0x2815bf0` enters writer `0x221aa80`. Its writer configuration bytes are `00 04 00 01`, followed by flag byte `00`. |
| Name | The binary reader `0x19f87a0` reaches descriptor `0x56874a8` on its sequence error path. The descriptor relocation and length point to `struct ExchangeMisc with 1 element` at `0x3b038b`. Its recognized field is the three bytes `uta` at `0x3d6bf6`; the writer names the same bytes. |

The established closure and builder were analysed in `research/work-items/RE-009-app-hash-builder-94`; this packet adds the previously excluded serializer and reader bodies. It does not re-establish the overall Keccak construction or claim the `uta` abbreviation's expansion.

### Writer and collection layout

```text
closure call -> 0x221aa80             one-field writer
             -> 0x25e84c0             collection adapter
             -> 0x256b9c0             tree-to-entry collection
             -> 0x1e35e60             entry sequence
             -> 0x1de7260             entry pair
                -> 0x1e0d6c0          20-byte-key formatting helper (shared)
                -> 0x1e0e570          integer adapter -> 0x25abd40
                -> 0x281d230          role text buffer writer
```

`0x221aa80` chooses one-element header helpers based on serializer byte `+0xb`, and emits `uta` when that byte equals 1; a failed header, field-name write or collection write follows a separate return path. The hash closure's configuration makes byte `+0xb` equal 1. The collection adapter handles the empty tree separately, calls the collector and sequence writer, then releases the temporary entry vector. Its unwind cleanup also releases the vector.

The collector derives each output pair from a tree node: a key pointer at node `+0xb8 + 20*i`, a value pointer at node `+16*i`, and an output pair of two pointers at stride 16. It checks multiplication/allocation size and has a distinct empty path. For counts whose upper 32 bits are zero, the sequence writer sends the collection length to its header helper; larger counts take a separate buffered allocation path. It then walks the entry vector at stride 16, forwarding each pair's error before continuing. The direct buffer path in `0x1de7260` writes a two-element marker `0x92` for an entry and another for its value pair; the value's first word is passed to the integer adapter, followed by the byte at value `+8` to the role writer. The address helper is shared; its full text encoding is not recovered here.

Both binary collection readers, and the related text-shaped collection readers, use insertion `0x284daa0`. At `0x284db20` it passes length 20 to the indirect call at `0x284db28`; the target slot's dynamic relocation names `memcmp`. Its equality path replaces the value and returns to the caller, whose duplicate branch rejects the collection. Inference: the key represents an address and the tree uses unsigned lexicographic byte order. The collector is consistent with in-order traversal; a separate runtime fixture is still needed to prove the exact serialized order for arbitrary tree shapes.

### Value encoding and role alternatives

In the direct buffer path, `0x1e0e570` passes the 64-bit value to `0x25abd40`. Its comparisons, marker stores and byte swaps give the following width choices. `integer_boundary_model` in `evidence.json` contains ten reproducible boundary examples, computed by a separate model from those pinned instructions; these are not captured node output.

| Unsigned value | Observed writer branch |
| --- | --- |
| 0 through 127 | one byte, the value |
| 128 through 255 | `cc`, followed by one byte |
| 256 through 65535 | `cd`, followed by two big-endian bytes |
| 65536 through 2^32-1 | `ce`, followed by four big-endian bytes |
| 2^32 through 2^64-1 | `cf`, followed by eight big-endian bytes |

`0x281d230` tests the byte at value `+8`: 1 writes `a8` followed by `treasury`; the other arm writes `a9` followed by `technical`. The binary classifier `0x280a770` and text-shaped reader `0x1bab5b0` both recognize exactly nine-byte `technical` as tag 0 and eight-byte `treasury` as tag 1; other lengths or contents reach error builders. These roles are wire labels; their business meaning and the effect of malformed in-memory tags are not established. The formatted 20-byte key and surrounding collection header are shared helper behavior, so no complete preimage or digest is asserted here.

### Reader and failure branches

```text
0x19f87a0 binary outer field or sequence -> 0x197ab70 collection
  binary map      -> 0x26563e0 -> 0x1961a70 value
  binary sequence -> 0x2680ef0 -> 0x1834eb0 entry -> 0x1961a70 value
  either collection reader -> 0x284daa0 insertion
  binary value -> 0x1689950 -> 0x1a38ab0 -> 0x280a770 role classifier
```

The separately selected text-shaped reader `0x2601410` also uses `0x284daa0`, as does its sequence reader `0x265b560`. Its value path reaches `0x1baac30 -> 0x281d3a0 -> 0x1bab5b0`; the latter classifies the same two role spellings as the writer. Inference: these represent the same key/value shape. The connection to the binary root is grounded in their common insertion specialization and layout, rather than a claim that these two reader formats call one another.

| Case | Selected branch and result |
| --- | --- |
| Binary named field `uta` repeated | `0x19f91b0` branches to duplicate-field diagnostic construction at `0x19f9770`. |
| Binary named form closes without `uta` | `0x19f922e` branches to missing-field diagnostic construction at `0x19f9251`. |
| Binary collection repeats a key | Both `0x26563e0` and `0x2680ef0` call the same insertion and construct the literal `duplicate key` on its duplicate return. |
| Text-shaped collection repeats a key | Both `0x2601410` and `0x265b560` also construct the literal `duplicate key` on the shared insertion's duplicate return. |
| Unknown role spelling or length | The binary classifier `0x280a770` branches to `0x280a804`; the text-shaped classifier `0x1bab5b0` branches to `0x1bab6cc`. |
| Truncated or malformed input | Separate early exits and parser-error paths are present in the selected readers; their complete error taxonomy is not classified. |

The binary reader's treatment of unknown fields and the text-shaped outer reader are not fully classified. A literal error path establishes a rejection branch; this is not a claim about application-level recovery or runtime state after an error.

## Implementation and comparison

not yet implemented. No Rust serialization, independent compiler build, node execution, binary-equivalence comparison, live snapshot or full app-hash fixture was performed. Shared helper semantics and the closure's hash use are bounded by the prior app-hash-builder packet and remain separate from this packet's selected functions. The integer examples are a static model of the pinned width branches, not a comparison against executed target code.

## Results and limitations

The generated records cover 25 selected FDEs, 62 fixed windows, 42 direct-call sites and 23 selected conditional branches; these denominators are the explicit scope above, not coverage of all functions or branches. Local validation: 21 unit tests passed with no skips, including changed digest, FDE extent and body, field and role literals, duplicate diagnostics, compare and closure relocation, opcode, integer-threshold, role-marker and binary role-classifier, out-of-range and NOBITS controls. The role model checks every single-byte substitution of each role label. The integer model tests both sides of the four width transitions and the u64 maximum. These controls validate extraction and the stated model, not execution equivalence.

The application meaning of `uta`, the complete key formatter, alternate codec configurations, arbitrary-tree traversal order, whole-reader corruption behavior and a target-backed digest fixture remain open. No progress gate is requested. Next question: can the matching snapshot writer and independent byte fixture establish a complete `ExchangeMisc` preimage, including key text and collection order?
