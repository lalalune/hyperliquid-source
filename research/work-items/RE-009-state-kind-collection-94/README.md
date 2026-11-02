# RE-009: state-hash address and kind collection serialization

The state-hash field captured at `+0x8a0` can now be reconstructed as an address-keyed collection whose entries contain collections of seven named variants, with a fixed prefixed-hex key path and distinct integer-payload and unit-variant encodings.

- Component ID: RE-009
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`; the inferred reference tree was not used as source for the codec.
- Claim status: byte windows, FDE records, relocation addends and decoded relative call/dispatch targets are observations; container meaning and the relationship between the writer and independently located JSON reader are inferences; global ordering and root equivalence are unresolved.
- Scope included and excluded: the sixteen FDE ranges in `summary.json`, selected instruction windows and their named dependencies. The previously mapped state-hash job is included only as a boundary call and its local setup, not reanalyzed as a new function. Shared dependencies are referenced but not claimed as newly recovered functions. No node execution, state data, network, keys, Rust implementation or milestone gate.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12 and the standard library. The extractor imports the repository's `elf_index` and `fde_extents` parsers. It authenticates the node file before any extraction, reads ELF bytes, matches fixed x86-64 byte windows, decodes signed relative displacements and RELATIVE addends, and never runs the node or invokes another executable. `CHECK_DIR` is a disposable directory selected by the operator.

```sh
CHECK_DIR=$(mktemp -d)
PYTHONHASHSEED=1 TZ=UTC python3 tools/re009_state_kinds94.py --out "$CHECK_DIR/a"
PYTHONHASHSEED=999 TZ=Pacific/Honolulu python3 tools/re009_state_kinds94.py --out "$CHECK_DIR/b"
diff -r "$CHECK_DIR/a" "$CHECK_DIR/b"
for name in anchors.tsv calls.tsv dispatch.tsv indirect.tsv variants.tsv summary.json; do
  cmp "$CHECK_DIR/a/$name" "research/work-items/RE-009-state-kind-collection-94/$name"
done
python3 -m unittest tests.test_re009_state_kinds94
(cd research/work-items/RE-009-state-kind-collection-94 && sha256sum -c MANIFEST.sha256)
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

`anchors.tsv` records each selected byte window and its linked virtual address and file offset; `calls.tsv` resolves direct calls; `dispatch.tsv` preserves all entries in the six examined tables; `indirect.tsv` records the one resolved formatter slot; `variants.tsv` joins the seven relocated names to their branch targets; `summary.json` records FDE ranges and body hashes. The manifest supplies output hashes. These files, including row counts, are reproduced from ELF bytes, not from disassembler text.

## Evidence

All addresses are linked ELF virtual addresses; file offsets are zero based. End addresses in `summary.json` are exclusive. The FDEs are unwind-described extents, not proof that all possible code boundaries or paths have been recovered.

The prior `research/work-items/RE-009-app-hash-builder-94/closure-rows.tsv` identifies low-lane job 34 as capturing state field `+0x8a0`. Its boundary dereference and call go to `0x25e3840`; the prior job's setup and call are recorded as context, while its function body and hash core remain outside this packet. The wrapper calls `0x2563060` to collect pairs and `0x1e193a0` to write them. The collector uses an input count times 16 for its allocation and materializes two pointers per element. Its key address calculation uses a 20-byte stride and its value address calculation a 24-byte stride. A count with nonzero high four bits or an allocated byte count above `0x7ffffffffffffff8` takes the allocation-error call; zero length follows a separate branch. These are observed guards, not a claim about an allocator's behavior after the call.

The outer writer calls a count-header helper and visits 16-byte collected entries. Pair writer `0x1dd48e0` passes count 2 to the same header helper or emits `0x92` on the direct path, writes the key, writes a value-collection header and invokes the variant writers for its elements. On header, key, value-header or variant failure, the tested status branches leave the normal path; `anchors.tsv` preserves the checks. Tree child and parent traversal windows are also retained, but complete ordering is not asserted here.

The two key writers pass input length 20, output capacity 42 and mode zero through slot `0x5773120`; its unique `R_X86_64_RELATIVE` relocation names the already studied prefixed-hex helper. The prior `research/work-items/RE-005-prefixed-hex-rust-94/README.md` establishes its `0x` prefix and lowercase alphabet in mode zero. Together these observations support a 42-byte lowercase prefixed-hex key representation. The shared formatter's body is not a new finding in this packet.

The direct variant writer's tag dispatch and relocated name descriptors yield the following table. `map` means a one-entry MessagePack-style map (`0x81`); `string` means a MessagePack-style fixstr. The integer payload is loaded as a 64-bit word and passed to the unsigned writer. The generic writer's separate branch addresses are retained in `variants.tsv`; this table does not assume its full error behavior matches the direct path.

| Tag | Name | Direct writer | Quoted JSON branch | Object JSON branch |
| --- | --- | --- | --- | --- |
| 0 | `Perp` | map, name, unsigned integer | reject | numeric helper |
| 1 | `Spot` | map, name, unsigned integer | reject | numeric helper |
| 2 | `Token` | map, name, unsigned integer | reject | numeric helper |
| 3 | `Pdi` | map, name, unsigned integer | reject | numeric helper |
| 4 | `ActivateDexAbstraction` | string | unit | null helper |
| 5 | `ActivateUnifiedAccount` | string | unit | null helper |
| 6 | `AllBoleTokens` | string | unit | null helper |

For successful direct unsigned output, the byte windows distinguish `0..127` as the byte itself, then markers `cc`, `cd`, `ce`, and `cf` for 1-, 2-, 4-, and 8-byte values; byte swaps establish big-endian multi-byte payloads. For example, the bounded model predicts `Perp(128)` as `81 a4 50 65 72 70 cc 80`. The model is a consequence of the retained instruction windows and is not captured target execution.

The independently located reader `0x25fa800` dispatches first-byte values from `0x5b` through `0x7b` through a 33-entry table; the object branch calls the kind-array reader after a colon and passes 20-byte operands to a comparison slot. The other lead-byte routes are retained as targets but not fully analyzed. The array reader calls `0x28e59d0`, checks its error sentinel and then calls a shared insertion helper. The variant reader accepts a quoted unit or an object branch as shown above; its object branch checks the colon and the closing brace, and propagates numeric and null helper errors. The null helper checks `n`, `u`, `l`, `l` in sequence. Unknown names take a separate classifier error path; the length dispatch covers the bounded range and sends other lengths to that path. The numeric helper rejects a negative signed result. This is an analysis of selected routes and failure checks, not a complete JSON grammar or an execution trace.

The single insertion helper is already referenced by `research/work-items/RE-003-pr-integration-1265-1275/`, so it is deliberately outside the newly examined FDEs. We do not infer duplicate handling, the order of entries or a particular Rust container from that call alone. The reader is paired with the hash writer by matching its element classifier to the writer's seven tags and the observed key/value shapes; the containing state-object linkage remains an inference.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler, Cargo lock, two-build comparison, masks and target execution: not yet measured. The Python models cover only the successful direct variant output, the borrowed mode-zero key formatter and collector allocation-size guards; they do not claim target equivalence. Direct and indirect call sites are separately recorded, while external helper behavior, data closure, relocation closure beyond the named descriptors and slot, vtables and whole-ELF equivalence remain open.

The tests include changed digest, instruction, call, dispatch, name, vector constant and relocation controls; unmapped and NOBITS addresses; all seven labels with single-byte name mutations; all integer width transitions; key length failures; and collector allocation boundaries. A model rejecting an out-of-range Python integer describes the model's admitted input, not how the machine code handles an impossible 64-bit argument.

## Results and limitations

For this bounded slice the extractor retains 16 FDE ranges, 133 fixed instruction windows, 30 direct-call sites, 6 tables containing 82 entries, 7 name descriptors and 1 formatter relocation. These counts are the selected analysis scope, not denominators for all node functions or all state fields. Fifteen focused unittest cases pass with no skips; the two differently seeded/time-zoned regeneration outputs agree byte for byte. No progress gate is requested.

The exact state-field name, complete JSON ownership, outer and inner ordering, duplicate behavior, other serializer modes, allocation failures, and full root construction remain unresolved. Next question: independently establish the ordering and error behavior of this field's outer and value collections without revisiting functions already covered by another packet.
