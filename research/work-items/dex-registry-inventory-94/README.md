# dex-registry-inventory-94: registry identifiers and Location census

- Component ID: `dex-registry` (`l1/dex_registry/*`); bounded packet, not a TASKS.md RE-00N task.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (identity from `provenance/artifacts.json`).
- Source commit: unavailable in this checkout (no `.git`). Reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` is recorded in `provenance/sources.json`, not independently checked here. The inspected unlicensed lead `references/can1357-hl/l1/dex_registry/dex_registry.rs` has SHA-256 `68b77f538f7fd6bc623324a43b131f81f479755179636e8c26d90a5cf6ef35fd`. Its names and constants are hypotheses; no Rust was copied.
- Claim status: static observations and explicitly marked inferences below; unresolved items remain open.
- Scope: reserved-name leads, numeric leads, enum-name leads, and first-party Location records for the three registry files. No codec proof, runtime behavior, #115, visor, reconstruction, full registry mapping, or gate.

Packet authored against hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985`.

## Reproduce

Working directory: repository root; Linux x86-64, Python 3.13.5 and GNU objdump 2.44. Python tooling uses only the standard library and the repository's `tools/info_request_path.py` ELF primitives (SHA-256 `ffe4f98ba84648f6ffa1fdaca288799cc62d51fa7d089c82fb28cba77c1d88d1`). Generator SHA-256 `c8ed3b5d35422c8327038cda67da9f1f70f68df9e1bb7a4e4e2ab2e31ad0f58a`. Binary and lead digests are checked before any output is written. No target executable, networking, or provider project is used.

```sh
python3 tools/dex_registry_inventory.py --out research/work-items/dex-registry-inventory-94/
python3 -m unittest tests.test_dex_registry_inventory -v
python3 research/work-items/dex-registry-inventory-94/verify.py
objdump -d --start-address=0x3330f30 --stop-address=0x3330f90 artifacts/node/94/hl-node
objdump -d --start-address=0x333140b --stop-address=0x33315cd artifacts/node/94/hl-node
objdump -d --start-address=0x2744b21 --stop-address=0x2744b49 artifacts/node/94/hl-node
objdump -s -j .rodata --start-address=0x58b7d3 --stop-address=0x58b7fe artifacts/node/94/hl-node
```

`inventory.json` SHA-256 `993e0854bf3b56d2b48c105c1557d001e61400f91ef8178cf3738c258c6e62b0`; `MANIFEST.sha256` pins the packet files. The excerpts preserve the objdump output in the command order above; objdump symbols near the sites are dynamic-symbol nearest-label artifacts, not names for these FDEs. `verify.py` checks the fixed manifest and regenerates exact JSON; tests check corruption and sample disassembly. No normalization is applied.

## Evidence

Addresses are linked ELF virtual addresses (PIE, no runtime rebasing); JSON also supplies file offsets for data anchors and Locations. Ends are exclusive, decoded from the actual FDE records referenced by `.eh_frame_hdr`, not the next unwind start. A pattern site is not by itself proof of an instruction boundary or of source-level ownership. The scanner finds `.rela.dyn` RELATIVE path pointers in `.data.rel.ro` with plausible `(length, line, column)` and the first-party source prefix. Scope is limited to this representation and RIP LEA forms `48/4c 8d` with RIP-relative ModRM in `.text`. Unreferenced or differently encoded records and xrefs are not covered; byte-pattern matches may be embedded in other instructions. Thus the listed FDEs are candidate owners of those Location references and may include inlining and false positives. They are not a census of all registry functions.

Five Location records survive this scan: `l1/src/dex_registry/clearinghouses.rs` **2** (lines 11 and 17), `dex_registry.rs` **1** (line 35), `perp_dex.rs` **2** (lines 25 and 30). JSON lists each record, relocation/path address and raw bytes, each candidate LEA, and the FDE bounds. There are 280, 19 and 91 file/FDE pairs respectively (390 summed; FDEs can occur under more than one file). These counts are scan results, not function coverage. The original catalogue and imported #94 inventory list the same three paths without the `l1/src/` prefix; `research/catalogue/seed-candidates.json` contains no registry match.

Fourteen reference reserved names (`nyse`, `cme`, `hl`, `hyp`, `hkex`, `lse`, `krx`, `sgx`, `cboe`, `ice`, `usd`, `eth`, `btc`, `sol`) each have an exact pointer and explicit length at consecutive comparisons in FDE `0x3330f30..0x3331d56`. For example `0x333140f` loads `0x20a0ec` (`nyse`) and `0x3331416` sets length 4; the sequence calls the same helper and branches on its return. All 14 LEAs and lengths are shown in the excerpt and checked by byte validation; tests independently disassemble all 14 LEAs. The JSON records all LEA-pattern sites targeting each selected anchor, their bytes and FDE bounds. Other arbitrary occurrences of short substrings are not classified as separate reserved strings, and helper semantics are not established. The shared result branch leads toward bytes `cannot use canonical name` at `0x58b7d3`; the reserved-name interpretation is an inference supported by this context and the lead, not by a recovered symbol.

At `0x3330f4f`, `cmpq $0x7cf,0x10(%r11)` and `jbe` distinguish unsigned values above 1,999; fallthrough loads the bytes `too many perp DEXs` from `0x58b7ec` (16 bytes via `movdqu`, final two via immediate). The same FDE contains the name comparisons. This supports an inferred 2,000 threshold for the compared field, but does not prove its original identifier or exact source-level collection/type. At `0x2744b2f`, an objdump-checked `cmpq $0x2710,0x10(%rsi)` is in FDE `0x27448f0..0x27450d0`, also containing the `perp_dex.rs` Location candidate `0x274501c`. The field and the relation to the reference `ASSETS_PER_DEX` are not uniquely established; it is a candidate, not a bound registry constant. No asset-ID encode/decode claim is made. The reference's `MAX_FULL_NAME_BYTES = 50` and `SUCCESS_RESULT_TAG = 390` are inventoried leads only.

The JSON inventories all 4 `DexStatus` and 18 `RegistryError` variant names in the specified lead and reports exact byte-substring occurrences in `.rodata`, with context and counts. `Live`, `Locked`, `Delisted`, `Deleted`, and `LengthMismatch` occur as substrings, but contexts include unrelated words, fields, or diagnostic text. No listed occurrence is attributed to those reference enum types; no numeric discriminant values are established. A zero count means no occurrence in `.rodata`, not proof of binary-wide absence. This scan neither assigns enum names to bytes nor assumes reference enum order. No call edge among the Location owner FDEs is claimed; the optional edge was not investigated.

## Implementation and comparison

Not implemented or measured: independent Rust, Cargo lock and compiler/linker flags; two-build reproducibility; raw or normalized body comparisons, masks, helper/call-target/data/relocation/vtable closure and whole-ELF comparison. No behavior fixture or boundary runtime test exists. Static controls cover pinned data, names, FDE end exclusivity, binary and reference corruption, regenerated bytes, and objdump instruction sites. No external target was executed.

## Results and limitations

The deterministic scan and samples are bounded to one authenticated ELF and the enumerated reference file. Neither FDE nor string counts provide a matched-window denominator, behavior proof, or reconstruction identity. No component gate is requested or changed. Next: establish the type and data flow of the memory operand at `0x2744b2f` with a digest-bound CFG/data analysis, including the origin of the compared field, before identifying it as `ASSETS_PER_DEX`.
