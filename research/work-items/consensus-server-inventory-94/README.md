# consensus-server-inventory-94: Location-linked static slice

Component: consensus, bounded to the exact binary path suffix `node/src/consensus/server.rs` in node #94, `artifacts/node/94/hl-node`, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Base repository commit `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference submodule commit `999556f6e0a474b8312db96ec3149e1c44e97c23`. Task: RE-001, a bounded server Location and direct-call question; no progress gate requested.

Observations are digest-bound byte records. FDEs are unwind extents, not complete verified functions, unique source ownership or a function-coverage denominator. Source names and behavior remain unknown. Full record coordinates are ELF link-time VAs and explicit file offsets; ranges end exclusively. ASLR and runtime addresses are not inferred. The embedded compiler path is represented by exact bytes in JSON, not an analyst filesystem path.

## Reproduce

Run from the repository root using Python 3.10+ stdlib (analysis used Python 3.13.5, Linux x86-64):

```sh
python3 tools/consensus_server_inventory.py --out research/work-items/consensus-server-inventory-94/
python3 -m unittest tests.test_consensus_server_inventory -v
python3 research/work-items/consensus-server-inventory-94/verify.py
make verify test catalogue-check
make reproduce
```

The tool maps one authenticated target read-only, validates ELF sections, scans RELATIVE relocations and exact path/length Location records, scans executable bytes for candidate RIP LEAs, then linearly decodes each candidate owner from its FDE start to end and checks internal direct branches land at decoded boundaries. Unknown encodings fail closed. Scanning finds candidates, not accepted xrefs: acceptance requires a complete FDE decode and exact instruction bytes. It does not require objdump, REA, external tools, network or execution. The restricted x86 decoder derives from the MIT tool at `slack-alert-inventory-94` recorded in JSON; instruction boundaries are static linear decoding, not reachability or CFG proof. Relocation records, raw instruction transcripts, CIE/FDE and unwind entries, literal proofs and external transfer partitions are retained in JSON. Input and producer digests are in `inventory.json`; `MANIFEST.sha256` authenticates packet files. The unlicensed reference supplies search hints only; it is not implementation evidence or copied code.

## Measured inventory

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 3 |
| decoded_instructions | 15212 |
| diagnostics_absent | 0 |
| diagnostics_bound | 19 |
| diagnostics_probed | 26 |
| diagnostics_unresolved | 7 |
| indirect_calls_unresolved | 772 |
| indirect_jumps_unresolved | 41 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 518 |
| location_leas | 54 |
| locations | 35 |
| pointer_length_anchors | 22 |
| scoped_fde_bytes | 81294 |
| scoped_fdes | 21 |
| scoped_rel32_calls | 4 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 26 |
| unresolved_external_rel32_calls | 548 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

<!-- BEGIN GENERATED LOCATIONS -->
| Location VA | Line:column | LEA sites | Owning FDE starts |
| --- | --- | --- | --- |
| 0x5692de8 | 535:18 | 0x1fd7d33, 0x1fd7d40, 0x1fd861d, 0x1fd862a | 0x1fd7d00, 0x1fd85f0 |
| 0x5692e00 | 543:50 | 0x1fd86c1 | 0x1fd85f0 |
| 0x5692e18 | 220:48 | 0x203d68d | 0x203d330 |
| 0x5692e30 | 225:29 | 0x203df04, 0x203e0c5 | 0x203d330 |
| 0x569ec90 | 535:5 | 0x227c632, 0x227cd22 | 0x227c0c0, 0x227c870 |
| 0x569eca8 | 69:40 | 0x226df60 | 0x226c2d0 |
| 0x569ecc0 | 76:42 | 0x226e068 | 0x226c2d0 |
| 0x569ecd8 | 41:76 | 0x22703ac, 0x22703ca | 0x226c2d0 |
| 0x569ecf0 | 37:49 | 0x227036d, 0x227038e | 0x226c2d0 |
| 0x569ed08 | 201:45 | 0x226e415 | 0x226c2d0 |
| 0x569ed20 | 192:65 | 0x22703e8, 0x2270406 | 0x226c2d0 |
| 0x569ed38 | 220:48 | 0x22be8c8 | 0x22be860 |
| 0x569ed50 | 225:29 | 0x22bf12f, 0x22bf1e3 | 0x22be860 |
| 0x56be198 | 205:30 | 0x27d6f52 | 0x27d6c70 |
| 0x571d0a8 | 579:5 | 0x435e502 | 0x435e3d0 |
| 0x571d0c0 | 114:57 | 0x438cf51, 0x438cf5e | 0x438cb90 |
| 0x571d0d8 | 153:55 | 0x4391c43, 0x4391c50 | 0x4391840 |
| 0x571d0f0 | 178:58 | 0x439a23c, 0x439a249 | 0x4399e80 |
| 0x571d108 | 302:52 | 0x439699f | 0x43965b0 |
| 0x571d120 | 360:25 | 0x43986b4 | 0x43965b0 |
| 0x571d138 | 458:54 | 0x4399734, 0x4399741 | 0x4399360 |
| 0x571d150 | 463:36 | 0x4399a23 | 0x4399360 |
| 0x571d168 | 466:17 | 0x4399afc | 0x4399360 |
| 0x572efb0 | 114:57 | 0x47b19ec, 0x47b19fb | 0x47b1930 |
| 0x572efc8 | 153:55 | 0x47b7062, 0x47b7071 | 0x47b6f90 |
| 0x572efe0 | 178:58 | 0x47b138e, 0x47b139d | 0x47b12d0 |
| 0x572eff8 | 302:52 | 0x47b1f89 | 0x47b1ef0 |
| 0x572f010 | 306:38 | 0x47b1fc1 | 0x47b1ef0 |
| 0x572f028 | 308:67 | 0x47b1ff4 | 0x47b1ef0 |
| 0x572f040 | 360:25 | 0x47b3984 | 0x47b1ef0 |
| 0x572f058 | 458:54 | 0x47b76a1, 0x47b76b0 | 0x47b75e0 |
| 0x572f070 | 466:17 | 0x47b7a5f | 0x47b75e0 |
| 0x5738710 | 579:18 | 0x4b37c3c, 0x4b37c49 | 0x4b363b0 |
| 0x5738728 | 591:42 | 0x4b36d9f | 0x4b363b0 |
| 0x5738740 | 466:30 | 0x4b3985c, 0x4b39869 | 0x4b39010 |
<!-- END GENERATED LOCATIONS -->

<!-- BEGIN GENERATED FDES -->
| Start VA | End exclusive | Bytes | FDE record VA |
| --- | --- | --- | --- |
| 0x1fd7d00 | 0x1fd85e1 | 2273 | 0x106cc48 |
| 0x1fd85f0 | 0x1fd8998 | 936 | 0x106cc9c |
| 0x203d330 | 0x203e0f8 | 3528 | 0x1077344 |
| 0x226c2d0 | 0x22713e1 | 20753 | 0x109a920 |
| 0x227c0c0 | 0x227c868 | 1960 | 0x109b05c |
| 0x227c870 | 0x227cf46 | 1750 | 0x109b0b4 |
| 0x22be860 | 0x22bf216 | 2486 | 0x109dae0 |
| 0x27d6c70 | 0x27d6fd0 | 864 | 0x10fa670 |
| 0x435e3d0 | 0x435e67a | 682 | 0x1234bd0 |
| 0x438cb90 | 0x438d2a7 | 1815 | 0x1237aa0 |
| 0x4391840 | 0x4392387 | 2887 | 0x1237cf0 |
| 0x43965b0 | 0x43988c4 | 8980 | 0x12381dc |
| 0x4399360 | 0x4399e76 | 2838 | 0x12382b8 |
| 0x4399e80 | 0x439a8af | 2607 | 0x123830c |
| 0x47b12d0 | 0x47b192a | 1626 | 0x12915b8 |
| 0x47b1930 | 0x47b1c5e | 814 | 0x129160c |
| 0x47b1ef0 | 0x47b3b78 | 7304 | 0x12916a0 |
| 0x47b6f90 | 0x47b75d1 | 1601 | 0x12917d4 |
| 0x47b75e0 | 0x47b7cf1 | 1809 | 0x1291828 |
| 0x4b363b0 | 0x4b39004 | 11348 | 0x12c61a0 |
| 0x4b39010 | 0x4b39991 | 2433 | 0x12c61d4 |
<!-- END GENERATED FDES -->

The catalogue lists the same seed addresses for this reference path. All are FDE starts with a scoped Location LEA in this digest; their names, body boundaries outside FDE extent and labels are not thereby confirmed. The reference path file hash and seed checks are recorded in JSON. The reference literal probes are present as byte substrings but fail the stricter exact-start pointer/length binding; this does not prove the reference prose false or the text unused elsewhere.

Prior [RE-008](../RE-008-consensus-wire-state/README.md) covers wire/state, not this census. [RE-009](../RE-009-storage-state-roots/hashers.json) records hasher co-location for FDEs `0x4391840` and `0x47b6f90`; our instruction transcript overlaps those ranges, but does not independently resolve or name their indirect calls or duplicate the hashing claim.

## Gaps and next question

No implementation, Rust build, comparison, normalization masks, helper closure, vtable/data closure or full relocation comparison exists here. Location co-location permits inlining and shared code; it does not establish exclusive file ownership. Decode more indirect call slots and validate control flow around one specific diagnostic before inferring semantics. [RESULT.md](RESULT.md) separates bindings, rejected candidates, calls and non-claims.
