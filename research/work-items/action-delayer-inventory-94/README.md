# action-delayer-inventory-94: Location-owned static census

- Component/task: `action-wire`, bounded component-map packet for `l1/action_delayer.rs`; not RE-011, dex-registry or rmp_signable.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (identity from `provenance/artifacts.json`). Node #115 and visor are separate artifacts.
- Reference: `references/can1357-hl/l1/action_delayer.rs`, SHA-256 `14e101da8d88626869f118a01d359689fef804e5083a0c033c275f834c1d1474`. `provenance/sources.json` records revision `999556f6e0a474b8312db96ec3149e1c44e97c23`; this checkout has no Git metadata to verify that revision. The unlicensed inferred tree supplies leads only; it is not implementation or authoritative source. Project source revision is unavailable in this checkout.
- Claim: observed bytes and scoped attribution; names and semantic interpretation are inferred. See [RESULT.md](RESULT.md) for findings, unresolved questions and command outcomes.

## Reproduce

From the repository root, with the pinned target and repository tools present:

```sh
python3 tools/action_delayer_inventory.py --out research/work-items/action-delayer-inventory-94/
python3 -m unittest tests.test_action_delayer_inventory -v
python3 research/work-items/action-delayer-inventory-94/verify.py
```

Python 3.13.5, Linux 6.12.94+ x86-64; stdlib only. The generator imports `tools/info_request_path.py` (SHA-256 `ffe4f98ba84648f6ffa1fdaca288799cc62d51fa7d089c82fb28cba77c1d88d1`) for ELF/FDE/Location and candidate RIP-LEA scanning. `objdump` GNU binutils 2.44 was used separately to inspect the scoped FDE and helper instruction boundaries, via `objdump -d --start-address=0x392fcc0 --stop-address=0x393033a artifacts/node/94/hl-node` and the range `0x392fab0..0x392fcba`. The Location and helper relocation slots were cross-checked with `readelf -rW artifacts/node/94/hl-node` (GNU binutils 2.44). The generator and verifier require neither objdump nor readelf. No captured binary is executed; these commands read the ELF. Generation fails before output on target digest mismatch and reproduces JSON and raw excerpts byte for byte.

`inventory.json` (SHA-256 `77e836a31b59af297c629f6f5cf7a3edd1d7c60d50e588c74b4b5be0fee4b2a2`) contains the census, file offsets, VA addresses, comparison bytes, string anchor and explicit unresolved statuses. `excerpts.txt` (SHA-256 `2620507fe60f2ebe164050eb4ddecb9cac6611ec3a591e6e31155cfc21830f4f`) retains raw byte ranges, including the helper lead. The exact packet file set, including this README and RESULT.md, is checked by `MANIFEST.sha256` and `verify.py`. The manifest is an integrity check, not a signature.

## Method and limitations

The census walks `.rela.dyn` RELATIVE relocations into `.data.rel.ro`, selects plausible Rust Location-shaped records with first-party `.rodata` paths beginning `l1/src/action_delayer.rs`, and scans `.text` for RIP-relative LEA byte patterns. Each candidate is attributed by decoded `.eh_frame_hdr` FDE ranges. Scoped LEAs and comparison instructions were independently checked with objdump. The scan is complete for this specified relocation/LEA pattern, not for every possible Location encoding, instruction form, or function in the component; byte patterns alone can identify non-instruction bytes. FDE bounds are unwind ranges, not automatically original function boundaries or a matched-window denominator. Address ranges use ELF virtual addresses and exclusive ends; selected file offsets and raw bytes are in the output. PIE rebasing is not assumed.

No normalization masks or binary comparisons were used. There is no reconstructed Rust, build, behavioral test, raw-equal or normalized body count, helper/call-target closure, relocation/vtable/data closure, or whole-ELF comparison. No component gate is requested. Further work should independently establish ownership and data flow in the called helper before binding its range tests to inferred names.
