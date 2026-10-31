# RE-005: Require unique relative offsets in the varint evidence map

- Component ID: serialization tooling; no component acceptance gate requested.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit: upstream `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference revision `999556f6e0a474b8312db96ec3149e1c44e97c23` remains pinned and unchanged.
- Claim status: observed representation defect in a static analysis helper, not a claim that repeated ELF relocations are generally invalid.

## Reproduce and evidence

`relative_relocs` creates one signed addend per type 8 offset for both encode and decode scans. The prior assignment silently overwrote an earlier type 8 record at the same offset. ELF relocation composition can be meaningful, but this single-value evidence map cannot represent its order or combined effect. Three duplicate controls fail against the unmodified helper: equal addends, conflicting addends, and duplicates separated by other records.

The changed helper raises `EvidenceError` for a repeated type 8 offset. Other relocation types remain ignored. Synthetic records cover negative and boundary signed addends, unique offsets, an empty section, and non-relative records at the same offset. No `.rela.dyn` truncation handling or PR #412 test was changed.

From this worktree with Python 3.12.14:

```sh
python3 -m unittest -v tests/test_bincode_varint_relocations.py
python3 -I -B research/work-items/RE-005-bincode-varint/verify.py
python3 -I -B -O research/work-items/RE-005-bincode-varint/verify.py
python3 tools/verify_imports.py
make doctor
make test
make catalogue-check
make verify
make reproduce
```

All 6 synthetic tests and the full 437-test `make test` suite pass. Both retained encode and decode JSON records recompute byte-for-byte under normal and optimized Python: SHA-256 `7e7a06b035c5b223cfa4573b9f315e344db2207c88c967e8079b88a0093a7657` and `6da03736b718d6c7db769a0a1be7e9131a6229cea6b198dd85d535282be5a56f`. Import verification, `make doctor`, catalogue check, `make verify` and `make reproduce` pass. The pinned can1357 node #94 LFS fetch was refused for lack of GitHub LFS credentials. Its pointer declared the same size and SHA-256 as the already authenticated local node #94 bytes, so those bytes were materialized locally. The submodule remains at its pinned commit with a clean index. No remote fetch was retried, and no captured binary was executed.

## Limits and next question

This change protects a static evidence representation. It does not implement ELF loader semantics, add a Rust codec, validate every relocation kind, or claim new target behavior. Existing packet addresses and function boundaries remain as recorded in `../RE-005-bincode-varint/`; no progress gate changes.

Next, review the bounded change before submission.
