# RE-001: require file-backed sections for unwind-index evidence

- Component: shared static function-map tooling; no component completion claim.
- Target: Linux x86-64 node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Affected paths: `tools/elf_index.py`, `tests/test_unwind_file_backing.py`.
- Observation: the indexer reads file offsets for `.eh_frame_hdr` and admits
  `.eh_frame` pointers and executable ranges even when their section type is
  `SHT_NOBITS`. Such sections describe no file-backed contents.

## Reproduce

With Python 3.12 and the authenticated retained artifact available, run:

```sh
python -m unittest discover -s tests -p test_unwind_file_backing.py -v
python -m unittest discover -s tests -p test_research_tools.py -v
python -m unittest discover -s tests -p test_fde_extents.py -v
```

The new regression first verifies the full node #94 digest. Each corruption
changes only one section-header `sh_type` to `SHT_NOBITS` in an owned memory
copy: `.eh_frame_hdr`, `.eh_frame`, or `.text`. No original file is changed.
On the base all three invalid inputs are accepted; with the fix all three
raise `ValueError`. The authentic control retains 121,299 unwind entries.
The existing research-tool suite passes 13 tests and FDE suite passes 17.
`results.json` records the target identity and valid-row digest.

## Implementation and limitations

The indexer requires file-backed header/FDE evidence and excludes NOBITS
executable regions. This does not decode additional functions or establish a
complete function denominator. Unwind start entries and their next-start upper
bounds retain their documented limitations. No normalization mask, target
bytes, source/reference pin, or generated catalogue is changed.

Validation host: Windows, Python 3.12.14. `make` is unavailable, so the Python
commands from its targets were invoked directly. Doctor reports missing GPG,
git-lfs on PATH, LLVM/Java and Rust toolchains. Artifact byte hashes verify
before signature verification stops at missing GPG. Import verification stops
at the incomplete can1357 checkout (`node/aux.rs` is a Windows reserved name).
Catalogue consistency reports an existing stale generated components file;
`reproduce` stops at artifact verification. None is reported passing. Full
suite outcomes are reported separately in the PR.

All analysis is static. Captured binary executions: zero. No recovered Rust
component, native build, hosted CI result, full binary equivalence, or accepted
progress gate is claimed. Next question: establish real FDE/CFG extents under
the existing RE-001 acceptance criteria, independently of this admission fix.
