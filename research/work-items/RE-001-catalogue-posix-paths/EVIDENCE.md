# RE-001: use POSIX coordinates for reference paths in the catalogue

- Component: shared static catalogue tooling, no completion gate requested.
- Target: node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; #115 and visor remain separate metadata inputs.
- Base revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference revision: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Changed implementation: `tools/catalogue.py`; native filesystem paths now use
  `as_posix()` before matching the existing POSIX taxonomy and serializing paths.

## Reproduce

```sh
python -X utf8 -m unittest discover -s tests -p test_catalogue_portable_paths.py -v
python -X utf8 -m unittest discover -s tests -p test_research_tools.py -v
```

The regression copies the actual component/progress/literal metadata, three
release inventories and retained node #94 into an owned temporary view. It
reads exactly `base/duration.rs` from the pinned Git object. No inferred Rust
source is copied into project-authored implementation or committed fixtures.

Before the change, Windows-native `base\duration.rs` fails classification even
though the file matches the established `base/*` component. Afterward, the
generator returns `base/duration.rs`, foundation ownership and the expected
single-reference count in this explicitly reduced fixture. The binary binding
remains the node #94 digest; the reference bytes remain unchanged. The reduced
view is a portability control, not the full reference catalogue or a function
denominator. POSIX hosts retain the same path spelling.

## Results and limitations

New regression: before one failure, after one pass. Existing research-tool
tests: 13 pass. Full suite: base 281 and changed 282 attempted tests both report
7 failures, 32 errors and 9 skips on this Windows host; full suite is not green.
Doctor/verification/reproduction also retain missing native tools and incomplete
reference-checkout limitations. The actual catalogue check still reports stale
components because the complete reference cannot be checked out as ordinary
Windows filenames (`node/aux.rs`). No generated catalogue/progress file is
hand-edited or regenerated from that incomplete tree.

Python 3.12.14, Windows. No target execution, recovered Rust build, equivalence,
reviewed gate or increased coverage claim. Next step: reproduce the unchanged
full catalogue on a host supporting the pinned reference filenames.
