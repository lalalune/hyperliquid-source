# Node94 packed IPv4 translation

This dependency-free `no_std` module independently implements the returned-word
projection of node #94 helper `0x45c3ae0` with its observed eight-row table from
`0x45be020`. The [evidence packet](../../research/work-items/RE-001-node94-ip-translation/README.md)
binds both bodies, the initializer relocation and the two direct call sites to
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`translate_packed(word, mode)` takes a newly chosen numeric API: little-endian
byte 0 is the observed tag and bytes 1 through 4 are address octets in written
order. It returns the low five bytes unchanged for an odd tag, an already
preferred address class, or an unsuccessful lookup. Mode 0 selects private to
public; a nonzero mode selects public to private. A match clears the tag.

The implementation intentionally covers the table-ready value computation.
It does not replace the original ABI, Once state machine, allocation, panic
behavior, concurrent initialization or caller collection. No original-machine
code is embedded or executed. The constants are historical input data from the
captured initializer; no current endpoint or network behavior is asserted.

Build from the repository root with pinned Rust 1.94.1; no Cargo dependencies
or root workspace are needed:

```sh
mkdir -p work/node94-ip-translation/a work/node94-ip-translation/b
rustc +1.94.1 --edition=2021 --test -C opt-level=0 \
  src/node94-ip-translation/lib.rs -o work/node94-ip-translation/test-o0
work/node94-ip-translation/test-o0
rustc +1.94.1 --edition=2021 --test -C opt-level=3 \
  src/node94-ip-translation/lib.rs -o work/node94-ip-translation/test-o3
work/node94-ip-translation/test-o3
rustc +1.94.1 --edition=2021 --crate-name node94_ip_translation --crate-type=rlib \
  -C opt-level=3 src/node94-ip-translation/lib.rs \
  -o work/node94-ip-translation/a/libnode94_ip_translation.rlib
rustc +1.94.1 --edition=2021 --crate-name node94_ip_translation --crate-type=rlib \
  -C opt-level=3 src/node94-ip-translation/lib.rs \
  -o work/node94-ip-translation/b/libnode94_ip_translation.rlib
cmp work/node94-ip-translation/{a,b}/libnode94_ip_translation.rlib
rustfmt +1.94.1 --check src/node94-ip-translation/lib.rs
```

The tests check target-derived boundaries, every first/second octet pair, every
tag and mode byte, each initialized table row and synthetic duplicate-key rows.
Synthetic rows demonstrate the observed loop's first-match rule; the captured
table has no duplicate keys. These are tests of the reconstruction against
statically recovered expectations, not execution-based comparison with the
captured program. Two identical local builds demonstrate self-build
reproducibility only; no rebuilt-byte match with the original is claimed.
