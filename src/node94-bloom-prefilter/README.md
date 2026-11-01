# Node #94 bloom prefilter

Independently authored, dependency-free `no_std` Rust for the positive mask
predicate recovered in [the evidence packet](../../research/work-items/RE-001-evm-bloom-prefilter-94/README.md).
It accepts a 256-byte bloom, a flat list of alternatives, and a list of groups
of alternatives. Empty lists are unrestricted. Every nonempty list must have
at least one mask whose bits are all present in the bloom.

The slice API is newly chosen; it does not reproduce an original type, layout
or ABI. This is a necessary prefilter on a selected path, not an exact log
matcher or an implementation of `eth_getLogs`. Mask hashing/construction, JSON
parsing, block selection and the downstream exact matcher remain unproved.
No inferred reference implementation was copied.

The actual build scope is this single safe Rust module with the repository's
`rustc 1.94.1`, edition 2021. It needs no external crates, Cargo manifest,
lockfile, build script or root workspace. From the repository root:

```sh
mkdir -p work/bloom-prefilter
rustc --edition=2021 --crate-name node94_bloom_prefilter --crate-type=rlib \
  -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-bloom-prefilter/lib.rs -o work/bloom-prefilter/libbloom.rlib
rustc --edition=2021 --test -D warnings -C overflow-checks=on \
  src/node94-bloom-prefilter/lib.rs -o work/bloom-prefilter/tests
work/bloom-prefilter/tests
python3 research/work-items/RE-001-evm-bloom-prefilter-94/verify.py --controls
```

The tests cover empty lists, OR within lists, AND between groups, positive
group matching, zero masks and every one of the 2,048 bloom bit positions.
These check the recovered predicate. They are not comparisons with execution
of the captured binary or proof of original compiled-code equivalence.
