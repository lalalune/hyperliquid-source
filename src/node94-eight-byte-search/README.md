# node94 eight-byte search projection

Independent dependency-free `no_std` Rust for the complete node #94 leaf
at ELF VA `[0x52ca970,0x52ca9e3)`, target SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`raw_index(entries: &[u64], key: u64, limit: u64) -> u64` preserves the
leaf's exact decisions. Key>=limit returns the last index modulo 2^64;
an empty table therefore returns `u64::MAX` on that shortcut. Otherwise
the function returns the terminal midpoint-search index. A sorted table
gives its lower bound; unsorted tables retain the original probe behavior
and need not return the first matching entry.

The domain is an ordinary valid, stable contiguous qword slice with
nonwrapping byte span below 2^63, as valid slices have on the supported
32/64-bit hosts. Malformed raw pointer differences, concurrent/volatile
memory, the original descriptor ABI and the limit's meaning are outside
this API. No table validation or sorting is silently added, no memory is
modified, and no captured code runs.

Reproduce from the repository root with installed rustc 1.94.1,
Python 3.14.3, Capstone 5.0.7 and GNU objdump:

```sh
python3 -B -O research/work-items/RE-004-node94-eight-byte-search-rust/validate.py
```

The validator uses standalone rustc to build this library and its
input-only driver. It does not create a Cargo workspace or dependency
lock. See the [evidence packet](../../research/work-items/RE-004-node94-eight-byte-search-rust/README.md)
for the proof, pre-Rust frozen interval oracle, original body/FDE/caller
evidence, native controls and limitations. This is a bounded RE-004
contribution; no component progress gate is changed.
