# RE-002: bind node #115 Grisu cached powers to rebuilt Rust source

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 source commit 59807616e1fa2540724bfbac14d7976d7e4a3860, rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

Two source GOTPCREL fields in the Grisu exact and shortest conversion bodies identify the same cached-power table. Their linked fields independently resolve to GOT VA 0x64e1f48. Its unique R_X86_64_RELATIVE record names .rodata VA 0x478770. All 1,296 bytes at that address equal the complete data symbol from the freshly built core archive. A one-byte table mutation fails comparison. The log retains both field coordinates and the matched data hash.

The published artifact census qualifies body windows. This result independently identifies and compares their shared data referent from release source. It does not claim full algorithm equivalence, runtime execution or a component gate.

Provision the Rust release cache as in RE-002-node115-umodti3-source-build. With Python 3.12+, Rust and Cargo 1.95.0, and a binutils directory containing GNU ar, nm-new, objdump and objcopy, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-grisu-cached-powers/verify.py /path/to/cache /path/to/binutils
```

The offline build uses the pinned harness plus explicit frame pointers. GNU objdump 2.42 supplied the source relocation records.
