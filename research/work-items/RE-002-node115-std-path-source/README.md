# RE-002: qualify node #115 path prefix helpers from Rust source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The Rust Path starts_with and strip_prefix helpers at ELF VAs 0x5c88fa0 and 0x5c89160 share a linked component iterator slot and the same direct comparison call. The strip helper alone uses the matched Components::as_path slot. The bodies match all 1,095 bytes outside their five actual source relocation fields. Verification follows the two RELATIVE slots and the direct target coordinates. Callee-body equivalence is not claimed.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-std-path-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds std and panic_unwind with explicit frame pointers. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
