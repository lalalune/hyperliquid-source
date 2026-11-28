# RE-002: compare node #115 RawVec error dispatch with rebuilt alloc

Target Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Public Rust 1.95.0 source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The source build produces the 21-byte RawVec handle_error and 29-byte capacity_overflow extents at ELF VAs 0x141e264 and 0x141e280. All 30 bytes outside the five source PC32/GOTPCREL fields match. In the target, the zero branch's GOT RELATIVE slot resolves directly to the second matched body. The other call slots resolve to concrete VAs and the selected 17-byte diagnostic data section from alloc matches exactly. The source-location record and bodies of the other call destinations remain unqualified. The log records all five fields and the failed instruction-byte control. This adds source-built linkage to earlier target references to capacity_overflow. It does not claim full behavior or a gate change.

Provision the pinned Rust cache as in RE-002-node115-umodti3-source-build. Run from the root with Python 3.12+, Rust and Cargo 1.95.0, and binutils exposing GNU ar, nm-new, objcopy and objdump:

```sh
python3 -B research/work-items/RE-002-node115-rawvec-error-source/verify.py /path/to/cache /path/to/binutils
```

The build uses the existing release harness with alloc added and explicit frame pointers. No target or rebuilt code is executed.
