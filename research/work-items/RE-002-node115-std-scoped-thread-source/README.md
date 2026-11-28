# RE-002: bind the node #115 scoped thread decrement and diagnostic linkage from source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The 59-byte decrement and 37-byte overflow diagnostic bodies at ELF VAs 0x5c82d00 and 0x5c82d40 match all 76 bytes outside their five documented relocation fields. The build using the default frame setting reproduces the first extent, and the build forcing frames reproduces the second. The second body links directly to the first through a RELATIVE slot and also to the panic formatting helper. The first reaches syscall@GLIBC_2.2.5. The two diagnostic-data fields and full behavior are outside scope.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-std-scoped-thread-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds std and panic_unwind under the stated frame-pointer settings. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
