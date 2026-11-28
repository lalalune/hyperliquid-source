# RE-002: reproduce the linked node #115 Rust exit chain

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The three rebuilt std bodies at ELF VAs 0x5c9b030, 0x5c9d030 and 0x5c9cfe0 match 75 of 111 bytes outside nine real relocation fields. The source process exit call links to the runtime cleanup and Unix exit wrappers. The Unix wrapper invokes the unique-thread helper and resolves its exit import to exit@GLIBC_2.2.5. In the unique-thread helper, the selected thread ID record and errno and pause imports resolve to concrete addresses. The panic-data and final panic-call referents remain unqualified.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-std-exit-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds std and panic_unwind with explicit frame pointers. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
