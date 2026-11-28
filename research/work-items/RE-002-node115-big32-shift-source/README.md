# RE-002: qualify node #115 Big32x40 shift linkage from Rust source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The source-built Big32x40::mul_pow2 at ELF VA 0x167de30 matches all 470 bytes outside its eight real relocation fields. The normal bulk-fill edge identifies memset@GLIBC_2.2.5. The diagnostic literal is byte-equal over its 29-byte source extent. The diagnostic calls, location addresses and shared bounds destination are independently resolved. This is distinct from DecimalSeq decimal-digit shifts. Location record contents and callee-body equivalence remain outside scope.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-big32-shift-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds core and compiler_builtins with explicit frame pointers. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
