# RE-002: bind the node #115 argv constructor from rebuilt std

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The rebuilt 18-byte initializer at ELF VA 0x5ca55c0 matches the capture outside its two real PC32 fields. These fields resolve to the linked ARGC and ARGV cells at 0x6500000 and 0x6500008. The source object registers the wrapper with R_X86_64_64 in .init_array.00099. The target init_array[0] at 0x63f36c8 has a RELATIVE entry naming that exact wrapper. Earlier target-only work identified the slots. This establishes the matching registration and stores in a fresh source build under the default frame setting.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-std-argv-init-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds std and panic_unwind under the stated frame-pointer settings. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
