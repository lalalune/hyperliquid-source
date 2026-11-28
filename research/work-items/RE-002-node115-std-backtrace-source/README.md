# RE-002: qualify the node #115 std backtrace support references from source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The rebuilt 26-byte filename callback at ELF VA 0x5c817c0 and 99-byte lock helper at 0x5c9d130 match all 85 bytes outside the ten real relocation fields. The callback (default frame setting) links to output_filename. The lock helper (forced frames) references the same storage base and its adjacent field, plus the selected panic counter, contended lock and panic slow path destinations. These are separate functions within the same source subsystem. Verification checks their references without inferring a direct call between them or executing a backtrace.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-std-backtrace-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds std and panic_unwind under the stated frame-pointer settings. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
