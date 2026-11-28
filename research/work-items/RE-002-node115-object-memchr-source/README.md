# RE-002: bind node #115 object delimiter reads to the rebuilt memchr backend

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The object slice delimiter helper and memchr detector use the same GOT slot. The slot points to the dispatch cell whose initial RELATIVE entry names the detector. The detector references the matched SSE2 body directly. The 431-byte SSE2 body matches in full with no relocation. The two callers match outside three real source fields. This qualifies a linked dependency handoff without asserting which backend a running CPU chooses.

Provision the cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the root:

```sh
python3 -B research/work-items/RE-002-node115-object-memchr-source/verify.py /path/to/cache /path/to/binutils
```

The supplied binutils directory must provide ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The pinned offline harness rebuilds std and panic_unwind under the frame-pointer settings in the verifier. The retained log records the comparison and changed-byte control. The captured code and rebuilt wrappers are never executed. No component gate or byte-window registry changes.
