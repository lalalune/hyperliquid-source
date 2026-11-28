# RE-002: qualify node #115 standard-library socket setup and address iteration from Rust source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The pinned std rebuild checks the listener setup and LookupHost iterator bodies with their selected linked references. The check has no live network operations.

| Source selector | Target VA | Equal bytes | Total bytes |
| --- | --- | ---: | ---: |
| `11TcpListener4bind5inner` | `0x5ca47c0` | 340 | 376 |
| `10LookupHostNtNtNtNt` | `0x5ca9f00` | 279 | 311 |

Provision the offline cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the repository root:

```sh
python3 -B research/work-items/RE-002-node115-socket-setup-abi-source/verify.py /path/to/cache /path/to/binutils
```

The binutils directory supplies ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The offline harness rebuilds std and panic_unwind with explicit frame pointers and one codegen unit. Verification reads the capture and compiled objects as files. This packet leaves component gates and the byte-window registry unchanged.
