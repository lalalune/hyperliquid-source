# RE-002: qualify node #115 core diagnostic failure helpers from Rust source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The source rebuild verifies the selected four core diagnostic bodies and their exact linked destinations. Earlier callers only identify the targets.

| Source selector | Target VA | Equal bytes | Total bytes |
| --- | --- | ---: | ---: |
| `6option13expect_failed` | `0x1680bd0` | 40 | 52 |
| `6result13unwrap_failed` | `0x1680c30` | 66 | 82 |
| `9panicking18panic_bounds_check` | `0x1680cbf` | 49 | 61 |
| `20copy_from_slice_impl17len_mismatch_fail` | `0x16862c0` | 52 | 64 |

Provision the offline cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the repository root:

```sh
python3 -B research/work-items/RE-002-node115-core-diagnostics-source/verify.py /path/to/cache /path/to/binutils
```

The binutils directory supplies ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The offline harness rebuilds core with explicit frame pointers and one codegen unit. Verification reads the capture and compiled objects as files. This packet leaves component gates and the byte-window registry unchanged.
