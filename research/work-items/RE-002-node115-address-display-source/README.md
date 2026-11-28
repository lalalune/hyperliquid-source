# RE-002: qualify node #115 IP and socket address display from Rust source

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

Rebuilds IPv4 and both socket address display bodies and checks their selected linked references under one source profile.

| Source selector | Target VA | Equal bytes | Total bytes |
| --- | --- | ---: | ---: |
| `12SocketAddrV4NtNtB9_3fmt7Display3fmt` | `0x16884d0` | 218 | 282 |
| `8Ipv4AddrNtNtB9_3fmt7Display3fmt` | `0x16885f0` | 245 | 301 |
| `12SocketAddrV6NtNtB9_3fmt7Display3fmt` | `0x1688810` | 428 | 528 |

Provision the offline cache using RE-002-node115-umodti3-source-build. With Python 3.12+, Rust/Cargo 1.95.0 and GNU binutils 2.42 or equivalent, run from the repository root:

```sh
python3 -B research/work-items/RE-002-node115-address-display-source/verify.py /path/to/cache /path/to/binutils
```

The binutils directory supplies ar, nm-new (or a link to GNU nm), objdump, objcopy and readelf. The offline harness rebuilds core with explicit frame pointers and one codegen unit. Verification reads the capture and compiled objects as files. This packet leaves component gates and the byte-window registry unchanged.
