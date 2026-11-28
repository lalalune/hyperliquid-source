# RE-002: Rust socket address display in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare both catalogued SocketAddrV4 and SocketAddrV6 Display bodies outside recorded relocation fields. Check selected format helpers, a port read and the public source's IPv6 scope-ID branches.

Place rust-src-1.95.0.tar.xz in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-rust-socket-address-display/verify.py /path/to/cache
```
