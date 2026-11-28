# RE-002: FileDesc read-to-end linked adapter in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The full registered FileDesc read-to-end object agrees outside source relocations. Both versioned libc imports independently resolve, and the selected ordinary interrupted-read branch returns to the same read call sequence.

Place rust-src-1.95.0.tar.xz in the local source cache. Run from the repository root with
Python 3.9 or later and GNU readelf.

```sh
python3 -B research/work-items/RE-002-node115-rust-filedesc-read-to-end/verify.py /path/to/cache /path/to/binutils
```
