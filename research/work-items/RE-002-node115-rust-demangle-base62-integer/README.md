# RE-002: v0 demangler base-62 integer in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The full catalogued demangler integer extent matches the licensed reference outside its source relocation fields. The radix and separator bytes are checked separately against the source expressions.

Place rustc-demangle-0.1.27.crate in the local source cache. Run from the repository root with
Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-rust-demangle-base62-integer/verify.py /path/to/cache
```
