# RE-002: Rust demangle output budget in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the catalogued demangle Display and limited writer bodies outside recorded relocation fields. Verify initialization of the output budget and checked byte-length subtraction against pinned public source.

Place rustc-demangle-0.1.27.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-rust-demangle-output-budget/verify.py /path/to/cache
```
