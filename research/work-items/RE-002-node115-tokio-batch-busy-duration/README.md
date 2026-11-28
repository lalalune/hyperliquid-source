# RE-002: Tokio scheduled-batch timing metrics in node #115

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df.

Compare the two catalogued scheduled-batch timing methods outside recorded relocation fields and verify their clock and timespec-subtraction references against pinned public Tokio source.

Place tokio-1.45.1.crate in the source cache and run from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-tokio-batch-busy-duration/verify.py /path/to/cache
```
