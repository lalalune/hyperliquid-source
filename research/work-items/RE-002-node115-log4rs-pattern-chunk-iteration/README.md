# RE-002: PatternEncoder chunk iteration layout in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The pinned PatternEncoder iteration body agrees with the complete catalogued 109-byte object outside actual relocation fields. The verifier confirms the 88-byte chunk stride, the linked encoder call and the separate failure tail transfer.

Place log4rs-1.3.0.crate in the local source cache. Run from the repository root
with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-log4rs-pattern-chunk-iteration/verify.py /path/to/cache
```
