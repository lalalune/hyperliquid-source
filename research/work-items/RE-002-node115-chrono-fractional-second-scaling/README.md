# RE-002: Chrono fractional second scaling in node #115

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

Both complete ten-entry multiplier tables reproduce in the capture. Two independent instructions refer to the separate linked objects used by fractional second scanners. The nine positive scales agree with a decimal digit count to nanosecond conversion.

Place chrono-0.4.38.crate from static.crates.io in the offline cache. The verifier
checks the archive digests and reads the captured ELF as data. Run from the
repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-chrono-fractional-second-scaling/verify.py /path/to/cache
```
