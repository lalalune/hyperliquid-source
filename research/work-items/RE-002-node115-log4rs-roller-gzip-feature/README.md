# RE-002: FixedWindowRoller gzip feature selection in node #115

Linux x86-64 node #115. SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 2da45cb0a761cff6b478e40421699857d87a94df.

The linked configuration builder references the pinned pattern-marker diagnostic and selects the no-gzip diagnostic for the gzip filename extension. The proof follows the materialized extension comparison to its concrete static diagnostic destination.

Place the release archive log4rs-1.3.0.crate in the local source cache. Run
from the repository root with Python 3.9 or later.

```sh
python3 -B research/work-items/RE-002-node115-log4rs-roller-gzip-feature/verify.py /path/to/cache
```
