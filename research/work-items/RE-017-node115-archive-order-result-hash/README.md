# RE-017 compare ordinary #115 order results with an archived response Hash

The earlier archive comparator supports selected default, error and cancel outcomes. This fixture adds the five ordinary order statuses to that comparator. It uses named MessagePack maps in native field order. A filled status includes normalized `totalSz` and `avgPx` strings and the unsigned `oid`. A resting status includes the unsigned `oid`. Both include `cloid` only when present. A present identifier preserves all 16 bytes in lowercase prefixed hexadecimal. Waiting statuses are strings and the error status is a one-entry map. [Initial Hash comparator](https://github.com/lalalune/hyperliquid-source/pull/7461) · [Named nested order contract](https://github.com/lalalune/hyperliquid-source/pull/2910) · [Direct order status evidence](https://github.com/lalalune/hyperliquid-source/pull/2342)

The offline test matches a manually assembled 324-byte named preimage. It contains all five statuses, a filled order with a cloid and a resting order without one, unsigned order IDs 128 and 2⁶⁴−1, and a separate existing default result. The independently compiled Rust Keccak helper hashes the manual bytes, and that digest agrees with the comparator. Reordering waiting states or removing the present cloid changes the result. Numeric quantity input and observations at different heights are rejected.

The verifier rechecks the named writer mode, exact static function bodies, literal locations and the five displacement-table entries in the pinned #115 capture with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Its input quantities are already normalized ordinary nonnegative fixed-point text. The initial renderer, provenance of the Full observation, any order execution, and production root verification remain outside the fixture. This archive response fingerprint describes outcomes at one height.

## Reproduce

Use Python 3.9 or newer with msgpack 1.1.2 and Rust 1.95. From the repository root set `packet` to this directory. Make the exact #7461 commit referenced in `verify.py` available locally.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --archive H-PLUS-ONE.jsonl --full LOCAL-FULL.json
```

Both source objects provide `height` and `resps`. Supply the archived `Hash` and independently acquired ordered `Full` observations for the same Block. A hash mismatch returns status 1. [Raw offline output](offline-log.txt)
