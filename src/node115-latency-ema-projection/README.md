# Node #115 latency-EMA row projection

This dependency-free `no_std` crate models the normal-return behaviour of the
row closure `0x5a327a0..0x5a329d8` and its collector `0x5b80ea0..0x5b810ce`
in Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- `quotient` reads the two `f64` lanes of a found record. A zero denominator
  gives `+0.0` without the numerator. A negative or NaN denominator reaches the
  native assertion `assertion failed: self.denom > 0.` at
  `base/src/ema_tracker.rs:58:13`, returned here as an error. Otherwise the
  result is the IEEE-754 double quotient.
- `sanitize` keeps zero of either sign and positive finite values, and turns
  positive infinity, NaN and negative non-zero values into `+0.0`.
- `project_row` is one closure call: no record gives no row; a found record
  gives the caller's 20 key bytes and the sanitised quotient.
- `collect` takes keys in iterator order, skips absent keys and appends found
  rows in that order.

The crate owns no native layout. It does not model the two container forms,
the key iterator, allocation, the later ordering and duplicate-removal calls,
the built collection or its consumer. Unwinding is not modelled. The code was
written from the evidence packet
`research/work-items/RE-008-node115-latency-ema-projection/README.md`; no
reference source was consulted and no captured code is linked or executed.

## Reproduction

```sh
python3 -B research/work-items/RE-008-node115-latency-ema-projection/verify.py --self-test
cargo +1.95.0 test --offline --locked --manifest-path src/node115-latency-ema-projection/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-latency-ema-projection/Cargo.toml --all-targets -- -D warnings
```

The 11 tests use hand-derived expectations for each native branch. They check
this model. They are not a compiled-code or runtime comparison with the
captured node, and they advance no component gate.
