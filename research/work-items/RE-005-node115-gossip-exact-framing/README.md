# RE-005: explicit request/response framing policy

This packet closes one narrow interface gap from issue #3907: the existing
Node115 request and composed response readers both decode a prefix and return
the unconsumed suffix, but callers that own a complete frame had no explicit
EOF policy. The change adds `decode_exact` to both APIs.

`decode_exact` reuses the existing reader and all three response selections;
it rejects only a successful decode with remaining bytes using
`Error::TrailingBytes { remaining }`. Reader failures, charge updates and
partial-cursor behavior are unchanged. `decode_prefix` remains the correct
API for a transport that carries a following message or trailer.

This is a logical framing contract, not a claim about the native async ABI,
network reachability or a recovered source-level message type. The request
consumer at `0x5a60a50` and the response parent at `0x5aac7c0` are retained
context from the earlier packets; this contribution does not assert they are
one dynamic call path.

## Reproduction

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-gossip-rpc-request/Cargo.toml --lib
cargo +1.95.0 test --offline --locked --manifest-path src/node115-gossip-response-composed/Cargo.toml
make doctor verify catalogue-check reproduce
```

The two new tests cover suffix rejection and preservation of the prior prefix
contract. No component gate or byte-coverage denominator is advanced.
