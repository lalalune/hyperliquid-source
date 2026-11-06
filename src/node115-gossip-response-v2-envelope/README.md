# Node #115 selected GossipRpcResponse variant2 envelope

Buildable no_std composition of the captured response tag, outer optional marker
and unchanged existing scalar-record decoder. Returns logical result, remaining
slice and charged counter on all exits; it performs no network or chain work.

`Selection::Variant2(Option<Record>)` is the completed selected branch.
`Selection::OtherVariant(0|1)` is an explicit unimplemented **selection boundary**
after tag consumption, not a decoded native response for those other branches.
Invalid variant indices and malformed tag/outer/record inputs retain the observed
cursor/charge progression. No EOF requirement or field units are invented.

The scalar Record and Reader are the actual pinned MIT research packages already
in main. Cargo.toml/Cargo.lock declare the real local dependency rather than a
recovered original node workspace. The copied logical u32 read_tag function is
credited to src/node115-gossip-rpc-request/lib.rs at base05bc2de303c05525b71e7e257426e741bc66a390;
no scalar/varint primitive reconstruction credit is claimed again.

Target SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Evidence: research/work-items/RE-005-gossip-response-v2-envelope-115/.

```
cargo +1.95.0 build --offline --locked --manifest-path src/node115-gossip-response-v2-envelope/Cargo.toml
python3 -B research/work-items/RE-005-gossip-response-v2-envelope-115/qualify.py work/v2-fresh
```

Only our newly compiled source executes. The captured node is never executed or
emulated. Original Result/enum niche layout, inactive/padding values, field units,
other response variants and integrated protocol compatibility remain unclosed.
