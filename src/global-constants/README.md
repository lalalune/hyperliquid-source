# `global-constants` (Node #115)

Independently authored Rust reconstruction of the `global_constants` component
(`global_constants/src/aws_name.rs` and `global_constants/src/static_config.rs`)
targeted strictly at Linux x86-64 node #115
(`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

Joins the existing verified node #115 micro-crates `node115-chain-name-codec`
and `node115-spot-mark-codec` with the binary-backed `AwsName` (79 variants,
discriminants `0..=78`, `NvTestnet = 33`) and `StaticConfig` (`STATIC_CONFIG`
`LazyLock`, `/cham` vs `/hl` directory selection, `/code/static_config` JSON
parsing, `/aws_name` missing-field fallback, and `0x4671d0` table / bitmask
predicates).

See `research/work-items/RE-015-global-constants-crate-115/README.md`,
`research/work-items/constants-static-name-flow-115/README.md`, and
`research/work-items/RE-015-static-config-path-115/README.md` for target-bound
binary evidence and explicit non-claims.
