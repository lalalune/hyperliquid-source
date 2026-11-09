# Node #115 action enum name matchers

Implements three exact byte-name-to-tag mappings documented in
`research/work-items/RE-010-enum-variant-matchers-115`. The packet binds these
visitor bodies to node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The mappings cover the 17 wire names of the perp action enum (including the
`setFeeScale` alias of tag 9), 114 short codes, and 18 short tags. Enum type
names and the serialized spelling of the alias remain unresolved. The model
returns only the matched tag; serde error construction and UTF-8 ownership are
outside its scope.

Tests compare all 4,271 saved cases and all 149 ordered name-pool entries,
including their observed tag words. They read committed packet TSVs and do not
run or emulate the captured binary. Run with `cargo test --manifest-path
src/node115-action-enum-variant-matchers/Cargo.toml`.
