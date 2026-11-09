# node115 governance enum codecs

This crate independently implements the node #115 governance vote and proposal
category unit-enum codecs from `research/work-items/action-wire-gov-vote-codec-115`.
The target is pinned to SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

It covers the total vote tag dispatch (0 = yes, 1 = no, all other byte values =
abstain), the four defined category tags, MessagePack fixstr output, and exact
name visitors using lossy UTF-8 conversion. Invalid category tags are left
undefined by the model because the target uses an unchecked jump table.

Run `cargo test --manifest-path src/node115-governance-codec/Cargo.toml` from
the repository root. Tests compare 2,188 saved serializer cases and all 58,536
visitor outputs against the committed evidence packet. The crate does not model
the enclosing `{choice, weight}` or proposal struct serializers, action handlers,
allocator internals, or signing behavior. No captured binary is executed.
