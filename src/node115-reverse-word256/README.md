# Node115 reverse-word256 leaf

Independently authored MIT `no_std` projection of the complete 98-byte leaf
`0x4332f70..0x4332fd2` from Linux x86-64 node #115. The digest-bound static
evidence and decoder are in
[`research/work-items/RE-001-node115-reverse-word256/README.md`](../../research/work-items/RE-001-node115-reverse-word256/README.md).

`append_reversed_word` models the observed 32-byte reversal, slot index update,
inclusive maximum index of 1023, and low-byte `0x2d` failure status including
the preserved upper RAX bits. It deliberately exposes no recovered source
name, ABI, state layout, codec, or protocol meaning. The modeled operation
assumes valid, non-overlapping memory; no captured instructions are executed.

Build and test offline with `cargo test --offline --locked` from this
directory. This standalone fragment is not integrated into a node workspace
and does not claim whole-component completion or byte equivalence.
