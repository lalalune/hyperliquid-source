# node94 pointer-mark walk

Independently authored, dependency-free `no_std` Rust state projection of the
complete 146-byte leaf `[0x50e69f0, 0x50e6a82)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This adds an implementation where the prior foundation packet provided only
static evidence and a Python decoded-rule model.

`mark` takes immutable `Link { id, next, node }` snapshots, mutable
`Stamp { id, value }` cells, eight inline head IDs, a tail of head IDs, a raw
`base_count`, and a once-loaded mark scalar. It follows each head's chain,
replacing sentinel `0x00ffffffffffffff` stamps until it reaches the head or a
non-sentinel stamp. Link IDs and payload-node IDs are distinct. Repeated stamp
IDs in links share one mutable cell, including across entries.

The entry count is `base_count + tail_heads.len()` modulo 2^64. Selection always
uses the eight inline heads first, then the tail; `base_count` need not be eight.
Unique nonzero map IDs are a new API premise. Missing cells are refused only
when reached. A nonterminating off-head cycle with an unchanged sentinel mark
is refused after a bounded prefix. `Refusal` variants are new API results, not
original target returns or faults. Earlier state writes survive an error.

The projection assumes valid forward array spans and immutable link, entry,
head and count cells disjoint from stamp cells. It does not model arbitrary
partial byte aliases, invalid native pointer dereferences, concurrent mutation,
original layouts, or RAX. The mark scalar has already been loaded, including
when the count is zero. See [PROOF.md](PROOF.md) for the domain and proof.

Build and validate with installed rustc 1.94.1:

```sh
python3 -O research/work-items/RE-004-node94-pointer-mark-walk-rust/validate.py \
  --output work/node94-pointer-mark-walk/recheck
```

The [RE-004 packet](../../research/work-items/RE-004-node94-pointer-mark-walk-rust/README.md)
contains the pre-Rust frozen oracle, native input-only driver evidence, static
closure, raw streams, counterexamples, and limitations. No root workspace,
external dependencies, captured execution, or completion gate is introduced.
