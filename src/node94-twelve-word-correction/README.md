# Node94 twelve-word correction family

Independent `no_std` Rust image reconstruction of three complete helpers:
addition `0x5657ce0..0x5657dec`, saved-register subtraction
`0x5657e00..0x5657f02`, and raw-register subtraction
`0x5657f20..0x5657ff1` (735 bytes total).

`apply` handles arbitrary twelve-word inputs and partial data aliases. It
preserves the unusual addition low-store order, the live high-B and correction
reads, the one-step upper-six-word correction, and thirteen full register
observations. The saved and raw variants differ in six returned register values.
It makes no claim that the result is a canonical modular reduction.

Supply one stable nonwrapping byte image, A/B/D 96-byte spans, an M 48-byte span,
and incoming RBX/RBP/R12/R13/R14/R15. Original stack/control memory must be valid
and disjoint from the image. `None` is a new atomic bounds refusal; original
faults, stack bytes, flags and native ABI are excluded. RDI/RCX remain input
addresses. The input-only driver is a synthetic record protocol, not that ABI.

The [proof](../../research/work-items/RE-004-node94-twelve-word-correction-rust/PROOF.md)
defines the full domain, byte ordering and final-register relation.
The [packet](../../research/work-items/RE-004-node94-twelve-word-correction-rust/README.md)
contains independently frozen expectations, four native builds and actual
mutation/static controls. No captured target code is executed.

Run qualification from the repository root:

```sh
python3 -O research/work-items/RE-004-node94-twelve-word-correction-rust/validate.py --output work/node94-twelve-word-correction/recheck
python3 -O research/work-items/RE-004-node94-twelve-word-correction-rust/verify_recorded.py
```

The validator pins installed rustc 1.94.1, compiles the library directly without
Cargo dependencies at opt0/opt3 twice, and uses binary input-only records. This
is one bounded component, not a root Cargo workspace or a build of the node.
