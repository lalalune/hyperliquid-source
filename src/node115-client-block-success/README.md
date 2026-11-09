# Node115 ClientBlocks success payload

Task: issue #3907, RE-005 Serialization fork. This is a bounded child decoder,
not completion of the issue or component acceptance gates. Target:
`artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This crate decodes the structural success payload selected after the outer
GossipRpcResponse and nested Result success tags have already been consumed.
It returns one prefix and preserves any trailing bytes. The wire graph is
bound to #115 by the existing
[`RE-001-node115-client-block-success-grammar`](../../research/work-items/RE-001-node115-client-block-success-grammar/README.md)
packet and its SHA-256-pinned evidence.

The returned fields are positional wire values. In particular, QC's five
scalars and TC's scalar are not assigned semantic names; timestamps pass the
separately qualified #115 day-count constructor and admission predicate;
signatures are eight U64 varints plus one raw recovery byte; attachment
content stays opaque.
No cryptographic verification, voter-map normalization, allocation-failure
equivalence, native ABI, malformed-input cursor equivalence, response framing,
or source-to-node equivalence is claimed. The safe parser's raw-field
shortfall leaves that field unconsumed; reused integer readers retain their
separately documented cursor behavior.

Reads are unmetered because the existing caller's nested budget accounting
has not been closed across this full graph. This crate does not replace the
existing composed response decoder's explicit `ResultSuccessBoundary`. It is
an independently usable structural child decoder until that calling contract
is established. New code is MIT. Timestamp admission is grounded in
[`RE-001-node115-client-block-timestamp-admission`](../../research/work-items/RE-001-node115-client-block-timestamp-admission/README.md)
and composes the existing MIT `node115-daycount-date` implementation.
