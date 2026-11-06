# Node115 logical header writer

This packet adds the complete ordered header-byte append operation to
[`node115-http-header-writer`](../../../src/node115-http-header-writer/), closing
the source gap left by the existing header-name lookup/reference packet. The
safe, dependency-free `no_std` API performs real tagged-name lookup over borrowed
logical groups, pairs successive spelling occurrences, falls back when spelling
occurrences are exhausted, and appends the selected names and values in order.
An empty value emits `name:\r\n`; a nonempty value emits `name: value\r\n`.
Optional ASCII title casing applies only to fallback names. Custom names and
values remain arbitrary bytes; this operation does not validate HTTP grammar.

The target is the complete `0x2e77070..0x2e7792e` writer in node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
[Native proof](HEADER-WRITER-PROOF.md), [scope and premises](SOURCE-SCOPE.md),
[host contract](design/HOST-CONTRACT.md), [finite chain relation](design/STRUCTURAL-CHAIN.md)
and the pre-execution [source argument](SOURCE-PROOF.md) separate the logical
operation from physical maps and external helpers. Native correspondence is a
manual conditional argument under those explicit invariants, not a captured
runtime comparison. Eager validation, error precedence and atomic refusal are
host policies. Hash/feed code, physical buckets, native constructors, allocator
failure, panic/unwind, ABI and network behavior are outside this implementation.

The existing `RE-012-node115-header-name-lookup` packet (commits
`3a46c477333f0f797216d6ca11016bc87e10d979` and
`e6409d494f294fff9659b80e70debbe9d3810814`) already supplied writer/table references;
`RE-003-pr-integration-20261103` already censused the writer. Active PR2943 owns
the byte-identical generic feed clone. These are credited context, not new byte
coverage or an unmerged dependency. No acceptance gate or compiled-byte claim is
changed by this packet. New source is MIT.

Actual qualification is recorded in [REPLAY.md](REPLAY.md) and
[validation/](validation/): both host profiles passed all 46 frozen literal tests
and exact 46-row probes. All 12 compiled variants exited normally with complete
output and differed at their predeclared witnesses (nine native-value faults,
three host-policy faults). The comparator accepted a valid changed value as one
mismatch and rejected ten malformed controls. Two same-basename Linux library
builds were byte-identical; neither was executed. Static controls passed 121/121
both normally and with Python `-O`, including 48 actual byte mutations; repeated
GNU exports matched all 16 native streams and semantic records.

The first generated-test compile failure and first unequal Linux archive result
are retained in [validation/PRESERVED-FAILURES.json](validation/PRESERVED-FAILURES.json).
The former was corrected solely by explicit `u8` literal suffixes; production and
frozen expected values did not change. The latter came solely from different
output basenames in the archive name table. Raw native exports are byte-exact;
receipt path projections and the two single-LF source normalizations are explicit
in [PATH-PROJECTIONS.json](PATH-PROJECTIONS.json). Finite tests and static replay
establish neither all-input equivalence nor whole-node behavior.
