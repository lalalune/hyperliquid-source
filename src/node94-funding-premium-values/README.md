# Supplied-book impact and premium values

This standalone dependency-free MIT component implements the bounded value
relation in `research/work-items/RE-007-impact-notional-walk-94/pre-rust` for
authenticated node94. `evaluate(Input)` takes two ordered entry slices over
one common slab, raw oracle/selected target, scale, mode and selected membership.
It returns absence or an active premium tuple and its selected producer record.
Absence preserves the raw oracle word in that record. Native inactive words
are not invented. Entries are never sorted and no allocation is needed.

Scale admission precedes zero-oracle bypass. On nonzero oracle, zero target
and reached cycles produce explicitly new safe refusals outside the native
ordinary theorem. Both ordinary impacts are calculated before zero testing.
The real source uses u128 products, exact integer alignment and nearest-even
significand rounding, including division by a positive fractional binary64
oracle. It performs no host floating arithmetic, unsafe code, I/O, callbacks,
transaction, hash lookup or captured execution.

Correspondence remains conditional on the packet's stable truthful native
views, selected lookup results, normal helper/frame/copy/allocation contracts
and ISA premises. This new safe API does not recover source types/layout, ABI,
economic units, live policy, scheduler completeness or all-asset settlement.
The packet's `source-validation/SOURCE-PROOF.md` proves the authored integer
width and rounding relations separately from the immutable pre-code oracle.

Source authoring is authorized; compilation needs a separate exact source/build
gate. Actual outcomes belong to later receipts. This draft alone does not
claim a successful build or a compiled-mutant result.
