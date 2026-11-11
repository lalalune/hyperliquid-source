# Fee-history reward-row constructor overlap assessment

The proposed node #115 question is the composed successful construction of reward inputs: the caller supplies a base-fee option and the shorter of two row counts; `0x2355610` consumes the 0x150-byte and 0x28-byte row streams, forms a tag-selected u128 fee less the optional u64 base with floor at zero and, for raw prefix values at least two, a further u128 priority cap. It pairs this value with the checked difference between successive receipt cumulative qwords and emits 0x20-byte rows. The exact input ABI, enum variant names and units, allocation effects, wider fee-history result and runtime reachability remain outside scope. This formulation is conditional on completing the native validation.

The nearest prior work is distinct but must be credited:

- #2129 traces the #115 fee-history future, its storage/range path and percentile selection *after* helper-built rows. It explicitly leaves both input-vector constructors unresolved.
- #355 studies #94 percentile request comparisons, not reward-row construction. #3205 studies the #115 short ordering path for constructed 32-byte rows, not their production.
- #1745 studies a #94 receipt-builder cumulative-gas subtraction and its underflow, a shared arithmetic primitive in a different output path; #1700 covers separate blob-gas price arithmetic.
- #2005 covers #94 call-request 256-bit cap, tip and base admission gates and errors, not this paired row construction.

The November 5 all-state census and available retained patches did not reveal a prior owner of the whole combined zip, fee-floor/cap and checked gas-delta relation. Current PR metadata and new/changed file lists are preserved in `/private/tmp/hl88-pr-census.json` and `/private/tmp/hl88-files-index.json`; the detailed comparison is `/private/tmp/hl89-fee-history-scope-audit.json`. This is a conditional finding, not a guarantee: 32 historical PRs are unavailable live, some file patches are missing or truncated, a prior PR reached GitHub's file-list cap, and alternative wording or unpublished work may conceal overlap. Refresh before publication.
