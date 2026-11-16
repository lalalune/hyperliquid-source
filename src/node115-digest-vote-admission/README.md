# Node115 selected digest vote admission

This read-only logical adapter models the selected per-key incidence limit
before creation of a new digest candidate. It assumes valid normalized maps
and a separately resolved eligibility result. Counts include the same key
once per unselected digest candidate across all heights, in the same key
family, with saturating arithmetic. An existing candidate bypasses the count;
a selected conflicting digest or failed eligibility prevents admission first.

It does not validate membership, signatures, mutate a tracker, determine a
selected digest or model native container ABI and failures. If the caller
processes the 32-byte and then 20-byte keys, the second query must receive a
snapshot reflecting any first insertion; this API is not a batch transaction.
