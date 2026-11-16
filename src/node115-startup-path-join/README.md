# Node115 startup path join and admission

This offline source adapter joins native entry-name bytes (excluding their C
NUL) to a supplied directory byte string, then invokes a caller-provided
metadata function on exactly those joined bytes before reusing the existing
UTF-8 and view admission. The crate performs no filesystem access; callback
effects are supplied by the caller. Absolute child
bytes replace the base; relative children add one separator only when a
nonempty base lacks a trailing slash. No dot, repeated-slash, backslash or
Unicode normalization is applied.

The source models valid input and successful allocations. Native allocator
failure, filesystem behavior, concurrency, tree construction, sorting and
checkpoint selection remain outside the claim. The prior admission crate and
its hashed evidence remain unchanged.
