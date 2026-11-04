# Node115 interior signed bound arithmetic

Dependency-free no_std research API for the two interior spans of FDE4483920.
Row contains six raw words; observe returns Word(RBX) before4483b14 or
DiagnosticBoundary before4483b65. Neither represents the original function ABI.
Signed routing, unsigned magnitude, two u128 multiplication guards, borrowing
and nested min/max are bound to original instruction observations. Guard order
matters for MIN: it reaches the diagnostic only after earlier guards admit it.
No financial unit, original type layout, caller domain or whole-node claim.

Direct rustc1.94.1/edition2021; use build.py in
research/work-items/RE-004-signed-bound-kernel-115. Original expectations were
committed before these Rust files existed. New MIT code, no copied reference.
