# Static results

- Authenticated input: node94 SHA256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
- Helper: one 113-byte FDE; neighboring truncation 85-byte FDE; identical 85-byte suffix.
- Closed data inputs: two 16-byte masks/constants. Four caller multiplication/call pairs and one RELATIVE slot validated.
- Independent model: 283 bit-pattern cases agree with the exact rational nearest/half-away reference under the declared binary64 round-to-nearest-even assumption.
- Six code/data corruption controls refused; three semantic controls distinguish incorrect alternatives.
- GNU objdump 2.47 independently decodes the helper, neighbor and four caller query windows. Retained nearest dynamic-symbol labels do not identify these functions.
- No captured target, visor, live chain/provider or source reconstruction was executed. No Rust implementation/build, full caller/timer behavior, MXCSR state, exception flags, NaN payload equivalence or component gate is claimed.
- Repository-wide required commands and their exact final-head results belong in the PR validation record; local static evidence alone does not establish those gates.
