# Node115 whole-state sponge permutation

Independent safe no_std mathematical construction over25u64 lanes in x+5*y
order, checked against the complete node115 original permutation. No dependencies
or invented Cargo graph. New source MIT, algorithm reference NIST FIPS202.

`permute(&mut [u64;25])` is an owned numeric API, not the recovered native ABI.
All200state bytes matter. No absorb/finalize/padding, complete digest, signing,
bridge preimage, cryptographic assurance, original library/build identity or
full-node/gate claim. See the
[evidence packet](../../research/work-items/RE-009-sponge-permutation-115/README.md)
for exact pre-Rust original-instruction expectations, actual full-state outputs,
primitive/compiled controls, compiler and remaining caller/environment gaps.
