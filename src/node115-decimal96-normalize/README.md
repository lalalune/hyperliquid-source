# Node115 Decimal96 scalar normalization

Dependency-free `no_std` Rust for the established96-bit coefficient/raw-flags
arithmetic cut in Node115 FDE3be4ba0..3be502b. See the
[evidence packet](../../research/work-items/RE-004-node115-decimal96-normalize/README.md)
for the exact SHA,306-byte span, input/output word values, proof and limits.

`normalize_parts(lo,mid,hi,flags)` returns our `Normalized` value type.
It does not expose a recovered native ABI or infer the parser's accepted types.
Zero clears flags; an initial scale0 preserves all flags; otherwise remove
at most scale decimal zeros and preserve only sign and remaining scale.
No captured code, unlicensed inferred source, dependencies or invented workspace
are used. The direct-compiler runner authenticates the entire target, checks
9856 frozen cases at opt0/3 and repeat, executes3 ordinary Rust tests, and
rejects4 compiled wrong implementations plus2 changed native operands.

Reproduce the static relation with `python3 tools/decimal96.py` and the observed
Windows research build with `python3 tools/decimal96_rust.py --rustc <Rust1.95.0>
--linker <bundled-rust-lld> --output <new-directory>` from the repository root.
Full node functionality, byte equivalence and all component gates remain open.
