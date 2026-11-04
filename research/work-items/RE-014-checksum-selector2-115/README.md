# RE-014: validate the selector2 checksum on node115

Component: foundation / storage checksum support. Target node115,
artifacts/node/94/hl-node, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Prepared on base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

## Gap and measured closure

This reconstructs the complete leaf FDE0x61da8b0..0x61daa52 (418 bytes,
110 instructions) as independently authored, dependency-free no_std Rust.
A separate complete177-byte/61-instruction wrapper at0x616bca0..0x616bd51
proves that raw DIL2 forwards its original RSI buffer/RDX length with seed0
through the tail jump0x616bcd6. Other selector arms and upstream reachability
are outside this reconstruction. The two native exports total595bytes/171
instructions; the reconstructed checksum denominator is the418-byte leaf.
No incoming-CALL-only scan is presented as a complete caller census.

The leaf has four16-byte accumulator lanes, little-endian words, four-byte
and one-byte tails, and a final32-bit avalanche. The observed five primes and
transfers agree with the [XXH32 algorithm specification](https://github.com/Cyan4973/xxHash/blob/bbb27a5efb85b92a0486cf361a8635715a53f6ba/doc/xxhash_spec.md).
This establishes XXH32-compatible values, not the captured library version,
source repository, compiler or original typed API. New code was authored from
the complete target disassembly before inspecting an upstream implementation;
authorship.json retains that frozen source identity. No unlicensed inferred
source or upstream implementation is copied. New code/docs MIT; captured
exports retain original rights.

The native null branch reaches avalanche before the length addition or any
buffer load. Null therefore yields the seeded empty checksum even for a
nonzero or maximal raw length. The Rust function preserves that target rule;
it does not substitute an invented input-refusal policy. Nonnull buffers must
be immutable for the call, initialized/readable for the supplied length, in one
valid allocation, nonwrapping and of length <=isize::MAX. Alignment is unrestricted
and read_unaligned is used. These unsafe-interface premises do not prove caller
validation or pointer provenance. Only the leaf's raw zero-extended RAX result
is reconstructed; other original scratch registers are unqualified.

## Actual component evidence

Real offline locked Cargo release library build: Rust1.94.1 / LLVM21.1.8,
Windows host, explicit Linux x86-64 target. No dependency or root workspace is
invented. The documented profile disables loop/SLP vectorization explicitly;
these are measured build flags, not code-comparison normalization masks.

The public comparator records2,684 actual own-code evaluations with zero mismatch:
1,620 length/seed/alignment cases;1,024 all-byte/seed/alignment cases;40 null
cases, including raw lengths above2^32,2^63 and u64::MAX. It compiles source
twice and observes identical own objects (450bytes/112instructions in this
profile). Own-object equality does not establish equality with the captured
418-byte function; no matching-byte metric or completion gate is advanced.

Six real source corruptions are compiled and rejected: null result, word prime,
16-byte stripe boundary, lane rotation, byte rotation and missing length.
Eight original immediate/branch changes alter the target-derived lowerer's
result and also fail the original full-image SHA gate. Original operands are
read separately at every lane/tail site; a single shared hardcoded prime does
not conceal individual changed copies. Derived parameters and numeric identity
certificates are retained. See [PROOF.md](PROOF.md) for the source/native relation.

Only freshly compiled own code enters the evaluator. The original capture is
static input and rejects at the own-object/erroneous-compiler boundary. Existing
shared helpers cannot evaluate the new scalar: the normal input61/seed0 stops
at rol0x10011f (evaluator-blocker.json). The smallest scoped extension implements
only the seven observed32-bit immediate rotation counts. It preserves SF/ZF,
tracks CF, defines OF only for count1 and leaves other OF unknown, following
the [Intel instruction reference](https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf).
The shared engine is untouched. Undefined registers/memory, external memory,
compiled helper calls and unsupported instructions still fail closed.

## Reproduce

See src/node115-buffer-hash32/README.md for Cargo/profile commands.

```
python tools/checksum_selector2_rust.py --rustc /path/to/direct/rustc --out-dir work/checksum-comparison
HYPERLIQUID_CHECKSUM_RUSTC=/path/to/direct/rustc python -m unittest discover -s tests -p test_checksum_selector2_rust.py -v
```

Without the explicit direct compiler variable or Capstone5.0.6, the compiler
method skips honestly, never a Rust pass. Compiler paths are screened before
a version probe; a dispatch spy proves the capture rejection without running
any captured program. The separate compiler test performs actual builds.
Public reproduction uses only native-bound parameters and independently chosen
synthetic inputs. No external test source or vector dataset is distributed.

## Required repository checks and remaining gaps

Exact base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; Windows/Python3.12.14, Capstone5.0.6.
Before:76 isolated files/373 tests; after:77 files/379 tests. Both retain23
failing files,8 failures,18 errors,9 skips with identical FAIL/ERROR header
multisets. All six new methods pass in the full run; installed focused6PASS
in2.804s. Full changed-tree runner wall time:639.843s.
Actual required check exits: doctor=1, verify=1, imports=1, packets=1, catalogue=0, reproduce=1, full-tests=1.
Catalogue consistency passes. Missing native/signature prerequisites, imported
checkout state and preexisting packet payload failures remain recorded; this
is not a full-suite pass. Original baseline/after logs are preserved locally.
The installed source and comparator reproduce the retained node115 evidence.
Offline locked Cargo release Linux-target library build passed on the documented
Rust1.94.1 profile. No captured execution or hosted CI is claimed.

No captured execution, live node/network service, native Rust test executable,
original panic/caller-ownership proof, streaming API, other selector recovery,
source/compiler provenance, hosted-CI pass or whole-node equivalence is claimed.
Next: close the actual callers' selector construction and remaining checksum
arms before replacing the complete dispatcher in a reconstructed storage path.

## Node115 migration evidence

The node115 image was independently scanned for the five encoded prime constants. The complete418-byte leaf and177-byte selector wrapper were then decoded at their actual node115 FDE ranges; both full body hashes match the historical evidence. This is original-byte identity for these two native functions across captures, not equality between Rust output and the native target. The selected tail jump is0x616bcd6. No other selector, caller or whole-node equivalence is inherited. The comparator re-reads all constants, branch operands, FDE/CIE records and both complete bodies from the authenticated node115 capture.
