# RE-004: Node115 Decimal96 coefficient/flag normalization

- Component: assets/foundation; a bounded arithmetic dependency of TWAP conversion.
- Target: Linux x86-64 node115,105896032bytes, SHA256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Scope authority: CONTRIBUTING, SCOPE included assets/quantities reconstruction,
  TASKS RE-004. This fills a reconstruction gap; it is not a discovered financial
  vulnerability or a claim the original arithmetic is defective.
- Result: independently authored dependency-free `no_std` Rust for the established
  scalar relation; no gate change and no whole-function or machine-code match.

## Before and after / independence

The base has no Decimal96 normalizer at this address. Its quantity-preparation
implementation is a different, outbound63-bit-input fixed-scale-eight cut at
`0x41c57f0..0x41c5b83`. This packet concerns inbound three-limb coefficients,
raw flags, dynamic scale and sign/reserved-bit handling in another real FDE.
No prior addresses, fixtures, inferred implementation or gate credit are reused.
The frozen9856case expected corpus and instruction record were generated while
`lib.rs` did not exist; freeze.json binds those bytes. The new Rust uses u128
arithmetic; the static oracle uses the target's split-u32 reciprocal equations
and cross-checks an independent decimal-string specification. A newly invented
failing base test would not prove a recovered native contract; the before state
is the actual absent reconstruction, supported by these previously unresolved bytes.

## Native evidence and coordinates

All addresses are ELF image VAs, not runtime addresses. records.json authenticates
one complete actual unwind FDE `0x3be4ba0..0x3be502b`:1163bytes, file offset
`0x3be3ba0`, body SHA256
`4ba03c8d6a7ee8008d5d4c2b0a2ee0ae9a48122b53d58e2051d0ff449ad11089`.
The selected scalar span is `0x3be4c25..0x3be4d57`:306bytes, SHA256
`7e588a425a2760a911d5a5e25b60f64db954f3e6a73269acd0ae3e3caaa29194`.
The span includes an unreachable-from-selected-entry error block at cfe..d23;
we do not claim that block or the rest of the FDE is implemented.
`native.objdump` is a full GNU objdump2.47 `-d -M intel` FDE export.
Nearest exported C++ symbol labels are tool decorations, not recovered names.

Five actual `TwapWireSerde` wrapper FDEs at292b300/292b470/3c4b540/3c4b690/51ab3a0
call this converter through GOT64e4d00. Its ELF64 RELA type8 record at file
144d50 resolves image VA3be4ba0. caller-context.json records those actual calls,
complete caller exports and three independently relocation-resolved alias tables.
Their12strings are `a,asset,b,isBuy,s,sz,r,reduceOnly,m,minutes,randomize,t`.
These observations establish context, not field layout or a complete wire schema.

Opaque parsing calls precede the selected entry. Native word loads establish
flags=EBP, high=R13d, low=[rsp+4], middle=[rsp]. The OR at c25..c2e tests all
three coefficient words. Zero jumps c4a->d3a with zeroed result registers.
Otherwise c52/c65 extracts `(flags>>16)&255`; initial zero scale jumps c6b->d3a
without masking the original flags. Positive scale enters the loop at ca0.
The rejected division branch ceb->d23 restores the current coefficient.
Accepted divisions replace all three limbs and decrement scale at cf6; cf8
returns to ca0. d33 preserves only sign before OR with remaining scale.
Output stores at d3a/d41/d49/d50 are **values** `[flags,high,low,middle]` at
stack offsets+b8/+bc/+c0/+c4. This is not a recovered Rust Decimal ABI.

## Arithmetic certificate

Let C=(high<<64)|(middle<<32)|low,0<=C<2^96, and S=(flags>>16)&255.
For C=0 the result is C=0,flags=0. For nonzero C,S=0, preserve both C and
all raw flags. Otherwise remove k=min(S,decimal trailing zeros of C), returning
C/10^k and `(flags&0x80000000)|((S-k)<<16)`. Reserved flags are cleared in
this positive-initial-scale path even when k=0. Nonzero96-bit C can have at
most28 decimal trailing zeros; the loop is finite even for raw scale255.

The target divides limbs without a u128 divide:

1. `0xcccccccd=ceil(2^35/10)`. For high<2^32, multiplication then >>35
   gives floor(high/10): reciprocal error <1/40, smaller than the1/10 gap
   between any nonzero tenth fractional part and the next integer.
2. The remainder carried into a lower32-bit limb gives N<10*2^32.
   `0x199999999999999a=ceil(2^64/10)=(2^64+4)/10`. The high64 bits of
   N times that reciprocal give floor(N/10), since error<2^-30<1/10.
3. `0xcccccccccccccccd` is inverse5 modulo2^64. The rotate-right-one
   test `ror(N*inverse5 mod2^64,1)<ceil(2^64/10)` holds exactly when
   10 divides N: the rotation value is then q=N/10 below the threshold;
   conversely an accepted q has5*rol(q,1)=10*q within u64, so N=10*q.
4. Three-limb long division preserves C=10Q+remainder. Only remainder0
   commits Q and decrements S; rejection retains C. Thus the loop invariant
   is initialC=currentC*10^k and initialS=currentS+k. The Rust u128 divide
   has the same value relation on this96-bit domain without intermediate overflow.

This proves the mathematical selected-cut relation; it does not prove all raw
flags are reachable through the opaque parser, original type validity, or
whole-program equivalence. Finite compiled comparisons remain finite evidence.

## Build, comparisons and controls

Research compiler Rust1.95.0(59807616e), host x86_64-pc-windows-gnullvm,
LLVM22.1.2; Windows bundled rust-lld via stable ld.lld/self-contained flags.
No Cargo workspace, dependencies or lockfile are invented: direct rustc builds
this real leaf library. This compiler is an observed research tool, not an
inference about the captured node's original toolchain.

```sh
python3 tools/decimal96.py
python3 tools/decimal96_rust.py --rustc /path/to/rustc.exe \
  --linker /path/to/rust-lld.exe --output /new/output/directory
```

Run from the repository root. Every native-image input is full-SHA authenticated
before analysis, FDE/anchors/RELA are regenerated, and frozen records and all
9856TSV rows must match. The compiled driver receives only four input words;
it never reads expected answers. Debug and optimized runs match9856/9856 each,
three ordinary Rust tests pass in each, and the optimized repeat library is
byte-identical. comparison.json contains raw command/output hashes.
Compiled mutants yield2976(high truncation),31(negative zero),556(initial
zero-scale flags),296(scale-cap) mismatches respectively; their ordinary tests
also fail. Two actual native-operand counterfactuals change the rejection
threshold and inverse5, each yielding a semantic witness and rejection below
the global identity check. Production never bypasses target authentication.
No normalization masks are applied to Rust output comparisons.

## Repository checks and limitations

The base `make doctor` passes. The base `make verify` fails during GPG public-key
import in this native Windows/MSYS environment; it is not a signature success.
Final-head checks and exact results are recorded in the PR/operator evidence.
No original assertions, skips, signatures or deadlines are weakened.
Only the named source/evidence files are staged. Materialized LFS binaries have
correct committed SHA and no Git diff, although status reports M in the minimal
operator environment; they are not staged or modified by this contribution.

No captured node/visor execution or emulation, network/chain/signing activity,
original formatting, parser/error/cleanup helpers, upstream input policy,
original type/ABI, TWAP wire codec, fullFDE equivalent implementation, Linux
integrated build, machine-byte equality or complete component gate is claimed.
No progress/components registry is edited. Next question: close the opaque
parser's accepted flags/scale domain and formatter input contract before
integrating this scalar primitive into a complete TWAP decoder.
New code is independently authored MIT work; imported evidence retains its rights.
