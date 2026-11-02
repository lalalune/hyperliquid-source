# Bounded production and validation plan — no source yet

After the coordinator admits this complete pre-code freeze, author one new
dependency-free MIT component, `src/node94-funding-premium-values`. The crate
will expose the borrowed logical entry/slot/book types, the supplied values,
small ordinary result/selected record types and separately named policy
refusals described in `CONTRACT.md`. No generic hash/map, scheduler, transaction,
logging/callback, foreign-pointer or public generic-floating API is proposed.
It will not depend on unmerged funding-rate/worker/storage components or their
packet modules. Any locally reused authored integer scaffolding must have
correct provenance and be proved for this operation's actual domain.

One shared slot slice/count serves both ordered entry slices, matching the
unchanged RDI at both native calls. No hidden per-side slab bound is permitted.
The operation itself needs no allocation: walk entries in their supplied order,
follow reached slots with a per-chain finite visit budget, use u64 saturation
and u128 full products, and keep each native early-return distinction. Source
will calculate the first and second ordinary impact before testing their zeros.
This ordering is reviewed in source, not falsely credited to ordinary output
mutants. Invalid scale precedes oracle zero; oracle zero skips target and book
work; zero target/cycle refusals remain new policy outside native ordinary
equivalence. The selected record preserves raw fallback bits.

Floating calculations will use integer encodings/significands with one exact
rounding at each observed operation, independently from this oracle's Fraction
bisection/adjacent-distance method. The required primitives are unsigned64 RN
conversion, finite normal add/subtract, exact half multiplication, finite
division with a **positive finite binary64 denominator**, and finite comparison.
The denominator is the scaled oracle as well as exact D or100. The previous
funding-rate positive-RN(integer-count) denominator proof is too narrow and
will not be reused as proof for this operation. Any u128 intermediate width,
alignment/sticky bits, sign-zero rules, normalized quotient and carry rounding
must be justified afresh in a separate source proof. The native domain bounds
exclude arbitrary NaNs/infinities and subnormal results; source must establish
and preserve those bounds, rather than add arbitrary floating policies.

The independent pre-code oracle, inputs and answers must remain immutable once
frozen. Author crate/tests and an input-only client only after the pre-code gate.
Freeze exact source, actual Cargo manifest/lock graph, client, runner, complete
installed toolchain admission and source proof before the separate build gate.
Reject source symlinks, build scripts, registry/path dependency surprises and
ancestor workspace/config influence; use audited isolated copies, explicit
offline/locked invocations and verify Cargo metadata workspace_root.

After that gate, run actual debug/release tests and compare every frozen output
from both profiles and a distinct clean build root. Retain all real command
stdout/stderr, status, source copies, built library/client identities and linkage.
Use comparator corruption controls, malformed-input controls and actual compiled
semantic mutants in both profiles. Mathematical false-model witnesses guide
mutant selection but are not reported as compiled kills. Report any first
required failure and stop rather than silently adjusting frozen inputs.

Raw same-source build equality is measured separately for rlibs and clients;
debug path differences, if present, remain unmasked and explicit. Public receipts
must exclude runtime caches, private home paths and absolute temporary locations
while preserving raw streams or clearly identified reversible metadata mapping.
Original published20, pre-code freeze and subsequent source/build chronology
remain intact. This is an additive implementation phase of PR1422, not a new PR.
