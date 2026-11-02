# Quota value and cache publication contract

Target: node #94 Linux x86-64, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked virtual addresses. The evidence retains the whole
initializer `[0x4e04830,0x4e061bd)` and callback adapter
`[0x4e061c0,0x4e061d2)`. The contract below covers selected stages, not every
instruction in the initializer.

## Admission and numeric stage

Inputs to the projection are successfully parsed unsigned quota `q`, nonzero
unsigned period `p`, and a separately obtained logical count `n`. File errors,
mount translation and the cgroup parser are outside this API. The V1 call sites
at `0x4e0586b` and `0x4e05892` use the bound quota/period filenames; a zero period
branches away at `0x4e0589f..0x4e058a2`. The V2 path uses `cpu.max` at
`0x4e0581c` and joins the numeric stage. This does not establish every textual
input accepted by either path.

At `0x4e058a4..0x4e058e6`, each u64 is independently converted to binary64.
PUNPCKLDQ interleaves the low and high halves with exponent words `0x43300000`
and `0x45300000`; subtracting the bound packed constants leaves exact
`low32` and `high32 * 2^32` values. ADDSD performs the input rounding. DIVSD
divides those rounded inputs. Thus the relation under round-to-nearest,
ties-to-even is `r = RN(RN(q) / RN(p))`, not `RN(q/p)` and not integer ceildiv.
The constant bytes and complete instruction stream are retained and checked.

The indirect call at `0x4e058ea` resolves through the actual RELATIVE slot
`0x57747c8` to `[0x565f670,0x565f6e7)`, the previously qualified ceil helper.
It returns the upward integral binary64 value. The following CVTTSD2SI,
comparison, sign-bit adjustment and conditional moves saturate that result
to u64. The bounds at `0x20a7f0` and `0x20a218` encode `2^63` and the greatest
binary64 value below `2^64`. These are bound by exact bytes, not inferred from
a nearby decimal string. This packet relies on the established ceil-helper
contract and retains its complete body as existing context.

For example, `q = 9007199254740993` and `p = 9007199254740992` both convert to
binary64 bits `0x4340000000000000`, so the ratio is 1 and its ceil is 1.
Integer ceildiv would produce 2. For `q = u64::MAX, p = 1`, conversion reaches
`2^64`, so the unsigned cast saturates at `u64::MAX`.

The independent oracle implements conversion and quotient rounding with
integer/rational arithmetic, then extracts the rounded quotient's rational
value to calculate ceil and saturation. Its 2,317 vectors were frozen before
the Rust implementation. They check intermediate float bits as well as the
final value. This is a target-grounded mathematical oracle; no captured
instruction stream was executed. The default environment also requires masked
invalid and precision exceptions: the first signed CVTTSD2SI can be out of
range for a high admitted quotient before the later unsigned saturation.
Sticky exception flags are not outputs of this API. It does not prove
correctness under a changed floating environment.

## Logical count and publication

The guard at `0x4e05cbe..0x4e05ccd` skips the store when the path has no quota
result or the rounded quota is zero. On the admitted path, the imported
`sched_getaffinity` call at `0x4e05d2b` receives PID 0 and a 128-byte mask.
Success enters the 1024-bit counting loop. A nonzero return selects
`sysconf(84)` at `0x4e05d3a`; a signed result below 2 becomes 1. Both import
slots are checked against their dynamic symbol indices and names.

The unsigned compare/CMOV at `0x4e05da8..0x4e05dab` selects the smaller of
the logical count and nonzero quota. The memory XCHG at `0x4e05daf` publishes
it to `0x57883f8`. The Rust API uses a sequentially consistent atomic store
and returns whether a write happened. It projects the value and publication
effect only; it does not promise the original XCHG encoding or old register
value. No concurrent execution or once-state transition is tested here.

A supplied zero logical count with nonzero quota therefore stores zero;
it differs from a skipped write. The projection deliberately preserves that
distinction with `Option<u64>`. This is a synthetic boundary case, not a claim
that Linux supplies an empty successful affinity mask in an ordinary process.

The consumer previously mapped in RE-001 reads this same address. Its once
setup uses vtable `0x5747f68`; actual RELATIVE relocations at `+0x18` and
`+0x20` bind the adapter and initializer. The adapter directly calls the
initializer at `0x4e061cb`. The once call's bound target is recorded as
`0x4ee3b20`; its state machine remains outside this reconstruction. The cache
is in SHT_NOBITS and in the actual writable PT_LOAD zero-fill tail
`[0x57882f0,0x59b0e80)`. Both are checked; the section type alone would not
establish loader initialization. Initial zero-fill does not imply the live
cache remains zero.

## Source comparison and exclusions

Public num_cpus 1.17.0 Linux source at commit
[`342af76b486335e5a955c7314fc96cd104e7a17b`](https://github.com/seanmonstar/num_cpus/blob/342af76b486335e5a955c7314fc96cd104e7a17b/src/linux.rs)
independently describes the float quota calculation, zero rejection, logical
cap and SeqCst cache publication. The Linux
[`cpu.max` specification](https://docs.kernel.org/admin-guide/cgroup-v2.html)
describes the quota/period interface; the Rust
[cast specification](https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast)
specifies saturating float-to-integer casts. These explain the relation;
they do not establish the target's complete source version or build recipe.
No upstream source text is copied into the new MIT Rust implementation.

The full initializer is 6,541 bytes and the adapter is 18 bytes. Their retained
6,559 bytes are context, not a denominator of source-matched bytes. The existing
312-byte consumer and 119-byte ceil helper are separately labeled context.
No original Rust types, ABI layout, parser, filesystem interaction, allocation,
cleanup/unwind, once synchronization, compiler lock, whole-object identity,
first-party node implementation or milestone completion is claimed.
