# Node115 quota, affinity and CPU-cache projection

The target is Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses below are linked virtual addresses. No captured code was executed.

## Complete bodies and the selected relation

The initializer is `[0x5ba8150,0x5ba9a92)`, 6,466 bytes. Its once adapter is
`[0x5ba9aa0,0x5ba9ab2)`, 18 bytes, and the logical-count/cache getter is
`[0x5ba9dc0,0x5ba9ef8)`, 312 bytes. These primary bodies total 6,796 bytes.
The complete 119-byte ceil dependency `[0x63f08e0,0x63f0957)` is context,
not additional first-party implementation coverage. Four FDEs cover 6,915
bytes and 1,449 instructions in agreeing Capstone, GNU and LLVM exports.
The initializer has 31 retained LSDA call-site entries; action/personality
semantics remain unresolved.

The Rust API reconstructs the numeric stage, selected publication effect,
affinity-mask count, signed fallback and getter's post-once cache precedence.
It does not implement the entire initializer, filesystem parsing, mount
translation, string allocation, cleanup, Once, Linux imports or the private
ABI. All 94 calls in the retained bodies are enumerated, including opaque
boundaries. Retaining a callee address or its enclosing FDE is not a proof of
that callee's behavior.

## Quota admission and floating calculation

The V1 route at `0x5ba9185` supplies `cpu.cfs_quota_us` and at `0x5ba91ac`
supplies `cpu.cfs_period_us` to the actual helper `0x5ba9f00`. Successful
results require RAX equal to one. Quota is retained in R12, period arrives
in RDX. At `0x5ba91cd`, a zero period skips the numeric path. The V2 route
supplies `cpu.max` at `0x5ba914c`; its later parse path moves R15 to RDX at
`0x5ba97f0`, tests nonzero and joins `0x5ba91d2`. These edges identify the
selected successfully parsed input relation, without claiming the complete
accepted text grammar or path-error behavior.

The block `0x5ba91d2..0x5ba9214` converts the two u64 inputs separately.
PUNPCKLDQ with `0x451210`, subtraction of the packed constant at `0x450170`,
and ADDSD form rounded unsigned-to-binary64 values. DIVSD then divides those
rounded operands. Under round-to-nearest, ties-to-even this is
`RN(RN(quota) / RN(period))`, not integer ceiling division.

The call at `0x5ba9218` uses the actual RELATIVE slot `0x64e7858` to the
complete ceil helper. On the admitted finite nonnegative ratio domain:
exponents above 0x432 already represent integral values; exponents at most
0x3fe map positive nonzero fractions to the bound 1.0 constant; zero stays
zero; the intermediate path adds the fractional-bit mask then clears it.
The retained negative branch and -0 constant are outside this caller domain.
The subsequent CVTTSD2SI/shift/AND/OR/conditional-move sequence saturates the
unsigned result, using 2^63 at `0x459360` and the largest binary64 below 2^64
at `0x458d58`. Masked invalid and precision exceptions are assumed; sticky
exception flags are not outputs. No changed floating environment is proved.

For quota 9007199254740993 and period 9007199254740992, both input conversions
produce the same bits, so the observed calculation gives one while integer
ceildiv gives two. For u64::MAX divided by one, the conversion reaches 2^64
and the unsigned result saturates to u64::MAX.

## Logical count and publication

At `0x5ba95f6..0x5ba95ff`, zero quota or the missing-result flag skips the
publication path. Otherwise the initializer zeros a 128-byte mask and calls
the bound `sched_getaffinity` import at `0x5ba9663` with PID zero and length
128. A zero return selects the complete 1024-bit count loop. It visits two
bits per iteration, indexes one of sixteen u64 words and increments a
32-bit counter. The retained counter-overflow branches cannot be reached
from a fixed 1024-bit mask and a zero initial counter.

A nonzero affinity return selects `sysconf(84)` at `0x5ba9672`. The signed
comparison and CMOVGE yield max(result,1). No errno or API execution is
inferred. At `0x5ba96e0..0x5ba96e7`, an unsigned minimum with the quota is
published by memory XCHG to `0x64fff08`. The Rust API uses a SeqCst atomic
store for this selected publication effect; it does not claim that a source
ordering or original opcode can be uniquely recovered from x86, nor does
it expose the old XCHG register value.

Skipping a write differs from storing zero. A successful supplied empty
mask has logical count zero; a nonzero quota therefore publishes zero.
This is an admitted boundary input, not a claim about ordinary Linux process
affinity. Missing/zero quota instead preserves the supplied initial cache.

## Once callback, loader state and getter

The getter initially reads the dword at `0x64fdfb0`. Its actual file bytes are
03 00 00 00. A nonzero state invokes the opaque once primitive through
`0x64df9f0`, which resolves to `0x5c87d50`. The selected callback vtable is
`0x64bccc8`: drop zero, size eight, alignment eight, with actual RELATIVE
writers at `0x64bcce0` to the 18-byte adapter and `0x64bcce8` to the initializer.
The adapter's direct call at `0x5ba9aab` reaches `0x5ba8150`. This binds the
producer, but does not reconstruct poisoning, wakeups or synchronization.

The cache word is distinct from the once state: it lies in the actual writable
PT_LOAD zero-fill tail `[0x64ffe08,0x6728924)`. Initial zero-fill does not imply
a live cache value. After any required once call returns, the getter loads
`0x64fff08`. A nonzero value is returned. Zero selects its own affinity request
at `0x5ba9e60` and signed sysconf fallback at `0x5ba9e6f`; the same 1024-bit
population-count relation follows. The Rust getter takes this already-loaded
cache word as input. It makes no concurrent-load or Once state-transition claim.

## Sources, qualification and migration

Official num_cpus Linux source at commit
`342af76b486335e5a955c7314fc96cd104e7a17b` corroborates separate float conversion,
ceil/cast, nonzero quota admission, logical cap and SeqCst cache publication.
Its retained MIT/Apache licenses apply to that source. It is an interpretive
comparator, not an identification of the node115 vendored revision or build.
The new Rust implementation is independently authored under the repository MIT
license. The target's compiler comment is not original build provenance.

The 2,317 quota vectors use the historical own integer/rational oracle, now
bound to freshly checked115 stages. Its ancestral commit and generator hash
are explicit; an older own Rust implementation already existed, so this is not
claimed as a newly invented blind oracle. The 1,318 affinity/getter fixtures
were frozen before the new115 Rust source, using binary-string bit counts and
signed integer formulas. Their union of3,635 cases matches four Rust builds
(1.94.1/1.95.0, opt0/opt3). Eight compiled value mutants return normally and
produce mismatches. Those are own-code experiments, not captured target outputs.
Atomic ordering and concurrency are not validated by value-only mutants.

The previous node94 packet was closed after the sole target changed. No old
artifact, address or packet is a runtime dependency here. The new initializer
extent, imports, data, relocations, frame records, native exports and byte-bound
stages were freshly checked. No source-byte equality, completed milestone,
whole-initializer/whole-node equivalence or network compatibility is claimed.
