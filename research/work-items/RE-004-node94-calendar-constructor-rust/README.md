# RE-004: all-i32 calendar constructor with exact return bits

This independently reconstructs complete node94 `[0x151f6f0,0x151f86a)`
in safe `no_std` Rust. The foundation-millis packet retained its arithmetic
and tables but explicitly left the complete accepted range and reconstruction
unresolved. This contribution proves that range for all 2^32 low-dword inputs,
closes all four unreachable panic arms, and preserves full RAX plus the
incoming-RAX value restored into RCX. It does not reconstruct the enclosing
millisecond conversion or its error formatter.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Base:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The reference gitlink remains
`999556f6e0a474b8312db96ec3149e1c44e97c23`; its unlicensed inferred
implementation was not read/copied. OpenAI / Codex authored the new work;
the runtime model identifier is not exposed.

## Full-domain result

The signed interpretation of input low32 is admitted for every value. RAX
is nonzero exactly on `[-95746129,95745399]` inclusive, representing years
`[-262143,262142]`. It zero-extends a packed u32 result, including negative
years. All other inputs return the original RAX zero. This API introduces
no `None`, error or refusal policy. Input high32 is ignored, and RCX always
restores full incoming RAX from the original saved stack slot.

[PROOF.md](PROOF.md) derives the exact day interval, reciprocal division,
Euclidean normalization, year correction, ordinal bounds, flags and packed
return. A finite arithmetic certificate covers every 146,097 possible cycle
residue; all 401 leap-prefix and 400 flag bytes match independent formulas.
All four panic arms are unreachable for the complete low32 domain, making
normal-return closure independent of their unknown deeper behavior.
The related packed-date-add packet/PR#1473 shares these tables but accepts
validated packed inputs and performs a different operation. This constructor
needs no prevalidated representation.

## Static closure

The complete 378-byte/92-instruction body, six padding bytes, actual FDE/CIE,
all 801 table bytes, four Location-shaped records, two source paths and exact
relocation records are bound. The one qualified call at `0x13c8e97` is retained
inside the complete 323-byte caller `[0x13c8e10,0x13c8f53)`. The three unreachable
error targets at `0x157b520`, `0x157b64f` and `0x157b480` also have complete
bodies/FDEs locked. Their downstream dependencies are excluded because no
input can reach them. Filename labels `caller-2/3/4-disassembly.gnu.txt` are
mechanical export labels for these unreachable target bodies, not incoming
caller claims; the role field in the lock and freeze records identifies them.

All 80,300 RELA records are scanned for exact naming and overlapping slot/data
writers. Entry slot `0x576e890` has its single expected RELATIVE writer.
E8/E9/FF15/FF25 scans produce 324 FF15 candidates through the slot, zero in
other classes. Only the one retained call is instruction-boundary qualified;
the other 323 candidates are not counted as decoded callers. The census does
not establish indirect runtime reachability or whole-program usage.

## Independent expectations and native qualification

The oracle was frozen before either Rust file existed at
`2026-11-01T21:46:35.596186+00:00`, source SHA-256
`c1e002670c96a0568cf5fef01a99b0cf74df13b314dbba087eebfdb17dc10eab`.
It binary-searches the absolute-year start function over the full admitted
year interval, then derives ordinal and flags from absolute day arithmetic.
Rust uses Euclidean 400-year decomposition and at most one year correction.
Neither is an instruction interpreter or executes captured code.

The 158,551 fixtures include every normalized residue, alternating cycles 0
and -1, century/year boundaries, exact domain endpoints,
signed-add overflow, ignored high32 bits and all saved-RAX bits. There are
153,672 nonzero results, 4,879 actual zero results, 416 initial-overflow cases
and 76,495 negative-year results. All 634,204 observations match across native
opt0/opt3 repeat builds, with identical same-opt rlib/client/stdout hashes.
All sixteen compiled wrong variants produce real mismatches; changing the
upper accepted year alone changes 133 observations. Selected counterexamples
and all counts are retained, alongside a malformed-driver control and a
one-changed-expectation comparator control.

The raw archive retains exact stdout/stderr with lossless base64/XOR-base64
encoding. `verify_recorded.py` reconstructs and hashes every stream and checks
all native mismatch counts. Readable GNU listings remove trailing whitespace
only; the unmodified bytes remain archived. GNU frame stdout is explicitly
limited to the relevant actual FDE/CIE records. No source-byte match or
original ABI result is inferred from native value agreement.

Fifty-six structural corruption controls reject. All 138 original command
streams round-trip with their byte counts and hashes; the lossless archive
is 4,837,867 bytes. The optimized-Python audit verifies all 20 native output
streams and mismatch counts. 18 focused predecessor tests, rustfmt,
`make doctor`, `make verify`, `make catalogue-check` and `make reproduce`
pass. Exact outputs and path-normalization hashes are retained in
`observed/repository-checks.json.gz`.

## Reproduction and limitations

Use unchanged materialized pins and a fresh output directory:

```sh
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
python3 -B -m unittest tests.test_foundation_millis -v
python3 -O research/work-items/RE-004-node94-calendar-constructor-rust/verify_static.py
python3 -O research/work-items/RE-004-node94-calendar-constructor-rust/verify_recorded.py
python3 -O research/work-items/RE-004-node94-calendar-constructor-rust/validate.py \
  --output work/node94-calendar-constructor/review
```

The actual native pin is rustc1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM21.1.8, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The observed host is macOS arm64; Python3.14.3, Capstone5.0.7 and GNU binutils
2.47.20260726 supplied static qualification. Exact commands, versions and
source/build/output hashes are retained in `observed/`.

The API projects RAX/RCX only. It excludes other scratch registers, flags,
ABI, physical stack, faults, MMIO, concurrent mutation and access traces.
No captured execution/emulator, copied unlicensed source, full-node identity,
component gate, per-head full-suite or hosted CI success is claimed.
Prior evidence, pins, generated catalogues and progress stay unchanged.

The separate shared baseline covered 971 files, reported 15,462 tests and 69
skips, and exited 2 solely from three disk-full errors. All 20 affected tests
passed isolated retries. This is not a clean original sweep or qualification
of skipped Linux tests.
