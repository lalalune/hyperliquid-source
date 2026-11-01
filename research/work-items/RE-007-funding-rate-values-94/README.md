# Ordered supplied-sample funding rate values

This pre-source packet extends merged #860/#899 with an exact conditional raw-bit value contract for rate `0x3750610`, its actual caller and selected lookup/frame boundaries. It preserves prior formula credit and proposes one real dependency-free Rust component only after independent admission. Production source and the input-only client do not yet exist.

Start with [CONTRACT.md](CONTRACT.md) and [PROOF.md](PROOF.md), then [ORACLE-PROOF.md](ORACLE-PROOF.md), [PROTOCOL.md](PROTOCOL.md) and [SOURCE-PLAN.md](SOURCE-PLAN.md). The native scope is three complete FDEs,2,038 bytes/484 GNU and LLVM rows: scalar1,015/241, actual caller681/157 and credited hash context342/86. A generic hasher/map theorem, final returned-map effects, arbitrary invalid-memory input and scheduler/economic claims remain outside scope.

The corpus contains3,153 mathematical expectations from exact Fraction arithmetic and adjacent-representable-distance rounding, frozen before future source. It retains raw signed-zero and NaN bits, including a conditional witness where clamp+0 and clamp-0 yield different zero signs. This is not a live behavior/security finding. The actual caller forwards present nonfinite results; only absent/empty samples become a missing rate, later projected to positive zero.

Static checks read the authenticated node94 artifact, compare all native bytes and structural branches, bind literal/relocation/FDE/LSDA records and use corruption controls below the image-hash gate. The generic static collector/checker derives from this author's prior funding-worker evidence tooling, copied locally for self-contained reproduction; no runtime dependency on that unmerged packet is introduced. The primary ISA assumptions are explicitly cited Intel SSE semantics, nearest-even, DAZ=FTZ=0 and masked exceptions; no target CPU/control state is measured.

From repository root:

```sh
python3 -O -B research/work-items/RE-007-funding-rate-values-94/verify.py
python3 -B research/work-items/RE-007-funding-rate-values-94/oracle.py --out /tmp/fresh-rate-corpus
```

The corpus output directory must not exist. Compare its four files with `corpus/`. Both complete native providers are retained; GNU is plain text and the second is deterministic gzip, for example:

```sh
gzip -dc research/work-items/RE-007-funding-rate-values-94/native/rate.llvm.txt.gz
```

The author pre-source qualification retained three actual commands and their complete compressed stdout/stderr in `precode-validation/`. It passed561 static corruption controls (including10 operative-field changes independently decoded by both providers), two exact native regenerations and two exact four-file corpus regenerations. Seventeen mathematical checks passed. The pre-source manifest/freeze binds these results and all authorities before production exists; coordinator admission is a separate gate. No source/build result, captured execution, whole-program equivalence, exhaustive finite-corpus coverage or completion gate is claimed.
