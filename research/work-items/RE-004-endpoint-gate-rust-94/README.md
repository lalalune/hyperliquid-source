# RE-004: reconstruct endpoint gates with full RAX/RDX

Component: foundation. Bounded question: can the established 48-byte gate
be reconstructed while retaining the raw span register, read short circuits
and full-width address arithmetic? This adds independent MIT Rust and a
full-domain proof to the earlier static-only
`foundation-two-endpoint-high-byte-gate-94` result. It does not change that
packet or claim a string/UTF-8 type.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates are linked ELF virtual addresses. Baseline main is
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
The unchanged can1357 reference gitlink is
`999556f6e0a474b8312db96ec3149e1c44e97c23`; its inferred unlicensed
implementation was neither used as source nor copied. #115 and visor are
outside scope. New files are independently authored by OpenAI / Codex;
the exact runtime model identifier is unavailable.

Before this contribution the static packet described RAX behavior but
explicitly excluded Rust reconstruction. After it, the complete leaf has
a safe readonly-image implementation returning both RAX and RDX. In
particular `(start,end)=(2,1)` returns RAX zero with RDX `u64::MAX`;
zeroing the whole result would lose that observable value. Ordered byte
admission retains the early start read even when the later end bound
rejects. [PROOF.md](PROOF.md) derives every path and states new errors
separately from native fault behavior.

The retained 20-instruction body, 521-instruction complete caller, exact
FDE/CIE records, no-padding adjacency, all internal branch destinations,
one direct call and no naming relocation close the local dependencies.
GNU/LLVM/Capstone byte and boundary agreement plus 20 downstream structural
controls pass. This is not a complete indirect-xref census.

The pre-Rust frozen oracle has 77,935 records, including every pair of
endpoint byte values. All four native runs (two builds each at opt0/opt3)
match exactly: 311,740 output observations. Three units per profile,
16 effective compiled mutants, malformed driver framing and two comparator
controls pass. The mutation report distinguishes original normal-return
cases from new safe refusals. Source/compiler/linker hashes, repeated
artifact equality, exact commands and all 138 stdout/stderr streams are
recorded in `native-result.json`, `native-commands.json` and the lossless
content-addressed `native-streams.json.gz`.

## Reproduce

Use the unchanged materialized pinned inputs. Python 3.14.3, Capstone
5.0.7, GNU binutils 2.47.20260726 and Apple LLVM 17 supplied static
analysis. Native qualification pins actual rustc 1.94.1 / LLVM 21.1.8,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Exact versions and options are retained with the raw results.

From the repository root:

```sh
make doctor
make verify
make catalogue-check
make reproduce
python3 -B -m unittest tests.test_foundation_two_endpoint_high_byte_gate -v
python3 -O -B research/work-items/RE-004-endpoint-gate-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-endpoint-gate-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-endpoint-gate-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/endpoint-gate-review
```

The output directory must be fresh. The validator invokes only the new
native Rust executable; captured code is never executed or emulated.
The library is dependency-free and uses direct rustc builds, without a
root Cargo workspace. Nine existing focused tests, rustfmt, doctor,
verify, catalogue-check and reproduce pass; `repository-checks.json.gz`
retains exact command results with path-only redaction and original hashes.

The shared 971-file legacy sweep is tracked separately and was still
running when this packet was prepared. Three disk-space failures have
separately passed all 20 affected tests after storage cleanup; that does
not turn the original aggregate exit into a success. Neither unfinished
aggregate nor hosted checks are claimed passed here.

## Limits

The ordinary stable-memory projection excludes original faults, MMIO,
concurrent mutation, instruction/control aliases, flags, timing and other
registers. Numeric high/wrapped addresses do not imply host mapability.
The checked image domain and each new refusal are explicit in the proof.
No target compiled-byte comparison or whole-node equivalence is claimed.
Component gates, generated coverage, pins and progress remain unchanged.
Caller meaning and integration into a recovered ABI remain unresolved.
