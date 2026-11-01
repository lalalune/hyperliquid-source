# RE-004: node #94 strided-array sum in safe Rust

The earlier [foundation packet](../foundation-strided-array-sum-loop-94/README.md)
validated this loop statically and left Rust unimplemented. This contribution
adds an independently authored safe slice projection of its complete 77-byte
FDE, with a full stable-memory proof, exact preflight span calculation and real
native table reads. It preserves u32 index zero-extension, all 64 masked count
residues, the 52,800-byte stride and modulo-u64 sum. It refuses insufficient or
unrepresentable slices before loads, without an arbitrary target count cap.

- Task/component: RE-004, bounded foundation arithmetic and memory-loop recovery.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, fetched origin/main before
  branch `research/node94-strided-array-sum-rust` was created.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- ELF VA range `[0x52cfe00,0x52cfe4d)`, file offset `0x52cee00`, body SHA-256
  `38f96284a7dbdba93c5d71048539f400cc09d1363f4107b557500a9d6eb9e869`.
- Reference pin remains `999556f6e0a474b8312db96ec3149e1c44e97c23` and node
  upstream remains `405cc08b17a727ee51b0f9128918955a84439915`.
  No inferred implementation was copied or used as an oracle.
- Claim: returned value for stable ordinary data in the stated safe slice
  domain, plus explicit newly chosen refusals. Original ABI, mutable-memory
  behavior, sparse/wrapping addresses, faults and application meaning are excluded.

## Static evidence and full-domain argument

[PROOF.md](PROOF.md) derives the exact iteration count, addresses, wrapping sum,
termination and preflight bounds from the retained bytes. The original base and
count fields are reloaded every iteration; the stability premise is explicit and
is not inferred from callers. `None` is a safe API refusal, never presented as
an original target result. Count `2^(field&63)` is always at least one.

[static.json](static.json) binds full leaf/caller bytes, executable section and
PT_LOAD-backed offsets, FDE/CIE records, loop edge, internal NOP, neighboring
padding and argument setup. Fresh GNU/LLVM exports agree without normalization
on all 22 leaf instructions and 23/157/354 instructions in the three complete
caller FDEs. Direct sites are `0x52cfe7e`, `0x52d0265`, `0x52d5b03`; the scan
is not an indirect-call census. Caller purposes and external helper behavior
are outside scope. All 80,300 RELA records are checked, including their observed
width-bearing types; none overlap protected code or name the selected entry.
The leaf has no calls or writes; runtime data consists of the fields and selected
qwords, plus the ordinary return-stack read. Seventeen structural corruptions
are rejected below the separate full-artifact identity gate.

## Oracle, implementation and native checks

[`lib.rs`](../../../src/node94-strided-array-sum/lib.rs) exposes `required_words`
and `strided_sum`. The preflight derives `index+(count-1)*6600+1` through checked
usize arithmetic and the Rust object-size limit; only then does the loop read
actual elements. Safe immutable slices are a stricter domain than arbitrary
original addresses. [The source README](../../../src/node94-strided-array-sum/README.md)
states the interface and its limits.

[oracle.py](oracle.py), [frozen.json](frozen.json) and compressed fixtures were
frozen before Rust source existed. The record binds the oracle source hash,
full target identity and static-record hash. This is local chronology, not an
independent timestamp attestation. Expectations use an unbounded closed-form
arithmetic-progression sum and a mathematical span inequality, without indexed
summation, target execution or the existing legacy rule.

Each 32-byte descriptor supplies index, field, actual length, seed and step.
The input-only driver fills a real contiguous Vec with
`(seed + step*position) mod2^64`, calls the library and returns tagged span/sum
values. Expected results are never available to that client. The oracle reduces
the progression algebraically; the implementation performs actual table reads.
Large-count cases use empty tables and check preflight/insufficient-slice refusals
without allocating their hypothetical span. The maximum actual table is 422,402
u64 words (3,379,216 bytes). A separate 500,000-word driver allocation guard is a
harness budget, not a library or target count cap.

There are 1,121 descriptors: 133 admitted, 748 short-slice refusals and 240
unrepresentable-span refusals. All count residues and high index/field bits are
represented. Admitted counts are 1,2,4,8,16,32,64, with exact/short/long spans and
wrapping values. Native opt0 and opt3 each match every expected 18-byte output
record and pass three focused unit tests. All nine compiled wrong variants fail
in both profiles: wrong stride, ignored index, zero iteration, 5-bit count mask,
saturating sum, missing final element, narrowed sum, rejection of exact fits and
omitted object-size limit. [native/value-controls.json](native/value-controls.json)
separately confirms normal sum mismatches on admitted real tables for stride,
index, zero-iteration, saturation, dropped-element and narrowing mutants; their
rejection does not rely only on span metadata. Four repeated rlib/client artifacts
are raw-byte identical without normalization.

## Reproduction and actual records

Use materialized pinned artifacts/submodules, Python 3.14.3 and the installed
GNU binutils. Exact commands, versions, exit codes and repository logs are in
[checks.json](checks.json). Home paths in repository logs are replaced with
`<home>`; both original and retained log hashes are recorded. Native comparison
bytes and streams are unmodified.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 research/work-items/RE-004-strided-array-sum-rust-94/verify_static.py
python3 research/work-items/RE-004-strided-array-sum-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/strided-array-sum-review
shasum -a 256 -c research/work-items/RE-004-strided-array-sum-rust-94/manifest.sha256
```

The verifier requires a new output directory and actual rustc executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`, release 1.94.1,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, host aarch64-apple-darwin,
LLVM 21.1.8. It records linker executable hash/version and source hashes before
and after qualification. The direct build uses edition 2021, explicit target,
`-Dwarnings -Ccodegen-units=1 -Coverflow-checks=on -Copt-level=0/3`, `/usr/bin/cc`,
fixed crate metadata and repository-path remapping. No dependencies, invented
Cargo lock or root workspace are introduced.

[native/calls.json](native/calls.json) retains every argument vector and stream
hash; [native/results.json](native/results.json) records observations, compiler,
source/fixture identities, repeat hashes and mutant witnesses. The deterministic
lossless `native/raw-streams.json.gz` archive stores 156 named streams as 16 unique
base64 payloads, including empty streams, in 11,208 compressed bytes. Every raw
payload hash and call-stream binding was checked. Records remain readable beside
the archive. The manifest covers the full packet and relevant existing tests.

Completed local checks: doctor, verify, catalogue-check, reproduce, all nine
existing strided-sum tests, exact legacy packet reproduction, rustfmt and static
regeneration under two seeds/timezones (one with Python `-O`). The initial native
attempt stopped because a mutation selector matched both code and a doc comment;
its exact-expression replacement was qualified in a fresh complete run, with no
Rust source change. Output corruption/truncation, partial descriptors and driver
allocation-limit controls also reject. Full-suite and hosted CI success are not
claimed here.

Only new Rust was executed. No captured code/emulator, live-node action, pin,
import, progress gate or coverage-registry change is involved. Original Linux
x86-64 compiled-byte identity is unmeasured. The remaining integration question
is what original table/object invariants guarantee stable fields and selected
values; this bounded value projection does not establish that application fact.
