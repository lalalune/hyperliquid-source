# RE-004: modular scaled cursor advance in independent Rust

The prior `foundation-bounded-scaled-cursor-advance-94` packet left Rust and the
factor's arithmetic interpretation open. This implements the complete leaf
`[0x4ea41e0,0x4ea4216)` and proves that its literal factor is the inverse of 11
modulo 2^64. Thus a nonwrapping span divisible by 88 gives an ordinary element
count. Other spans retain the exact modular product, unsigned clamp, wrapped
cursor update and full RAX remainder; they must not be silently normalized.

Target node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink:
`999556f6e0a474b8312db96ec3149e1c44e97c23`. New Rust/docs are independently
authored under MIT. No inferred unlicensed implementation was read or copied;
retained target bytes/disassembly keep original artifact rights. Existing
source, evidence, imports, pins, catalogues and component gates are unchanged.

## Exact relation and newly closed arithmetic question

For entry u64 values cursor C, end E and request R:

```
n = ((E-C) mod 2^64) >> 3
s = (n * 0x2e8ba2e8ba2e8ba3) mod 2^64
t = min_unsigned(R, s)
C' = (C + 88*t) mod 2^64
RAX = R-t
```

The product identity `11*0x2e8ba2e8ba2e8ba3 = 2*2^64+1` establishes the inverse.
If E>=C and E-C=88*m, then s=m and the update is an ordinary bounded advance.
That conditional theorem is not an inferred invariant on every caller. A span
of eight gives n=1 and s equal to the large inverse constant, so request one
advances by 88 even past E. Source uses the exact full-domain operation.

The [proof](PROOF.md) covers all 2^192 input triples, both product widths,
unsigned CMOV, the sole field write and full returned register. It also derives
an independent exact quotient equation for the oracle. The numeric API uses a
mutable cursor and copied end/request values, representing the two stable,
disjoint original qword fields and RSI. Original object addresses must have
valid ordinary nonwrapping accesses for target correspondence. No numeric
cursor/end ordering, span alignment, or pointer validity is invented. Native
ABI, faults, flags, MMIO/concurrency, source type and caller meaning are excluded.

## Complete static closure

Fresh GNU, LLVM and Capstone agree on the complete 54-byte/14-instruction body.
There are no branches, outgoing calls or RIP-relative data loads. Exact FDE/CIE
records, the ten following INT3 bytes and every instruction are retained. The
whole-text E8 scan returns no direct caller candidate. All 80,300 RELA entries
are checked, with exactly one symbol-zero RELATIVE entry at slot `0x574faf8`
naming the leaf; its original eight zero bytes and mapping are pinned. This
establishes `load_bias+entry` after relocation, not a source-level vtable or
callback identity. Indirect consumer completeness and neighboring cluster
functions remain outside this scope.

Sixteen downstream corruption controls reject changes to field offsets,
subtraction, shift, factor, product width, unsigned selection, stride, store,
remainder, FDE/CIE, padding and naming relocation/slot bytes. They bypass only
the complete-file SHA gate. Exact raw disassembly command outputs and tool
binary hashes are retained; no target-byte normalization is used.

## Pre-Rust quotient oracle and actual native results

Before Rust existed, `oracle.py` froze 70,066 input/output records. It computes
s by solving `11*s=n+k*2^64`, choosing `k=(-9*n) mod11`; because `2^64 mod11=5`,
this is an exact integer division and the unique solution in the u64 range.
The oracle does not use the inverse multiplication, Rust code, instruction
interpretation or captured execution. It separately checks all 4,903 canonical
spans against ordinary element-count division.

Cases cover all 11 count residues and all eight discarded low span bits,
request boundaries at s-1/s/s+1, high count bits, wrapped/reversed spans,
explicit canonical spans and 4,096 seeded additional triples. The input-only
client emits both cursor and full returned remainder. Four opt0/opt3 repeated
native builds/runs match all 280,264 observations exactly; library, client and
stdout hashes repeat within each optimization. Three unit tests pass per
optimization. No expectation is supplied to the native process.

All 13 wrong libraries compile, exit normally and differ from the frozen
results. Replacing inverse multiplication by ordinary division changes 41,783
cases while passing every canonical-span case. Saturating span subtraction
changes 23,731 cases and saturating cursor addition changes 22,090, again with
zero canonical mismatches. Signed minimum changes 17,777 cases including 828
canonical cases; taking the high product changes 45,081. These denominators are
reported in `native/result.json`, with first witnesses and source/artifact
hashes, rather than confusing canonical tests with full-domain validation.
Two comparator controls detect a changed output row and a missing byte, and
partial input is rejected before output. `native/streams.json.gz` retains all
120 actual command stdout/stderr streams losslessly with deduplicated payloads.

Independent review rederived the modular inverse independently, checked every
70,066 frozen result including all 4,903 canonical cases, redecoded the next FDE
and reran static verification under Python `-O`: no blocker. A minor proof
wording clarification about the three discarded span bits was applied without
source/oracle changes. `peer-review.txt` binds the reviewed hashes. All 8 focused
legacy tests, rustfmt, doctor, verify, catalogue-check and reproduce passed;
`repository-checks.json.gz` retains raw check results with path-only redaction.

## Reproduction and limits

After materializing pinned artifact inputs, from repository root:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-scaled-advance-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-scaled-advance-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-scaled-advance-rust-94/verify_rust.py \
  --out work/scaled-advance-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_bounded_scaled_cursor_advance -v
rustfmt +1.94.1 --check --edition 2024 src/node94-scaled-advance/*.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-scaled-advance-rust-94 && shasum -a256 -c MANIFEST.sha256)
```

The native verifier requires a fresh `--out` directory and actual pinned rustc
bytes. Qualified host: macOS ARM64, Python 3.14.3, rustc 1.94.1 commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8; compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Build flags, linker/compiler/source hashes, commands and exact results are
retained. Static tools are GNU binutils 2.47.20260726, Apple LLVM 17 and Capstone
5.0.7. Exact tool/version pins intentionally require separately labeled
qualification on other hosts. Python `-O` native verification uses explicit
exception guards. No external dependency or artificial workspace is added.

This is a complete bounded value/state relation, not original compiled-code,
whole-caller or whole-node equivalence. The parent's shared full legacy sweep
is separate and unfinished; aggregate and hosted-CI success are not claimed.
No captured code or instruction emulator ran, and no acceptance gate advanced.
