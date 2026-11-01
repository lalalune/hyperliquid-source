# RE-004: full thirty-step numeric core

This contribution independently reconstructs complete node #94
`[0x565f2e0,0x565f390)` in safe `no_std` Rust. It resolves the fixed-loop
pair reduction, four signed coefficients, full-width accumulator and last-step
register snapshots. It is distinct from the neighboring six-word multiply/apply
helper; preparation, the following 48-step loop and caller algorithm are not
claimed. No gcd/Jacobi, field-modulus or source-identity meaning is assigned.

Target: node #94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are ELF VAs. Base commit:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Reference pin
`999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged; its unlicensed
inferred implementation was not read or copied. Provider/client: OpenAI /
Codex; the exact model identifier is not exposed in this session.

## Bound result and new findings

The API accepts all u64 triples from entry R8, R9 and RBP and returns the
fourteen explicitly written value registers. There is no new refusal domain.
The core has no data-memory input or mutation. Ordinary unchanged code and
valid return control are premises of correspondence; flags, actual register
allocation/ABI, unchanged RSI and stack/RET effects are excluded.

The branch gate tests the original first value's low bit, canceling speculative
swaps and accumulator changes when it is even. Odd values select an unsigned
larger-minus-smaller step, optionally swapping both matrix rows. The second
row doubles each iteration. A row's coefficient magnitude sum is at most 2^k
after k steps, proving the original biased 32-bit fields remain separate
through all thirty steps. Final unbiasing is 64-bit: negative coefficients
must keep their high bits.

The accumulator is a full u64 result, not only a parity flag. Its per-step
`(second+2)` wraps before the logical shift by two; widening that addition
changes real outputs. Last-iteration R10/R11, R12/R13 and R14 retain the pair,
packed rows and accumulator from before the last step. The safe API returns
those snapshots as well as the final state and coefficients. The
[proof](PROOF.md) derives every returned field and all arithmetic bounds.

For arbitrary even second inputs, per-step floors matter. This packet does
not assert an exact `final_pair=M*initial_pair/2^30` relation; it proves each
floored scalar transition and each matrix transition independently over the
entire domain.

## Complete static closure

The actual FDE at `0xfbda14` covers 176 bytes and 47 instructions, ending
with the two-byte `repz ret`. Sixteen alignment bytes are bound separately.
There are no calls, data-memory accesses or RIP-relative data dependencies.
The only conditional edge loops from `0x565f370` to `0x565f301`; the counter
starts at 30 and reaches zero exactly after thirty iterations.

Full body SHA-256:
`4299dd428172e672a044f0bb98a3d07e0fbd8188497b720bbb9812b50a63ed20`.
`static-lock.json` binds both selected bodies and exact FDE/CIE records. GNU
and Capstone decode each complete body and the verifier checks FDE PC/range
and actual CIE linkage, not next-start spacing. Complete RELA scans find no
naming or overlapping code relocation.

Full `.text` E8/E9/EB scans find only the short tail jump at `0x565f2d5`.
It is instruction-qualified in the complete 185-byte, 50-instruction incoming
preparation FDE `[0x565f220,0x565f2d9)`. Its argument-production semantics and
other incoming paths are not reconstructed. Zero E8/E9 candidates and one EB
candidate do not establish a complete indirect-xref census.

## Independent expectations and actual validation

The oracle and full target facts were frozen at
`2026-11-01T21:26:46.931935+00:00`, before either Rust file existed.
Oracle SHA-256:
`3c2ab9fc748f03ab731b5602238dfcda881363ada38531621efa3a8b424fab9b`.
It uses general 2x2 integer matrix products, componentwise vector floors,
unbounded batched accumulator addition and a quotient/remainder formula for
the inner wrap. Rust instead uses scalar unsigned steps, direct signed row
updates and explicit wrapping additions. The input-only client receives only
three raw hexadecimal words and prints the fourteen outputs in documented
register order, without expectations or captured instruction bytes.

All **66,000 cases** match each of four native opt0/opt3 repeat builds.
Same-optimization rlib, executable and stdout hashes repeat exactly. Coverage
includes all pairs below 128, full-width bit boundaries and neighboring values,
all accumulator bit positions at selected pairs, and deterministic random
triples. Across 1,980,000 modeled steps there are 1,368,914 even steps,
482,855 odd subtract steps and 128,231 odd swap steps. The corpus includes
18,904 inner-addition wraps and 19,593 cases with accumulator wrap. These are
finite observations; the proof covers all 2^192 input triples.

All sixteen compiled wrong variants produce actual mismatches:

| Wrong variant | Differing cases |
| --- | ---: |
| Twenty-nine steps | 66000 |
| Even instead of odd gate | 66000 |
| Signed pair comparison | 6373 |
| Swap on equality | 24224 |
| Omit matrix swap | 47845 |
| Omit second-row doubling | 66000 |
| Add instead of subtract rows | 58218 |
| Omit swap accumulator term | 26422 |
| XOR instead of AND in swap term | 47845 |
| Widen second+2 before shifting | 1142 |
| Return accumulator parity only | 65098 |
| Zero-extend negative coefficients | 58218 |
| Return current packed row | 66000 |
| Return final accumulator as old snapshot | 37786 |
| Return final pair as old snapshot | 38282 |
| Reverse packed coefficient fields | 66000 |

All 33 structural corruption controls reject after bypassing only the identity
gate, checking instructions, bias/count/shift fields, snapshots, loop/return,
padding, FDE/CIE, incoming tail target and relocation changes. One deliberately
changed expectation produces exactly one native comparator mismatch.
`observed/selected-controls.json` retains actual counterexamples and the
recorded-stream checker independently recounts every discrepancy.

Focused FDE/index legacy tests: **22/22 pass**. Rustfmt, `make doctor verify
catalogue-check reproduce`, optimized-Python raw-stream verification, manifest
and staged whitespace checks pass. Parent source/proof/fresh GNU disassembly
review found no blocker; committed native replay remains a separate review
step. No captured execution/emulator, ABI reproduction, target machine-code
match or whole-node completion is claimed.

No full-suite duplicate was run for this head. The separate shared main-baseline
sweep covered 971 files, reported 15,462 tests and 69 skips, and exited 2 from
three disk-space errors; all 20 affected tests passed isolated retries. That
is not a clean original sweep, a full-suite run on this head or qualification
of skipped Linux tests. Hosted CI success is not claimed.

## Reproduce and audit

From the repository root with authenticated pinned artifacts:

```sh
python3 -O research/work-items/RE-004-node94-thirty-step-matrix-rust/validate.py
python3 -O research/work-items/RE-004-node94-thirty-step-matrix-rust/verify_recorded.py
python3 -m unittest tests.test_fde_extents tests.test_elf_index -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-thirty-step-matrix-rust/MANIFEST.sha256
```

Actual tools: macOS 27.0.1 arm64, Python 3.14.3, Capstone 5.0.7, GNU binutils
2.47.20260726 and rustc 1.94.1 commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8. Installed paths can
be selected by `--rustc` and `--objdump`; the compiler identity remains pinned.
The component is a standalone dependency-free library/client, not a fabricated
Cargo workspace or reconstructed node build.

`observed/commands.json` records exact labels/arguments with repository prefix
normalized to `/repo`, return codes and original raw stream hashes. One
11,796,357-byte deterministic gzip archive retains all **128 exact command
streams**. Ordinary streams are base64; later same-length native stdout is
base64 XOR against the first native stdout. Each entry includes its basis
label when needed, original byte count and original SHA-256. The verifier
restores every byte before checking hash, command binding and mismatch count.
No output normalization, omitted native rows or per-run duplicate raw files
are hidden by this compression.

Readable GNU exports strip trailing whitespace only, checked against the raw
archive. The huge full GNU frames stdout is explicitly retained only as the
selected actual CIE/FDE records in `target.frames.txt`. Repository/focused
logs retain only path-prefix sanitation and both original/retained hashes in
`observed/repository-checks.json.gz`. The manifest binds every new source and
packet file except itself and Python cache files.

Live PRs/issues/recent merges and local source were checked before reservation
and again before submission (`overlap.json`), with no overlap. Only the new
source and evidence packet change. Prior evidence, pins, generated catalogues
and progress gates are unchanged. New code/docs are MIT; imported static
bytes/disassembly keep upstream rights. No unlicensed source, secrets, keys,
chain action or live networked node was used. The preparation and larger
algorithm remain unknown and outside the claim.
