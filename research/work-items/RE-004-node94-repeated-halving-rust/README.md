# RE-004: repeated conditional-add halving over every raw count

This packet reconstructs the complete node #94 159-byte loop
`[0x565dbc0,0x565dc5f)` in independent no_std Rust. It resolves its full
257-bit carry before halving, arbitrary correction/initial-value relation,
low32 do-while count (zero means 2^32), ordered image writes, and seven
written register values. A universal acceleration proof makes every count
practical without constraining the original input to a reduced range.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base source: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Component: bounded foundation arithmetic under RE-004. All addresses are
original ELF VAs. No neighboring helper, source-symbol identity, operand
meaning, whole-node build/ABI or progress gate is claimed. Imported evidence,
submodule pins and generated catalogues remain unchanged; no unlicensed
inferred source was read or copied.

## Established behavior and all-count proof

For a 256-bit value X and correction M, each pass is
`floor((X+(X mod2)*M)/2)` including the 257th addition bit. The original
loop always executes at least once and decrements EDX until zero, ignoring
entry RDX's high32 bits. Its entire numeric domain is admitted.

`PROOF.md` derives the normalized positive odd integer D: M when odd, M-1
when even and nonzero. For M>0 a pass becomes `(X+(X mod2)*D)/2` exactly.
After 256 passes, every initially positive X is in 1..D, even when X started
above D. Further passes are multiplication by inverse-of-two modulo D, with
zero residue represented by D. M=0, X=0 and D=1 are closed separately. The
source uses this result for at most 32 exponent bits, without replaying up to
2^32 original iterations. No original modulus interpretation is assumed.

The same proof derives the final auxiliary registers independently from the
last pre-shift sum. RAX is the final top result bit; RSI is the top bit of
result word2; R8 omits the cross-word bit stored in result word0. RDX is zero;
R9/R10/R11 are result words1/2/3. Reporting only the four stored words would
miss these register effects.

Original X is read once and M is read on every iteration. The correspondence
requires M and all other input memory to remain stable and readable throughout.
No output store occurs before the final iteration, so the safe byte-image API
preserves partial and full input/output aliases. Data windows exclude original
stack scratch, saved registers and return control. Faults, flags, concurrent/
volatile memory and machine ABI are outside this value/image projection.
Range refusal is explicitly new safe API behavior, not a recovered target
return or fault policy.

## Static closure and independent expectations

`static-lock.json` binds all 159 bytes, the exact complete FDE/CIE and the
one following NOP. Complete Capstone and independent GNU disassembly retain
the only back edge, count width, all carries/shifts, reads and output stores.
There is no callee, RIP-relative data/table dependency or indirect transfer.
Full `.text` E8/E9/EB scans find no incoming candidate. All 80,300 RELA
records are checked for naming addends and overlapping code/padding writers;
none match. This is bounded absence, not a complete caller census or proof
that the leaf is unreachable.

The oracle was frozen before Rust existed. Its SHA-256 is
`7a93340f338b050dab036eb9b995270944703bc95c3045cbd1a451b998cdb5f9`.
For up to 256 iterations Python uses an inverse modulo 2^n to compute the
unique whole-integer closed form without an iteration loop. For larger n it
uses the derived positive residue modulo D. The independent Rust uses u128
limb carry sums, 256 direct passes, then bounded add-and-double multiplication
and binary exponentiation. `frozen/ORACLE-FREEZE.json` records the UTC freeze,
source hash, raw fixture hashes and full static admission facts.

The 7,850 cases comprise 7,823 admitted projections and 27 new API refusals.
They cover all 256 input bit positions and adjacent values, zero/one/even/max
corrections, 3,262 unreduced inputs, 617 zero-low32 count encodings, 922 high32
count encodings, 3,419 counts above256, 397 output/input alias cases and 87
input/input alias cases. Every result byte and all seven registers are compared.

## Actual validation and retention

Pinned installed rustc 1.94.1 built the library/client at opt0 and opt3 twice
each, with overflow checks, panic abort and warnings denied. All 7,850 cases
matched in every profile: 31,400 total observations, comprising 31,292 admitted
projections and 108 API refusal checks. Same-option library/client/output
hashes repeated exactly. Native execution was only newly built Rust on macOS
arm64; no captured node, instruction emulator or Linux target execution ran.

Sixteen compiled wrong variants completed normally and caused actual admitted
mismatches. Controls include zero-count one-pass treatment, using high count
bits, losing the 257th sum bit, accelerating after128 instead of256 passes,
incorrect even-M normalization, zeroing positive fixed points, wrong inverse/
modular carry, incorrect final register bits, byte order and early stores.
All 24 structural controls were rejected. Corrupting one expected row caused
exactly one comparator mismatch; malformed driver input exited2 without stdout.
The counts and real counterexamples are retained in `observed/results.json`
and `selected-controls.json`. No mutant depends on changing API refusals.

`observed/raw-streams.json.gz` losslessly stores 130 exact command stdout/stderr streams,
using base64 or XOR against the first native stdout before compression. This
is storage encoding, not comparison normalization. The audit restores every
stream, checks raw hashes, counts, exits and counterexamples. GNU's large full
frame stdout is explicitly retained as selected original CIE/FDE records.
Readable disassembly strips only line-ending whitespace; its original bytes
remain in the archive. No native build or control failure occurred.

## Reproduce and limitations

From repository root with installed Python3.14.3, Capstone5.0.7, GNU binutils
2.47.20260726 and rustc1.94.1:

```sh
python3 -O research/work-items/RE-004-node94-repeated-halving-rust/validate.py \
  --output work/node94-repeated-halving/recheck
python3 -O research/work-items/RE-004-node94-repeated-halving-rust/verify_recorded.py
shasum -a 256 -c research/work-items/RE-004-node94-repeated-halving-rust/MANIFEST.sha256
```

The validator checks the full target digest and complete static closure,
regenerates and byte-compares frozen fixtures, then builds/runs only new source.
Exact command arguments, compiler executable hash, platform and raw output
hashes are retained. The component has no dependencies or invented Cargo
workspace/lockfile; target machine-code equivalence is unmeasured.

`make doctor verify catalogue-check reproduce`, 24 focused ELF/FDE/GNU tests,
rustfmt and manifest/archive checks passed; their output is retained separately.
The shared
baseline attempted 971 files / 15,462 tests / 69 skips; original make exit2
was solely three disk-full errors, and all 20 affected tests passed isolated
retries. This is not a new full-suite result on this head, skipped Linux-native
qualification or hosted CI success. No progress gate changes are requested.
A remaining bounded question is how callers select this entry and constrain
its operands; none of the established all-input relation assumes an answer.

Authorship: OpenAI / Codex client. The exact runtime model identifier is not
exposed and is not invented.
