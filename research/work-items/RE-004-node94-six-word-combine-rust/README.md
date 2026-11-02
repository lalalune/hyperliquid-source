# RE-004: ordered six-word coefficient combination

This independently reconstructs the complete node #94 arithmetic helper
`[0x565f000,0x565f20c)` in safe `no_std` Rust. The gap is its full-domain
coefficient arithmetic, intermediate memory aliases and returned value
registers. It is distinct from the existing 52-bit limb fold and scalar
subtraction helpers. No source identity, field modulus or GCD/Jacobi purpose
is inferred from the arithmetic neighborhood.

Target: node #94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Addresses are ELF VAs. Base commit:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Reference pin
`999556f6e0a474b8312db96ec3149e1c44e97c23` remains unchanged; the unlicensed
inferred implementation was not read or copied. Provider/client: OpenAI /
Codex; the exact model identifier is not exposed in this session.

## Resolved behavior

The source is 96 adjacent bytes holding two unsigned 384-bit little-endian
values. The coefficients occupy full-width RDX and RCX and their sign bits
control the target's transformations. The first six-word product is stored
before the second input is loaded. Destination overlap can therefore change
the second value, including at unaligned byte offsets. All final image bytes
and the projected value registers are preserved by the safe image API.

Three details distinguish the actual arithmetic from a simplified expression:

- A negative coefficient times zero retains a high correction because the
  six-word negation's final carry is discarded. With 384-bit x and signed c,
  the mathematical product is `P(x,c)=c*x-abs(c)*2^384` for x=0,c<0, and c*x
  otherwise, represented modulo 2^448.
- The two products add modulo 2^448. The top bit of that modular result selects
  the sign; an unbounded signed sum would be wrong at some full-width inputs.
- The target shifts by 30 before conditional six-word negation. The stored
  value is `abs(floor(signed448_sum/2^30)) mod 2^384`; negative nonmultiples
  round magnitude upward. Raw RAX/RDX remain the last MUL result, not the
  low result word or corrected product high word.

`Outcome.words` are R8..R13 and the six final stored words. RBX is 0/1,
R14 is the matching sign mask, and R15 is the second product's corrected
seventh word. RCX keeps the second coefficient, RSI is restored and RDI/RBP
are unchanged. The [complete proof](PROOF.md) derives every projected output
and the memory schedule from the full body. Flags and pointer/stack ABI are
explicitly excluded. MissingSpan is a new safe-API refusal, not original fault
behavior. Ordinary stable mapped memory and nonwrapping addresses are required;
code/control/stack aliases, MMIO and concurrent mutation are excluded.

## Static closure

The actual FDE at `0xfbd9ec` covers 524 bytes and 153 instructions, ending
with the two-byte `repz ret`. Twenty alignment bytes follow separately. The
body has no call, jump, global/RIP-relative data reference or table. Full
GNU disassembly, complete body hash, exact FDE/CIE bytes and linkage are bound
by `static-lock.json` and the frozen oracle. All RELA records are scanned;
none names or overlaps the helper.

The full `.text` E8 pattern scan finds two candidates at `0x565ef7c` and
`0x565ef8e`. Both are qualified by complete caller decoding from its actual
FDE `[0x565eec0,0x565efe9)`, 297 bytes and 72 instructions. The older
`foundation-multiply-subtract-94` packet called that excluded neighboring
FDE 129 bytes; the actual extent is 297. Its original evidence is preserved.
No caller algorithm, register-indirect census or adjacent helper is claimed.

The exact bounded body SHA-256 is
`97980991da3bcee2127ab2633ca1c2b2a78df2a14079be4d2d07cf0def7da4ab`.
The four native builds are newly authored code and are not compared for
machine-code equality with that target hash.

## Independent authority and observed validation

The oracle was frozen at `2026-11-01T21:14:14.607430+00:00`, before either
Rust source file existed. Its SHA-256 is
`0daa4a76dda740b2925b2368b9b6bf575ed48208faf1edc80722a99ea9d093e0`.
It uses arbitrary-precision signed products with the zero correction,
immutable byte overlays, a single modular 448-bit sum, mathematical floor
and absolute value. Rust instead uses wordwise complement/carry, unsigned
products, a seven-word addition and cross-word shifts. The input-only client
receives no expected result or captured instructions.

All 13,604 fixtures match in each of four opt0/opt3 repeat native builds.
Same-optimization rlib, executable and stdout hashes repeat exactly. There
are 13,316 admitted image cases and 288 new span-refusal cases. Overlapping
coverage counts include 2,114 first negative-zero cases, 2,015 second
negative-zero cases, 6,280 changed second inputs after the store, 777 signed
448-bit sum wraps, 2,375 negative nonmultiples and 7,792 negative sums.
The corpus covers every byte offset where a 48-byte destination can overlap
the 96-byte source, every one-bit position of both 384-bit inputs, carry and
coefficient endpoints, deterministic random images and missing-span cases.
This is finite qualification; the proof covers the complete admitted domain.

All 15 compiled and executed wrong variants differ on admitted inputs:

| Wrong variant | Differing rows |
| --- | ---: |
| Omit negative high correction | 10299 |
| Repair negative-times-zero | 3799 |
| Truncate coefficients to i32 | 5957 |
| Treat negative magnitude as unsigned bits | 9395 |
| Omit addition carry | 4507 |
| Discard seventh sum word | 10127 |
| Shift by 31 | 11075 |
| Omit cross-word shifted bits | 10188 |
| Skip intermediate product store | 5820 |
| Negate without carry propagation | 6341 |
| Return result low word in RAX | 8483 |
| Return corrected high word in RDX | 6521 |
| Put first product high word in R15 | 10921 |
| Read sign from sixth word | 6429 |
| Take absolute value before floor shift | 2375 |

`observed/selected-controls.json` retains actual counterexamples and audited
admitted/all-row counts. All 31 structural corruption controls reject after
bypassing only full-file identity: operand/width/carry/shift bytes, store/load
order, return, padding, actual frames, caller edges and naming/code relocation
changes. A corrupted expected row yields exactly one native comparator
mismatch. These checks use neither captured-code execution nor an instruction
emulator.

Focused FDE/index legacy tests: 22/22 pass. Rustfmt, `make doctor verify
catalogue-check reproduce`, optimized-Python recorded-stream checks, manifest
and staged whitespace checks pass. No duplicate full-suite run, hosted CI,
original ABI, target-byte match, whole-node equivalence or component gate
completion is claimed. Parent independently reviewed the source, full proof
and complete GNU disassembly without a blocking finding; a committed native
replay is still a separate review step.

## Reproduce and inspect

From the repository root with authenticated pinned artifacts:

```sh
python3 -O research/work-items/RE-004-node94-six-word-combine-rust/validate.py
python3 -O research/work-items/RE-004-node94-six-word-combine-rust/verify_recorded.py
python3 -m unittest tests.test_fde_extents tests.test_elf_index -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-six-word-combine-rust/MANIFEST.sha256
```

Actual tools: macOS 27.0.1 arm64; Python 3.14.3; Capstone 5.0.7; GNU binutils
2.47.20260726; rustc 1.94.1 commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8. The validator accepts
installed `--rustc`, `--objdump` and `--output` paths while enforcing that exact
compiler. This is a real standalone library/client build without Cargo,
external dependencies or a fabricated node workspace.

`observed/commands.json` records command labels, argv (repository prefix only
normalized to `/repo`), outcome and exact stdout/stderr SHA-256. One
4,322,666-byte deterministic `raw-streams.json.gz` retains all **122** streams.
Ordinary streams are base64. Native stdout after the first run is stored as
base64 XOR bytes against that first same-length stdout, with an explicit
basis label, original byte count and original SHA-256. The verifier restores
every byte before checking its hash, command binding and actual mismatch
count. This is lossless compression, not normalized or discarded output.

The final validator was rerun after changing only the archive packing. Every
one of its 122 reconstructed stdout/stderr streams is identical to the prior
raw archive; `observed/lossless-repack-audit.json` retains both archive hashes
and all original raw bindings. Four build outputs and fifteen mutant outputs
remain separately identified even when bytes repeat. Readable GNU exports
strip trailing whitespace only, checked against the raw archive. The very
large GNU frames output is explicitly retained only as the selected actual
FDE/CIE records in `target.frames.txt`.

`observed/repository-checks.json.gz` records focused/global check output with
only local repository/home prefixes sanitized and both original/retained
hashes. `MANIFEST.sha256` binds every new source/evidence file except itself
and Python cache files. Live PRs/issues/recent merges and source were checked
before reservation and again before submission with no overlap (`overlap.json`).
Only the new source and packet are added. Pins, prior evidence, generated
catalogues and progress gates stay unchanged. New code/docs are MIT; imported
static bytes/disassembly retain the artifact's rights. No unlicensed source,
keys, secrets, captured execution, chain action or live networked node was used.
The unknown caller algorithm and original memory/fault environment remain
outside this reconstruction.
