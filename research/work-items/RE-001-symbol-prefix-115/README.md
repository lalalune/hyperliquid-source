# RE-001: executable unqualified-symbol prefix contract

One bounded exchange reconstruction question: once the unqualified lane is
selected, which exact input bytes return immediately, reject, or reach the
first allocation with which numeric value and decimal bytes? This advances
the approved independent Rust reconstruction scope; it does not claim a bug
in the deployed node.

Target Linux x86-64 node115,105896032 bytes, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base05bc2de303c05525b71e7e257426e741bc66a390; unrebased ELF VAs.
Merged #2576 first bound the complete resolver and canonical suffix relation.
Its original-byte/FDE findings are credited, and its opaque helpers remain
opaque. Live all-state outcome/symbol, outcomeToken/Rust, prefix VA and
normalization queries found no competing implementation within search limits;
open issue searches found no assigned task for this question. #2835 concerns
a distinct consuming parser at `0x2e564b0`.

## Actual scope and observations

The single complete containing owner is `0x46dbba0..0x46dc0ac`,1292 bytes /315
instructions. Those are static context previously mapped by #2576 and receive
no new selected-byte credit here. Actual qualified replay begins at
`0x46dbd05`, with R14=input pointer, R15=exact byte length and RSP=a valid
existing synthetic frame. Remaining registers/flags start unknown. This is
an independently fresh lane premise, not a fabricated split/helper result or
proof that a whole native caller reaches it for every supplied string.

The selected508 bytes/143 instructions all execute in the frozen corpus. The
selected spans exclude the unused qualified-lane cleanup and the unreachable
empty-after-sign block; full containing-body exports remain intact. GNU and
Capstone agree byte-for-byte; the evaluator's decode agrees at all selected
starts. Actual FDE/CIE bytes and the200-byte digit-pair table at `0x46ea12`
are bound in FREEZE.json. The inline formatting code is observed as part of
this prefix; no unsupported library ownership or additional dependency byte
credit is claimed.

Observe only one of:

- `R`: execute actual RET with tag0; inactive RDX is ignored.
- `D:0` / `D:1`: execute actual RET with tag1 and the active RDX, for exact
  four-byte USDC/PURR respectively.
- `A:<u64>:<hex>`: stop **before** the allocation call `0x46dbf19`; observe
  R15, R13 and the significant decimal stack bytes addressed by RBX. This
  is not a native return or final accepted symbol.

Ordinary RET restores RSP to entry+0x150 and checks the actual return marker.
Input bytes remain unchanged. Reads/writes are bounded to the explicit input,
existing frame and immutable original digit table; all calls are forbidden.
No allocator, copy, comparison or metadata callback is mocked or executed.

The original scanner provisionally accepts one leading plus and zeros,
including more than20 zeros, while rejecting nondigits and u64 overflow.
It computes the canonical decimal bytes inline. Thus `outcomeToken001`
reaches `A:1:31`. The subsequent allocation/copy/comparison is outside scope;
the existing parent explains why that noncanonical spelling ultimately
rejects. Moving canonical spelling or side/metadata admission into this API
would wrongly change the observed stage.

## Before-source evidence and independent implementation

Original expectations were sealed in Git commit
`66e9b42c1646be7380bf801f00c7882cb4d47135` before any new Rust file existed.
Freeze completed in110.584s at serial0.10 duty.4072 distinct byte inputs yield
2574 rejection returns,2 direct returns and1496 allocation frontiers. Inputs
include byte substitutions over all256 values at nine relevant positions,
short/long parser boundaries, powers of ten, u64 ceiling/add/multiply overflow,
sign-only strings, embedded NUL/non-ASCII and long leading zeros. Four of
the nine selected positions overlap the prefix; two are near the short/long
digit-count boundary. All positions and inputs are reproducible in native.py.
The finite corpus is not exhaustive input or native-ISA equivalence.

Twelve real copy-on-write instruction/data changes alter actual observations:
both direct shortcuts, both prefix halves, sign, digit limit, short multiply,
long multiplication overflow, addition carry, formatter lane/store and the
original digit-pair table. Original capture SHA is checked before/after; no
original export or imported artifact changes.

The independent Rust library uses checked arithmetic and a fixed array decimal
conversion rather than reproducing instruction bytes or building artificial
native code. Its input-only client receives hex input, never expected values,
and runs with an empty working directory. The public builder compares opt0/3
results to freshly regenerated sealed original streams and runs ordinary source
smokes and compiled semantic variants. Build and repository results are recorded
in rust-results.json, repository-checks.json and validation.txt after completion.

The only task-local ISA additions interpret actual MOVD/PINSRW/MOVD operands
for this formatting path, preserving upper-vector/word-lane semantics and
unknown-value rejection. They do not call a Python decimal formatter as a
substitute for original code. Focused tests exercise the three actual forms;
the real lane/store byte controls independently change their output.

## Reproduce and limits

From the repository root, use the commands in the source README. Run packet
hashes from the same root: entries in MANIFEST.sha256 are root-relative.
`freeze.py` intentionally refuses once the new Rust exists; use native.verify
or build.py to regenerate and compare the already-sealed original corpus.
All raw commands, original streams, compiler/client/test outputs and failed
attempts are retained outside the committed packet; durable summaries and
input/source hashes are retained here. No failed or incomplete run is called
a pass.

No complete resolver/qualified grammar, actual allocation lifetime, canonical
comparison return, side/metadata result, original ABI, compiled-byte identity,
Linux executable build, container, live node or whole-component claim exists.
All92 gates remain false. New analysis/source MIT; the mmap helper and builder
scaffold reuse licensed project work with credit to the book-source/margin-row
packets. No unlicensed inferred source was read or copied. Slop/OAuth deferred
by the operator. No captured process, Unicorn, service, chain/signing or wallet
operation runs.

Actual final validation: owned-source build202.503sPASS; seven focused tests44.016sPASS, formatting/Clippy/twelve packet-integrity tests/doctor/verify/reproduce PASS (initial scoped407.388s). The first catalogue pass preceded staging new source; final staged catalogue/check separately PASS in116.121s, correctly including35 Rustareas and561 research packets. Catalogue-only #2655 immutable-snapshot overlay is disclosed by validation-overlay.json and restored before reproduce/commit; no duplicate helper fix or unmodified-head catalogue pass is claimed. Own full upstream CI is pending. Build-attempts.json preserves the first smoke-miss failure and unchanged golden provenance.
