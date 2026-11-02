# RE-005: actual nested hash enum admission, output and ownership

The actual255eba0 caller composes a u32 selector with the credited single-map,
fixed32/two-map and three-record decoders. This packet closes its conditional
field/error/counter/ownership relation under stable mode1, limit1000 and C0..1000
at THIS helper's entry. The generic three-arm GreetingHash schema is already
credited to stream-msg-codecs-94; primitive/child semantics and clone contexts
remain credited to1779/1816/1853 and their predecessors.

The selector charges4 before input and accepts u32 widths1/3/5, including
nonminimal forms. FD/FE/FF are errors expected2/found3,4,12 in both fast and
slow paths. Fast means remaining>4 and leaves an invalid marker unread; slow
consumes the marker. Unknown decoded tags return active diagnostic type/range
references. The actual outer error is QWORD3. The initial error8 hypothesis
was rejected by the native store BEFORE any new oracle;8 belongs to an
enclosing wrapper. It is not a post-model expectation repair.

Tag0 succeeds with outer0, exact fixed32 at+8, map root/height/length40/48/56.
For original attempts M, C+44+96M<=1000 is required; M<=9 and complete charge
is C+44+85M. Tag1 succeeds with outer1 and an additional independent map at
64/72/80. BOTH C+44+96M<=1000 and C+52+85M+96N<=1000 must hold. Total attempts
are at most10, attained only with M2..9,N10-M and C<=11M-12. The child-fresh
eleven-attempt witness(10,1) cannot be reached after this selector charge.
Original attempts include duplicates; cardinality/final-charge-only tests
misstate admission. At fresh C0, consumed success wire is at most883bytes
for tag0 and985bytes for tag1, with final charges809/902 respectively. These
are helper consumption bounds and do not constrain unused suffixes or a full
enclosing message.

Map associations retain unsigned20byte key order and last value;72byte value
movement includes65active value bytes. Each nonempty map owns one symbolic
1024byte leaf. Tag1 later failure releases a partial second map before the
completed first map. The enum adds no extra map release or success allocation.
Tag2 can read at most its two leading u64 scalars. Each charges8, then the
first2048byte array charge necessarily exceeds1000 BEFORE any array byte is
read. Its0x1830box branch is unreachable in this domain. Scalar FE/FF errors
use expected5, unlike the selector/map families. Arbitrary limits, including
the separately credited3B path, are excluded from this unreachability claim.

Unknown-tag active output is outer3/kind5, offending DWORD+12, symbolic
GreetingHash reference+16, length12at+24 and symbolic0..2range reference+32.
Other ordinary errors retain reached stores/cursor and active kind at+8,
needed+16 for kind0, expected/found+9/+10 for kind3. Inactive stack cells,
empty map height and concrete ASLR pointer bits are excluded.

PROOF.md is the unchanged manual pre-checker snapshot; its remaining-work
wording describes that earlier time. FREEZE-CHECKPOINT.json predates the new
whole-caller checker. Sealed supplied-field sources construct expectations
without parsing arbitrary bytes. PRIOR-FROZEN.json preserves38172V1cases;
V2 adds478distinct high-bit key-order cases before checker creation, for38650.
No V1 expectation was changed. The extracted single-map constructor adds
explicit zero-byte availability guards for supplied invalid-marker metadata
before this new freeze; original1779authorities remain unchanged. See
AUTHORITY-LINEAGE.json for exact original/extracted hashes.

The separate byte parser maintains mathematical leaves and compares42wrong
rules against the sealed authorities. Cases include all1001entry counters,
u32 marker/width boundaries, unknown diagnostics, joint original-count limits,
overflow store order, duplicate histories, all fixed32bits and key/word bits,
selected full wire cuts, suffixes, child cleanup and array/box exclusion.
These are independently constructed field mathematics, never captured outputs,
CPU instruction evaluation or native equivalence. Replay changes only the
recorded wall-clock freeze timestamp; all other metadata, sources, proof and
compressed expectation bytes must match exactly.

Reviewed base e5c9b6436876b2a4a39daef813171f9879317699; node94 Linux x86-64
91774280byte ELF SHA2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Identity includes25completeFDEs/21517bytes/4701GNUrows,30initialRELA,
48direct transfers and34data extents1045bytes. Raw GNU/LLVM, full FDE/CIE,
initial helpers/data records and every byte are retained without masks.
These include credited dependencies and excluded split/terminal/unwind/box
context. Identity denominators are not semantic coverage or new recovered
byte credit. Initial file addends do not prove loaded pointers/callees.

The seven-page non-atomic open inventory contained506PRs and no focused
actual-caller/error-site match; own1816child context was found and credited.
Canonical schemas/shared range209410and all child/primitive packets remain
credited. Recheck live ownership/base/feedback before submission.

VALIDATION.json records observed checks and gaps. Full make test is NOT RUN:
flat discovery includes captured-instruction evaluators outside authorization.
No captured execution, CPU interpreter/symbolic CPU, compiler/Rust build,
hosted CI, arbitrary modes/limits, faults/aliases/races/unwind/allocation
failure, full trees/allocator, original nominal types/ABI, full greeting or
component gate is claimed. All global registries, pins and gates stay as-is.
New code/docs are MIT; artifact excerpts retain their original terms.

Reproduce against an authenticated non-executable node94, using fresh outputs:

```sh
python3 -B survey.py --binary /absolute/node94.elf --output /fresh/observed
python3 -B verify.py --binary /absolute/node94.elf --receipt /fresh/integrity.json
python3 -B check_bindings.py --binary /absolute/node94.elf --receipt /fresh/bindings.json
python3 -B crosscheck_llvm.py --binary /absolute/node94.elf --output /fresh/llvm
python3 -B regenerate_expectations.py /fresh/expectations
python3 -B check_relation.py /fresh/relation.json
```

Repeat optimized Python, compare exact mode receipts, and run root doctor,
verify, catalogue-check and reproduce. Identity/control success alone does
not prove the conditional semantic relation or satisfy a component gate.
