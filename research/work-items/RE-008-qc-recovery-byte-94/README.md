# RE-008: QC row recovery-byte reader

This packet closes one native parsing gap left after timeout serialization
PR #1444: the final byte's width, cursor effects and charge/empty-input errors
in an actual QC vote-row reader. It does not recover a complete tag-2 decoder.

- Component: consensus, task RE-008; partial static research, all gates false.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred reference code copied.
- Coordinates: linked ELF VAs; intervals are half-open. New Python/research uses root MIT; target/reference rights remain separate.

## Exact field contract

The complete owner is `0x4c7e340..0x4c7e60d`, FDE `0xf443ac`.
The claim begins at `0x4c7e4f3`, after the raw20 reader and both preceding
group readers have returned their required success statuses. At that point let:

| Native field | Meaning used here |
| --- | --- |
| DWORD `[D+0]` | m, compared with exactly 1 |
| QWORD `[D+8]` | L, charge limit |
| QWORD `[D+0x10]` | P, input pointer |
| QWORD `[D+0x18]` | R, remaining input length |
| QWORD `[D+0x20]` | C, charge |
| RBX | O, row result/output pointer |

These are observed access widths/offsets. Decoder, charge, QC, signature and
recovery-byte names are inferred roles. The source enum/type names are unknown.
The local successful result stores the byte at `O+0x60`; the row data begins
after its eight-byte result prefix, matching row offset `+0x58` in #1444.

Let M=2^64-1. Under the premises below, normal-return behavior is:

| Condition, tested in order | C after | Input movement | Row result |
| --- | --- | --- | --- |
| m=1 and C=M | C | none | tag 1, kind byte 2 |
| m=1, C<M and C>=L | C+1 | none | tag 1, kind byte 2 |
| charge permitted and R=0 | C+1 if m=1, otherwise C | none | tag 1, kind byte 0, shortfall word 1 |
| charge permitted and R>0 | C+1 if m=1, otherwise C | P+1, R-1 | tag 0, byte `[P]` at O+0x60 |

For m!=1 this field bypasses charge and limit checks. This is a local machine
domain statement; reachability/validity of arbitrary source mode values is
unknown. In particular, the frozen mode2 example is conditional on entering
this field, not proof that a complete decoder admits mode2.

The charge store precedes limit comparison. On success the pointer store
precedes the remaining-length store, then the output byte and success tag.
Both error arms bypass input reads/movement and the recovery-byte output store.
Physical EOF can therefore retain a successful charge increment while leaving
the input cursor unchanged. No byte-value test lies between the byte load and
its output store: values 0..255 have the same one-byte projection here.
This does not establish cryptographic validity or valid recovery identifiers.

## Native proof and callers

The frozen windows are in `freeze.json`, and all instructions are retained in
`observed/native.gnu.txt` and `observed/native.llvm.txt`.

1. At `4c7e4f3/4c7e4f7`, DWORD m==1 selects charging. `4c7e505` compares C
   to M and `4c7e509` takes the error join before any state store on equality.
2. `4c7e513` computes C+1; `4c7e517` stores it. `4c7e51b` compares old C
   with L, and unsigned JAE at `4c7e51e` rejects equality and greater values.
   With no overflow this is equivalent to requiring new charge<=L.
3. `4c7e524` loads R. Zero takes `4c7e52b ->4c7e601`, setting EDX=1 and
   ESI=0, then joining error copying. This path does not load P or `[P]`.
4. Otherwise `4c7e535` loads one byte through P. INC RDI and DEC RSI are
   followed by stores to D+0x10 at `4c7e53e` and D+0x18 at `4c7e542`.
   The intervening success corridor contains no call or EDX/byte-value change.
   `4c7e5f7` stores DL at O+0x60; `4c7e5fa` zeros EAX before the common
   QWORD result-tag store at `4c7e4df`.
5. Charge failure prepares SIL=2 and EDX=1. The empty arm prepares SIL=0
   and EDX=1. The shared path stores SIL at O+8 and RDX at O+0x10, then
   stores row tag 1. This proves those stores, not initialization or meaning
   of all other copied error bytes. The original Rust error layout is unknown.

The complete local graph proves the byte read, pointer update, remaining
update and output-byte store occur in order before success. It rejects an
unreachable success as vacuous. The graph also requires the three earlier
read call nodes before field entry. It does not prove their return values.

Concrete caller/data bindings are retained in `observed/records.json`:

- Payload reader `47ad520..47ad690` calls raw20, the established u64 wrapper,
  then QC reader `4779eb0` at `47ad59b`. Its successful output places round
  at +0x50 and signer at +0x58, matching #1444's payload layout.
- QC reader `4779eb0..477a064` LEAs row callback `4c7e340` at `4779fdb`
  and calls vector reader `4589520` at `4779fea`.
- The vector saves incoming RDX at stack+0x28 (`4589531`) and calls that
  slot at `45896a1`; its row stride is 0x60. Vector allocation, cleanup and
  complete error propagation remain outside this field contract.
- The row reads raw20 at `4c7e358` and calls `466bf60` at `4c7e395` and
  `4c7e422`. That helper's four direct calls to the established u64 wrapper
  are bound as context. Their value/error/cursor semantics are premises here;
  they are not re-proved or claimed as new recovery.

The five complete FDE bodies total 2709 bytes / 662 instructions. Both native
decoders agree on every instruction boundary and byte. Exact FDE/CIE records,
body hashes and file offsets are retained. These are static selected-range
denominators, not reconstructed-byte matches or component coverage.

## Premises and limits

The relation assumes actual arrival at field entry, required prior successes,
ordinary callee/stack preservation, valid accessible input and output, stable
and disjoint decoder/input/output/stack regions, and nonwrapping pointers.
The field itself calls no helper. Whole-call composition also requires opaque
vector/allocator/earlier callees to preserve live storage and the callback slot.
Exceptions, concurrency, reentry, invalid pointers and full decoder reachability
remain outside scope. Success copies of preceding words and inactive error
bytes do not prove those bytes initialized. Wire tags, signature validation,
canonical integer decoding and complete consensus behavior remain unresolved.

## Reproduce and controls

Requirements are Python 3, GNU objdump 2.44, LLVM objdump 19.1.7, the hydrated
authenticated capture, and the repository's existing ELF/FDE readers. Commands
perform static analysis only; no captured program or instruction evaluator runs.

```sh
python3 research/work-items/RE-008-qc-recovery-byte-94/evidence.py \
  --llvm /path/to/llvm-objdump --out work/qc-recovery-fresh
diff -r research/work-items/RE-008-qc-recovery-byte-94/observed work/qc-recovery-fresh
python3 research/work-items/RE-008-qc-recovery-byte-94/verify.py \
  --llvm /path/to/llvm-objdump --report work/qc-recovery-validation.json
python3 -O research/work-items/RE-008-qc-recovery-byte-94/verify.py \
  --llvm /path/to/llvm-objdump --report work/qc-recovery-optimized.json
python3 -m unittest discover -s tests -p test_qc_recovery_byte94.py -v
(cd research/work-items/RE-008-qc-recovery-byte-94 && sha256sum -c MANIFEST.sha256)
```

`boundaries.csv` freezes 12 manually derived boundary cases, including C=M,
C=L, R=0 and charge-before-EOF behavior. `project_field` is their mathematical
relation, not a CPU evaluator or Rust implementation. Six focused tests also
exercise all 256 byte values at two positive lengths in both selected modes,
and assert the exact state-write order and distinct error kinds.
The boundary values are field-entry states; their reachability from a complete
wire message is not established.

The verifier rejects 12 window byte-identity changes plus wrong-image/mapping
controls. Six real, inert mode 0600 mutant ELF copies are decoded by both tools
with identity/window checks disabled: EOF bypass, unreachable success, aliased
charge store, two-byte load, shortfall 2 and an equality-admitting limit branch.
The first two fail local graph properties; the others fail independent operand,
width or guard relations. `validation.json` retains their changed bytes and
observed rejections. These finite controls do not constitute a complete x86
semantics proof. Two fresh exports must match every retained output byte.

Scope/ownership and repository check receipts are in `scope-check.json` and
`repository-validation.json`. All gates stay false. Full `make test` remains
with coordinator integration; no hosted-CI result is claimed. Next question:
qualify the prior four-word reader's cursor/charge composition for one failed
integer, without treating its normal-success premise as unconditional.
