# RE-001: one additional TokenSpec writer caller

- Component: serialization; one bounded static RE-001 caller question.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `a8a165e65d53abc1c996bcc9b609749529cfc41a`.
- Independent stdlib static parsing and GNU objdump, no target execution/emulation.
- No implementation, whole-schema, registration-policy or completion-gate claim.

## Gap and observation

`RE-005-node115-token-id-derivation` records that the `TokenSpec` field writer
`0x3c453f0` has two more callers, in FDEs `0x3c44290..0x3c446c4` and
`0x41b3000..0x41b30fe`, and that the pair serializer `0x41d4b30` also calls it.
`RE-001-node115-tokenspec-extra-caller` (#6630, merged) traced the first of
the two named callers. This packet traces the second, `0x41b3000`, and nothing
else. A raw `e8 rel32` byte scan of `.text` for the writer address finds
exactly three direct call sites (`0x3c443f7`, `0x41b3083`, `0x41d4baf`); the
scan is byte-level, and only the site in this FDE is confirmed at instruction
boundaries by the objdump cross-check.

Actual FDE `0xe7c11c` and its CIE establish `[0x41b3000,0x41b30fe)` (254 bytes).
The body hash is retained but it is not a full semantic analysis. The whole
FDE is retained as the excerpt (254 bytes), with raw bytes, instruction
boundaries and unwind records in `discovery.json`; there are no normalized
comparisons.

At entry, incoming R8 is saved in R15, RSI in R14 and RDI in RBX, and R12 is
set to the result head `0x8000000000000000`. A guard compares zero with the
qword at incoming RSI and branches on overflow: the fall-through path calls
string writer `0x41c6110` with the field at incoming RSI+0x28, the taken path
calls string writer `0x41c6610` with the whole incoming object. Both paths
require a return of 2 and store the head (`0x8000000000000000`, or that value
plus 4) into the output object at incoming RDI before reaching the writer.
On the taken path the counter at incoming RSI+0x20 is incremented unless it
is already `0xffffffff`, in which case control reaches the abort branch at
`0x41b30f1`.

At `0x41b3083`, the direct call (`e86823a9ff`) reaches `0x3c453f0`. Thus this
writer receives the output object at incoming RDI, the serializer pointer at
incoming R8, and the field at incoming RSI+0x28. The immediate post-call jump
goes to the shared epilogue at `0x41b30a2`, which returns the output object.

The taken path also has a second helper edge: when the qword at incoming RSI
differs from the head, control reaches `0x41b30b3`, which calls `0x3c45120`
with stack-local output storage, the incoming R8 serializer pointer and the
incoming object, then either increments the same counter and stores the head,
or copies the helper result into the output object. The abort branch loads a
RIP-relative pointer at VA `0x6481ff8` and calls through slot `0x64df520`; the
contents of that pointer and slot are not interpreted here. No field-name
literal is pinned for this caller: the writer handoff is register-only.
`TokenSpec` is a contextual role label from RE-005, not a recovered Rust type.

Register-flow interpretation assumes the usual callee-saved-register
convention at the intervening calls; no runtime behavior or public ABI is
established.

## Reproduce and controls

From repository root:

```sh
python3 research/work-items/RE-001-node115-tokenspec-second-caller/verify_target.py --with-objdump
python3 -m unittest discover -s tests -p test_node115_tokenspec_second_caller.py -v
```

The verifier checks full digest before any native tool. It maps ELF sections,
locates the unwind-index entry, checks actual FDE/CIE records, decodes the extent,
checks body/excerpt bytes and selected instruction operands, then optionally
cross-checks the contiguous excerpt with GNU objdump. Discovery used GNU
binutils 2.42; cumulative discovery timing is recorded in `discovery.json`.
The retained excerpt is the whole caller FDE. Controls mutate every bit of
selected operand/opcode groups in a private bytearray, plus digest and FDE
pin. These are evidence-integrity controls, not behavioral equivalence or
tests of a reconstructed serializer.

## Results and limits

Actual execution results are retained separately in `local-proof.json`.
The local proof predates independent validation; independent check results are
reported in the PR and controller validation record. No hosted-CI or full-suite
pass is claimed here. Imported binary bytes retain upstream rights; newly authored code
and documentation use the repository MIT terms. There is no whole-component
function denominator, Rust implementation, source-built node, helper closure,
network/chain operation, signing or paid dataset. All gates stay false.

Next: the RE-005 open question — what the three request generators
(`0x2c54de0`, `0x55c7640`, `0x55c78a0`) and their six callers pass in the
0x78-byte request, where the state word `+0x28` is incremented, and what the
tree branch of `0x3f19f10` stores next to the id — is outside this bounded
packet.

## Audit note

`setup-audit.json` records the inspected install/build hooks and tooling at
the source base. Its `audit_execution` value is the first 32 hex characters
of the SHA-256 of the sorted `path sha256` lines of the audited files.
