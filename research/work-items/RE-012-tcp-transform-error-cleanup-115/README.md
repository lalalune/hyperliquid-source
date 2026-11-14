# RE-012: node115 TCP transform-error cleanup handoff

- Component: transport; bounded static RE-001/RE-012 question, not completion of issue #3911.
- Source baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Target: node #115, Linux x86-64 ELF, 105,896,032 bytes; SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Result: instruction-backed local error-to-cleanup/return handoff. No component
  gate change, captured execution, network action, or original-source claim.

## Question and distinct result

The existing frame-policy and LZ4 decoder packets deliberately exclude native
async ownership/result behavior. This packet joins their actual producer and
consumer at **one transform error branch**, rather than adding another scalar
frame adapter. It answers whether a returned decoder error reaches a concrete
buffer-cleanup call, and what local ownership/state stores follow that call.
It does **not** answer whether the surrounding connection is reusable or closed.

All addresses below are linked ELF virtual addresses. `evidence.json` contains
file offsets, exact selected instruction bytes, FDE/CIE records and relocation
bindings. The new verifier independently maps PT_LOAD segments, scans unwind
records and decodes the selected relative destinations. It does not emulate or
execute proprietary instructions.

## Manual causal derivation

1. Reader `0x2b788e0..0x2b79e2e` passes an output-record address at stack+0x50,
   input pointer owner+0x68, input length owner+0x70 and maximum owner+0x28.
   Call `0x2b79ace` uses slot `0x64e7790`; its unique ELF RELATIVE writer
   resolves to decoder `0x477f8c0..0x4780322`.
2. Existing decoder proof supplies the logical error interpretation. Its
   successful stores at `0x477ff84..0x477ff8b` are capacity, pointer and logical
   length. Capacity is the zero-extended u32 prefix, hence cannot equal
   `0x8000000000000000`. Header-error stores at `0x477ffd3..0x477ffe1`
   and shared decoder-error stores at `0x47800e8..0x47800f6` instead put an
   opaque factory result at output+8 and that sentinel at output+0. These are
   concrete stores, not an asserted Rust Result/Vec ABI or error-box layout.
3. Reader loads the first word into R12 and second into RBP, compares R12
   with that sentinel at `0x2b79ae8`, and JNE `0x2b79aeb` takes the nonerror
   edge to `0x2b79b7d`. Equality falls through to `0x2b79af1`.
4. On equality, it tests owner+0x60. Zero capacity skips the call through JE
   `0x2b79af8 -> 0x2b79b06`. Nonzero capacity passes `(owner[+0x68],
   owner[+0x60], 0)` in RDI/RSI/RDX through call `0x2b79b00`, slot
   `0x64df4a0 -> 0x635de30`. Existing allocator evidence identifies that
   destination as the fast deallocator with slow fallback, not a promise of
   OS release. This is precisely one local deallocation **handoff** under
   valid allocation/normal-return premises; transitive destruction is not
   reconstructed here. This error arm does not test owner+0x49 before calling.
5. Both capacity alternatives store zero to owner+0x49 at `0x2b79b06`, then
   jump to `0x2b79b4e`. The join stores an earlier stack+0x1a0 word at the
   caller output+0, RBP (the opaque error handle) at +8 and live R15 at +16,
   sets AL=1, stores it to owner+0x48, restores registers and returns at
   `0x2b79b7c`. **The earlier stack word and R15 are not established as an
   error discriminant/valid length by this bounded slice.** Do not interpret
   the third output word as an initialized error payload. The ownership byte
   is cleared; the pointer/capacity cells themselves are not zeroed here.
6. This equality route skips the nonerror block beginning `0x2b79b7d`,
   including its timing/metric call context. That is a local control-flow
   observation, not a promise about every instrumentation site in the reader.

The branch destinations and call slots are decoded again from signed relative
operands by `verify.py`, not accepted from disassembler labels. Exact bytes are
checked below the full capture hash as well. FDE parsing uses the observed
32-bit PC-relative initial-location format; exact CIE records lock that premise.
This is not a general-purpose ELF or arbitrary-unwind-format parser.

## Provenance, rights and reproducibility

The only newly disassembled reader interval in the bounded discovery was
`0x2b79aa3..0x2b79c86` (483 bytes). Later reading reused existing native exports;
no second target extraction or captured execution occurred. New instruction
clauses reuse authenticated existing GNU exports listed and hashed in
`evidence.json`: frame-plan reader and LZ4 decoder. Interpretation also credits
`RE-012-lz4-decode-115/PROOF.md`,
`RE-005-node115-tls-value-object/dealloc.objdump.txt`, and
`RE-001-node115-lu-slow-dealloc/README.md`. Existing excerpts remain imported
material under their original rights; this independently authored research and
verifier do not relicense the captured binary or copy inferred source.

From repository root, with the pinned LFS artifact materialized:

```sh
python3 -B research/work-items/RE-012-tcp-transform-error-cleanup-115/verify.py
python3 -B -m unittest discover -s tests -p test_tcp_transform_error_cleanup_115.py -v
make doctor
make verify catalogue-check
make reproduce
make test
```

Python standard library only; no setup/install hook, network or target execution.
Original runner: Python 3.11.11 / GNU binutils 2.40. The bounded recovery
used Python 3.12.3 / GNU binutils 2.42, NumPy 2.3.5 and Rust 1.95.0;
see `environment-recovery.json` and `recovery-scoped-run.json`. Historical
packet versions (3.14.5 / 2.45) are not claimed as this runner's tools.

## Evidence limits and next question

Ten selected instruction-clause groups, three exact owner FDE/CIE records and
two unique relocation writers are structural evidence, **not** counts of source
reconstruction or behavioral equivalence. Tests corrupt one byte per clause
group, each selected FDE range, each associated CIE and both relocation targets
below capture identity, plus reject wrong/truncated captures. They show that
the checker rejects those corruptions; they do not prove the manual derivation
or execute error cases in the proprietary program. No native/model oracle or
allocation-failure/unwind proof is claimed.

Required independent validation remains separate from local test results; see
`VALIDATION.md`. No full gate, deployment, hosted CI, acceptance or payment claim.
The next semantic question is the caller-output first word and outer future's
post-return handling. It needs its own bounded scope, not an inference that
clearing one byte makes a network connection safe to reuse.
