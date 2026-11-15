# RE-001: node115 TLS runtime-context installation coordinates

- Task: RE-001; component: Node runtime and gossip (partial static mapping).
- Target: Linux x86-64 hl-node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Discovery baseline: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Refreshed replay baseline: `a8a165e65d53abc1c996bcc9b609749529cfc41a`.
- Status: observed instructions and native FDE; inferred runtime-context role.
- No component/progress gate requested. No reconstruction/equivalence claim.

## Question and prior gap

`../RE-005-node115-remaining-edges/README.md` documents the TLS accessor
`0x5cf2b50..0x5cf2c34`, destructor `0x5cdf410..0x5cdf457`, and cell
`fs:-0x1130`, but explicitly leaves installation of a live handle outside
its traced chain. This packet identifies one installer site, not all writers.
Existing wrapper exports may already contain these bytes; the contribution
is the explicit cell-writer relation and replayable local control/data flow,
not discovery of a previously unexported function or a new dependency version.

## Observations

Coordinates are ELF VAs, not assumed Ghidra analysis addresses. The native
unwind FDE contains `0x15d6fd0..0x15d8447`; no assertion that this is the
only possible source-level function partition is made.

1. `0x15d7146`: r14 becomes -0x1130. At `0x15d7159` the byte
   `fs:[r14+0x48]` is read. The comparison with 1 and direct taken edge
   `0x15d7162 -> 0x15d728c` give an already-initialized path with no
   intervening call or r14 overwrite. The alternate registration block at
   `0x15d7276` passes the known destructor address `0x5cdf410`, calls via
   slot `0x64e0510`, and stores state byte 1; that callee is not analyzed here.
2. `0x15d728c`: counter `fs:[r14]` must equal zero to fall through the
   branch at `0x15d7291`. The other edge leaves this local installation
   block at `0x15d73b7`; no claim about that arm is made.
3. `0x15d7297` sets the counter to -1. The stack words at rsp+0xa0 and
   rsp+0xa8 load into rsi and rax. `0x15d72b9` atomically increments the
   word pointed to by rax, returning its previous value in rcx. No rax
   write occurs between its load and the TLS pointer store.
4. If rsi == 1, edx remains 1 and a nonnegative old atomic value reaches
   `0x15d72d9`. Otherwise the nonnegative arm clears edx to 0 before the
   same join. Both negative arms leave the local block at `0x15d8065`.
   These tag meanings are inferred, not recovered Rust enum declarations.
5. The join loads the old TLS tag/pointer at +8/+16, then stores the new
   tag at `0x15d72e3` and rax at `0x15d72e8` (`fs:-0x1120`). The counter
   increments at `0x15d72ed`. Thus this is a concrete writer of the pointer
   consumed by the prior accessor, not merely a .tdata initializer or dtor.

The successful local path dereferences rax before installing it. This is
not proof of runtime validity, non-nullness under every environment, or
that execution reaches this block. The original stack-word producer,
external registration callee, later restoration/drop paths and whole-wrapper
CFG are unmeasured. The already-initialized edge alone supports the local
writer relation; no ABI assumptions about the alternate callee are needed.

## Reproduce and controls

From repository root, with Python 3 stdlib and GNU binutils (observed 2.42):

```sh
python3 research/work-items/RE-001-node115-tls-context-install/check.py
python3 tests/test_node115_tls_context_install.py -v
objdump -d -Mintel --start-address=0x15d7146 --stop-address=0x15d7310 artifacts/node/115/hl-node
readelf --debug-dump=frames artifacts/node/115/hl-node
```

`check.py` authenticates the entire target, maps each selected VA through
one file-backed executable PT_LOAD, checks exact instruction bytes without
normalization, and checks the native FDE. Three windows cover the anchor,
registration block, and contiguous counter/tag/pointer installation block.
`evidence.json` records the exact byte denominator, offsets, hashes and FDE.
`disassembly.txt` is a bounded raw native export, not imported source.
`local-checks.json` retains exact local commands, versions and observed results.
Tests replay real captured bytes before exercising per-byte corruption,
truncation, coordinate, wrong-target, frame and ambiguous/missing-mapping
controls. They validate this record, not independently reconstructed runtime
behavior. Required project checks and independent validation are separate.

## Rights, comparison and next question

New verifier/tests/prose are independently authored; only short literal
instruction windows are retained as research evidence. No inferred can1357
source, crate source or transplanted binary implementation is included.
No captured executable, network service or chain action was run. No Rust
implementation or comparator was attempted; whole-function, whole-ELF,
helper/data/relocation closure and runtime equivalence remain unmeasured.
No masks, completion percentages or build-provenance claims are introduced.
Next bounded question: trace the producer of rsp+0xa0/+0xa8 to determine
which runtime-handle alternative reaches this installation site.
