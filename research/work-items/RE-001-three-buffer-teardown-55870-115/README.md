# RE-001: map node #115 three-buffer teardown 0x5d55870

Bounded question: what does the 114-byte routine at 0x5d55870 tear
down, in what order, and where is it used?

## Answer, end to end

The routine takes one object pointer in rdi, returns nothing, and
frees four fields in a fixed order. It writes nothing back to the
object — no field is cleared, no size is reset.

1. Buffer A: begin at object +0x1e0, end at +0x1f0. If begin is
   null, skip; otherwise sized delete (begin, end - begin) through
   the `_ZdlPvm` PLT stub.
2. Buffer B: begin at +0x1c8, end at +0x1d8, same rule.
3. Buffer C: begin at +0xc0, end at +0xd0, same rule.
4. Refcounted field: pointer at +0x48. If null, return; otherwise
   tail-jump to the shared release helper 0x5d350c0 with the
   pointer, so the helper's return is the routine's return.

Two edge semantics are pinned, not assumed: an empty but non-null
buffer (end == begin) still reaches the sized delete with size 0,
because only the begin pointer is null-tested; and a null buffer
skips only its own free — the later phases still run.

## Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 25 direct calls, 0 tail jumps, across 20
distinct caller FDEs. Three callers invoke it more than once
(0x5f9521e three times, 0x6086e00 three times, 0x5f98c8e twice).
There are 0 RELATIVE relocations for 0x5d55870 and no stored
qword: the routine is reached only by code, never by data. The
caller bodies beyond their call sites are not pinned.

## Evidence and honesty notes

- Target: node #115, artifact `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json).
- `main.txt` is the RAW disassembly text exactly as objdump
  emitted it for the whole function (FDE 0x5d55870..0x5d558e2);
  the only modification is the header normalized to the bare
  binary name. Instruction-level detail lives in that file only;
  `records.json` carries semantic records, not a per-instruction
  list. Mnemonics such as `endbr64` are genuine instructions
  present in the target binary, not placeholders.
- The release helper 0x5d350c0 is pinned by call shape only in
  this packet; its internal contract is established in the
  RE-001 derived-destructor packet for the same helper address.
- What the three buffers contain, and the owning class name, are
  recorded as unknowns in records.json, not claimed.
- Environment limits: this VM has no cargo/rustc, no git-lfs and
  no Ghidra; the model in tools/ and its tests are Python only,
  and pytest is not installed, so the test functions are invoked
  directly.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-three-buffer-teardown-55870-115/verify.py

It checks the binary digest and provenance binding, the manifest,
byte-for-byte regeneration of the excerpt and frames, every
excerpt instruction line against the raw binary, every FDE line
against fresh readelf output, the full 25-site census plus the
empty relocation census, the semantic-only shape of records.json,
and the model spot checks plus every test in
tests/test_three_buffer_teardown_55870_115.py.
