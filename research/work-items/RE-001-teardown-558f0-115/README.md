# RE-001: map node #115 guarded teardown 0x5d558f0

Bounded question: what does the 119-byte routine at 0x5d558f0 tear
down, in what order, and where is it used — including the
condition-variable destroy wrapper it calls?

## Answer, end to end

The routine takes one object pointer in rdi, returns nothing, and
frees six fields in a fixed order. It writes nothing back to the
object — no field is cleared, no size is reset.

1. Refcounted field: pointer at object +0xc0. If null, skip;
   otherwise call the shared release helper 0x5d350c0.
2. Guarded cell: pointer at +0x98. If null, skip. If its first
   qword is nonzero, the routine calls std::terminate and nothing
   later runs. If the first qword is zero, the cell is freed with
   the sized delete passing (cell, 8) through the `_ZdlPvm` PLT
   stub.
3. Condition variable: the inline variable at +0x40 is destroyed
   unconditionally through the wrapper 0x60d5470 — there is no null
   test, because the variable is not a pointer.
4. Array at +0x38: if null, skip; otherwise delete[] through the
   `_ZdaPv` PLT stub.
5. Array at +0x28: same rule.
6. Array at +0x18: if null, return; otherwise tail-jump to the
   same delete[] stub, so the stub's return is the routine's
   return.

The wrapper at 0x60d5470 (144-byte FDE) is pinned whole, not by
call shape only. It saves a stack canary, calls
pthread_cond_destroy on its argument, and returns normally when
the return code masked with ~0x10 is zero (codes 0 and 16) or
exactly 110; any other code takes an abort path that calls a
diagnostic helper at 0x61d1f30, prints via __fprintf_chk,
disposes the stack string and aborts. Its trailing endbr64 plus
jump fragment at 0x60d54f7 targets a dispose-then-terminate
fragment of the preceding function and is not on the wrapper's
normal or abort return paths.

## Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): the routine has exactly 2 direct calls, 0 tail jumps,
across 2 distinct caller FDEs (0x5d8479c..0x5d85475 at 0x5d84c07,
0x5d878f0..0x5d887b0 at 0x5d886cb). Both consumers sit in teardown
sequences of a larger rbx holder: each first destroys two
subobjects through the 0x5d5b300/0x5d5b4c0 pair, then calls this
routine, then releases the holder +0x758 pointer through the
shared helper and calls 0x60d5170 on +0x700. Caller A passes a
stack object (rbp-0x3a0); caller B passes rbx+0x760. Caller bodies
beyond those sites are not pinned. There are 0 RELATIVE
relocations for 0x5d558f0 and no stored qword: the routine is
reached only by code, never by data. The wrapper itself has 34
direct calls across 17 caller FDEs (wrapper_callers.tsv); both of
this routine's consumers also call it directly for their own
condition variables.

## Evidence and honesty notes

- Target: node #115, artifact `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json).
- `main.txt` and `wrapper.txt` are the RAW disassembly texts
  exactly as objdump emitted them for the whole functions (FDEs
  0x5d558f0..0x5d55967 and 0x60d5470..0x60d5500); the only
  modification is the header normalized to the bare binary name.
  Instruction-level detail lives in those files only;
  `records.json` carries semantic records, not a per-instruction
  list. Mnemonics such as `endbr64` are genuine instructions
  present in the target binary, not placeholders.
- The release helper 0x5d350c0 is pinned by call shape only in
  this packet; its internal release contract is established in
  the RE-001 derived-destructor packet for the same helper
  address. The wrapper's diagnostic helper 0x61d1f30 is likewise
  pinned by call shape only.
- What the refcounted object, the cell and the three arrays
  contain, and the owning class name, are recorded as unknowns
  in records.json, not claimed.
- Environment limits: this VM has no cargo/rustc, no git-lfs and
  no Ghidra; the model in tools/ and its tests are Python only,
  and pytest is not installed, so the test functions are invoked
  directly.

## Verification

Run from the repository root:

    python3 research/work-items/RE-001-teardown-558f0-115/verify.py

It checks the binary digest and provenance binding, the manifest,
byte-for-byte regeneration of the excerpts and frames, every
excerpt instruction line against the raw binary, every FDE line
against fresh readelf output, both censuses incl. exact site
lists, the empty relocation census, the semantic-only shape of
records.json, and the model spot checks plus every test in
tests/test_teardown_558f0_115.py.
