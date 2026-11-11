# RE-001: map node #115 three-release routine 0x5d55830 with its shared release helper pair

Bounded question: what does the 58-byte routine at 0x5d55830
release, in what order, through what shared helper — and where is
it used?

## Answer, end to end

The routine takes one object pointer in rdi, returns nothing, and
releases three refcounted pointers in a fixed order. It writes
nothing back to the object — no field is cleared after its release.

1. Pointer at +0x28: if null, skip; otherwise call the shared
   release helper 0x5d350c0.
2. Pointer at +0x18: same rule, direct call.
3. Pointer at +0x08: if null, return; otherwise tail-jump to the
   same helper, so the helper's return is the routine's return.

The helper pair is pinned whole, not by call shape only. It works
on a packed 64-bit count at target +0x08, viewed as two 32-bit
halves (low at +0x08, high at +0x0c):

- Low half (0x5d350c0, 133-byte FDE): if the whole qword equals
  0x100000001, the count is zeroed, vtable slot 0x10 is called,
  and control tail-jumps to vtable slot 0x18. Otherwise the low
  half is decremented — with a plain store when the guard byte at
  0x64ed290 is nonzero, with a locked xadd when it is zero — and
  if the old low half was 1 (the low half reached zero), control
  passes to the high-half fragment.
- High half (0x5d35070, 76-byte FDE of its own): vtable slot 0x10
  is called, the high half is decremented (plain or locked by the
  same guard byte), and if the old high half was 1, control
  tail-jumps to vtable slot 0x18; otherwise it returns.

So slot 0x10 (the destructor body) runs when the low half reaches
zero, and slot 0x18 (the deleting destructor) runs only when the
high half also reaches zero — or immediately on the packed
0x100000001 sentinel, where both halves are 1. The plain-vs-locked
choice changes no observable event.

## Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): the routine has exactly 8 direct calls, 0 tail jumps,
across 7 distinct caller FDEs (the 0x5d8479c..0x5d85475 function
calls it twice, with two different stack objects). Two callers sit
in the same teardown functions as the 0x5d558f0 teardown's
consumers, but with opposite site order: in 0x5d8479c..0x5d85475
the 0x5d558f0 call precedes this routine's call, in
0x5d878f0..0x5d887b0 it follows it. Four callers pass stack
objects, two pass rbx-relative objects (rbx+0x08, rbx+0x570), one
passes r14; two callers sit on exception-cleanup paths into
__cxa_begin_catch, after the same 0x5d5e860/0x5d5e220 teardown
pair. There are 0 RELATIVE relocations for 0x5d55830 and no stored
qword: the routine is reached only by code, never by data. The
helper pair's own callers are not censused here; only the pair's
bodies are pinned whole.

## Evidence and honesty notes

- Target: node #115, artifact `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json).
- `main.txt`, `helper_low.txt` and `helper_high.txt` are the RAW
  disassembly texts exactly as objdump emitted them for the whole
  functions (FDEs 0x5d55830..0x5d5586a, 0x5d350c0..0x5d35145 and
  0x5d35070..0x5d350bc); the only modification is the header
  normalized to the bare binary name. Instruction-level detail
  lives in those files only; `records.json` carries semantic
  records, not a per-instruction list. Mnemonics such as `endbr64`
  are genuine instructions present in the target binary, not
  placeholders.
- What the +0x28, +0x18 and +0x08 refcounted objects are, what the
  guard byte at 0x64ed290 represents beyond its observed role,
  and what vtable slots 0x10 and 0x18 do beyond the
  destructor/deleter roles their call positions imply, are
  recorded as unknowns in records.json, not claimed.
- Caller bodies beyond the call sites and their argument setup are
  not pinned.
