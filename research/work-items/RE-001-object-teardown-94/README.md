# RE-001: object teardown at node #94 0x514bfe0

Task ID: RE-001. Bounded question: what does the 97-byte function at
0x514bfe0 in node #94 do to its input object — which fields does it
free, in what order, and how does it free the object itself? Answer:
it is a null-safe teardown. A null input returns at once with no
delete call. A non-null input has two embedded SSO strings disposed
(the +0x1a8 string first, then the +0x48 string), each freed only
when its pointer differs from its own inline-buffer address, with
delete size = union field + 1 (mod 2^64); the object itself is then
deleted with size 0x2e0 (736) via a tail jump to the _ZdlPvm PLT
stub, so the non-null path never returns to its caller.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514bfe0..0x514c041, 97 bytes, FDE at .eh_frame+0x0029a800
  (length 0x18), 15 int3 padding bytes to the next FDE at 0x514c050.
- No stack canary in this function; the only callee-saved register
  is rbx, pushed after the null test and popped before the tail
  jump, so the stack stays balanced on both paths.

## Observations (read from the bytes)

- Null guard: test %rdi,%rdi, then je at 0x514bfe7 to the ret at
  0x514c040. The push of rbx at 0x514bfe9 runs only on the non-null
  path, which is why the null path needs no pop.
- First string (offset +0x1a8): pointer = [object+0x1a8]; inline
  address = object+0x1b8. If pointer == inline address, the je at
  0x514bffe skips to 0x514c010. Otherwise rdi is still the pointer
  (loaded at 0x514bfed and never overwritten before the call),
  rsi = [object+0x1b8] + 1, and the call at 0x514c00b goes to the
  _ZdlPvm PLT stub at 0x5660440. The union field at +0x1b8 doubles
  as the inline buffer's first 8 bytes when the string is short:
  that is why the same offset supplies both the SSO comparison
  address (+0x1b8 as an address) and the heap size (+0x1b8 as a
  value, plus 1 for the terminator).
- Second string (offset +0x48): exactly the same shape, 0x160 bytes
  earlier — pointer = [object+0x48], inline address = object+0x58,
  je at 0x514c01b to 0x514c02a on the SSO case, otherwise delete
  (pointer, [object+0x58] + 1) via the call at 0x514c025.
- Object delete: rdi = object, esi = 0x2e0, pop %rbx, then the jmp
  at 0x514c033 tail-jumps to the same PLT stub. The function has
  no ordinary return on this path.
- PLT stub 0x5660440 (16 bytes, SHA recorded in records.json):
  jmp through GOT slot 0x5778f48, which carries relocation
  R_X86_64_JUMP_SLOT _ZdlPvm@CXXABI_1.3.9. The slot's file bytes
  are the stub's own lazy-binding entry, not a resolved address,
  and are recorded as such, not mistaken for the delete target.
- Direct-caller census (full .text disassembly scan for e8 rel32
  calls and e9 rel32 jumps): the entry has NO direct callers and
  NO tail jumps. It is bound here as a complete behavior — a whole
  function plus both string disposals plus the sized self-delete —
  not as a lone window fragment, and no caller is invented for it.

## Inferences (labelled, not observations)

- The +0x1a8/+0x48 fields are read as embedded SSO strings because
  each shows the exact three-part shape of the list-teardown
  function 0x514bd40's string disposal (pointer vs own-buffer
  comparison, delete size = union + 1): same protocol, two sites,
  one object. No source-level field or type name is claimed.
- The 0x2e0 delete size is read as the object's allocation size;
  no field beyond the two strings is claimed to be part of any
  particular sub-object.

## Unknowns (not claimed)

- How the entry is reached (no direct caller exists): virtual or
  indirect dispatch is plausible but not established by these bytes.
- What the object is, what the two strings mean, and what any other
  field holds: the bytes dispose only these two strings and delete
  the object; nothing else about the object is claimed.
- The endbr64 at 0x514bfe0 is a genuine instruction in the target
  binary, not a placeholder; the nopl at 0x514c038 is genuine
  alignment padding before the null-path ret. Instruction-level
  detail lives only in the raw excerpts; records.json holds
  semantic records only.
- objdump's nearest-symbol annotations are explicitly not claimed
  as symbol names.

## Distinguished from neighbours

- The preceding FDE at 0x514bf60 is the chain teardown bound in the
  previous item of this series (recursive child + sibling walk);
  this function is a different protocol (two string disposals plus
  a sized self-delete, no recursion, no list walk) and is not a
  re-claim of it.
- The following FDE at 0x514c050 is a large variadic-looking
  function, unexamined beyond its first lines, and is not claimed
  here.
