# RE-001: map node #115 wrapper destructor 0x5d55a20 with its dynamic-dispatch guard

Bounded question: what does the 123-byte routine at 0x5d55a20 do
end to end — how does it decide between dynamically dispatching
destruction and destroying the embedded object at +0x10 inline, and
what exactly does the inline path release?

## Answer, end to end

Arguments: rdi = object. The embedded object's vptr lives at
object +0x10. The routine has no stack canary and no landing pads
in its FDE range, and both exits are tail jumps.

### 1. The dispatch guard

The routine loads the value at object +0x10, then loads the first
qword of that value, and compares it against the qword stored at
0x64ed3f0, whose relocation value is 0x5d55970 — the derived
complete destructor pinned in the RE-001 derived-destructor packet
(0x5d55970 / 0x5d559c0).

- If the compared value differs from 0x5d55970, the routine
  tail-jumps to that value with rdi unchanged. This is the dynamic
  path: the embedded object's actual most-derived destructor runs.
  Which function that is depends on the embedded object's dynamic
  type; it is recorded here as an indirect tail call, not pinned to
  one address.
- If the compared value equals 0x5d55970, the embedded object is
  exactly the derived class, and the routine destroys it inline
  instead of calling the derived destructor.

### 2. The inline path (guard matches)

In order, with nothing written back to the object itself:

1. [object +0x10] := 0x64d08a8 (the derived table, whose slot 0
   relocates to 0x5d55970 and slot 1 to 0x5d559c0).
2. The pointer at object +0x48 is released through the shared
   helper 0x5d350c0 when non-null, and skipped when null.
3. [object +0x10] := 0x64cf200 (the middle table).
4. The pointer at object +0x38 is released through the same
   helper when non-null, and skipped when null.
5. Tail-jump to the base destructor 0x5fe70b0 with
   rdi = object +0x10.

### 3. Why this is the derived destructor, applied at +0x10

The offsets line up exactly with the derived pair: the subobject
at object +0x10 has its +0x38 field at object +0x48 and its +0x28
field at object +0x38, so the two releases here are the derived
destructor's two releases, and the two vptr writes are its two
vptr writes, with the same base destructor (0x5fe70b0) at the end.
The new content this packet pins is the wrapper around it: the
guard that decides between dynamic dispatch and the inline path,
and the fact that this routine is itself reached through virtual
dispatch (see Consumers).

## Consumers

No direct call or tail-jump site reaches the routine (exhaustive
executable-LOAD-segment E8/E9 scan with objdump confirmation,
reproduced by census.py and re-run inside verify.py). It is
reached through virtual dispatch: exactly one stored reference,
the qword at 0x64c9840 whose relocation value is 0x5d55a20, in a
vtable run whose neighbouring slots are 0x5d486f0 (0x64c9838) and
0x5d492e0 (0x64c9848). The helper 0x5d350c0's own callers are not
censused here; only its release contract (established in the
RE-001 three-release packet) is used.

## Unknowns (recorded, not filled in)

- The source names of the classes involved.
- Which class's vtable contains the slot at 0x64c9840.
- Why the fallback tail jump keeps rdi unchanged instead of
  adjusting it to object +0x10; the excerpt is literal on this
  point and this packet does not explain it away.

## Evidence and method

- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json (artifacts/node/115/hl-node).
- main.txt is the whole-function objdump excerpt for
  0x5d55a20..0x5d55a9b, verbatim except the header normalized to
  the bare binary name. Detail at the single-step level lives
  only in that excerpt; records.json above carries semantic
  records, not a per-step list. The mnemonics in the excerpt
  (including `endbr64`) are genuine instructions present in the
  target binary, not placeholders.
- frames.txt holds the routine's FDE line plus the FDE lines of
  the derived destructor, the release helper and the base
  destructor used as context.
- verify.py re-checks the digest, the manifest, byte-for-byte
  excerpt regeneration, every excerpt line against the
  raw binary, every FDE line, the census, the stored-reference
  census, the semantic records and the model tests.
- Run the packet checker from the repository root:
  `python3 research/work-items/RE-001-wrapper-destructor-55a20-115/verify.py`
- Generate the excerpt with:
  `python3 research/work-items/RE-001-wrapper-destructor-55a20-115/export_excerpts.py`
