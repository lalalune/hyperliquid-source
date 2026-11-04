# RE-001: map node #115 destructor pair (0x5f10180 / 0x5f10d00)

Task: RE-001 (#115 function map). Bounded question: how is an object
of the class whose vtable is 0x64cc5d8 torn down — what does the base
destructor do, what does the deleting destructor add, and what does
the member destroy at +0x60 do?

- Component: node #115 destructor pair for one class, two whole
  functions plus the member destroy they both call, extracted from
  the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  base destructor `0x5f10180..0x5f101b2` (50 bytes; FDE .eh_frame
  offset 0x358c70, length 0x1c, CIE 0, no LSDA), deleting destructor
  `0x5f10d00..0x5f10d3c` (60 bytes; FDE .eh_frame offset 0x358c90,
  length 0x18, CIE 0, no LSDA), member destroy
  `0x605cc30..0x605cf73` (835 bytes; FDE .eh_frame offset 0x75a040,
  length 0x68, CIE 0x730230, LSDA 0x41ee3e, not decoded here — the
  member window's landing pads are not part of this packet's claim).
- Claim status: observation for the window bounds, the vtable slots,
  the install order, the member call, the array delete, the sized
  self-delete size, and the caller census; inference for the names
  "member" and "array" (they describe the observed roles, not proven
  source names); unresolved for the items listed in records.json
  (the class's source name, the element destroy's internals, the
  other virtuals' behavior).
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them
  (including `endbr64` at both destructor entries) are genuine
  instructions present in the target binary, not placeholders; the
  packet checker re-verifies sampled instructions byte-for-byte
  against a fresh objdump run and the raw binary.
- Relationship to earlier work: no open PR covers these windows
  (checked this cycle: open-PR snapshot of 103 open PRs plus a
  repository search for 5f10180 and 5f10d00, no hit). The vtable at
  0x64cc5d8 sits immediately before the memtable-iterator vtables
  mapped by the RE-014 packets (0x64cc610, 0x64cc648, ...), but it
  is a different table with different virtuals — the destructor
  pair's class is not the iterator class. The cold-part function at
  0x5f101b2 (which calls the 0x5f10180 window's neighbour helper
  0x5f0a1dc) was examined this cycle and deliberately NOT used: it
  shares its caller's frame (rbp-relative locals, no prologue), so
  modelling it as a standalone function would be false.
- The pair, stated literally. Both windows install the same vtable
  pointer first: the address 0x64cc5d8 is stored to object + 0x00
  (base at 0x5f10197, deleting at 0x5f10d17). Both then call the
  member destroy 0x605cc30 with the member at object + 0x60
  (base at 0x5f1019b, deleting at 0x5f10d1b). Both then load the
  pointer at object + 0x48 and, when it is non-null, free it with
  operator delete[] (PLT 0x63f0dc0): the base destructor tail-jumps
  there (0x5f101aa) and returns on the null path (0x5f101b0), while
  the deleting destructor calls it (0x5f10d29) and falls through.
  Only the deleting destructor frees the object itself: it loads the
  object pointer, sets the size argument to 0x9b0 (0x5f10d31), and
  tail-jumps to sized operator delete (PLT 0x63f0d80, 0x5f10d37).
  The object is therefore 0x9b0 bytes, the array at +0x48 is a heap
  array freed by delete[], and the member at +0x60 is destroyed
  before either free. Neither window reads the vtable pointer it
  overwrites, and neither returns a value.
- The vtable, stated literally. The installed pointer 0x64cc5d8 is
  the table's first virtual slot: the .rela.dyn RELATIVE entries
  resolve slot 0x64cc5d8 to 0x5f10180 (the base destructor itself),
  slot 0x64cc5e0 to 0x5f10d00 (the deleting destructor), slot
  0x64cc5e8 to 0x5f11c40 (1314 bytes, FDE bounds verified, behavior
  not modelled here), slot 0x64cc5f0 to 0x5f117a0 (1176 bytes, FDE
  bounds verified, behavior not modelled here), and slot 0x64cc5f8
  to 0x5f04da0 (bounds not verified here). The preceding slots are
  the offset-to-top (0x64cc5c8, zero, no RELATIVE entry) and the
  typeinfo pointer (0x64cc5d0, RELATIVE addend 0x64cc550). The
  slots are zero in the file and exist only through their RELATIVE
  entries — that is why the census reports them as RELATIVE slots
  and why the whole-file qword search hits are the addend fields
  of those same entries, not separate references. The next table
  starts at 0x64cc610 (typeinfo slot 0x64cc608, addend 0x64cc568),
  so this table holds exactly five virtuals.
- The member destroy 0x605cc30, phase by phase (excerpted whole;
  modelled in the pair as one step, its element semantics left for a
  follow-up item): it installs its own vtable 0x64d1fb8 at member
  + 0x00 (0x605cc50); when member + 0x8e8 is non-null it calls
  0x605e8a0 on it (0x605cc5f); it then destroys element arrays
  through the element destroy 0x60d4f70 (sites 0x605ccc7,
  0x605cd07, 0x605cd27, 0x605cee7), delete[]-ing null-checked entries
  and sized-deleting 0x200-byte entries (0x605cd64, 0x605ceac);
  when member + 0x868 is non-null it sized-deletes that array with
  size 8 * (member + 0x870) (0x605cd7c..0x605cd84); when member +
  0x818 is non-null it sized-deletes that array with size 8 *
  (member + 0x820) as its tail jump (0x605ceca..0x605ced6), and
  returns directly on the null path (0x605cf38). The element
  destroy 0x60d4f70 and the +0x8e8 destroy 0x605e8a0 are cited by
  contract only — their bodies were not read for this packet.
- The member's own vtable, for the same reason, starts at
  0x64d1fb8: offset-to-top 0x64d1fa8 (zero), typeinfo slot
  0x64d1fb0 (RELATIVE addend 0x64d1f90), first virtual slot
  0x64d1fb8 resolving to 0x605cc30 itself — so the member destroy
  is the base destructor of its own class — followed by 0x605cf80
  (27 bytes: call 0x605cc30, then sized delete of the member
  itself with size 0x8f0, i.e. the member class's deleting
  destructor and the mirror of the outer pair), 0x605d930
  (55 bytes), 0x605d7b0 (374 bytes) and the 12-byte getter
  0x605cc20 (returns member + 0x810). The member class is
  therefore 0x8f0 bytes. The three non-destructor virtuals are
  recorded here only by slot and bounds; their behavior is a
  follow-up item, not this packet's claim.
- Census: see records.json (direct calls, tail jumps, qword hits
  and RELATIVE slots for all three windows, each direct call site
  confirmed as a real call instruction in objdump output).
