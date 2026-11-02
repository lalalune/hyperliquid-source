# RE-001: Indexed create-and-format at 0x514eb90 (node #94)

Bounded question: what does node #94 function 0x514eb90 do with its
outer argument, destination string and view — which parser and index
gates must pass, how does its get-or-create lookup dispatch between
returning 0 and formatting a fresh record, and which callers consume
it?

## Composed rule

- Arguments: outer in rdi (preserved in rbp), destination string in
  rsi (preserved in r12), view pointer in rdx (saved at rsp+0x00),
  view length in rcx (saved at rsp+0x08).
- The view is parsed by the decimal parser 0x54307c0 (bound by the
  level-ratio item, same SHA, cited as a callee only): checked uint64
  accumulation, failing above 0x1999999999999999, or equal with a
  digit above 5; a non-digit stops the scan; success requires at
  least one digit consumed, and the view is left at the stopping
  character.
- Gates, in order, each returning 0 with the destination unchanged:
  parser failure (je at 0x514ebd8 to the canary check); trailing
  characters, i.e. remaining view length != 0 (jne at 0x514ebe0);
  the parsed value's low 32 bits, read as a signed integer, >= the
  signed count at [outer + 0x778] (cmp at 0x514ebed, jge at
  0x514ebf3).
- The parsed index is a gate only: it is passed to neither the
  lookup nor the formatter. A consequence of the 32-bit signed
  compare is that a parsed value whose low 32 bits are in range
  passes the gate even if the full value is larger; this is the
  observed instruction behaviour, recorded as such rather than as
  an intended rule.
- The lookup 0x51e9220 (cited as a callee only) is called with the
  status slot at rsp+0x30, the field at [[outer + 0x788] + 0x30]
  and the shared slot at rsp+0x20 (zeroed by movaps before the
  call). Its two-path return contract, derived from the callee's
  own return paths together with this function's dispatch on the
  status byte, is: on the path where the entry already exists the
  callee returns a status struct whose first byte is nonzero; on
  the path where it creates a fresh record it returns a zero
  status struct and stores a fresh record pointer plus a control
  pointer in the shared slot (stores at 0x51e957e and 0x51e958d,
  zero status written at 0x51e95a4; the found path moves the
  nonzero-byte struct into the status slot at 0x51e92e9-0x51e92fb).
- This function compares the status byte at rsp+0x30 (cmpb at
  0x514ec18, je at 0x514ec1d): nonzero runs the cleanup and
  returns 0 with the destination unchanged; zero takes the format
  path.
- Format path: the string constructor 0x514b6d0 (bound by the
  string-ctor item, cited as a callee only) builds "=" from the
  bytes at 0x1f5e86 (string at rsp+0x60) and "; " from the bytes
  at 0x1efff7 (string at rsp+0x40); the record formatter 0x5407f00
  (cited as a callee only) is called with the temporary string at
  rsp+0x80, the record pointer (first qword of the shared slot),
  the "; " string and the "=" string; the move-assign 0x514b4f0
  (bound by the string move-assign item, cited as a callee only)
  moves the temporary into the destination. Disposal order is the
  temporary, then "; ", then "=", then the cleanup: the status
  struct's array pointer (via _ZdaPv, skipped when zero) and the
  shared slot's control pointer (via 0x4f94a90, skipped when
  zero). The function returns 1 (the parser's return value, kept
  in ebx through the format path).
- The function is stack-canary protected: the canary is stored at
  rsp+0xa8 and checked before return, with __stack_chk_fail on
  mismatch. Its exception cleanup is the staged landing pad at
  0x514eb3a, entered at 0x514eb3a, 0x514eb42, 0x514eb4a or
  0x514eb59 depending on how much was constructed, disposing the
  constructed strings and lookup-owned pieces before
  _Unwind_Resume.

This item is distinct from the sibling unconditional
create-and-format function 0x514e9f0, which calls the same lookup
and formatter without the parser and index gates; that function is
not modelled here. It is also distinct from the level-ratio and
level-index-sum formatters, which pass their parsed index into a
ratio or sum computation — here the index gates only.

## Callers (consumers only)

A full .text direct-rel32 scan, a full .text rel32 tail-jump scan
and a whole-file qword scan found no direct caller, no tail jump
and no absolute pointer to 0x514eb90, so no caller is claimed and
the reaching path is left unclaimed. (Relative-relocation tables,
if any, were not scanned.) The window appears in the string-ctor
packet only as the enclosing function of its two 0x514b6d0 call
sites, and in the string move-assign packet only as a caller site;
neither packet models this window's gates, lookup dispatch or
format behaviour.

## Evidence notes

- The raw disassembly excerpts in this packet are verbatim objdump
  output for whole functions (plus int3 padding to the next FDE
  where padding exists), produced by `export_excerpts.py --binary
  work/hl-node-94.bin`. Instruction text such as `endbr64` in
  those excerpts is genuine instruction text present in the target
  binary, not a placeholder.
- The packet JSON (`records.json`) carries semantic records only —
  function ranges with SHA-256, call sites, gate encodings, branch
  targets, literals and censuses. Instruction-level detail lives
  only in the raw excerpt text files.
- `verify.py` re-derives every record from the binary: the target
  digest, the carve SHAs, the padding, the FDE records, the direct
  call targets, the rip-relative literal resolutions, the gate
  encodings, the canary sequence, the PLT stub GOT resolutions,
  the censuses, the excerpt regeneration and the packet manifest
  hashes.

## Unknowns

- The identity and contents of the outer object, its +0x778 count
  field and its +0x788 container.
- The lookup's internal search and creation rules, and the meaning
  of the fresh record's fields to the formatter.
- The formatter's output text for a given record (it is a callee
  only here).
- The reaching path (see Callers above).
- Why a fresh record is formatted while an already-existing entry
  returns 0 without formatting.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java. The
binary used here is the digest-verified work copy
`work/hl-node-94.bin` (SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
matching provenance/artifacts.json for artifacts/node/94/hl-node);
`artifacts/node/94/hl-node` is still an LFS pointer on this
checkout. The full `make verify` / `make test` suites were not run
in this environment; the packet's own `verify.py` and the new
`tests/test_foundation_indexed_create_format.py` suite were run
and pass.
