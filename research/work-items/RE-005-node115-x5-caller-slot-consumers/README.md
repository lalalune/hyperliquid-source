# RE-005 node 115: who consumes the X5 schedule caller's GOT slot

## Question

The X5 env-pair packet (`RE-005-node115-x5-env-pair-source`, PR
#3227) pinned the schedule-caller body `0x5cf5100` and showed it has
no direct callers: the only static holder of its address is one
RELATIVE relocation in `.got` slot `0x64e7718`. It left one question
open: who loads that slot, along what path, and under what call
conditions — or is the slot never loaded at all?

## Method

Static analysis only, against the authenticated node 115 binary
(SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`). A disp32 candidate scan
over every executable section (.fini, .init, .plt, .text)
enumerated every position whose disp32 field could end an
instruction at the target with 0–8 trailing bytes; each candidate was
verified by decoding the instruction that ends there. The same scan
ran on the caller address itself and on the two neighbouring slots
as controls. Independent passes excluded the other reference forms:
absolute disp32 addressing, stored 8-byte copies of either address
outside the `.rela.dyn` section's own serialised entries, and
relocations whose addend is the slot.

## Answer

The slot has exactly **63 consumers**, and
every one of them uses the slot the same way: a single indirect call
`call qword ptr [rip + disp32]` (bytes `ff 15 …`) inside its own FDE
body. There is no data load, no `lea`, no immediate materialisation,
and no PLT stub for the caller body, which itself keeps
0 direct callers. The
consumers form 6 address clusters:

- 23 bodies, 0x2b3a8c0..0x2b3e8ad, body sizes 685/725/732/742/743/747/771
- 1 body, 0x2e8e7b0..0x2e8ea97, body sizes 743
- 1 body, 0x37136d0..0x371397d, body sizes 685
- 1 body, 0x5a79730..0x5a7b155, body sizes 6693
- 36 bodies, 0x5a9c620..0x5aa6c91, body sizes 1169
- 1 body, 0x5cf4540..0x5cf47ed, body sizes 685

Each consumer body runs the same call template (pinned per site in
`records.json`):

1. allocate a fresh buffer through GOT slot `0x64df590` — the size
   is the body's per-type value size (`alloc_size` in
   `records.json`: 0x100, 0x300, 0x400, 0x480 across the pinned set) — and take
   an error path if it returns null;
2. select one of two pair entries: a flag byte is inverted, masked
   to 0/1, shifted left 6 (×0x40), and added to a base at `+0x1f8` —
   the same bool-indexed pair shape the env-pair packet pinned
   inside the caller;
3. copy the stack-built value into the allocation through GOT slot
   `0x64df508`;
4. call the slot with `rdi` = selected entry, `rsi` = allocation,
   `rdx` = 1 (the `mov edx, 1` sits immediately before the call at
   every site), `rcx` = a stack out-slot, and test the `(al, rdx)`
   return pair (`test rdx, rdx; setne cl; and cl, al; cmp cl, 1`).

## Boundaries

RE-005-node115-gate-checkers pins the slot relocation and narrates one consumer body (0x2b3c9d0); RE-009 records one consumer site (0x2b3ad3b) as a transfer row; RE-017 records one direct caller of one consumer body (0x5a9c620) as a transfer row; RE-003's integration review carries the 0x5a79730 consumer body as a start record; RE-001-node115-lu-park-queue pins one instruction inside the caller body; the X5 env-pair packet (#3227) pins the caller body and the slot value and leaves the consumers open. None enumerates the consumers or excludes the other reference forms.

Which of the two bool-indexed pair entries a given consumer selects at run time, and the concrete Rust types of the consumers, are not established by static evidence.

Every consumer body has at least one direct rel32 caller and none has a relocation slot of its own; the consumers' own callers are outside this packet's question.
