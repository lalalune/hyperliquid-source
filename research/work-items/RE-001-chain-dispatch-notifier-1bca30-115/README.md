# RE-001: chain-dispatch notifier 0x61bca30 (node #115)

Task ID: RE-001 (node #115 function map). Bounded question: what does
routine 0x61bca30 do end to end — how does it pick a handler from the
+0x20 chain, what message does it build, how does it frame the
handler's return value, and where does it deliver the frame — and
who is its sole caller?

## Bound to

- Target: node #115, `work/hl-node-115.bin`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (from `provenance/artifacts.json`)
- Routine FDE: 0x61bca30..0x61bcd5a (810 bytes)
- Caller FDE: 0x61bcde0..0x61bcee4 (260 bytes), sole call site 0x61bcebd
- Expected-slot walker FDE: 0x5d4d490..0x5d4d552 (194 bytes)
- ULEB128 encoder FDE: 0x61bd410..0x61bd4e9 (217 bytes)
- Frame builder FDE: 0x61b1260..0x61b13a3 (323 bytes)
- Shared cleanup fragment FDE: 0x61bc9f6..0x61bca28 (50 bytes)

## How to reproduce the excerpts

From the repository root:

```
objdump -d --start-address=0x61bca30 --stop-address=0x61bcd5a work/hl-node-115.bin
objdump -d --start-address=0x5d4d490 --stop-address=0x5d4d552 work/hl-node-115.bin
objdump -d --start-address=0x61bd410 --stop-address=0x61bd4e9 work/hl-node-115.bin
objdump -d --start-address=0x61b1260 --stop-address=0x61b13a3 work/hl-node-115.bin
objdump -d --start-address=0x61bc9f6 --stop-address=0x61bca28 work/hl-node-115.bin
objdump -d --start-address=0x61bcde0 --stop-address=0x61bcee4 work/hl-node-115.bin
objdump -d --start-address=0x61bcea8 --stop-address=0x61bcec2 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
python3 research/work-items/RE-001-chain-dispatch-notifier-1bca30-115/census.py
python3 research/work-items/RE-001-chain-dispatch-notifier-1bca30-115/verify.py
```

Or regenerate every excerpt at once with the packet's
`export_excerpts.py` (same commands, same windows). `verify.py`
re-runs the regeneration and checks every excerpt line byte-for-byte
against the raw binary, plus the census, the relocation record and
the model. Note: mnemonics such as `endbr64` in the excerpts are
genuine instructions present in the target binary, not placeholders;
the excerpts are verbatim objdump output.

## Observations

### Inputs and frame

- `rdi` is the owner, kept in r12 and returned in rax on the normal
  path. `rsi` is the subobject, kept in rbp: `*(rsi)` is the chain
  head, `*(rsi + 0x28)` is the delivery target.
- Stack frame 0xa8 bytes, canary at rsp+0x98, six callee-saved
  registers pushed. Value block at rsp+0x50: qword = slot-call
  return value, byte +0x08 = 1, qword +0x10 = 0, message string at
  +0x18 (rsp+0x68: data +0x00, size +0x08, SSO buffer at rsp+0x78).
  Second string at rsp+0x30 (data +0x00, size +0x08, SSO buffer at
  rsp+0x40) is the framed output. Varint scratch at rsp+0x93 (5
  bytes, ending exactly at the canary).

### Phase 1 — handler selection (0x61bca4b..0x61bcaea)

- The head link's vtable slot +0x98 is compared against the global
  at 0x64ecf80. That global's file bytes are zero; a single
  RELATIVE relocation at 0x64ecf80 with addend 0x5d4d490 sets it at
  load time, so the expected value is the address 0x5d4d490.
- On a mismatch the mismatching link's slot function is called at
  once (0x61bccb0 for the head, 0x61bcca0 for later links) with
  `rdi` = the link, `rsi` = the subobject (unchanged), `rbx` =
  &message string, then control joins the store at 0x61bcaf0.
- While the slots match, the walk advances via `+0x20`, comparing
  each link's slot against the previous link's slot, for links 1,
  2 and 3. If all four comparisons pass, link 4's slot is called
  unconditionally at 0x61bcaea. The return value is stored at
  rsp+0x50.
- The routine never checks for a null link: at least five links
  must be reachable via +0x20 from `*(rsi)` (recorded as an
  assumption, not an observation).

### The expected-slot walker 0x5d4d490

- FDE 0x5d4d490..0x5d4d552. It is the value the chain is compared
  against, and the function the homogeneous path resolves to.
- It starts at `*(rdi + 0x20)` and walks eight pairwise slot
  comparisons (the first against the same global 0x64ecf80), then
  tail-jumps to the first differing link's slot function, or to
  the ninth link's slot function when all eight pass. No stack
  frame, no return: `jmp *%rax` / `jmp *%rdx` at 0x5d4d548 and
  0x5d4d550, `jmp *0x98(%rax)` at 0x5d4d53f.

### Phase 2 — message build (0x61bcaf0..0x61bcbe4)

- The tag is the std::string global at 0x6508800 (data +0x00,
  size +0x08). That address is in the BSS tail of the fourth LOAD
  segment (file bytes end at vaddr 0x64ffe08); no relocation sets
  it, so its bytes are not retained in the file and are not claimed
  here — only the access pattern is pinned.
- `0x61bd410(rdi = rsp+0x93, esi = tag size)` writes the ULEB128
  of the tag size and returns the end pointer; the encoded length
  is `rax - r13`. The encoder is pinned whole (varint.txt): 1 byte
  to 0x7f, 2 to 0x3fff, 3 to 0x1fffff, 4 to 0xfffffff, 5 above.
- Appends, in order, each guarded by `length <=
  0x3fffffffffffffff - size` else `__throw_length_error` with
  `"basic_string::append"` (string at 0x4474d2):
  the varint bytes, the tag bytes, 4 bytes `08 00 00 00`
  (dword 8 stored at rsp+0x1c), 4 bytes `01 00 00 00` (dword 1
  stored at rsp+0x20). The two 4-byte appends require remaining
  capacity >= 4 (`cmp $0x3` / `jbe` to the throw arm).
- Message layout: `ULEB128(len(tag)) || tag || LE32(8) || LE32(1)`.

### Phase 3 — framing (0x61bcbe4..0x61bcc0e)

- `0x61b1260(rdi = &value block at rsp+0x50, rsi = &string at
  rsp+0x30)` builds the framed string (framer.txt, whole function):
  it appends the 8 raw bytes of the return value, then one byte
  equal to the value block's +0x08 byte (1), then LE32 of the
  message size, then tail-jumps to `_M_append` with the whole
  message string. Each append has the same length guard as phase 2.
- Frame layout: `raw8(return value) || byte(1) || LE32(len(message))
  || message`.

### Phase 4 — delivery (0x61bcc13..0x61bcc38)

- `rsi = *(rbp + 0x28)` (the delivery target); `rax =
  *(vtable + 0x10)`; the call is `*%rax` with `rdi` = owner,
  `rsi` = the target object, `rdx` = rsp+0x20, which by then holds
  a `{data, size}` view of the framed string (data = rsp+0x40 SSO
  buffer or heap pointer, size = *(rsp+0x38)). The slot-0x10
  target is virtual and is not pinned to one address.

### Phase 5 — cleanup and return (0x61bcc3a..0x61bcc95)

- The framed string is freed by sized delete of `(data, size + 1)`
  unless its data is its own SSO buffer at rsp+0x40; the message
  string the same way unless its data is its own SSO buffer at
  rsp+0x78. The canary at rsp+0x98 is checked; on failure
  `__stack_chk_fail`. The owner (r12) is returned in rax.
- The two landing pads at 0x61bcd42 and 0x61bcd4e jump into the
  shared cleanup fragment 0x61bc9f6..0x61bca28 (landing.txt), which
  disposes both strings via `_M_dispose`, checks the canary and
  resumes unwinding with `_Unwind_Resume`.

### Sole caller (FDE 0x61bcde0..0x61bcee4, site 0x61bcebd)

- Census (executable-LOAD E8/E9 scan with objdump confirmation,
  reproduced by census.py): exactly 1 direct call, 0 tail jumps,
  0 stored qwords, 0 RELATIVE relocations for the routine.
- The caller first calls 0x606ca40 on `(rsi + 0x20)`. When
  `*(rbx + 0x60)` is non-null it writes the header `(11, 0, 0)` at
  `*(rbp + 0x00/0x04/0x08)` and jumps to the shared tail, skipping
  the notify. When null it copies 0x19 bytes from `(r12)` to
  `(rbx)`, allocates a 0x30-byte subobject with `_Znwm(0x30)`,
  builds it with `0x61bc290(new, rsi = saved rdx, rcx = r13, rdx
  = r12)`, stores it at `*(rbx + 0x60)` with byte `*(rbx + 0x68)
  = 1`, then calls 0x61bca30 with `rdi` = owner (rbp),
  `rsi` = the new subobject, and afterwards calls 0x60d52f0 on
  `(rsi + 0x20)` and returns the owner.
- The caller's callees 0x606ca40, 0x61bc290 and 0x60d52f0 are
  recorded only at their call sites; their bodies are not pinned
  in this packet.

## Inferences (kept separate from observations)

- The +0x20 chain with per-link slot-0x98 handlers reads as a
  handler chain with one handler kind per link; the name of that
  kind is not in the binary.
- The message (varint length-prefixed tag plus LE32 8 and LE32 1)
  reads as a framed record, and the 0x61b1260 output reads as a
  second framing (value, flag, length, payload); the record names
  are not in the binary.
- The slot-0x98 function is read as taking (link, context,
  out-string) from the registers live at the call sites; its name
  and return meaning are not pinned.

## Assumptions (explicit)

- At least five chain links are reachable via +0x20 from `*(rsi)`;
  the ninth link must be reachable for the walker path.
- The BSS tag string at 0x6508800 is initialized before the call.
- The global at 0x64ecf80 holds 0x5d4d490 after relocation (verified
  by the single RELATIVE record, not by file bytes).

## Unknowns

- The literal bytes of the tag string at 0x6508800.
- The identities of the virtual slot-0x98 and slot-0x10 targets.
- The bodies of the caller's callees 0x606ca40, 0x61bc290, 0x60d52f0.

## Relation to neighbouring work

Unlike the teardown routines mapped in #2702–#2762 and the
drain-and-append construction in #2979, this pins a dispatch:
a handler-chain walk with its expected-slot walker, a varint
message build, a value framing, and a virtual delivery, with its
sole lazy-init caller. No open PR covers 0x61bca30, 0x61bcde0 or
0x5d4d490 (checked at the pre-submit gate).

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so
`make doctor` exits non-zero on the missing Rust/Ghidra toolchains
(pre-existing) and `make verify` / `make test` /
`make catalogue-check` were not run in a tooled environment; no
hosted CI result is claimed. Verification here is the packet's own
`verify.py` (digest, provenance, manifest, excerpt regeneration
byte-for-byte from fresh objdump runs, all excerpt lines
byte-for-byte against the raw binary, all FDE lines, the census
including the exact site list, the relocation record, the records
and the model spot checks) plus the 17 model tests, run directly
because pytest is not installed on this VM.
