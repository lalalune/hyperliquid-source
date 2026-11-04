# RE-005: node 115 `rmp_signable` caller tags — who calls the serializer's two callers, and with which tag values

- Component ID: `serialization` (RE-005, Serialization/signing:
  `bincode_fork/*`, `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for the call census, the forwarding
  prefixes, the dispatch mechanics, the jump-table partitions and the
  tag provenance below, all re-derived from the pinned target bytes by
  the checker; **unresolved** for every naming or semantic claim listed
  under the boundary.

## The bounded question

The `rmp_signable` serializer packet (RE-005-node115-rmp-signable-layout)
established that the serializer at `0x36aa9a0` emits result tag byte
`0x61` when its third argument (`edx`) equals 3 and `0x62` otherwise,
and that its only two direct callers forward their own third argument
unchanged. Who calls those two callers, and with which tag values — that
fixes which of the two tag bytes the node emits in practice.

## Why this item

The operator action is answering the one question the serializer packet
explicitly leaves open. The basis for the expected behaviour is the
serializer's own contract: its emitted byte stream differs by exactly
this one byte (the parent packet's claim), so any reconstruction of the
signing payload must know which tag values actually reach the
serializer. The loss when it is wrong is a payload whose tag byte
differs from the node's — a signature over different bytes.
Independence by repro case: the other open RE-005 packets cover the
bincode varint size-state (#2257), the bincode u64 reader state (#2300)
and the `rmp_signable` `.rodata` census (#2311); the serializer packet
(#2399) retains the two callers as boundary evidence only and does not
follow their callers. None touches the two dispatchers below, their
jump tables, or the tag-provenance question.

## Exact scope

| role | FDE half-open range | bytes | body SHA-256 |
| --- | --- | ---: | --- |
| serializer | `0x36aa9a0..0x36aade6` | 1,094 | `18c066ea3b97c2de167b8e7557d1e3e3cdbbd2f757dd83a00eafc827718eca9d` |
| caller_a | `0x36aadf0..0x36aaf0e` | 286 | `d334db07754d3444527141f0c43ec5316b25cef9dac35cfdb48a6728d6052127` |
| caller_b | `0x36aaf10..0x36aaff6` | 230 | `98513eb74d9449bf469425940d4ae673921f4494e34133e938a9f4f37f324582` |
| grand_a | `0x36c2050..0x36c2f99` | 3,913 | `eaa2515d051afca85d5136bd3c53c7a6423abdb86d6832ef7b4d6132df182514` |
| grand_b | `0x36c5350..0x36c5676` | 806 | `19f158b96c98c1a4622032b450f29f35a8226cd2c17dea6fdd80ccc0a8f12662` |

The caller body hashes are re-derived here and agree with the parent
packet's pins. Measured denominator: each caller has exactly **1**
direct call site in the whole `.text` (83,719,936 bytes) — caller_a is
called only at `0x36c208b` inside grand_a, caller_b only at `0x36c5388`
inside grand_b; there are no direct jump (tail-call) sites to either
caller and no `.rela.dyn` entry references the serializer, either
caller, or (for the callers) any other relocatable pointer.

## Trace

1. Forwarding (re-pinned). In caller_a the 29 bytes from entry to its
   serializer call, and in caller_b the 26 bytes, contain no write to
   `rsi`, `rdx` or `rcx`; only `rdi` is replaced with a stack-local
   result buffer. The serializer's tag is therefore each caller's own
   third argument.
2. Dispatch head (identical shape in both dispatchers). `rax` loads
   the qword at `[rsi]`; `rax -= 0x86`; `r9d = 0x14`, replaced by
   `rax` when the subtraction did not borrow (`cmovae`); a 92-entry
   table of signed 32-bit offsets relative to the table base
   (grand_a `0x79a9f0`, grand_b `0x79b290`) is indexed by `r9` and the
   selected entry is jumped to. Discriminants below `0x86` therefore
   use index `0x14`; both tables' index-`0x14` entries select the
   direct pad (step 3).
3. Direct pad. Most table entries land on a 3-instruction pad:
   `movzx edx,dl` / `mov rdi,rbx` / call the caller. Grand_a's table
   sends 70 of 92 entries here, grand_b's 71 of 92. On this path the
   tag is the low byte of the dispatcher's own entry `edx`, with the
   upper bytes cleared.
4. Variant arms. The remaining entries select 21 per-variant arms, at
   the **same 21 discriminants in both dispatchers** (`0x87`, `0x91`,
   `0xa3`, `0xa8`, `0xae`, `0xb6`–`0xbc`, `0xc3`–`0xc5`, `0xcb`, `0xcf`,
   `0xd1`–`0xd3`, `0xdb`), plus — grand_a only — one equality gate at
   discriminant `0xd7` (step 6). Every arm head is the same 27-byte
   template, and its third instruction is `movzx ebp,dl`: the entry
   tag byte is captured into `ebp` before the arm makes its
   per-variant helper call through a relocation slot.
5. Arm exits. Each arm then inspects the helper-produced record.
   Grand_b's arms converge on one inspection block: a zero first byte
   reaches the fallback, any other byte copies the record to the out
   buffer and returns without calling. Grand_a's arms each carry an
   inspection block (the checker pins one full instance and the
   uniformity counts): record word `0x1a2` with byte `0x01` selects a
   shared success block that copies the record out and returns; any
   other byte value branches to the fallback. The fallback block is
   byte-identical in shape in both dispatchers (`mov rdi,rbx` /
   `mov rsi,r14` / `mov edx,ebp` / `mov rcx,r12` / `mov r8,r15` /
   `jmp` to the call site): it restores the tag from the captured
   `ebp` and jumps straight to the call instruction.
6. Equality gate (grand_a only, discriminant `0xd7`). The gate block
   is entered from the table with the entry registers untouched. When
   `[rcx+0x10]` equals `[rsi+0x98]` it jumps to the direct pad (step
   3); otherwise it writes word `0x60` to the out record and returns
   without calling.

## Result

On **every** path that reaches either call site, the tag handed to the
caller — and through it to the serializer — is the zero-extended low
byte of the dispatcher's own entry `edx` (its third argument):

| reaching path | tag value at the call |
| --- | --- |
| jump-table direct pad (70/92 grand_a entries, 71/92 grand_b entries, and every discriminant below `0x86` via the default index) | entry `edx` low byte (`movzx edx,dl` at the pad) |
| variant arm → inspection → fallback | entry `edx` low byte (captured as `movzx ebp,dl` at the arm head, restored as `mov edx,ebp` in the fallback) |
| grand_a equality gate (discriminant `0xd7`), gate passes | entry `edx` low byte (via the direct pad) |

No reaching path materialises a constant tag, and no reaching path
loads the tag from memory. Combined with the serializer's rule, the
emitted tag byte is therefore `0x61` exactly when the dispatcher's
caller passed a third argument whose low byte is 3, and `0x62`
otherwise. Which concrete values occur is decided one level further
up, by whoever calls the dispatchers.

## Boundary

This packet does not name the enum or the action types the
discriminants denote, does not trace the per-variant helper calls
(their targets sit behind relocation slots), and does not decode what
the arms' helper-produced records mean. The jump tables' length (92
entries each) is bounded by the next referenced table base in
`.rodata` — both dispatchers sit in a family whose table bases are
spaced `0x170` bytes apart — not by a stored length field, and the
dispatch head applies no upper bound check, so discriminants above
the table span are not claimed. The dispatchers' own callers are not
followed: grand_a has exactly one direct call site in `.text`
(`0x37133b3`, inside FDE `0x3713300`) and grand_b has none, so grand_b
is reached indirectly; which entry `edx` values occur at runtime
remains open at that level.

Next question: who calls grand_a at `0x37133b3`, how is grand_b
reached, and which third-argument values do those sites pass — that
fixes which tag byte the node emits for each action family in
practice.

## Reproduce

```sh
python3 -B tools/rmp_signable_caller_tags_static.py --output research/work-items/RE-005-node115-rmp-signable-caller-tags
python3 -B -m unittest discover -s tests -p 'test_rmp_signable_caller_tags_static.py' -v
cd research/work-items/RE-005-node115-rmp-signable-caller-tags && sha256sum -c MANIFEST.sha256
```

The checker authenticates the pinned binary (size and SHA-256) before
any analysis, re-derives every value above from the target bytes,
validates each pinned address and every jump-table target as a native
instruction start against GNU objdump output, and carries corruption
controls (mutated pad, fallback, arm-capture, caller-prefix and
jump-table bytes, and a wrong public identity) that must all be
rejected. It writes only the packet directory, uses the Python
standard library plus the repository's own tools, and never executes
the target.
