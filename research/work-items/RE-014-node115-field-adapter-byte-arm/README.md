# RE-014: node #115 field-adapter byte-arm callee of the adapter table

- Component: RE-014 migration validation; foundation (field/newline
  adapter family).
- Target: node #115, 105,896,032 bytes; SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: the merged field-adapter drift packet binds the 48-byte
  adapter table at `0x64078f8` and retains its three pointer relocations,
  but leaves the +32 and +40 callees opaque; the merged newline packet
  then qualifies only the +24 bulk callee `0x1686bd0`. What does the +32
  callee `0x1686b70` compute for a single input byte?
- Observation: `0x1686b70` is the per-byte arm of the same adapter. It
  loads a 24-byte state (data pointer at +0, callback table at +8,
  flag-byte pointer at +0x10). If the flag byte is nonzero it first
  requests the four-space literal at `0x45a128` through the callback
  table's +0x18 method; a nonzero status byte from that call returns
  `AL = 1` immediately, with the flag byte not written and the byte
  method not called. Otherwise it writes the flag byte as
  `(byte == 0x0a)` and tail-calls the table's +0x20 method with
  `(data, byte)`. It is reached only through the table: zero direct
  callers and exactly one relocation reference exist in the capture.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| adapter table +32 callee (byte arm) | `0x1686b70..0x1686bcf` | 95 | 37 |

The measured denominator is **one complete FDE, 95 bytes**, retained as a
complete native export. The adapter table, its header words and the
four-byte literal are separate context domains, pinned but not counted
as recovered function bytes. The body is hash-pinned without
normalization. This is not a raw-equal or normalized cross-function or
cross-release equivalence claim.

## Trace stages

1. **Table binding (re-derived).** The table at `0x64078f8` stores three
   header qwords raw — `0x0`, `0x18`, `0x8` — and three pointer slots
   whose inline qwords are zero; the bindings come from symbol-free
   RELATIVE (type 8) relocations: +24 → `0x1686bd0`, +32 → `0x1686b70`,
   +40 → `0x168aa10`. The drift packet retained the same three
   relocations as context and the newline packet recorded the +32/+40
   targets as opaque; this packet qualifies +32.
2. **Census.** A full-`.text` E8 scan finds **zero direct callers** of
   `0x1686b70`. In `.rela.dyn` exactly one addend names it: the table+32
   slot `0x6407918`. Its raw 8-byte address form occurs exactly once in
   the whole file — as that relocation's addend field. No other table,
   GOT slot or code site references it.
3. **State loads.** After the register prologue, `R14 = [RDI+0x10]`
   (flag-byte pointer), `RBX = [RDI]` (data pointer), `R15 = [RDI+8]`
   (callback table). The state span the loads describe is 24 bytes,
   the same size the table header's second word records (`0x18`); the
   header words themselves remain raw metadata, not a recovered type.
4. **Indent arm.** `cmp BYTE PTR [R14],0` / `je 0x1686bb7` skips the arm
   when the flag byte is zero. Otherwise the callee materializes the
   four-space literal at `0x45a128` (its first four bytes are pinned
   spaces; the same literal VA the newline packet binds for the bulk
   callee), sets `EDX = 4`, saves `ESI` in `R12D`, and calls
   `[R15+0x18]` with `(RDI = data, RSI = literal)`. It restores `ESI`,
   then `test AL,AL` / `je 0x1686bb7`: on a nonzero status byte it sets
   `AL = 1` and returns through the plain epilogue — the flag byte is
   **not** written and the +0x20 method is **not** called.
5. **Flag update and byte tail.** At `0x1686bb7`, reached from either
   arm, `cmp ESI,0x0a` / `sete BYTE PTR [R14]` writes the flag byte as
   exactly `(byte == LF)` **before** the payload step. Then
   `RAX = [R15+0x20]`, `RDI = RBX`, the epilogue restores the saved
   registers and `jmp RAX` tail-calls the +0x20 method with
   `(data, byte)`; the callee's result on this path is that call's
   result.

## Result summary

For the pinned premises (state layout as loaded; both methods returning
normally with a status byte in AL), the complete behaviour is:

| Flag in | Indent call | Indent AL | Flag written | Flag value | Outcome |
| --- | --- | --- | --- | --- | --- |
| 0 | no | — | yes | `byte == 0x0a` | tail-call +0x20 method |
| 1 | yes | 0 | yes | `byte == 0x0a` | tail-call +0x20 method |
| 1 | yes | nonzero | no | — | return `AL = 1` |

Only the byte's equality with `0x0a` is observed; every non-LF byte
behaves identically. The six concrete rows (LF and `0x61` crossed with
the arms above) are retained in `records.json`.

## Explicit boundary and next question

Only the callee's own 95 bytes are qualified. What the +0x18 and +0x20
methods do inside the callback owner, which concrete writer a given
state names, the flag byte's history before this call, the provenance
of the full `ESI` register beyond the pinned equality compare, and any
nominal type for the state or the table remain unestablished — the same
premises the merged newline packet states for the sibling +0x18 method
apply here. The +40 callee `0x168aa10` (a 19-byte shim that shifts the
arguments, inserts this table as the second argument and tail-jumps
through GOT slot `0x64df6f0`, RELATIVE-bound to `0x1680500`) is recorded
as table context only; its behaviour is a separate packet's question.
The sibling bulk callee at table+24 is qualified by the merged RE-014
newline packet and is cited context, not re-derived. No gate is
claimed.

Next question: what the +0x20 method computes with `(data, byte)`
inside the callback owner, and how the +40 shim's target `0x1680500`
uses the table it is handed.

## Reproduce and validation

From repository root with the materialized pinned capture and native
GNU tools on PATH:

```sh
python3 -B tools/field_adapter_byte_arm_static.py --output research/work-items/RE-014-node115-field-adapter-byte-arm
python3 -B -m unittest discover -s tests -p test_field_adapter_byte_arm_static.py -v
(cd research/work-items/RE-014-node115-field-adapter-byte-arm && sha256sum -c MANIFEST.sha256)
```

The whole capture is authenticated before analysis, output or native
calls. Readelf/objdump receive a private byte-identical snapshot; the
snapshot path is replaced with `<authenticated-node115>` in retained
text. Wrong-release, truncated and same-size modified public inputs are
rejected before output creation.

Focused controls alter the actual indent-length immediate, the LF
compare immediate, both callback method offsets, the literal reference,
a state field displacement, branch displacements, the table header
words, each table relocation addend, the literal bytes and the FDE
record; each makes the checker reject the counterfactual. Below the
full public digest gate, this checks the named obligations, not
arbitrary-byte error detection or target execution equivalence.

No captured executable/emulator, live chain/wallet/signing action or
network access is performed. Captured inputs/imported code/pins and
all progress gates are preserved. No hosted-CI result or
whole-component completion is claimed.
