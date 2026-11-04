# RE-001: node115 raw-tag text dispatch and structured tag10 formatting

Component: foundation. Base `05bc2de303c05525b71e7e257426e741bc66a390`.
Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105896032 bytes,
SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Addresses are original ELF VAs. New code/docs are independently authored MIT;
no inferred private source, source oracle or captured execution is used.

## Question and owner

What are the byte-output branches reached by raw tags0..11 in this dispatcher,
and how does its payload-bearing branch propagate callback returns? This is a
complete separate owner, not the adjacent `Error`/field adapter or a microscopic
split of that adapter: their selected field method is `0x15ea550`, not this body.

Actual FDE `0x14ca4b0..0x14ca6fe`, `.eh_frame+0x7870`: **590 bytes,150 native
instruction rows**. Full raw bytes, exact FDE/CIE-backed extent, all branch/call
and RIP LEA records,48B signed-offset table, and literal bytes are in
`evidence.json`; full native instructions are in `owner0.objdump.txt`. Only the
native input pathname is normalized. There is no source equivalence or byte
comparison credit, and the FDE is not inferred from a nearby symbol label.

## Dispatch encoding and literal branches

Read `u32[RDI]` into EAX. LEA places `T=0x46456c` in RCX; MOVSLQ loads the
**signed32** entry at `T+4*EAX`; ADD RCX computes target `T+entry`; indirect JMP
enters that target. No local bounds guard precedes the load. Exactly the12
selected entries below point to independently decoded instruction boundaries
inside the measured owner. This is a supported raw-index slice, **not proof of
the original valid-tag set**. Adjacent bytes are not imported as extra entries.
Out-of-slice memory reads, reachability and invalid-object behavior are unknown.

| Raw index | Target | Literal / payload branch | Length |
| --- | --- | --- | ---: |
| 0 | `0x14ca4c2` | IncorrectSignature | 18 |
| 1 | `0x14ca571` | InvalidMessage | 14 |
| 2 | `0x14ca526` | InvalidPublicKey | 16 |
| 3 | `0x14ca53f` | InvalidSignature | 16 |
| 4 | `0x14ca4f4` | InvalidSecretKey | 16 |
| 5 | `0x14ca58a` | InvalidSharedSecret | 19 |
| 6 | `0x14ca5a3` | InvalidRecoveryId | 17 |
| 7 | `0x14ca558` | InvalidTweak | 12 |
| 8 | `0x14ca608` | NotEnoughMemory | 15 |
| 9 | `0x14ca50d` | InvalidPublicKeySum | 19 |
| 10 | `0x14ca5bc` | InvalidParityValue + structured payload | 18 prefix |
| 11 | `0x14ca4db` | InvalidEllSwift | 15 |

The11 literal-only arms load `[RSI]` as first callback argument, literal pointer
and exact length as the next two, and **tail-JMP** to `[[RSI+8]+0x18]`. Thus no
owner-side AL mask follows those callbacks: a normal callback return goes to the
owner's caller. Literal spellings alone do not establish an upstream crypto
library, original enum type, key type, protocol, input validator or security
property. These are output bytes and raw branch indices only.

## Whole structured branch (index10)

Save payload pointer `original RDI+4` at stack+8. Save formatting descriptor
`F=original RSI` in R15, `W=[F]` in R14, `V=[F+8]` in R13, callback
`C=[V+0x18]` in R12. Emit prefix `InvalidParityValue`, length18, through C.
Nonzero **AL** takes the early epilogue. Only BL was set to1; MOV EBX to
EAX then returns low AL=1 with upper24 EAX bits inherited from entry EBX under
the assumed preserving ABI. RAX upper32 bits are zeroed by that MOV. Therefore
the full EAX is not guaranteed to equal1. The tests use the callback low byte,
not its full integer.

If the prefix returns AL0, test `[F+0x12]&0x80`:

- Zero: emit `"("` length1 through C. ALnonzero takes that low-AL1 early epilogue. Otherwise call
  direct helper `0x14c2530` at `0x14ca646` with `(address stack+8,F)`.
  ALnonzero takes that low-AL1 early epilogue. After a normal AL0 return, reload W and C from F, then
  proceed to the closing `")"` call. Helper writes are not assumed absent.
- Nonzero: emit `"(\n"` length2 through C. ALnonzero takes that low-AL1 early epilogue. Otherwise put
  byte1 at stack+7, `{W,V,address stack+7}` at stack+0x28,+0x30,+0x38,
  payload pointer `[F+0x10]` at stack+0x20, and descriptor
  `{address stack+0x28,0x64078f8}` at stack+0x10,+0x18. Call the same direct
  helper with `(address stack+8,address stack+0x10)` at `0x14ca6b7`.
  ALnonzero takes that low-AL1 early epilogue. On AL0, use the **post-helper** descriptor pair at
  stack+0x10/+0x18 to emit `",\n"`, length2. ALnonzero takes that low-AL1 early epilogue.

Both successful paths finish by emitting `")"`, length1, through saved/reloaded
C and W. The final callback **full EAX** is copied through EBX to EAX and
returned; it is not normalized to0/1 by this owner. The explicit early exits
guarantee low AL=1, with the entry-EBX upper24 bits described above. Thus an
arbitrary normal final callback return must not be modeled as
only Boolean, and no claim of success/error conventions is required here.

Selected actual descriptor RELATIVE slot `0x6407910 -> 0x1686bd0` is retained,
consistent with the helper adapter discussed by existing RE-014 evidence. Its
semantics, the direct helper's payload rendering, other descriptor slots,
original source ABI, full writer/caller effects and exception behavior remain
open. An observed stack pointer is not proof of an original Rust type.

## Reproduce and real negative controls

From repository root:

```sh
python3.11 -B research/work-items/RE-001-node115-tag-text-dispatch/collect.py --negative-controls
python3.11 -B research/work-items/RE-001-node115-tag-text-dispatch/collect.py --output work/tag-text-fresh
```

Python3.11/native LLVM version strings are in evidence.json. `--output` must
name a fresh directory; `--objdump PATH` optionally selects an installed LLVM
objdump. Before native invocation the full target digest is verified, then a
private byte-identical snapshot under work/ is disassembled as data. Fresh
`owner0.objdump.txt`, `frames.json`, `evidence.json` must exactly equal this
packet; two fresh exports matched all3. No instruction/data operand is masked.
Verification stdout must equal `validation.json`.

All34 actual controls rejected:1 full-image identity,14 instruction-anchor,
17 data (including the whole table slice),1 FDE,1 actual RELA. The33 downstream
controls **bypass full/body hashes and retained native-row comparisons** and
reach specific exact-operand/data/FDE/binding checks. They do not execute mutant
code or establish a semantic differential oracle. Complete590B coverage is
checked separately by authenticating every retained instruction and its unique
byte span against the measured FDE.

Before this packet the table-to-literal mapping, structured branch and final
return-width distinction were not recorded here. After, all12 selected entries
and the entire owner are byte/FDE bound, including its opaque-call boundaries.
No native or source behavior was run to produce that before/after statement.

## Acceptance boundary

No node/library/crypto operation, formatter callback, instruction interpreter,
network service or source reference was executed. All92 acceptance gates remain
false; no whole-function source match or module coverage is claimed. **Required
full suite was not run** because its default oracle producer exceeds static
authorization. This packet is for a **DRAFT PR** pending maintainer-arranged
compliant full validation, not ready/full-gate or hosted-CI success.
