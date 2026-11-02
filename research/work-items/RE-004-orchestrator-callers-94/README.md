# RE-004 orchestrator callers — node #94

## Claim status

**Claimed.** #170's Next question — does the orchestrator's caller read
`[rdi+0x9..0x10]` / `[rdi+0x19..0x28]` of the orchestrator's output
object, i.e. does the propagated residue survive one more call
boundary, or is it overwritten before any read? — is answered by a
complete census of the orchestrator's direct callers:

- **Neither read nor overwritten.** All 3 direct call sites pass the
  orchestrator's output object straight through: each caller saves
  its own `rdi` to `r14`, passes `rdi` unchanged into the
  orchestrator, and on the normal path returns `r14` in `rax`
  without any load from, or store to, the output object. The
  propagated residue therefore **survives one more call boundary
  untouched** — it escapes to the caller's caller in `rax`.
- The only post-call memory traffic in any caller FDE targets the
  caller's `rcx` object (`rbx`): loads at `[rbx+0x28]`,
  `[rbx+0x30]`, `[rbx+0x38]`, a `lea` of `[rbx+0x40]` for a vtable
  call, and PLT calls with `rdi=rbx`. No instruction in any caller
  FDE reads the output object's stale spans
  (`[rdi+0x9..0x10]`, `[rdi+0x19..0x28]`).

**Not claimed.** No read by the callers' callers is claimed: the
object is returned, so whether anyone further up the chain reads the
spans is the Next question. No defect, exploitability, or security
severity is claimed. Indirect (vtable) callers of the orchestrator
are not enumerated; the census covers direct `E8` call sites only
(plus an `E9` tail-jump scan, which found none).

## Scope

Included:

- 3 direct `E8` call sites of the orchestrator `0x4e6fef0`:
  `0x4e6cff0`, `0x4e6d6a0`, `0x4e6e7e0`, in 3 caller FDEs of 119
  bytes each.
- The full caller FDEs as census scope (normal path + landing
  pads), the orchestrator prologue anchor (`mov rbx,rdi` at
  `0x4e6ff04`, proving `rbx` is the `rdi` output object), and the
  pairwise template diff of the three FDEs.
- 4 byte segments in `segments.txt` (3 claim segments, 357 bytes;
  1 anchor segment, 3 bytes).

Excluded:

- Indirect/vtable callers of the orchestrator (none found by the
  direct-call scan, but indirect reachability is not disproven).
- Readers of the output object after the callers return (the Next
  question).
- The internals of the PLT callee at `0x576e010` and of the
  destructor at `0x4e6e8b0`: only their call-site argument routing
  (`rdi=rbx`, never the output object) is used here.
- The #157–#170 subjects and #1543's fixed-eight topic. #170's
  propagation verdicts are cited, not re-claimed; the orchestrator
  prologue instruction is an anchor (`kind=anchor`).

## Observations

### The census: 3 call sites, 0 tail jumps

A scan of the whole `.text` section for `E8` + rel32 and `E9` +
rel32 resolving to `0x4e6fef0` finds exactly 3 direct calls and 0
tail jumps. Each call site falls inside exactly one FDE.

| site | caller FDE | call VA | verdict |
|---|---|---|---|
| oc1 | `0x4e6cfe0..0x4e6d057` (119 B) | `0x4e6cff0` | NO-READ, returned untouched |
| oc2 | `0x4e6d690..0x4e6d707` (119 B) | `0x4e6d6a0` | NO-READ, returned untouched |
| oc3 | `0x4e6e7d0..0x4e6e847` (119 B) | `0x4e6e7e0` | NO-READ, returned untouched |

### One template, three instances

The three 119-byte FDEs differ **only** inside seven
address-displacement fields (21 pair-field rows in
`template-diff.tsv`; every other byte is identical):

| field (FDE offset) | instruction | target |
|---|---|---|
| `0x11..0x15` | `E8` call | orchestrator `0x4e6fef0` |
| `0x34..0x38` | `FF 15` PLT call, normal path | `0x576e010` |
| `0x52..0x56` | `FF 15` PLT call, landing pad 1 | `0x576e010` |
| `0x5a..0x5e` | `E8` call, landing pad 1 | `_Unwind_Resume` PLT `0x5660110` |
| `0x65..0x69` | `E8` call, landing pad 2 | destructor `0x4e6e8b0` |
| `0x6d..0x71` | `E8` call, landing pad 2 | `_Unwind_Resume` PLT `0x5660110` |
| `0x73..0x77` | `FF 15` PLT call, landing pad 3 | `0x576e128` |

Per pair, 2–3 bytes differ inside each 4-byte field (the low bytes
of the displacement); no opcode, ModRM, register, or immediate byte
differs anywhere. The three callers are one template instantiated
three times, so the NO-READ verdict, traced once, holds for all
three by byte identity.

### Argument routing: rdi passes through untouched

Normal path of each caller (identical in all three instances):

```
push r14; push rbx; push rax
mov rbx,rcx            ; rbx = caller's rcx object
mov r14,rdi            ; save output-object pointer
mov rsi,rdx            ; orchestrator arg 2 = caller's rdx
mov rdx,rcx            ; orchestrator arg 3 = caller's rcx
call 0x4e6fef0          ; rdi UNCHANGED: still the output object
mov rax,[rbx+0x28]     ; rcx object, not the output object
mov rsi,[rbx+0x30]
lea rdi,[rbx+0x40]
mov rdx,[rbx+0x38]
call [rax+0x20]        ; vtable call on the rcx object
mov esi,0xa0; mov rdi,rbx; xor edx,edx
call [PLT 0x576e010]   ; rdi = rbx, not the output object
mov rax,r14            ; return the output object untouched
add rsp,0x8; pop rbx; pop r14; ret
```

`rdi` is never modified before the call, and `r14` (the saved
`rdi`) is never dereferenced on the normal path — it is only moved
to `rax` for the return. The orchestrator's prologue
(`0x4e6ff04: mov rbx,rdi`, anchored) confirms the orchestrator
writes its output object at `rdi`, so the object the caller returns
is exactly the object carrying the propagated spans from #170.

### Landing pads: no output-object traffic either

- Pad 1: PLT call with `rdi=rbx`, then `rdi=r14` where `r14` is the
  exception object (`mov r14,rax` on entry) for `_Unwind_Resume` —
  not the output object.
- Pad 2: destructor call with `rdi=rbx`, then `_Unwind_Resume`
  with the exception object.
- Pad 3: a single indirect PLT call whose only memory access is
  the GOT slot dereference — no load from the output object.
- No pad reads `[rdi+0x9..0x10]` or `[rdi+0x19..0x28]`, and none
  stores to the output object.

### What this settles

#170 showed the orchestrator reads the 22 stale bytes and copies
them into its output object, which "survives the return". This
packet shows the next boundary does not consume them either: all 3
direct callers hand the object back untouched. The residue is now
two boundaries deep (verbatim install → orchestrator propagation →
caller passthrough) with no reader yet. The remaining question is
whether the callers' callers read it.

## Inferences (separated from observations)

- The residue's survival is structural, not accidental: the three
  callers are thin wrappers whose only job is to forward arguments
  and return the output object, so they have no reason to inspect
  it. A reader, if one exists, must live further up the chain.
- The template identity means the three sites are not three
  independent data points about caller behavior — they are one
  behavior observed three times. The census is complete for direct
  callers, but its behavioral weight is that of a single wrapper
  shape.

## Limitations

- Direct `E8` call sites plus an `E9` tail-jump scan only. A
  vtable/indirect caller of the orchestrator would not appear;
  none was found, but indirect reachability is not disproven.
- The callers' callers are not censused: the object is returned in
  `rax`, and whether anyone up the chain reads
  `[obj+0x9..0x10]` / `[obj+0x19..0x28]` is open (see Next
  question).
- Segment-claim overlap with prior packets is zero bytes: no
  claimed segment byte is shared with #157–#170. The orchestrator
  prologue instruction is #170's claim re-cited as an anchor, and
  the caller FDEs sit outside every prior packet's claimed
  segments.
- Static analysis only; no node execution, so no runtime values of
  any stale byte are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (verified: the
recorded instruction bytes match the binary at those offsets, and
the generator fails loudly on any mismatch).

```sh
# the three caller FDEs
objdump -d -M intel --start-address=0x4e6cfe0 --stop-address=0x4e6d057 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e6d690 --stop-address=0x4e6d707 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e6e7d0 --stop-address=0x4e6e847 \
  artifacts/node/94/hl-node
# orchestrator prologue anchor
objdump -d -M intel --start-address=0x4e6fef0 --stop-address=0x4e6ff10 \
  artifacts/node/94/hl-node
python3 tools/orchestrator_callers.py --out /tmp/orch-callers
diff -r /tmp/orch-callers research/work-items/RE-004-orchestrator-callers-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/orchestrator_callers.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/orchestrator_callers.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

The generator reads only `artifacts/node/94/hl-node`, checks its
SHA-256 and size first, writes only to --out, and performs no
execution, evaluation, disassembly or network access.

## Next question

- Do the callers' callers read `[obj+0x9..0x10]` /
  `[obj+0x19..0x28]` of the returned output object — i.e. does the
  propagated residue survive a third boundary, or is it finally
  consumed (or overwritten) there? That needs a caller census over
  the direct callers of oc1/oc2/oc3, symmetric to this one.
- Is there an indirect (vtable) caller of the orchestrator at all?
  The direct census is complete, but a vtable edge would extend the
  caller set.

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — census, template summary, verdicts, segment inventory
- `caller-sites.tsv` — 3 rows, one per direct call site
- `template-diff.tsv` — 21 rows (3 pairs x 7 displacement fields)
- `segments.txt` — 4 rows: 3 claim segments (357 bytes) + 1 anchor
  segment (3 bytes), each with start..end, length == end − start,
  and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
