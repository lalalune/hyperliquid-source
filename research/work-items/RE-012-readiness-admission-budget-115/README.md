# RE-012: readiness admission and conditional TLS budget restoration

- Component: network transport; RE-012 continuation of the accepted send-helper
  packet, PR [#3159](https://github.com/lalalune/hyperliquid-source/pull/3159).
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
- Question: when does `0x5cf22f0` enter its lower readiness operation, how does it
  project the lower result, and when are the saved TLS bytes restored?
- Claim: static branch/store/call observations and a conditional scalar
  interpretation. No original symbol/type or complete scheduler is recovered.

## Why this is new

The accepted send-helper packet identifies calls through slot `0x64e14d8` to
`0x5cf22f0` and explicitly leaves this producer for follow-up. Its numeric send
results and its two CAS loops are unchanged and are not re-claimed here.

The current tree's `RE-002-node115-rust-tokio-io-references` packet resolves
selected operands in the lower `0x5cfd010` body, not this wrapper's admission or
result policy. `RE-001-node115-lu-tag-meaning` lists `0x5cf1d10` as an external
callee without decoding it. The present packet includes that complete 85-byte
helper only to qualify the wrapper's explicitly observed restoration call.
It does not claim the existing lower-body linkage work or the LU function.

Live PR searches for `5cf22f0`, `5cdf1b0` and readiness were inspected on
2026-11-07. The error classifier was excluded because PR #2032 already recovers
it. A full current-tree README/PROOF search for `5cf22f0`, `5cfd010` and
`5cf1d10` found the three packets above; no separate wrapper recovery was found.
These searches do not prove exclusive ownership of every historical patch.

## Evidence identity and reproduction

All coordinates are linked ELF VAs. No relocation normalization or guessed
load bias is used. The two complete FDE-described extents are:

| Body | End, exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| `0x5cf22f0` wrapper | `0x5cf24a2` | 434 | 117 |
| `0x5cf1d10` restoration helper | `0x5cf1d65` | 85 | 25 |

`records.json` retains every original body byte and SHA-256, actual FDE/CIE
bytes, LSDA address where present, all decoded direct branch destinations,
calls and unique RIP-relative call-slot bindings. `disassembly.txt` covers
both full extents. FDE membership and linear decoding do not prove all runtime
entries or recover a source function boundary/ownership by themselves.

Use Python 3.12.14, Capstone 5.0.6 and pyelftools 0.32, with the retained binary
materialized. From the repository root:

```sh
python research/work-items/RE-012-readiness-admission-budget-115/verify.py --write
python research/work-items/RE-012-readiness-admission-budget-115/verify.py
```

`--write` regenerates records and listing; the ordinary invocation compares
both files byte for byte. The complete target digest is checked first. The
verifier performs static ELF parsing and decoding only; no target instruction,
TLS helper, scheduler, socket or captured executable is executed/interpreted.

## Observed TLS admission

At `0x5cf2304`, R15 is the sign-extended constant `-0x1130`. The state byte is
at FS-relative R15+0x48 (`-0x10e8`), and the two-byte budget-shaped field at
R15+0x44 (`-0x10ec`). These are this body's exact offsets, not inherited TLS
layout assumptions from another packet.

- State 1 enters the two-byte field path directly.
- State 2 sets EBP to zero and bypasses that field, proceeding to the lower
  operation without this wrapper's byte-based admission/restore condition.
- Other state values call slot `0x64e0510`, R_X86_64_RELATIVE addend
  `0x5ca0d20`, passing TLS-base+R15 and callback VA `0x5cdf410`. The wrapper then
  writes state 1 and reads the field. The initializer's effects remain opaque.

For state 1, let F be the field's low byte and B its high byte. If F bit 0 is
set and B is zero, the wrapper bypasses the lower call, invokes slot
`0x64e0520` (addend `0x5cf3b90`) with the loaded context word and data VA
`0x64c6648`, and then writes output byte +9 as 3. Behavior inside that helper
and its scheduling effects are not reconstructed.

If the low bit is set and B is nonzero, the wrapper writes B-1 to TLS byte +0x45
before the lower call. If the low bit is clear it stores B unchanged. The
original F and B survive in BP/R12B for the conditional restoration path.
The term "budget" is a role inference from this decrement/restore policy, not
an independently recovered Rust type or a fairness guarantee.

## Lower call and output projection

At `0x5cf239c`, the wrapper calls `0x5cfd010` with a temporary output record,
the numeric address `[owner+0x10]+0x80`, the context argument, and the low byte
of the supplied mode. PR #3159 supplies mode 1 at its two selected send sites;
this packet does not claim that every wrapper caller supplies mode 1.

Let T be the lower record's byte +9. The ordinary output path is:

| Lower result | Output stores | Enter restore path? |
| --- | --- | --- |
| T = 2 | byte +9 becomes 3; payload bytes are not assigned here | if saved F bit 0 is set |
| T != 2 and T bit 0 is set | call slot `0x64e0750`, addend `0x5c700a0`, with EDI=0x28, data VA `0x94d74e`, EDX=0x38; store returned qword at +0, byte +9 becomes 2 | if saved F bit 0 is set |
| other T | copy temporary qword +0, byte +8, dword +0x0a and word +0x0e; byte +9 becomes 0 | no restore on this path |

The data VA above is computed from the actual LEA at `0x5cf23e3`; it is a
bound argument address, not an assertion that the data is an error type or
that the constructor always returns normally. Original ADT names, valid tag
sets, and the meaning of byte +8 remain unresolved. Unwritten bytes on pending
or error paths must not be treated as initialized payloads.

The key consequence is conditional: for the admitted state-1 low-bit-set path,
the lower even/non-2 result skips restoration. Pending-like and error-like
projections enter the restoration path, which rechecks the current TLS state;
if it is still 1, the saved high byte is restored. State 2 at that later check
skips the stores. The initial state-2 path has no such charge in this wrapper.
Helpers may change TLS state; stable state across them is an explicit
assumption of the finite scalar control below, not a binary-backed guarantee.
These are local transitions, not end-to-end I/O.

## Restoration and exceptional boundary

On ordinary restoration, TLS state 1 writes low byte 1 at +0x44 and the saved
original B at +0x45. State 2 skips the stores. Other states pass the TLS address
and callback `0x5cdf410` through `0x64e0510`, write state 1, then write the two
bytes. The restored low byte is **1**, not an arbitrary original F.

The separate `0x5cf1d10` helper tests its first argument's low bit before any
TLS access. Bit-clear returns immediately. Bit-set uses the same `-0x1130`
base and state admission: state 2 skips restoration, state 1 stores low byte 1
and the supplied second argument's low byte, and other states initialize first.
The wrapper's block at `0x5cf2484` passes saved F/B to this helper at
`0x5cf248f`, then passes its saved RAX to `0x63f0a50`. The wrapper has an LSDA,
but this packet does not decode its call-site/action table, prove dispatch to
that block, or qualify a complete Rust unwind/drop contract.

## Controls, validation and remaining work

Thirteen modified instruction operands/conditions are rejected with the
whole-file guard deliberately disabled in those controls only. They cover TLS
offset, admission bit, exhaustion branch, decrement, lower-call target, output
tags, restore flag and the helper's early return. The finite check covers 360
boundary combinations with zero disagreements between two separately written
scalar expressions. Both are same-author derivations; this is not independent
target execution, opaque-helper validation or a TLS interleaving proof.
The scalar expressions assume normal helper returns and stable TLS state and
exclude writes performed inside those helpers. They qualify the wrapper's
selected store/skip policy, not a live TLS value after arbitrary external code.

See `validation.md` for actual repository check results. Every acceptance gate
and byte-window registry entry remains unchanged. No source build, original
Rust name/type/ABI, runtime equivalence, helper closure or full readiness
primitive is claimed. New notes/verifier are MIT; captured bytes retain their
existing rights. No unlicensed inferred source is copied.

Next: recover the lower `0x5cfd010` success record's byte +8 and its relation
to the generation byte used by the accepted send helper before claiming the
complete sampled-readiness contract.
