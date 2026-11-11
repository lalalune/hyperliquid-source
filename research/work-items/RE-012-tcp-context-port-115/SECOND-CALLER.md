# RE-012 follow-up: a second initial caller retains port 4002

Target: node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source baseline and component are the same as [the first route](README.md).
This extends the bounded producer question to caller `0x2b69d20..0x2b6ae9f`,
without extending the claim to every state of either caller or the whole node.

The second selected initial path explicitly initializes a tag-zero address
with the u16 **4002**, calls the same producer `0x2b782e0`, and carries its
context field through five copies into sender context `caller+0xa0`.
This supplies another concrete producer binding, rather than assuming that
the first caller's layout transfers to every call site.

## Original bytes and dataflow

The complete FDE-described interval is 4,479 bytes / 855 Capstone rows, body
SHA-256 `5b854640e07f22fdce4262d719e531d12d68014e9518b7f848b2dcb4c13069ba`.
Raw native exports and FDE/file-offset metadata are in [followup/](followup/).
The same byte/boundary comparison and FDE limitations as the first packet apply;
these counts do not measure reconstructed functions or equivalent source code.

| VA / range | Observation |
| --- | --- |
| `0x2b69d91..0x2b69da8` | Initial state dispatch uses table `0x604b48`; its entry zero lands at `0x2b69da8`. |
| `0x2b69dbb` | Bytes `66c78386000000a20f` write u16 4002 at caller `+0x86`. |
| `0x2b69dc4` | Bytes `66c783800000000000` write tag zero at caller `+0x80`. |
| `0x2b69e31..0x2b69e83` | RCX becomes `caller+0x140`; its first qword receives `caller+0x80`. RCX is also retained at caller `+0x180`, then carried directly across the jump to `0x2b69f54`. |
| `0x2b69f90` | Stores that RCX at caller `+0x1a0`. The fresh path does **not** reload caller `+0x180`; the reload at `0x2b69f4d` belongs to a separate nested entry. |
| `0x2b6a369..0x2b6a3a4` | Loads `[caller+0x1a0]`, dereferences its first qword, copies 32 input bytes to caller `+0x278`, initializes the producer state to zero and calls `0x2b782e0`. |
| `0x2b6a3cb` | Copies the admitted `0x98`-byte producer result to caller `+0x1d0`, through imported `memcpy`. |
| `0x2b6a3f4/3f8` | The selected result-tag-non-2 branch reaches the tail copy at `0x2b6a51f`. |
| `0x2b6a533`, `0x2b6a57f` | Copy its `0x88`-byte tail from caller `+0x1e0` through stack `+0x1a0` to stack `+0x248`. |
| `0x2b6a5ae` | Loads unique GLOB_DAT slot `0x64df508` (`memcpy`, symbol 7, addend 0) into R12. |
| `0x2b6a5ba`, `0x2b6a5ed` | Calls R12 twice, copying the `0x88`-byte tail through stack `+0x2d0` into caller `+0xb0`. No R12 reassignment occurs between those calls. |
| `0x2b6a5c4` | RBP = caller `+0xa0`, the context whose first two qwords precede that copied tail. |
| `0x2b6a687..0x2b6a6a6` | Saves RBP at caller `+0x178`; sets sender state zero and calls `0x2b7a290` with sender base caller `+0x168`. Thus sender `+0x10` points to context caller `+0xa0`. |

The selected word is preserved at these locations:

```text
producer result +0x90
  -> caller +0x260
  -> stack +0x220
  -> stack +0x2c8
  -> stack +0x350
  -> caller +0x130 = context (caller+0xa0) +0x90
```

The shared producer/constructor/socket proof is reauthenticated by the follow-up
collector. Under the stated conditions, the retained 4002 passes the sender's
port exclusion, leaving eligibility dependent on input length >= 1025.
This says nothing about the actual serialized length or whether compression,
connection establishment or delivery succeeds.

## Reproduce and controls

With the same tools and PATH as the first route, from repository root:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/followup.py --out work/context-port-second
python3 -B -O research/work-items/RE-012-tcp-context-port-115/followup.py --out work/context-port-second-optimized
```

Both output directories must be fresh. Each invocation authenticates the target,
rechecks the first route's pinned bindings, exports the second caller with GNU
and LLVM, and rejects eleven span mutations plus one initial-dispatch mutation.
The two recorded invocations produced byte-identical exports and JSON records.
No captured instruction execution or emulation occurs. `followup/records.json`
contains the 12 negative-control results and `followup/commands.json` preserves
the exact native commands. Git's existing `.objdump` attributes preserve raw
GNU CRLF output; authored JSON/text uses LF without altering native output.

The second caller was independently reviewed against original bytes, including
the fresh-path RCX distinction, the R12 import binding and field-copy offsets.
Repository-wide validation limitations in [validation.json](validation.json)
still apply; this follow-up does not fix the baseline test/catalogue failures.

## Remaining gaps

This result assumes the selected initial/admitted-result path, normal
ABI-conforming helper and `memcpy` returns, and no conflicting alias writes.
Formatting, preparation, cleanup and retry helpers remain unclosed. Nested
state-table entries alone do not establish legal resume behavior. The observed
constant does not recover a port's application role or an original Rust type.
No Rust build, behavioral equivalence, byte window or component gate is added.

Next: trace the remaining sender callers and their mutation/resume paths before
promoting the field to a shared typed Rust context. New code/docs are MIT;
captured evidence keeps its existing terms.
