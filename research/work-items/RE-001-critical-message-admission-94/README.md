# RE-001: critical-message entry admission and one real caller

- Component: foundation logging/runtime utilities. Bounded question: which
  option bytes control the three entry gates of the node94 function led by
  the inferred critical-message label, and what does a real caller establish
  about their representation and the result ABI?
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base and unchanged reference pins:
  `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Actual FDEs: `0x143d010..0x143e888` (6,264 bytes) and selected caller
  `0x4779e30..0x4779eac` (124 bytes). Raw disassembly is retained for the
  complete enclosing ranges; only the entry gates and specified caller flow
  are interpreted. This does not recover every operation in the 6,264 bytes.
- No captured execution, network/alert action, new Rust implementation,
  component completion number or progress gate.

## Why this evidence is needed

The unlicensed inferred `base/crit_msg.rs` describes policy names, independent
option fields, a supplied environment and a rich decision enum. Those are
leads, not a recovered ABI. The target actually reads an options pointer,
formatting-related arguments and a source Location; the three gate inputs
include a lazy global object's discriminant, another global byte and the low
byte returned by a helper. This packet binds those reads and branch order
without copying the inferred implementation or replacing unknown policy with
new behavior. It does not certify the reference's names or defaults.

In particular, a complete 64-bit word is loaded from options `+0`, and a second
word from `+8`. The selected caller initializes the first word and five flag
bytes, but does **not** establish initialization of the second word. This is
not proof of a specific Rust `Option` layout, nor permission to model those
words as independently valid fields. Treating the whole buffer as zero-filled
would misreport the actual caller. Likewise, the common suppressed return
sequence does not construct the inferred structured decision value, and this
caller discards the callee's RAX. A complete concrete return type remains open.

## Observations

1. Before reading any option flag, the function calls slot `0x576e8a0` at
   `0x143d047`, whose RELATIVE addend is `0x151cba0`. Its timing role is a
   contextual inference; its transitive implementation is not proved here.
   Disabling the three gates does not bypass this preceding call.
2. Option byte `+0x12 == 0` bypasses the first gate. Otherwise slot
   `0x576e928` supplies object `0x577b288`. A DWORD at object `+0x50` selects
   a slow initialization path when nonzero. Both the fast path and the path
   after the initialization helper returns load the byte at object `+0x48`.
3. That byte is compared **unsigned** with 30, followed by `bt` against mask
   `0x40006000`. Only raw discriminants **13, 14 and 30** continue. The bound
   check matters: values above 31 must not be allowed to wrap the x86 bit index.
   This does not identify those discriminants as log levels, network modes or
   a recovered enum. The initialization helper may fail or not return; the
   conditional predicate assumes it returned and uses the resulting byte.
4. Option byte `+0x13 == 0` bypasses the second gate. Otherwise a nonzero byte
   at VA `0x5788310` branches to the common return epilogue.
5. Option byte `+0x14 == 0` bypasses the third gate. Otherwise slot
   `0x576e898` -> `0x13c8f60` is called, and a nonzero **AL** branches to the
   same epilogue. No concrete testing/environment semantics are assigned to
   that helper from its inferred label alone.
6. All three failed gates converge on `0x143e355`, which restores the 0x278-byte
   stack frame and saved registers and returns at `0x143e366`. There is no
   structured result store or canonical decision-tag assignment in that
   epilogue. This observation does not prove a language-level unit return.

The slow path `0x143d3a1..0x143d3fd` passes object `+0x50`, a closure-related
record at `0x567b210`, and Location slot `0x567b238` to call slot `0x576e8b8`
-> `0x4ee3b20`. The Location resolves to the compiler-stamped std sync once
source, line 219 column 20. This is source/edge evidence, not a proof of lazy
initialization or concurrency correctness.

A later instruction at `0x143def3` references Location `0x566a278`, resolving
to `/home/ubuntu/hl/code_Mainnet/base/src/crit_msg.rs:291:19` (length 49).
That binds the function to a critical-message source context; it does not make
every inferred method or line in the reference authoritative.

### Selected caller

The 124-byte caller has a call at `0x4779e9d` through slot `0x576e978`, whose
RELATIVE addend is the actual callee entry `0x143d010`. Before that call:

- RDI points at `rsp+0x18`; its QWORD `+0` and bytes `+0x10..+0x14` are zeroed.
  The QWORD `+8` and padding are **not** shown initialized by this window.
- RSI is loaded with VA `0x1f3bf3`, retained as an uninterpreted formatting
  address; RDX points at `rsp+8` and RCX at Location slot `0x572e8a8`.
- That Location resolves to `base/src/file_mod_time_tracker.rs:63:13`.
- After the call, RAX is replaced with the caller's saved pre-call pointer
  from RBX. Thus this caller supplies no evidence for a structured decision
  result being consumed.

The three gate flags are disabled in this caller, so no universal default
policy can be inferred from the callee alone. This packet uses the edge as
supporting evidence for entry ABI only; it does not redo PR #31's distinct
file-tracker initializer/fallback question. No global caller count is claimed.

## Reproduce and retained records

From the repository root, with pinned captures materialized and native tools:

```sh
python3 -B tools/critical_message_static.py --output work/critical-message-admission-94
python3 -B tests/test_critical_message_static.py
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-critical-message-admission-94/SHA256SUMS
```

Python 3.12.14, GNU binutils 2.47.20260726 on macOS. The generator authenticates
one full snapshot and feeds that same private temporary snapshot to
`readelf -wf` and `objdump -d -M intel --insn-width=16 --start-address=...
--stop-address=...`. Captured code is never spawned or emulated. Temporary
paths alone are replaced by `<authenticated-node94>`; instruction/data bytes
have no normalization masks. `foundation_millis.decode_export` verifies native
bytes/contiguity/end bounds, and all selected control/RIP sites must be decoded
instruction starts from the full FDE entry.

`frames.txt` and the two `.objdump.txt` files preserve the native evidence.
`records.json` retains original VAs, file offsets, body hashes, gate/option
fields, instruction controls, source Locations and eight exact RELATIVE
bindings. Independent transient Capstone 5.0.6 consumed 1,177/29 instructions
covering all 6,264/124 bytes respectively; that checks decoding extents, not
independent semantic reconstruction.

Five focused tests cover bindings; all **8,192** combinations of a raw byte
tag and five boolean gate inputs, plus noncanonical nonzero-byte controls;
**23** changed instruction/data/Location bytes below the digest gate; **8**
actual relocated-addend changes; and native packet regeneration with wrong
input admission rejection. The finite predicate table uses an independent
closed set `{13,14,30}` expectation and explicit gate priority. It is a
conditional model of the decoded entry predicate, not whole-function
execution, valid-state proof or a simulation of alert side effects.

Required suite/reproduction results are recorded in the PR after completion.
SHA256SUMS covers the durable evidence and both independently authored files.
Captures, original imports, reference pins and all progress gates are preserved.

## Limits and next question

Unknown: source-level policy names/defaults, complete options/format argument
layout, concrete tag enum, helper closure/non-return cases, all callers,
initialization correctness, occurrence/repeat/ignore/statistics gates after
entry, later external side effects, concrete return type, Rust build and runtime
equivalence. Observed early returns do not prove no effects occurred before
them. Next validate the lazy object's initializer and tag constructors before
assigning semantic names to the three accepted raw values.
