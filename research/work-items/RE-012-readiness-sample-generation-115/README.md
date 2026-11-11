# RE-012: readiness sample, generation byte and callback replacement

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Baseline `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; network transport / RE-012.
Question: where does the readiness record's byte +8 come from, and which
state words and callback operations precede its publication?

## Gap and existing work

Accepted PR #3159 consumes a generation byte in its send-side CAS loops but
does not recover its producer. PR #3987 identifies `0x5cfd010` as the lower
operation and leaves that record's byte +8 open. This independent packet
recovers the lower body; no change from #3987 is required on this branch.
The existing `RE-002-node115-rust-tokio-io-references` packet resolves 22
reference operands across four bodies, including this one, and is credited
for linkage context. It leaves runtime object layout/behavior open; its
source labels are not used as proof of the following raw contract.

Live exact-address PR search and the current-tree packet search on 2026-11-07
found no other semantic recovery of this body. Search absence does not prove
exclusive ownership. This is a bounded extension, not a whole transport claim.

## Original evidence and reproduction

Complete FDE-described extent `[0x5cfd010,0x5cfd1c8)`, 440 bytes. Coordinates
are original ELF VAs, with no rebase or normalized operands. `records.json`
and `disassembly.txt` retain all bytes, their digest, the actual FDE/CIE,
LSDA address, decoded branches, direct calls, relocation-backed calls and
unresolved callback operands. Linear decoding is complete for this extent;
FDE membership alone does not establish source ownership or all runtime entries.

Use Python 3.12.14, Capstone 5.0.6 and pyelftools 0.32 from the repository root:

```sh
python research/work-items/RE-012-readiness-sample-generation-115/verify.py --write
python research/work-items/RE-012-readiness-sample-generation-115/verify.py
```

The ordinary command regenerates and compares both exports byte-for-byte.
The full retained target digest is checked before extraction. No captured
instruction, callback, lock helper, socket or executable is run/interpreted.

## Fast sampled result

RDI is output, RSI is the selected owner address, RDX is context, and ECX is
the raw mode. At `0x5cfd027`, load W from owner+0x10. With 32-bit wrapping
arithmetic, form `I = (5*mode+5) & u32(W)`. Separately retain W bit 31. If I
is nonzero or that bit is set, publish qword I at output+0, bits 16..23 of W
at output+8, and bit 31 (0 or 1) at output+9. There is no callback-slot access
or byte-lock acquisition on this early return. The sample is a qword load;
the mask and generation extraction use its low dword.

Thus the generation consumed by the send helper is the same **bit position**
in the shared word it later compares, not an independently loaded counter.
At the wrapper call qualified in #3987, lower RSI is `[transport_owner+0x10]
+0x80`; this body's +0x10 sample is therefore at that state object's +0x90,
matching #3159's CAS offset. This is a numeric call/offset composition, with
owner-field stability across opaque calls still an assumption.
This does not yet identify who increments it, its lifetime or wrap policy.

## Slow callback path and resampling

If the initial test finds no selected bits and bit 31 clear, the code attempts
locked byte CMPXCHG at owner+0x18, expected 0 and desired 1. Failure calls
slot `0x64e01f8` with EDX=1,000,000,000, then rejoins the body after acquisition.
That helper's lock/parking contract is an external assumption, not proven here.

The callback slot offset is `0x30 + 16*u8(mode)`. Its first word is tested for
null. If nonnull, both words are compared with the two-word record reached
through `[context]`; exact equality skips clone/replacement. Otherwise the
new first word's function pointer at +0 is invoked with the new second word.
Its two-word return is saved while an existing callback is released through
its first word's +0x18 slot. The null-old-word route re-reads that old slot
after cloning and conditionally releases a now-nonnull value. This post-call
reload must not be simplified to an immutable pre-call assumption.

The cloned pair is then stored at the mode-selected owner slot. The original
state word at owner+0x10 is loaded again at `0x5cfd0ed`, after these opaque
callback calls. The result uses this **new sample**, not the initial sample.
Callback object validity, aliasing, allocation and ownership remain assumptions.

## Locked-path result

Here mode low byte zero selects mask 5; any nonzero low byte selects mask 10.

| Resampled W | Stores before unlocking |
| --- | --- |
| bit 31 set | qword full mask 5 or 10; byte +8 = bits 16..23; byte +9 = 1 |
| bit 31 clear, selected mask bits nonzero | qword masked bits; byte +8 = bits 16..23; byte +9 = 0 |
| neither condition | byte +9 = 2; no qualified qword/+8 store on this route |

The normal release attempts locked byte CMPXCHG expected 1, desired 0. Failure
calls slot `0x64e0f38` with ESI=0 before returning. The full FDE also contains
cleanup-shaped callback publication and unlock blocks; LSDA dispatch/action
tables and complete unwind correctness are not decoded or claimed.

Two differences are material. On bit-31-set samples, the fast route publishes
the actual masked bits, while the slow route forces the selected full mask.
For modes beyond 0/1, the fast 32-bit arithmetic is not equivalent to the slow
low-byte zero/nonzero selection. For example mode 2 and word 1 produce a fast
record `(1,0,0)`, whereas the locked model has tag 2 and no initialized payload.
The mode-1 send caller is grounded by #3159; no generalized mode API is inferred.

## Controls and limits

Thirteen instruction mutations are rejected with whole-file authentication
disabled only in those negative controls. They alter mask arithmetic, bit-31
selection, generation extraction, byte publication, slot stride, equality
branch, resample masks, pending tag and lock-helper argument. The finite corpus
covers 16,384 low-bit/generation/bit-31/mode-0-or-1 combinations and the explicit
mode-2 counterexample. It checks same-author conditional branch models, not
actual callbacks, lock interleavings or native execution. Callback effects
are excluded; the sample words are supplied to each model separately.

No original Rust symbol, ADT ABI, scheduler guarantee, full callback ownership,
lock-helper closure, Rust implementation, compiled comparison, whole-node
behavior, component gate or byte-coverage increase is claimed. New notes and
verifier are independently authored MIT; captured evidence retains its rights.
See `validation.md` and the PR for actual repository-level checks.

Next: identify the shared word's generation increment/publication sites and
the lock-helper contract before claiming freedom from lost wakeups.
