# RE-001: shared daily/hourly rotation and conditional flush

- Component: foundation / rotating writer support. Question: which raw fields
  control rotation and the post-write flush call in the two related paths?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used as a lead only.
- Status: instruction/data observations and raw decision models. Runtime
  configuration meaning and complete source interfaces remain unresolved.

## Reproduce

Repository root, CPython 3.12.14 on Windows:

```sh
python tools/daily_rotation_static.py --out work/daily-rotation-94.json
python -m unittest discover -s tests -p test_daily_rotation_static.py -v
python research/work-items/RE-001-daily-rotation-94/export_disassembly.py
```

Verifier/model/tests use the standard library. Optional export uses Capstone
5.0.6, x86-64 Intel syntax, inspected wheel SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
No captured code or actual file operation executes.

The packet retains complete FDE windows `[0x1401d40,0x1402049)` (**777 bytes /
164 instructions**) and `[0x14023c0,0x1402744)` (**900 bytes / 192
instructions**): **1,677 bytes / 356 instructions** total, contiguous complete
byte consumption, raw FDE/CIE records and body hashes. All selected observations
are instruction starts. Coordinates are ELF VAs; `.text` offsets are VA minus
`0x1000`. No normalization masks.

## Shared preconditions and rotation

Both selected paths use a word at object `+0x48`. `CMP 0,word; JO` bypasses the
selected write/rotation path exactly for raw `0x8000000000000000`. This is not
a no-side-effects claim for either complete entry: the second entry already
calls a clock helper and copies 168 bytes of opaque input before this guard.
The reference's `write_owned_line` label does not establish that entry's ABI.

For an active word, both inspect the raw dword at time `+4`. Values at least
921,600 enter an unwrap arm bound to `base/src/time.rs:62:44`; values in
[90,000,921,600) enter the hour-assert arm bound to `base/src/hour.rs:12:13`.
The order matters. Inputs below 90,000 continue; these bounds do not establish
that every such raw timestamp is a valid Chrono value or that its other fields
have been validated.

The hour primitive is `(raw_second * 0x91a2b3c5) >> 43`. The product fits u64
throughout the declared domain. It agrees with independent integer division
by 3,600 for **all 90,000 raw inputs**, yielding 0..24. This primitive claim
does not assign a timezone or validate the opaque date word.

| Mode byte at +0xa8 | Raw comparison | Selected path |
| --- | --- | --- |
| Exactly 1 | hour at +0xa9 differs, or date word at +0x98 differs | Hourly-template replacement |
| Exactly 1 | both equal | No replacement |
| Any other byte | date word differs | Daily-template replacement |
| Any other byte | date word equal | No replacement |

The hourly format prefix contains `/hourly/` at `0x1e9393`. Replacement paths
call the same initializer and old-value helper and copy an 80-byte result.
They update the date word; the hourly path also writes mode 1 and its hour.
These are conditional store/call observations after ordinary helper returns,
not a claim that an actual file is created or successfully opened.

The first path calls `0x13d12a0`, and the second calls `0x13d1060`. Each then
copies 12 timestamp bytes into object `[0x9c,0xa8)`. Complete inner write, clock,
formatting, initialization, allocation and error/unwind behavior is unresolved.

## Flush requires three observed gates

Both paths reach slot `0x576eaa8 -> 0x13d1880` only when:

1. Local byte at object `+0xaa` is nonzero.
2. The byte obtained through RELATIVE pointer `0x576ef18 -> 0x5788312` is nonzero.
3. The post-replacement word at object `+0x48` is not raw INT64_MIN.

The reference `base/daily_liner.rs` describes a flush based on the local flag;
that alone omits the captured shared-byte and post-state checks. This packet
does not name the shared byte's policy or read its live value. On-disk bytes
do not establish runtime configuration, and the global is not constant-folded.
The gate proves a call-selection condition, not successful flushing or durability.

## Controls and required checks

Six focused methods pass. In addition to the 90,000 hour inputs, **393,216**
declared rotation combinations (all mode/hour byte pairs, two date-equality
classes, three representative raw second values) agree with an independent
decision form. **131,072** local/global byte-pair and post-head combinations
agree with the three-way gate. Raw-byte domains include representations that
need not be valid source-language booleans or reachable runtime states.

Actual-capture controls mutate precondition/order, magic multiplier/shift,
rotation fields, local/global/post-state branches, global/flush relocations,
write helpers, time/hour source records, template, FDE and identity. Both related
copies are in this one packet. Make is absent; required Makefile Python commands were run directly. Full suite:
**363 tests in 107.195 seconds; 7 failures, 16 errors, 21 skips**. All six new
methods pass. This independent main-based branch excludes unmerged #227. Doctor
reports missing native prerequisites. Eight artifact size/digest checks pass
before missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained);
catalogue fails on native backslash paths. Reproduce stops at artifact
verification. These failures are not marked passed.

No reference code/imported evidence changes, runtime I/O, full Rust layout,
second-entry API, helper/concurrency closure, binary equivalence, hosted CI or
progress gate. Next question: close the inner writers and shared-byte producers
before describing effective flush/durability policy.
