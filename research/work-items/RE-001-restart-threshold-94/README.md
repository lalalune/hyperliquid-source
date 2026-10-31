# RE-001: restart-threshold template source and returned-word floor

- Component: foundation.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: does the restart-threshold wrapper take a caller-supplied root and unwrap a fallible integer reader, as its inferred reference suggests?
- Status: digest-bound static observations plus explicitly conditional return-word reasoning. No recovered implementation or gate.

## Why this packet

The unlicensed inferred `base/u.rs` lead describes a root argument, path joins,
a plain trimmed integer-file reader and a Result fallback. These are not evidence
for the captured API. The complete 213-byte wrapper instead constructs a formatting
argument from a relocated global; no incoming SysV argument register contributes
to that construction. Its reader result is a raw return word with no Result-tag
check in the wrapper. The minimum-one rule is confirmed, but a complete IO/parser
fallback implementation is not. This changes the API and error-handling obligations
that a reconstruction would need to prove; it is not a defect claim against a
running Hyperliquid node.

Reference pin: `can1357-hl` commit `999556f6e0a474b8312db96ec3149e1c44e97c23`,
`base/u.rs` SHA-256 `bfb6ee7d565591f37e8d02cc5b5384d4e65720657882df9d7bab7c634d71e141`.
The reference is a question/label lead only; no implementation is copied or edited.
Open #428 owns the adjacent `0x13ca0e0` path-sort FDE, not either selected range.
No sort, address-discovery or process-execution function is included here.

## Observations

`records.json`, the complete GNU disassemblies and FDE/CIE bytes bind these ranges:

| Function | FDE half-open VA range | File offset | Bytes | Decoded instructions |
| --- | --- | --- | ---: | ---: |
| wrapper | `0x13ca000..0x13ca0d5` | `0x13c9000` | 213 | 53 |
| selected reader | `0x144b900..0x144bfcb` | `0x144a900` | 1739 | 370 |

There are 1,952 bytes / 423 decoded instructions in this explicit export denominator.
Export completeness is not semantic recovery of the reader or a function census.
The producer parses actual FDEs, independently confirms their endpoints with GNU
readelf, and validates complete objdump byte coverage with the existing decoder.

### Global-derived template argument

| Site | Actual data flow |
| --- | --- |
| `0x13ca007` | RIP load through `0x576e928`, RELATIVE addend `0x577b288`, into RBX |
| `0x13ca00e..0x13ca013` | inspect global `+0x50`; nonzero enters an initialization/helper path that rejoins `0x13ca015` |
| `0x13ca015..0x13ca024` | use global `+0x18` as argument storage, with formatter pointer `0x13da090` |
| `0x13ca029..0x13ca038` | RSI selects template `0x1de68f`; RDI selects output stack storage; RDX selects stack argument pair; call via `0x576e040 -> 0x1344760` |
| `0x13ca03e..0x13ca052` | load constructed pointer/length from stack and call reader `0x144b900` |

The template bytes are `c0 29 /hyperliquid_data/n_restarts_to_page.json 00`.
The literal is 41 bytes; the prefix argument value and final rendered path are
unknown. Under the
[compiler-stamped Rust layout](https://github.com/rust-lang/rust/blob/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/fmt/mod.rs#L662-L706),
`c0` is a default argument slot, not padding. Source file SHA-256:
`ff56f0d7f3ce245b6171f2b742bfa07e1a7596158e43a9917a0340c7e9eb8a27`.
The revision stamp is compatibility evidence, not proof of an unmodified compiler.
The global's concrete type, initialization implementation, argument formatter and
full rendered path are not closed. There is no incoming RDI/RSI/RDX/RCX/R8/R9 or
XMM read before local setup in either wrapper entry branch. Saved RBX/R14 are
callee-saved register preservation, not evidence of a root input.

### Raw result, ownership and error limits

After the reader returns at `0x13ca057`, the wrapper conditionally calls the
relocated deallocation-like helper using its stack capacity; RBX preserves the
returned RAX across that call. Both normal paths reach:

```
0x13ca072: cmp rax, 1
0x13ca076: adc rax, 0
```

For raw unsigned `n=0`, CF=1 and result=1. For every raw unsigned
`n in [1, 2^64-1]`, CF=0 and result=n. These disjoint intervals cover all u64
patterns, and the only addition of one occurs at zero, so there is no overflow.
The result is exactly `max(1,n)`, conditional on the reader returning normally.
No signed comparison, result-tag check or caller-supplied default occurs here.

The reader has several delegate/error paths. One common error tail at
`0x144bd9d..0x144bdbe` conditionally releases storage, loads a callback receiver,
calls its first method at `0x144bdba`, then zeroes EAX at `0x144bdbc` **if that
callback returns**. Its callback implementation is unknown: it may terminate or
unwind. Therefore this does not prove that missing/invalid files are silently
mapped to one. The packet deliberately does not substitute a guessed fs/read,
UTF-8, trimming, serde or rmp implementation for the captured delegates.

The wrapper materializes `base/src/u.rs:549:5` Location `0x5666b80` into RDX before
the reader call. Reader entry immediately overwrites RDX from RSI. Thus the
Location is observed caller setup, not a claim that this reader consumes it.
The alternate wrapper branch also materializes the stamped Rust once.rs:219:20
Location. Call/helper relocations and both Location paths/layouts are retained.
Full initialization, all callers, allocation/drop/unwind and error callback
closure remain unknown; this is not a complete Rust ABI or runtime-equivalence claim.

## Reproduce and validation

macOS 26.4 arm64; Python 3.12.14; GNU Binutils 2.47.20260726.
From repository root, with GNU `objdump`/`readelf` on PATH:

```sh
python3 -B tools/restart_threshold_static.py --output work/restart-threshold-check
# Compare all generated files against this packet, except this README/manifest.
python3 -B -m unittest discover -s tests -p test_restart_threshold_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-restart-threshold-94 && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the complete capture once before parsing or exporting
a temporary byte-identical snapshot to native tools. Public entry rejects changed,
truncated and #115 inputs before output creation. Tests deliberately bypass the
identity gate only to exercise actual downstream byte controls: 22 real instruction/
template mutations, six actual relocation retargets, three Location corruptions
and two actual FDE extent changes. Five focused tests also check deterministic
regeneration and 197 unsigned boundary samples plus the full-domain interval proof.
These are static architectural tests, not executions of captured code.

Validation observed: focused five tests pass in 32.291 seconds; full required
suite passes 436 tests, with doctor, signature/import verification, catalogue
check and reproduce passing. Hosted CI was not run.

No captured binary/emulator, restart file, shell command, network endpoint or
production state is executed/accessed by this workflow. Original captures/imports,
source pins and catalogue/progress gates remain unchanged. No Rust reconstruction,
full parser recovery, hosted CI or whole-node equivalence is claimed.

## Next question

Close the selected error callback and reader delegates before deciding whether
any IO or parse failure can reach the wrapper's minimum-one return.
