# RE-001: node115 lazy record initialization and registered cleanup state

## Current repository validation

The user explicitly authorized the disclosed isolated offline evaluator tests. The original repository `make test` command exercised **583 modules**, 5409 reported unittest cases, 899 pytest passes and 9 recorded built-in skips. Script modules may not report an assertion count; no count is invented. Optional compiler/version skips are listed in `repository-tests.json`, not presented as compiler-comparison passes.

The original full command's exit code was 2: one pure-static catalogue fixture hit macOS sandbox hardlink policy. Its unmodified13-test module then passed with a stronger TMPDIR process-exec deny; network and artifact execution restrictions were not relaxed. Original failures/logs remain preserved, and all583 final module results are successful.

The full suite actually ran on PR2829 head `196bb08453803749319890a91ee2e640cc772283`. All eight PRs have byte-identical tools/tests/src/provenance/artifacts/build-rule trees and differ only in their independent evidence packet plus generated inventory. Shared results are combined with fresh per-packet controls/native regeneration and per-head doctor/verify/catalogue-check/reproduce. This follow-up changes only this README, the test receipt and its manifest; it does not alter target evidence or testing logic.

Execution used an OS network-denying sandbox, isolated HOME/TMPDIR, no inherited auth/proxy state, explicit `HL_ALLOW_CAPTURED_INSTRUCTION_EVAL=1`, offline Cargo and disabled automatic toolchain installation. Captured native binaries, real services, signing and private runtime data were not used. Raw logs and checksums are preserved in the operator findings; this compact receipt pins their identities. The earlier static collection metadata remains historical rather than rewritten. Repository test success does not recover opaque helpers, prove target equivalence or advance any reconstruction/component gate. Hosted CI success is not claimed.

Component: foundation. Base `05bc2de303c05525b71e7e257426e741bc66a390`.
Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,105896032 bytes,
SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are original ELF VAs. Independently authored new MIT analysis and
scripts; no inferred private implementation, reference oracle or target run.

## Bounded question and evidence scope

How do the raw state byte at record+0xa0, a conditionally consumed source, and
three cleanup size/pointer pairs interact across initialization and the exact
callback passed by that initializer? This closes a whole two-owner record
protocol, not global TLS initialization, an allocator implementation, the old
lu lock/fallback work, or an unrelated storage/block-reader task.

| Owner | Exact actual FDE | Bytes | Native instruction rows | .eh_frame offset |
| --- | --- | ---: | ---: | --- |
| Initializer | `0x1629300..0x162939f` |159 |40 | `0x17f98` |
| Passed callback | `0x16293a0..0x1629418` |120 |37 | `0x17fc4` |

Combined denominator: **279 body bytes,77 native instruction rows**, exactly
covered without padding or duplicate bytes. `evidence.json` retains every raw
body byte, FDE/CIE-backed extents, actual RELA records, constant, RIP references
and local branch/call edges. Both complete native outputs remain unabridged;
only temporary input pathname becomes `<authenticated-node115>`. The native
`.text` label is not an original function/type name.

## Initializer observations

Let R=original RDI and S=original RSI. Read byte `[R+0xa0]`:

| Raw state | Local behavior |
| --- | --- |
| 1 | return R, no initialization |
| nonzero other than1 | return0, no initialization |
| 0 | enter initialization below |

For state0, load16B at `0x455a10`: qword0 followed by qword
`0x8000000000000000`. If S!=0, first read qword `[S]` into RAX and16B
`[S+8..S+0x18)` into XMM1, then **store qword0 to `[S]` before testing** the
previous qword for equality with1. Therefore a nonnull source whose old tag is
not1 is still modified; no tag-specific early-return assumption is valid.

If that old tag was1, pass `(stack+0x10,S+0x18,0x90)` to the actual GLOB_DAT
`memcpy` slot `0x64df508`. Save/restore XMM1 across it and use XMM1 as the first
16B result. Otherwise keep the sentinel first16B constant.

Then store that first16B into `[R..R+0x10)` and call the same `memcpy` slot with
`(R+0x10,stack+0x10,0x90)`, unconditionally on this state0 path. Only the
S!=0/oldtag1 branch has established a source for those0x90 stack bytes in this
owner. **For S==0 or oldtag!=1 the body does not establish defined contents for
that copied stack payload.** This packet preserves that observation; it does
not invent zero-filled bytes, a safe source object, or a fully initialized
record for those cases. Alias/valid-memory/initialization contracts are unknown.

After the copy normally returns, store byte1 at `[R+0xa0]`, then pass
`(R,0x16293a0)` to slot `0x64e0510` with actual RELATIVE addend `0x5ca0d20`.
The callback LEA itself is retained, independently tying the two exact FDEs.
Return R only after that helper normally returns. State1 is published **before**
the helper call; its return is unused. Registration, TLS lifetime, concurrency,
rollback, and whether the callback is ever invoked are not established by the
argument alone. The helper is not executed or reconstructed here.

## Callback observations and scalar predicates

At callback entry read old byte `[R+0xa0]`, immediately store2 there, and compare
old byte with1. If old!=1 return without cleanup helper calls. This includes
old0 and old2; numeric states do not establish original enum names.

For old1, load first qword `n0=[R+8]`, negate a copy in RAX, and test JO first:
`n0==0x8000000000000000` triggers immediate return, skipping **all three**
size/pointer pairs. For other inputs, JAE after NEG skips only the first helper
when n0==0 (NEG sets CF iff input is nonzero). Every other raw64 value takes
that first helper call; it is not a signed-positive or high-bit-clear check.

| Pair | Raw count word | Pointer word | Local call gate |
| --- | --- | --- | --- |
| first | `[R+0x08]` | `[R+0x10]` | oldstate1, n0!=0 and n0!=INT64_MIN bits |
| second | `[R+0x20]` | `[R+0x28]` | reached second block and count!=0 |
| third | `[R+0x38]` | `[R+0x40]` | reached third block and count!=0 |

Each taken call supplies `(pointer,(count<<4) mod2^64,0)` to actual RELATIVE
slot `0x64df4a0 -> 0x635de30`. The first two are ordinary calls with R preserved
through RBX and restored afterwards; the last is a **tail JMP** after POP RBX.
There is no local size-overflow or pointer-null gate. Counts/pointers can be
changed by earlier helper effects, so later values are the values read when
those blocks are reached, not assumed frozen entry values. Destruction/free
labels are inferred convenience only; actual allocator, original type/element
size, ownership and helper effect/return semantics remain open.

State2 is stored before any count read or helper call. A separate later normal
callback invocation observing state2 takes the early-return arm; this is a
local ordering observation, not a proof of safe repeated destruction,
reentrancy, races, or complete object lifetime semantics.

`algebra.py` records eight scalar NEG/shift boundary witnesses (including0,
INT64_MIN bits and large overflowing shifts). These are mathematical
zero/overflow/borrow/modulo identities only, not target instruction evaluation,
record simulation, allocator requests or callback execution.

## Reproduce and controls

From repo root:

```sh
python3.11 -B research/work-items/RE-001-node115-lazy-record-state/collect.py --negative-controls
python3.11 -B research/work-items/RE-001-node115-lazy-record-state/collect.py --output work/lazy-record-fresh
python3.11 -B research/work-items/RE-001-node115-lazy-record-state/algebra.py
```

Python3.11/native LLVM version strings are recorded in evidence.json.
`--output` requires a fresh directory; optional `--objdump PATH` selects LLVM.
The complete node identity is checked before native export, which uses only an
authenticated byte-identical private snapshot under work/. Compare fresh
`owner0.objdump.txt`, `owner1.objdump.txt`, `frames.json`, `evidence.json` exactly
to this packet. Two independent fresh exports matched all4 outputs. Algebra
stdout equals algebra.json; verification stdout equals validation.json.

All29 actual corruptions reject:1 full identity,22 instruction anchors,
1 sentinel data,2 FDE extents,3 actual RELA records. The28 downstream controls
explicitly bypass full/body hashes and retained-disassembly comparison so that
exact selected operands, data, decoded FDE extents or bindings must detect the
changed bytes. They validate static checks, not execution of mutations or a
semantic differential oracle. Complete native/raw279B binding is checked
separately.

Before: this record's state/source/registered-callback relationship and special
first-count gate were not documented here. After: complete connected owners,
actual imported memcpy binding, both opaque helper bindings and all local
state/count branches are preserved with explicit undefined-payload and helper
limits. No Rust implementation or target-run before/after claim is made.

## Unfinished acceptance

Original ABI, field/source object types, higher callers, helper bodies, source
aliasing, initializedness, allocation/cleanup policy, unwind closure and global
lifetime/concurrency remain unknown. No node, callback, allocator, instruction
interpreter, live service or chain action was executed. All component gates
remain false; no matched-source or whole-foundation coverage credit is claimed.
