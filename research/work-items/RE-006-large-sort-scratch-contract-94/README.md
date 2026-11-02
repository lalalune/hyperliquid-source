# RE-006: scratch contract of the large pending-key sort delegate, node #94

- Component: `orderbook`; bounded RE-006 argument/resource contract.
- Target: node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Research base: revalidated upstream main
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: `can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Its implementation was not consulted or copied. The address lead comes
  from the separately authored pending-key collector packet, commit
  `4b7c253c5068e3bec7ad6bc12da663e7d00322ed`; this branch does not change or
  require that commit's files.
- Status: complete static wrapper partition, selected call interface, exact
  cleanup table and conditional arithmetic proof. No sorting/comparator,
  independently authored Rust, target execution, binary equivalence or
  component gate is claimed. Quantity/rounding semantics are not assumed.

The unresolved call at collector `0x44503af` reaches a 269-byte scratch
wrapper. This packet establishes how that wrapper chooses stack versus heap,
sizes the heap without admitting a wrapped layout on its ordinary path,
forwards arguments to the lower core, and schedules heap cleanup on both
normal return and the recorded exception route. Sorting itself remains in
the unproved lower core `0x4dbd490`.

## Reproduce and inputs

Run from the repository root using GNU Binutils 2.44 and LLVM 19.1.7:

```sh
python3 -B research/work-items/RE-006-large-sort-scratch-contract-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
python3 -O -B research/work-items/RE-006-large-sort-scratch-contract-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
python3 -m unittest discover -s tests -p test_large_sort_scratch_contract94.py -v
```

`--llvm` selects an existing tool; no installer is run. `--write` regenerates
the ten derived exports. Native streams only replace the absolute target
filename with `<authenticated-node94>`. Other rendering differences are not
silently normalized. All raw bytes, native versions, linked virtual addresses
and exact section-derived file offsets are retained in `records.json`.
The existing ELF/FDE parsers and two static disassemblers read an authenticated
file; no captured instruction evaluator, executable, emulator or live node is
used. Synthetic counts cause no actual allocation.

Author environment: Linux x86-64/glibc 2.41, Python 3.12.14, Git 2.52.0,
Git LFS 3.6.1. Ghidra is absent. Attribution: OpenAI, `gpt-6.1-sol`, reasoning
`xhigh`, UI `GPT-6.1 Sol Extra High`, client Codex cloud; model/UI identity is
parent-supplied and user-confirmed, not an independent machine metadata read.

## Boundaries and ownership

All coordinates are linked ELF VAs; `.text` file offset is VA minus `0x1000`
here. FDEs establish unwind-described extents, not recovered Rust symbols.

| Role | Full FDE, half-open | Full bytes | Exported native evidence |
| --- | --- | ---: | --- |
| New scratch wrapper | `0x4486d10..0x4486e1d` | 269 | Complete, 75 instructions |
| Shared error entry | `0x1346068..0x134607d` | 21 | Complete, 6 instructions; support only |
| Unproved lower core | `0x4dbd490..0x4dbdb5e` | 1,742 | Entry `0x4dbd490..0x4dbd4c0`, 14 instructions |
| Selected collector | `0x4450210..0x44503d3` | 451 | Call `0x44503a4..0x44503ba`, 5 instructions |

GNU and LLVM instruction partitions agree on 100 exported instruction rows /
360 bytes without masks. Four further resume-context bytes are retained as
bytes, separately from that native denominator. The lower-core and collector
full digests/FDEs are bound for context; their full bodies are not claimed or
exported. Shared error/allocator targets are already referenced in existing
growth, allocation and book packets and earn no new recovery claim here.

Before selection, all 71 then-open PR bodies and the latest 100 merged bodies
were searched for the wrapper, slot, selected call and lower-core addresses.
No address claim was found. On main, `RE-006-user-book-cancel-94` names only
the delegated sort slot. The pending-key packet explicitly leaves the
delegate's contract unresolved. The final 83-open-PR snapshot has one address
hit: [collector PR #1430](https://github.com/lalalune/hyperliquid-source/pull/1430),
head `4b7c253c5068e3bec7ad6bc12da663e7d00322ed`. Its complete body was read;
it establishes the call to this delegate and leaves the large-sort helper
unresolved. Its collector work is credited here, and this packet addresses
the separate wrapper contract. Final live inventory and exact body hashes
are in `overlap.json`; address absence alone is not proof of nonoverlap.
No public claim, push or PR was made in this lane.

## Observations: selection and forwarded arguments

Let incoming `rsi = n`, interpreted only as an unsigned 64-bit count. At
`0x4486d23..0x4486d46` the wrapper computes

```text
h = n - (n >> 1) = ceil(n/2)
s = max(min(n, 1,000,000), h)
```

The first selection uses unsigned `cmovb`; the second uses unsigned
`cmovbe`. `0x4486d46` selects the stack branch when `s <513`. It reserves
4096 local bytes at `0x4486d19`, uses current `rsp` as scratch, and supplies
capacity 512. Since `s <=512` iff `n <=512`, this is the exact stack/heap
count boundary for the raw-count relation.

The ordinary heap branch computes `(8*s) mod 2^64` in `r12`. Its guard and
allocation are detailed below. Across that allocation, the input pointer and
count are saved and restored through callee-saved registers. At direct call
`0x4486db8 ->0x4dbd490`, the wrapper supplies:

| Register | Observed value |
| --- | --- |
| `rdi` | Original input pointer |
| `rsi` | Original count `n` |
| `rdx` | Stack scratch base, or nonzero heap-allocation result |
| `rcx` | Capacity 512 on stack, otherwise `s` |
| `r8d` | Exactly `1` for `n <65`, otherwise `0` |
| `r9` | Original incoming `rdx`, unchanged and uninterpreted |

The lower-core entry spills `r9` and `r8d` and checks `n <2`; this support
window confirms an interface boundary, not sorting behavior. The meaning of
the flag and original third argument remains unknown. In the selected
collector call, the incoming third argument is a stack scratch pointer; it
must not be relabeled as a comparator or callback without further evidence.

The selected collector resumes with an unconditional jump to `0x4450308`,
which overwrites `rax` with the projected buffer's end pointer. No returned
status/value is consumed on that route. This does not establish a general
return-register contract for the wrapper or other callers.

## Observations and proof: layout and failure dispatch

For `s >=513`, the actual guard before the heap allocation is

```text
bad = (h >> 61 != 0) OR ((8*s mod 2^64) > 0x7ffffffffffffff8)
```

When `bad` is set, `0x4486d72..0x4486d7d` calls slot `0x576dfb8` with
`rdi=0` and the wrapped byte size in `rsi`. A null heap-allocation result
selects `0x4486de9..0x4486df7`, calling that same slot with `rdi=8` and the
same requested bytes. The exact RELATIVE record binds the slot to
`0x1346068`. That 21-byte entry tests `rdi`: zero first calls relocated
`0x1346080`, while the nonzero route calls relocated `0x1345e2a`. It contains
no `RET`. Their transitive abort, panic, unwind or diagnostic behavior is not
established here. The guard claim is which dispatch path is selected; it
assumes no invented ordinary return from a failure helper when composing the
subsequent success path.

The ordinary heap path is selected exactly for `513 <= n <=2^61-2`:

- Up to `n=2^61-2`, both `min(n,1,000,000)` and `h` are at most
  `2^60-1`, hence `8*s <=2^63-8` without wrapping and `h >>61 =0`.
- For `2^61-1 <= n <=2^62-2`, `s=h` is in `[2^60,2^61-1]`. Its unwrapped
  byte size is in `[2^63,2^64-8]`, so the unsigned byte-size guard rejects it.
- For `n >=2^62-1`, `h >=2^61`, so the high guard rejects the input even
  when multiplication wraps to zero or a small word.

The last ordinary request is therefore `n=2^61-2`, `s=2^60-1`,
`bytes=0x7ffffffffffffff8`. The practical allocator can refuse far smaller
requests; arithmetic admission is not memory availability. Piecewise,
`s=n` through one million, stays one million through two million, and then
equals `ceil(n/2)`. Every ordinary scratch capacity is at least that half.

## Observations: normal and exceptional cleanup

After the inner call returns normally, `0x4486dbd` checks `s >512`. Heap
cleanup calls slot `0x576e010` with the allocation pointer, `8*s`, and zero
in `edx`; the stack path does not call it. The original `s` is retained in
callee-saved `rbx`, so cleanup uses the allocation's byte count. The slot's
RELATIVE target is `0x54c8cb0`; naming this a free operation is an inference
consistent with existing allocator packets, not a claim about its internals.

The FDE at `0x124b280` points to LSDA `0xb42000`. Its exact twenty-byte
record has omitted LPStart/type table, ULEB128 call-site rows, and no action
table. The three rows are:

| Protected range | Landing pad | Action |
| --- | --- | ---: |
| `0x4486d10..0x4486db2` | None | 0 |
| `0x4486db2..0x4486dbd` | `0x4486df7` | 0, cleanup |
| `0x4486dbd..0x4486e1d` | None | 0 |

The entire five-byte inner call lies in the second row. At its landing pad,
incoming `rax` is saved, the same `s >512` check performs the same heap-only
cleanup, then the saved value is passed to `_Unwind_Resume@plt` at
`0x5660110`. This is metadata plus static call/argument evidence, conditional
on the runtime personality and unwinder honoring the recorded cleanup. No
exception or allocator was run. Transitive unwind behavior and input-buffer
preservation during failure remain unknown.

## Controls and limits

The normal/optimized verifier and seven root unittest methods cover the
actual target operand/branch pins, the three-row LSDA, and arithmetic boundary
controls. Local corruption checks bypass only whole-target SHA admission:
22 operand/control mutations, one landing-pad offset mutation and one FDE
range mutation must fail their actual local qualifier. The original input
also passes every local qualifier. The complete wrapper's 75-node normal CFG
retains every call and explicit local branch; call fallthrough is conditional
on normal return, and exceptional edges are separately bound through LSDA.

An independent piecewise oracle agrees on 4,889 synthetic counts, including
0..4096, the 64/65, 512/513, million/half boundaries, every unsigned bit
boundary and deterministic large words. Five explicit wrong relations are
distinguished: floor half, minimum instead of maximum, heap at 512, inclusive
65 flag, and a missing high overflow guard. These are consequence checks of
the addressed proof, not differential target execution or proof of a generic
sorting algorithm. The model's invalid-type/count rejection is its own API.

Exact commands and observed results are in `checks.json`; local full streams
remain under ignored `work/re006-large-sort-scratch/`. Repository-wide
`make test` is deferred to coordinated integration. No hosted CI, Rust build,
new matched-byte count, target behavior comparison or progress gate is
claimed. Imported evidence, pinned revisions, the previous collector packet
and all generated progress files remain unchanged.

Next question: use this established six-argument scratch interface to recover
one bounded ordering branch of `0x4dbd490`, including its called comparison
or merge helper and exact input domain. Its complete sorting/comparator and
stability contracts remain unresolved.
