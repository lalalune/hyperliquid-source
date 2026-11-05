# RE-012 node115 rwlock release and wake selection

This packet maps the transition from lock release into the imported futex
wake operation. Target Linux x86-64 node #115 has SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base is 05bc2de303c05525b71e7e257426e741bc66a390. The std census names
the wake body as the Rust standard library's wake_writer_or_readers.
The census identifies the body, while this packet follows its observed
state transitions and two concrete release callers.

## Release handoff

The RELATIVE writer at 0x64ec5b0 binds the two selected tail calls
to 0x5c847a0. At 0x5c7411c the static reader-release routine atomically
adds -1 to the lock word and forms the post-update word. It enters the
wake routine precisely when clearing bit 30 from that word leaves
0x80000000. The guard routine at 0x5d00260 has the same reader predicate.
Its writer path at 0x5d002ae instead adds 0xc0000001 and enters the wake
routine for an unsigned post-update word at least 0x40000000.
The guard's intervening ownership and panic checks are context.

## Wake policy

The low 30 bits must be clear. Otherwise the entry takes the diagnostic
call at 0x5c84871. Bit 31 selects the writer path and bit 30 the reader
path in the observed state transitions below.

| Entry word | Atomic transition | Wake action after success |
| --- | --- | --- |
| 0x80000000 | Compare-exchange to 0 | Increment word at +4 and wake one on +4 |
| 0xc0000000 | Compare-exchange to 0x40000000 | Increment word at +4 and wake one on +4 |
| 0x40000000 | Compare-exchange to 0 | Wake up to 0x7fffffff on the state word |
| 0 | None | Return |

With both flags set, a positive writer wake result returns immediately.
A zero or negative result attempts the reader compare-exchange. If the
first writer-only compare-exchange fails, the observed replacement word
is used for the subsequent flag selection. A failed compare-exchange
on the both-flags or reader-only path returns without another wake.

The dynamic relocation at 0x64e06b8 resolves syscall. The selected
call and tail call use syscall number 202, operation 0x81 and the
word address and wake count above. The two addresses differ by four
bytes. The proof stops at the imported syscall. It does not establish
kernel scheduling, fairness, native ABI equivalence or a live lock test.

## Reproduction

From the repository root with the pinned artifact, Capstone 5.0.7,
GNU 2.45 and LLVM 23.1.4, run the following against fresh output paths.

```sh
python3 -B research/work-items/RE-012-rwlock-wake-115/collect.py --out work/rwlock-wake-fresh
python3 -B research/work-items/RE-012-rwlock-wake-115/verify.py --out work/rwlock-wake-check-fresh.json
```

Three complete FDEs cover 383 bytes and 110 instructions. GNU, LLVM
and Capstone agree on the instruction bytes. GNU readelf independently
checks the extents. The verifier detects 14 instruction-window
corruptions, one RELATIVE addend corruption, one imported symbol
writer corruption and two identity controls. No captured code or
kernel operation is executed. Collector scaffolding is reused from
the project's MIT ELF Build ID packet.
