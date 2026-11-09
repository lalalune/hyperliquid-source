# Node 115 warm-resident SSTORE execution

This independently authored Rust contribution advances issue #3918 with the
selected SSTORE execution path: stack and gas guards, real logical account and
storage mutation, journal entries, variable gas, reserve accounting and refund
updates. It accepts accounts and storage slots already resident and warm in the
current transaction. The issue remains open and component gates stay false.

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `0781ce04826eeefd89fe336cb8ea073be0c1de30`. Coordinates below are ELF virtual
addresses, and ends are exclusive.

## Prior work and distinct scope

Merged #3931 maps the interpreter SSTORE handlers and gas/refund helpers while
stubbing the host operation. Merged #3343 (`RE-011-storage-warm-cold-115`) maps the
host touch/load/write path with provider, reserve and growth boundaries. This
work credits both and supplies one independently authored source operation that
joins the selected interpreter to real logical storage and journal effects.
Open #4367 covers other storage/account operations and explicitly excludes
SSTORE; its full changed scope was inspected. This contribution does not redo
its SLOAD, transient storage or account-read implementations.

The public API uses `BTreeMap<Address, Account>` and each account's
`BTreeMap<Word, Slot>`, where `Address` is 20 bytes and `Word` is four u64 limbs.
It performs actual lookups, writes and journal pushes; no supplied callback
chooses a host result. Word operations are exact equality and zero tests across
all 256 bits. The stack's last word is the key, and the preceding word is the
new value. Other accounts, slots and stack-prefix words remain unchanged.

The equivalence domain requires that each reached account and slot exist and
that the slot has the current transaction id and the native zero cold byte
(`Slot::warm == true`). This is a real native fast path at
`0x4e337d2..0x4e337f5 -> 0x4e33a49 -> 0x4e33a89`, which returns the resident
original/current payload with cold flag zero. It does not call a database or
append a warming entry. Physical hash probing, invalid containers, missing or
cold slots, provider errors, transaction changes, fallible host clone
`0x2977cd0`, other interpreter clones and allocation failure are outside scope.
Boundary faults are explicit owned errors, not modeled native provider statuses.

## Recovered operation and state order

The selected handler is `0x2994990..0x2994e87`. Its actual host call is
`0x2977910..0x2977cc4`, whose relocation slot `0x64e6d90` binds to storage loader
`0x4e33680..0x4e33eec`. Variable gas is `0x299f910..0x299fa60`; refund is
`0x299f680..0x299f90d`. Successful allocation and valid logical maps are premises;
owned journal variants project native tag 2 (touch) and tag 8 (old storage),
without claiming enum padding or byte-for-byte journal ABI.

1. Static mode returns `0x28`. Fewer than two stack words returns `0x2c`.
   Both leave the stack unchanged. Otherwise the key and new value are popped
   **before** any later rejection.
2. Raw spec greater than 5 rejects gas less than or equal to the configured
   sentry (`+0xc0`) with `0x25`. Fixed gas (`+0x98`) is then subtracted with an
   unsigned check. Underflow returns `0x20` without publishing the subtraction.
3. The host sets account flag bit 4 and appends one touch entry if that bit was
   clear. Other flag bits are preserved. The warm loader supplies original and
   current words. When the new value differs, the host writes it and appends an
   entry containing address, key and the previous current value. Same-value
   stores produce no storage-change entry.
4. Variable gas is computed on the captured **pre-write** triple. For raw spec
   below 6, zero-current/nonzero-new charges `set` (`+0xa0`), otherwise `reset`
   (`+0xa8`). For spec at least 6, unchanged or already-dirty values cost zero;
   an original/current match charges set for zero original, reset otherwise.
   The warm cold flag is zero, so the cold surcharge is absent. A variable-gas
   underflow retains the host writes and the already-published fixed-gas debit.
5. When reserve accounting is enabled and the value changes, an original and
   current zero consumes configured reserve amount (`+0x150`). Any shortfall is
   taken from ordinary gas. A shortfall underflow retains the host write and
   both earlier gas debits, but leaves reserve and host-spent fields unchanged.
   Successful allocation adds the amount's **signed i64 bit interpretation** to
   host-spent with signed saturation. Restoring a zero original subtracts that
   signed amount with saturation and adds it to reserve with unsigned saturation.
   Release does not add ordinary gas. No public fork names or default gas schedule
   are inferred from the raw selectors and fields.
6. The legacy refund is `clear` (`+0xb0`) only for a nonzero current to zero new
   value. Modern unchanged values return zero. A clean clear returns `clear`.
   Other changes undo a prior clear with checked negation or add a new clear;
   restoration to original adds `restore_zero` (`+0x138`) or
   `restore_nonzero` (`+0x140`) with checked signed addition. The final refund
   accumulation is also checked. Each overflow is an owned fault category that
   identifies the native overflow boundary; it does not reproduce panic strings,
   unwinding, native error objects or a recoverable native ABI.

A successful operation returns byte `0`. There is **no rollback** in this API.
The native host writes precede later gas, reserve and refund failures. Consumers
must not mistake a failed return for unchanged host state. Higher-level
transaction rollback and EVM execution completeness are separate work.

## Evidence and validation

`records.json` retains all five FDEs: 5,364 bytes and 1,314 decoded instructions.
The verifier authenticates the original digest, FDE and instruction boundaries,
all retained rows, 662 selected facts and 53 corruption controls. Controls alter
stack arity, sentry/spec gates, gas offsets and borrow branches, touch/write
journals, warm-generation checks, reserve saturation, refund rules and the real
loader relocation. Corruptions must fail fact checks while whole-image and
window-digest checks are bypassed. Retention of a full FDE does not imply all
its branches are implemented; only the stated warm-resident domain is claimed.

Five Rust integration tests pass in debug and release. Manual cases cover
failure prefix effects, same-value writes, existing touch flags, unrelated
storage, reserve release, refund overflow and the owned boundary rejection.
A separate arbitrary-precision Python state model generates 16,000 cases across
raw specs 0, 5, 6, 7 and 255, static/short stacks, all limbs, and u64/i64 extremes:
10,439 success, 2,203 out-of-gas, 1,898 sentry, 165 static, 1,187 underflow,
79 accumulation, 25 negation and 4 refund-delta overflows. The test compares
status, gas, reserve, spent, refund, full remaining stack, account flags,
storage, journal order and previous values. The model is an independent
synthetic arithmetic/state check, **not an execution of the native binary**.
Changing the modern cutoff to 7 differs in 2,041 cases; rolling back host writes
on failure differs in 889; journaling same-value writes differs in 1,630.
Fixture SHA-256:
`36166a5b222403223e4e6873c44fd885c793b7a6891790a8c4271b5da0dba680`.

```sh
python3 research/work-items/RE-011-node115-sstore-warm-source/verify.py
python3 research/work-items/RE-011-node115-sstore-warm-source/reference.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-sstore-warm/Cargo.toml
cargo +1.95.0 test --offline --release --locked --manifest-path src/node115-sstore-warm/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-sstore-warm/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --manifest-path src/node115-sstore-warm/Cargo.toml -- --check
shasum -a 256 -c research/work-items/RE-011-node115-sstore-warm-source/MANIFEST.sha256
make doctor verify catalogue-check reproduce
```

The validation record lists the exact checks run with existing Python 3.14.7,
Capstone 5.0.7 and Rust 1.95.0. Full unfiltered `make test` is excluded because
its discovery includes captured-instruction emulation. No captured code was
executed or emulated; no live network, signing or chain actions were used for
behavioral validation. New source is independently authored and MIT.

Implementation, original artifact analysis and reference: OpenAI `gpt-6-astra` /
`codex-desktop`. GitHub/browser reads, independent review and publication:
OpenAI `gpt-6.1-terra` / `codex-desktop`.
