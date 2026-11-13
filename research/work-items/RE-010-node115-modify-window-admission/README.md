# Modify admission updates both windows before rejecting

This advances **HL115-039** for node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It reconstructs a concrete state effect inside the actual modify call chain: in the selected admission branch, both per-entry window records are updated even when their combined decision rejects the request. This is a bounded step toward the modify failure ledger, not a conclusion about complete order rollback or queue priority.

## Prior work and actual caller

[#4131](https://github.com/lalalune/hyperliquid-source/pull/4131) owns the single-modify wrapper's payload and result handoff; [#6638](https://github.com/lalalune/hyperliquid-source/pull/6638) owns the batch row continuation. Neither reconstructs the inner admission counter writes studied here. The old node #94 modify studies are also not reused as evidence of node #115 behavior.

The real single-modify implementation `0x555f0d0` calls `0x5591630` at `0x555fc0a`, with its retained state pointer in `rsi`. The callee returns its result at caller stack+0x190; the caller copies the status at result+0x10 to stack+0x2e0 and tests it against raw `0x1a2` at `0x555fcb5`. This supplies a concrete downstream consumer for the reconstructed rejection path.

## Selected branch and ownership

Let `S` be `0x5591630`'s state argument. It performs a 20-byte identity lookup against `S+0x14d8`; a missing pointer selects a default object. This packet selects the branch whose resulting class byte at object+0x3c is **4**, with bit 0 at `S+0x7b8` clear. The semantic name of that class and the lookup's insertion/ownership contract are not inferred.

The selected branch copies the current packed time from `S+0x60` (12 bytes). It calls `0x4ef46d0` with `S+0x1520` and the same identity, then `0x582c0a0` to obtain the actual entry pointer `T`. The latter returns an indexed 0xe8-byte row after an index bound check; its vacant-entry branch passes a zeroed default record with the two timestamp words set to `0x00f6401a` to the insertion helper. The insertion helper itself remains a dependency.

The wrapper then makes two unconditional calls to the **same** helper `0x420bdc0`, bound by relocation slot `0x64e5130`:

| Call | Window | Period in milliseconds | Maximum | Current time |
| --- | --- | --- | --- | --- |
| `0x5591722` | `T` | `S+0x728` | `S+0x730` | copied `S+0x60` |
| `0x559173f` | `T+0x18` | `S+0x738` | `S+0x740` | same copied time |

Each 24-byte window has a u64 count at +0 and a 12-byte packed timestamp at +8. Padding is not part of the source contract. There is no short-circuit between the calls. The two returned bytes are ORed at `0x5591745`.

## Exact update rule

The helper converts both saved and current packed timestamps to milliseconds, clamping negative results to zero. It divides each by the supplied nonzero period. If the saved bucket is strictly less than the current bucket, the new count is **1**; otherwise it is the prior count plus one, saturating at `u64::MAX`. A backwards bucket therefore increments rather than resetting.

It always writes the new count and the current packed timestamp before returning `new_count <= maximum`. Equality is accepted. A zero maximum can reject a reset count of 1. A false return is a decision after mutation, not an instruction to undo the window update.

The packed date arithmetic extracts signed year from bits31..13 and ordinal from bits12..4, ignoring the low four bits. The equivalent day count is:

```text
y = year - 1
days = 365*y + floor(y/4) - floor(y/100) + floor(y/400)
       + ordinal - 719163
milliseconds = max(0, (days*86400 + seconds)*1000 + floor(nanos/1000000))
```

The native negative-year path shifts by whole 400-year eras before its divisions; the source implementation uses Euclidean division for the equivalent arithmetic. This is arithmetic over the native packed words, not a calendar validator or a claim that every raw word is produced by the application. The 32-bit and 64-bit native division paths compute the same quotient for a nonzero period.

## Rejected admission ledger

When both window calls return false, `0x5591747` branches directly to `0x5591861`. The output receives raw outer word 1, word+8 zero, and status word+0x10 **0x186**. The selected normal cleanup frees only candidate-owned buffers before returning at `0x5591bfd`.

The two updated windows remain at this callee's normal return. The path does not take the later increments at `T+0x30` and `S+0x1618`, and does not invoke submission helper `0x559d110`. This conclusion assumes valid, nonaliasing objects and normal cleanup returns. It does not assert that later caller logic cannot change those fields, that earlier old-order preparation was mutation-free, or that the complete modify operation is atomic.

## Source and validation

`src/node115-modify-window-admission` owns packed-time conversion, one-window mutation, and ordered two-window mutation with OR admission. It does not accept callbacks for unresolved order handlers. Its safe API rejects zero periods before mutation; that is a domain boundary, not an emulation of native division-by-zero behavior.

```sh
python3 research/work-items/RE-010-node115-modify-window-admission/verify.py --target /path/to/original/hl-node
cargo test --manifest-path src/node115-modify-window-admission/Cargo.toml
cargo test --release --manifest-path src/node115-modify-window-admission/Cargo.toml
cargo clippy --manifest-path src/node115-modify-window-admission/Cargo.toml --all-targets -- -D warnings
```

The static check covers seven windows (1656 bytes, 370 instructions), 243 facts and 243 corruption controls. Four tests cover fixed epoch/leap fixtures, 24,090 timestamp comparisons against a separate year-by-year calendar count, both-false mutation, lack of short-circuit, exact limit equality, saturation, bucket regression and reset, ignored low date bits, and the safe zero-period boundary. Debug/release tests and strict Clippy pass. No captured target code was run or emulated.

Remaining HL115-039 work includes old-order write and restoration ownership, all other admission classes, later helper effects, complete rejected replacement outcomes and exact queue-priority behavior. The new result should be used as one explicit effect in that ledger rather than as proof of the entire transaction.
