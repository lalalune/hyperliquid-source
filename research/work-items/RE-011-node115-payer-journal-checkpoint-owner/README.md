# Payer journal owner and the first frame's rollback cutoff

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Partial HL115-072 / RE-011 research. Static inspection only; no native execution or emulation.

The payer-deduction code and the first frame's selected provider-failure rollback use the same journal owner. The first frame saves a cutoff from that owner's current journal length and passes it to the rollback traversal. This closes the pointer and cutoff relationship, but does **not** establish that every payer entry remains below the cutoff or prove final transaction balance/nonce retention.

## Reused work and new scope

[#3332](https://github.com/lalalune/hyperliquid-source/pull/3332) owns the caller deduction and tag-2/3/6 writes. [#4360](https://github.com/lalalune/hyperliquid-source/pull/4360) owns post-preflight record filters. [#4394](https://github.com/lalalune/hyperliquid-source/pull/4394) owns journaled-state account operations and the reverse checkpoint traversal. [#2049](https://github.com/lalalune/hyperliquid-source/pull/2049) already describes tag 2's conditional flag clear, tag 3's saved-balance restore, and tag 6's saturating nonce decrement in `0x5be3400`; it also describes a checkpoint in the distinct `0x296e2b0` frame path. [#4363](https://github.com/lalalune/hyperliquid-source/pull/4363) owns transient-storage restoration in the same dispatcher.

The addition here is the concrete owner returned by `0x5463980` at `0x2963499`, its use by payer writes, and its identity with the `0x29837a0` first-frame checkpoint and selected rollback. It does not reimplement those predecessor contracts or claim whole-transaction rollback.

## Owner identity

Let `H` be the driver's local host object at `rsp+0xff0`, and `S = H+0x270 = rsp+0x1260` its journaled-state subobject.

At `0x296348e`, the driver passes `S` as the second argument to relocation-bound helper `0x5463980`. That helper retains the argument in `r15`, and its selected successful return writes `S+0x18` into output `+0x08` (`0x5463de8`, `0x5463e0b`). The driver reads this exact word into `r12` at `0x29634b5`.

The already-mapped payer writes use `[r12]` / `[r12+8]` / `[r12+0x10]` as journal capacity, backing pointer and length. Tag-2, tag-3 and tag-6 insertion sites compute an 88-byte stride and increment that returned vector's length. Their twenty-byte account identity is copied from `rsp+0xd4..0xe7`; the source is the helper's returned identity at output `+0x24`, staged by `0x29634c5..0x29634df`. This packet does not re-prove the helper's database or hash-map internals.

The first frame invocation at `0x2964595` receives `H` as its second argument. `0x29837a0` saves this pointer at local `rsp+0x18`; `0x2983dae` derives `H+0x270`, and `0x2983f97` retains that pointer in `r15`. The relevant address equivalences are:

| Driver/host address | Journaled-state address | Meaning |
| --- | --- | --- |
| `H+0x288` | `S+0x18` | Journal vector capacity field / descriptor base |
| `H+0x290` | `S+0x20` | Journal backing pointer |
| `H+0x298` | `S+0x28` | Journal length |
| `H+0x338` | `S+0xc8` | Account map passed to per-entry reversal |

The descriptor owner stays the same even if a vector-growth helper changes its backing pointer. This is object/field identity, not an assumption that a particular allocation address never changes.

## Snapshot and selected rollback

At `0x2983f54..0x2983f7e`, the first frame saves three values from the same host: `H+0x280`, `H+0x298`, and `H+0x2b0` into its local checkpoint at `rsp+0x238`, `+0x240`, and `+0x248`. The checkpoint's second word is therefore the current length of the payer journal owner. Its depth increment is separate.

The provider returns at `0x2984373`. Raw status `0x38` takes an earlier special path, and status zero takes a different continuation. On the selected nonzero/non-`0x38` path, statuses below 5 skip the failure rollback. For statuses at least 5, after the intervening log-collection helpers return normally, `0x2984a97..0x2984aa2` calls `0x29710e0` with `rdi = S` and `rsi = &checkpoint`.

The credited traversal loads the saved second word at `0x2971136` and the same journal's current length at `0x297113a`. If saved cutoff is at or above current length, no journal suffix is visited. Otherwise it publishes the saved length, then visits 88-byte entries backward from old length minus one down to the cutoff. The tag-`0x0c` early stop remains authoritative. Other visited entries are copied and passed to `0x5be3400` with account map `S+0xc8`, auxiliary map `S+0xf0`, and the existing spec gate. Entries below the cutoff are outside this traversal.

This yields a conditional implication useful for the next reconstruction: **a payer-origin entry that is still in the prefix when this checkpoint is captured is excluded from this particular rollback**. It does not prove that intervening record processing preserves every payer entry, that later outer cleanup keeps the journal, or that balances/nonces are unchanged by other operations. Validation refusal, interpreter revert, post-execution rejection and eventual transaction output still require separate end-to-end analysis. Those unresolved conditions must not be replaced by an unconditional claim that payer charges survive failure.

## Reproduction

The verifier checks 11 selected windows, 2,008 bytes / 377 instructions, 144 facts and 144 altered-instruction/relocation controls against the full digest:

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-011-node115-payer-journal-checkpoint-owner/verify.py --target /path/to/original/hl-node
```

These controls detect drift in recorded static evidence. They are not execution fixtures or an independent proof of runtime correctness. All helper normal-return and valid-object/checkpoint premises remain explicit.
