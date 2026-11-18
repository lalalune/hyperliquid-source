# Position-side capture through the quantity-change entry

The Rust crate `src/node115-position-transition` connects the selected fill-side record at `0x4487910` to the position value store and the existing quantity-change source. This scope begins with the side selection and assumes the native account/market lookup has supplied the indicated existing or newly inserted row. It ends at the first boundary returned by the existing quantity-change implementation.

The prior [position transition packet](../RE-001-node115-position-sign-transition-value/README.md) and [PR #2892](https://github.com/lalalune/hyperliquid-source/pull/2892) establish the four arithmetic arms. [PR #2880](https://github.com/lalalune/hyperliquid-source/pull/2880) supplies the quantity-change entry, also exposed by the [notification continuation](../../../src/node115-quantity-notification/). This contribution binds the two size sources at the real caller, implements the value update in Rust and passes the observed operands directly to that existing source.

Target `artifacts/node/115/hl-node` is 105896032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are image VAs. The executable was read as data.

## Which size reaches which use

1. `0x4487926..0x4487952` selects the record at context +0 for ESI zero and +0x120 otherwise, then requires its dword tag to equal one. It saves the qword at selected +8 at `0x448796d` and copies the 20-byte account at selected +0xf8. The direction byte saved at `0x4487921` is SIL.
2. `0x4487a6f..0x4487a94` builds a bundle containing the address of that saved qword, the original fill context, and the direction-byte address. The caller passes the bundle in R9 to `0x4203320` at `0x4487c1e`. In the callee, `0x4203592..0x420359a` dereferences its first member twice to obtain the **supplied old size**. This value controls the +0x30 store. The fill contributes the qwords at +0x248 (crossing unit value), +0x250 (nonnegative magnitude) and +0x258 (increase).
3. An existing row saves its own +0x10 in RSI at `0x42034b4`. A newly inserted row takes the explicit zero path at `0x4203589`. After updating +0x30 the callee reloads row +0x10 into RDX at `0x42037ea`. These are the old and new **row** inputs passed to `0x4206f70`. The caller supplies state +0xf0 as the non-null total context and state +0xa8 as the non-null notification context accompanying the 20-byte account. The model calls `node115_quantity_notification::prior::entry` with these projected inputs.

The saved side size and the row size have different physical provenance. The integration test deliberately supplies distinct values to make accidental substitution observable. The fixture exercises the source contract. Whether a particular unequal pair occurs in a reachable exchange state remains open and requires tracing writers of the side record.

## Value update

A zero resulting size clears the value. A transition from zero or across sign uses the absolute new size times the unit value, with a maximum accepted product of `i64::MAX - 1`. A same-sign increase saturates the existing u64 value plus the supplied increase. The opposite-direction same-sign path uses a signed-convertible old value times the binary64 ratio of new to saved size, then truncates. The float multiplication follows the rounded division. Signed size addition saturates. The source represents native panic frontiers as `Stop` and preserves the pre-store row on these paths. Native lookup, telemetry calls, source record construction, and the later change-of-kind notification are outside this implementation.

## Reproduce

```sh
python3 research/work-items/RE-006-node115-position-transition-caller/verify.py --target artifacts/node/115/hl-node
cargo test --offline --manifest-path src/node115-position-transition/Cargo.toml
```

The Python verifier checks the original ELF digest, instruction bytes, function boundaries, imported slots and binary64 constants. The Rust tests cover both side records, full tag width, exact account boundaries, all four value arms, saturating addition, checked multiplication, unrepresentable operands, and handoff to the existing quantity-change source. A case with saved size 9007199254740991, new size 2 and stored value 4503599627370495 distinguishes division-first binary64 from an integer quotient or multiplication-first result.
