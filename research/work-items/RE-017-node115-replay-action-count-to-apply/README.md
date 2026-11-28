# RE-017 · Node #115 segmented Block input and collected row count reach ABCI

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `2da45cb0a761cff6b478e40421699857d87a94df`. All coordinates are linked ELF virtual addresses.

## Question

The [segmented receive](../RE-017-node115-replay-receive-poll/README.md) and [Block publication](https://github.com/lalalune/hyperliquid-source/pull/7286) establish queue records. The [bundle-to-owner study](../RE-017-node115-replay-signer-owner/README.md) covers the converter's retained action owners. The existing [expanded-state](../RE-017-abci-expanded-result-115/README.md) and [engine](../RE-017-abci-block-root-115/README.md) packets connect the callback owner to the apply engine. This packet supplies the complementary payload link: which action-row descriptor reaches the collector and which two counts the selected apply engine compares.

## Observations

| Boundary | Selected normal transfer |
| --- | --- |
| Segmented queue to record converter | A ready first probe through `0x581a100` makes `0x5ab6df0` return tag 1 with the selected row's pair at +8/+0x10. `0x5a6e328` receives into worker stack+0x468. The worker preserves that same pair at stack+0x3c8/+0x3d0. If the first owner is nonzero and the worker's prior identity gate and callbacks admit this record, `0x5a6e48d` passes the pair's address through slot `0x64e76e8` to `0x4fad300`. The converter loads the first and second owners from the supplied +0/+8. |
| Converter to dispatch and collector | On the ordinary non-sentinel result, the converter writes its 40-byte-row vector descriptor at result+0/+8/+0x10. The worker copies it from stack+0x4f8 to stack+0x320. One selected path retains the same row owners in a separate allocation by copying 40 bytes per row and incrementing each row's +0x20 owner reference. That allocation occupies the callback's pending +0x600 field. The collector instead receives the original vector's pointer and count directly from stack+0x328/+0x330 at `0x5a6e923` and `0x5a6e950`, followed by a pointer to the local closure byte. It writes into worker stack+0x1b0, whose first three qwords are initialized to `(0,8,0)`. Its entry `0x3d9ce60` is the collector already described in the [slow ABCI packet](../RE-008-slow-abci-apply-115/README.md). |
| Apply call | At `0x5a6e97b..0x5a6e9a5`, the worker packs the collected vector triple and the address of the original descriptor into the first 32 bytes of the input to `0x4f122c0`. The selected zero-wrapper-byte arm forwards that argument to `0x4fcb590`. At `0x4fcb764..0x4fcb795` the first 32 bytes are copied unchanged into the input to `0x56186c0`, which copies them again and supplies their address as argument 3 to `0x5a06600`. |
| Engine check | The selected engine reads original descriptor pointer from input+0x18, then reads original row count at descriptor+0x10. At `0x5a06705` it loads the collected count directly from input+0x10 and compares the two before entering the existing begin path. The comparison therefore uses converted and collected row counts for the same selected input. The separate pending clone does not supply this engine argument. |

This chain assumes the selected no-borrow ready path, valid initialized pointers and records, earlier identity agreement, normal callback and collector returns, admitted engine state, and no conflicting writes through aliases. Rows on the normal converter arm need not match the input attachment count if decoding rejects other rows. This packet starts from a selected ready row and establishes the applied call's inputs. It does not identify the actual first archived block at height H+1, execute ABCI against captured state, validate a root, or claim complete proof or lifecycle semantics.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-action-count-to-apply/verify.py
```

The [instruction spans](windows.txt) and [offline run](offline-log.txt) pin the selected calls, copy fields and comparisons in the authenticated ELF. The verifier checks data movement and projection controls distinguishing original storage, pending clone, converted count and collected count. The target is read as ELF data.
