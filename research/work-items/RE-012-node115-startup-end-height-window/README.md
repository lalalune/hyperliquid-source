# RE-012: node #115 startup end-height sampling window

This packet closes the previously opaque producer between the startup end-height parent and its per-file helper. Under valid-tree, ownership and ordinary-call premises, it samples **at most five entries in reverse structural order**, retains both successful and failed results, drains the remainder without evaluating it, and lets the credited parent select the unsigned maximum successful sampled value. An error consumes an attempt; a sixth entry cannot replace it.

The prior parent packet explicitly left `0x5accff0` opaque: “Its parsing, input source and complete validity conditions remain unclosed.” At reference revision `05bc2de303c05525b71e7e257426e741bc66a390`, that README has SHA256 `18b0740ab6cdc846d68b4517757de11e26282c213793495f35de8de9f582066b`. This packet closes the conditional sampling cardinality, traversal, materialization and drain relation while preserving the filesystem/input-order gaps. The prior packet is unchanged.

This is bounded static reconstruction of the startup call path. It adds no Rust wrapper, filesystem implementation, captured execution, byte-equivalence comparison, or completed component gate. The [proof](PROOF.md) separates the result relation from the callback and ownership assumptions.

## Target and complete native scope

- Target: Linux x86-64 node #115, 105,896,032 bytes.
- SHA256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Reference revision: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Coordinates: ELF virtual addresses; complete FDE extents, not comment-seed windows.

| Complete interval | Bytes / instruction rows | Scope and credit |
| --- | ---: | --- |
| `0x5accff0..0x5acd160` | 368 / 97 | bounded result-vector materializer |
| `0x543dab0..0x543dc44` | 404 / 110 | attempt budget, result stores and remaining-entry drain |
| `0x5152d00..0x515313a` | 1082 / 235 | reverse consuming cursor |
| `0x51ded00..0x51df0aa` | 938 / 225 | forward cursor and terminal drain |
| `0x595b1a0..0x595b512` | 882 / 212 | credited parent and maximum selection, PR2098 |
| `0x595b520..0x595bc3a` | 1818 / 415 | credited per-file operation and canonical ordinary tags, PR2578 |

The four dependency bodies total 2,792 bytes / 667 rows. With the two credited context bodies, the retained complete scope is 5,492 bytes / 1,294 rows. These figures describe evidence extent, not newly reconstructed bytes, source equality, or whole-component coverage. No first-byte credit is claimed.

The [startup end-height packet](../RE-012-node115-startup-end-height/README.md), [PR2098](https://github.com/lalalune/hyperliquid-source/pull/2098), already established the parent and selected startup consumer. The [file-height composition packet](../RE-001-node115-startup-file-height-composition/README.md), [PR2578](https://github.com/lalalune/hyperliquid-source/pull/2578), supplies the per-file operation. Neighboring [PR3190](https://github.com/lalalune/hyperliquid-source/pull/3190) covers its line-count dependency, and [PR3193](https://github.com/lalalune/hyperliquid-source/pull/3193) covers command rendering. Their helpers remain credited conditional dependencies.

## What the composition establishes

For structural entry sequence E of length N, the sampled entries are E[N-1] through E[N-min(N,5)]. The collector decrements budget before each file-height call and stores every returned pair. It then drains the unsampled prefix through the opposite cursor, with no file-height call in the drain. The maximum applies only to successful results from that bounded sample.

The parent tests a tag's low byte when selecting successes but its whole qword when dropping errors. The complete credited file-height body returns canonical tags 0 or 1 on its ordinary paths, which reconciles those tests. Arbitrary raw result tags are not part of the proved domain.

The two cursors share a remaining count and require a live-frontier ownership invariant. Their structural traversal does not establish filename, chronological or numerical-height order. Stable input across the allocator is also required: the producer re-reads the original iterator and contains a growth branch if the second bound exceeds the first. The stated preservation premise excludes that branch; it does not prove the generic growth helper.

## Reproduction interface

The task-local collector authenticates the complete target before static native decoding and binds complete exports, FDE/CIE bytes, selected operands, call/data/relocation records and credited context. Its checks are static data checks; the target is never launched. From the repository root, use an existing GNU objdump and a fresh output path:

```sh
python3 research/work-items/RE-012-node115-startup-end-height-window/collect.py \
  --objdump /absolute/path/to/GNU/objdump \
  --output work/startup-end-height-window-review --check

PATH=/path/to/GNU/bin:$PATH python3 -m unittest discover -s tests \
  -p 'test_node115_startup_end_height_window.py'
```

The generated tree contains `records.json`, `commands.json`, version stdout/stderr, and complete stdout/stderr exports for all six bodies under `native/`. `obligations.json` is the separate static expectation set. The focused controls reject corrupted operands, traversal/count/stride boundaries and dependency records beneath the outer target-identity check; their rejection is not native behavioral execution.

Actual qualification: the initial collector completed with exit 0 and all 16 generated artifacts were retained unchanged. The focused suite passed **13 tests in 9.495 seconds**, including a second authentic collection and exact comparison of all twelve native stdout/stderr files. The named controls mutate the first and last byte at each of 54 sites. Separate tests cover CFI records/index, relocation fields and overlays, data/import records, address mappings, changed instruction widths, missing/duplicate rows, capture-as-tool refusal, and retained decoder-failure streams. These are evidence-integrity checks, not semantic execution of the captured node. [Validation receipts](RUN-RECEIPTS.json) record actual commands and declared public log projections.

## Limits

The loader, filesystem/process behavior, rendered diagnostics, allocator implementations and dynamic error-object drops remain opaque. The proof requires finite valid trees, exact counts, correct parent edges/heights, disjoint live ownership and preserving ordinary callbacks. It does not cover malformed state, concurrent mutation, allocation failure, generic growth, unwind completion or actual memory reclamation.

All observations share one authenticated native capture and one retained GNU instruction decoder. Separate ELF/raw-byte checks establish identity and partition consistency, not an independent decoder or organization. The packet does not establish five successful calls, a global maximum, full startup acceptance, or a source-native ABI implementation. Full-scope gates remain unchanged.
