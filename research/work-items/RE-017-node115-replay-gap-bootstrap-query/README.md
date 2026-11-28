# RE-017 · Node #115 replay gap into bootstrap query input

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Analysis base `c42e4eebf847462db32c934af4140a346ebba310`. Addresses are linked ELF virtual addresses.

## Question

The [parent-round comparison](https://github.com/lalalune/hyperliquid-source/pull/7266) establishes the staged parent and receive-round baseline. [RE-014 / PR #2031](../RE-014-bootstrap-range-rust-115/README.md) establishes a bounded range builder given two raw inputs, and leaves its initialization and request framing open. Where do the two raw inputs come from when an admitted Block reports a parent above the local receive baseline, and where do they go?

## Observations

Let F be the replay future. On the selected continuation after the Block preparation helper, `0x5a87fbd..0x5a87fc4` compares parent (F+0x1f8) to baseline (F+0x200) again. Equality enters the existing worker path. Unsigned parent greater than baseline instead prepares a diagnostic referencing the bytes `missing client blocks before received client block, bootstrapping from peer`.

The normal returning diagnostic continuation stages **baseline plus one, saturating**, at F+0x258 and F+0x278, and the **incoming parent word**, unchanged, at F+0x260 and F+0x280. This establishes the inputs to the prior RE-014 range builder: `0x5a88206` and `0x5a8820d` install pointers to the lower and upper words at +0x278/+0x280, and `0x5a88391` reloads them. The branch for a supported inclusive span reaches `0x5a83026`, whose existing cap is 100 values per first chunk. The requested Block's own successor word is a separate operand from the parent bound.

| Selected stage | Where the first chunk's two inclusive bounds are kept |
| --- | --- |
| Query construction | `0x5a8306c..0x5a8308c` fills F+0x2d0 with four qwords: literal address, literal length 20, first bound, last bound. The literal bytes read `node_bootstrap_query`. |
| Construction of nested frame | `0x5a830fc` copies from F+0x2e0, the first bound. The next copies preserve both words via F+0x1100, stack+0x3190, stack+0x1490 and stack+0x630, into F+0x1f68/+0x1f70. |
| Selected nested request preparation | State table entry 0 at `0x939ba8` selects `0x5a833af`. This code reads those two qwords and saves them at F+0x1f80/+0x1f88 in the same order. |

For example, baseline 120 and parent 123 lead to a first chunk with bounds `[121, 123]`. Baseline 120 and parent 260 lead to `[121, 220]` under the prior range cap. These are synthetic projections and there is no network request in the validation.

The selected flow assumes normal helper returns, stable parent and baseline fields, ordinary copy binding and no intervening aliases replacing the staged words. Span calculation belongs to the credited packet. The transport, subsequent responses, reconnects, actual Block processing and state-root behavior remain open.

## Reproduction

```sh
python3 -B research/work-items/RE-017-node115-replay-gap-bootstrap-query/verify.py
```

See [pinned instruction spans](windows.txt) and [offline output](offline-log.txt). The verifier hashes the ELF, confirms indexed FDE membership, decodes the selected comparison and copy fields, resolves the name bytes and initial nested dispatch table, and checks the projected first range and byte-corruption controls.
