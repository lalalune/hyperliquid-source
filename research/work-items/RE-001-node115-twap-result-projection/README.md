# RE-001: node #115 TWAP creation/cancellation result shapes

- Component: post-block response serialization; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Two complete FDEs: create result `0x5183a40..0x5183c1e`; cancellation result `0x5184250..0x518437a`. Exclusive ELF virtual-address ends. Gates remain false.

## Finding

Both TWAP result serializers start with a one-field structure. Serializer byte `+0x0b` selects a named map in valid mode 1 or a positional array in valid mode 0. The name in map mode is `status`. Inside this wrapper, successful creation and successful cancellation deliberately have different shapes.

| Result | Mode 1 shape | Mode 0 shape |
| --- | --- | --- |
| Creation succeeds, ID 7 | `{"status":{"running":{"twapId":7}}}` | `[{"running":[7]}]` |
| Cancellation succeeds | `{"status":"success"}` | `["success"]` |
| Either fails | `{"status":{"error":"MESSAGE"}}` | `[{"error":"MESSAGE"}]` |

These are JSON-like illustrations of MessagePack value types, not claims about a JSON endpoint. Enum payload maps (`running` and `error`) remain one-entry maps in both modes. Only structures switch to positional arrays. In particular, cancellation success is a string, not `{"success":null}`, and creation's numeric ID sits inside the running structure rather than directly under `status`.

Both serializers identify success by exact first-qword value `0x8000000000000000`, a native representation niche rather than a wire tag. A different first qword selects an error string descriptor at pointer `+8`, length `+0x10`. Successful creation loads its unsigned 64-bit `twapId` from `+8` and calls `0x57d00b0`; cancellation calls string helper `0x57cf860` with exact seven-byte `success`. No extra ID is read in cancellation success.

Map/array headers, field names, enum labels and values are emitted in the shown order. Primitive helper success is word 2. Each returned status is checked before the next emission; the first failure populates the error carrier and exits the selected path. Successful aggregate output uses niche-plus-four. This packet binds those checks and layouts, while generic MessagePack bytes and allocator behavior remain helper boundaries.

## Limits

Valid internal descriptors, UTF-8 strings, raw enum representations and mode bytes 0/1 are assumed. No claim covers TWAP validation, scheduling, fills, cancellation effects, caller mode selection, generic codec equivalence, memory allocation failures or complete post-block output. No captured code is executed or emulated.

Offline relations cover both actions, both modes, both result arms, unsigned-ID boundaries and varied error strings, with independent shape expectations. A separate helper-result matrix probes each first-failure position under the observed success marker. Actual mutations of the two niche branches and two key literals must change the derived output. Case counts measure these static relations, not target runs.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-twap-result-projection/export_disassembly.py
python3 research/work-items/RE-001-node115-twap-result-projection/verify.py --controls
python3 research/work-items/RE-001-node115-twap-result-projection/relations.py
python3 -m unittest discover -s tests -p 'test_node115_twap_result_projection.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-twap-result-projection/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2342](https://github.com/lalalune/hyperliquid-source/pull/2342) supplies the outer post-block dispatcher context. [#1058](https://github.com/lalalune/hyperliquid-source/pull/1058) covers status-stream logging, [#1839](https://github.com/lalalune/hyperliquid-source/pull/1839) tracker state, [#2202](https://github.com/lalalune/hyperliquid-source/pull/2202) action decoding/removal and [#265](https://github.com/lalalune/hyperliquid-source/pull/265) slice processing. This paired packet adds the nested creation/cancellation result shapes and their differing success values, not those lifecycle findings.

GPT-6.1 Terra searched open and closed PR metadata and available file evidence. The retained audit records missing historical content and patch limits; unavailable material prevents an absolute uniqueness guarantee. New analysis and relations are independently authored under MIT; ELF/export/corruption scaffolding adapts existing MIT packets. No unlicensed inferred source is copied or input rights changed. Full component completion, source equivalence and hosted CI are not claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
