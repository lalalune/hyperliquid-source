# RE-001: node #115 filled/resting order-status nested fields

- Component: post-block response serialization; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Nine complete FDEs are recorded in `records.json`, with exclusive ELF virtual-address ends. Parent `0x5188f20..0x5189312`, quantity field `0x526ff60..0x5270074`, cloid field `0x526ebb0..0x526ed08`, normalization `0x44a61d0..0x44a6312`; five generic encoding/hex functions are context. Gates remain false.

## Finding

The filled and resting variants use a one-entry outer map, then a nested structure whose container depends on serializer byte `+0x0b`. Valid mode 1 emits a map with names; mode 0 emits an array with the same values in the same order. The option byte at input `+1` controls whether `cloid` is included. For valid 0/1 flags, absence removes the field entirely; it does not leave a nil slot.

| Variant | Ordered nested fields | Input locations | Nested length |
| --- | --- | --- | --- |
| filled | totalSz, avgPx, oid, optional cloid | f64 at +0x18, f64 at +0x20, u64 at +0x28, optional 16 bytes at +2 | 3 + present |
| resting | oid, optional cloid | u64 at +0x18, optional 16 bytes at +2 | 1 + present |

Both quantities call `0x526ff60`, which loads binary64, calls the relocated formatter/normalizer `0x44a61d0`, then writes its result through the MessagePack **string** helper `0x57cf860`. They are not encoded through a floating-point MessagePack primitive. The order ID calls the unsigned integer helper `0x57d00b0`. Present `cloid` uses exactly 16 input bytes, a 34-byte buffer, lowercase hexadecimal with a `0x` prefix, then the string helper. It preserves leading zero nibbles because the helper's trimming flag is zero.

`0x44a61d0` calls an initial Rust float formatter through `0x1688740`; the initial rounding, precision and exceptional-value formatting remain opaque. Its returned text then loses terminal `0` bytes until either a nonzero byte is reached or the final two bytes are `.0`. It retains that `.0`. After trimming, exact `-0.0` becomes `0.0`. Thus supplied intermediate `12.50000000` becomes `12.5`, `100.0000` becomes `100.0`, and `-0.00000000` becomes `0.0`. These examples describe the proven post-normalization relation; they do not assert what the opaque initial formatter produces for any particular float.

The parent and field helpers check each helper's success result before proceeding. A field-name or value failure exits the current path rather than emitting later fields. The evidence binds these branches, while the relation matrix assumes successful storage and does not reconstruct allocation failures or partial output recovery.

## Limits

Only the filled/resting nested projection is new here. The other three status variants, outer response dispatch, generic MessagePack size encodings, allocator behavior, float rendering, caller choice of mode and complete post-block response equivalence remain outside this question. Invalid Rust option/enum bytes are not protocol inputs. No captured code is executed or emulated.

The offline relation reads real field offsets, branch polarities, key literals and normalization constants from target instructions. It compares independent named-field expectations for both variants, both valid modes, optional-field absence/presence, unsigned integer boundaries and varied 16-byte identifiers. Separate arbitrary-ASCII probes isolate post-normalization. Four actual byte mutations distinguish the size field location, declared field count, optional omission and `.0` stop rule.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-order-status-nested-fields/export_disassembly.py
python3 research/work-items/RE-001-node115-order-status-nested-fields/verify.py --controls
python3 research/work-items/RE-001-node115-order-status-nested-fields/relations.py
python3 -m unittest discover -s tests -p 'test_node115_order_status_nested_fields.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-order-status-nested-fields/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

[PR #2342](https://github.com/lalalune/hyperliquid-source/pull/2342) owns the outer status/dispatcher work and leaves nested bodies open. [#1543](https://github.com/lalalune/hyperliquid-source/pull/1543) reconstructs an older node #94 formatter that removes a final decimal point and changes `-0` to `0`; this node #115 post-normalizer instead retains `.0`. [#2107](https://github.com/lalalune/hyperliquid-source/pull/2107) and [#2332](https://github.com/lalalune/hyperliquid-source/pull/2332) provide the existing prefixed lowercase-hex context. Those general encoders and prior outer dispatches are credited rather than presented as new discoveries.

GPT-6.1 Terra searched open and closed PR metadata and available file evidence. The retained audit describes unavailable historical content and patch limits; it cannot prove uniqueness in unavailable material. New analysis and relations are independently authored under MIT; ELF/export/corruption scaffolding adapts existing MIT packets. No unlicensed inferred source is copied or input rights changed. Full component completion, source equivalence and hosted CI are not claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
