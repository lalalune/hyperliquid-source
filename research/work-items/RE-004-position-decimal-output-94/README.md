# RE-004: position price formatting and field failure order in node #94

On its normal path the position builder sends present `entryPx` and `liquidationPx` values through a ten-fractional-digit formatting request before trimming, so reconstruction must preserve that conversion instead of assuming shortest-round-trip float text.

- Component ID: RE-004, quantities and rounding; position price display.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is an unlicensed lead only.
- Claim status: observations for the selected bytes, fields, direct calls, conditional targets and descriptor; the meaning of the tag and the formatted numerical examples are qualified inferences. Unresolved behavior is listed below.
- Scope included and excluded: five selected unwind extents from the `FAssetPosition` object through the two price-field adapters, the 11 field calls and their local success/failure edges, the format descriptor, and the optional-tag and allocation decisions. Existing shared scalar writer, formatting engine, trimming helper, map insertion and final JSON serialization are external boundaries. No target execution, #115, visor, or financial behavior is included.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/position_decimal_output94.py --out research/work-items/RE-004-position-decimal-output-94
python3 -m unittest tests.test_position_decimal_output94
python3 tools/catalogue.py --check
(cd research/work-items/RE-004-position-decimal-output-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=1 TZ=UTC0 python3 tools/position_decimal_output94.py --out <tmp-dir-a>
PYTHONHASHSEED=2 TZ=Pacific/Honolulu python3 tools/position_decimal_output94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The generator authenticates the full input digest before parsing, uses `tools/elf_index.py` and `tools/fde_extents.py`, excludes NOBITS from file mapping, and calls no external program. It does not run the captured binary. `evidence.json` records the five complete FDE byte ranges, hashes, offsets and descriptor bindings; `fields.tsv`, `branches.tsv`, `windows.tsv`, `tag-classes.tsv`, `failure-model.tsv`, `conditional-model.tsv`, `conditional-zero-region.tsv` and `optional-entry-classes.tsv` are generated from the same invocation. The manifest binds these files and this README.

## Evidence

Coordinates are linked ELF virtual addresses before load bias. FDE ends are exclusive and are unwind extents, not proof of complete source functions.

| Role | Start | End | Bytes |
| --- | --- | --- | ---: |
| Outer object | `0x2a31160` | `0x2a312aa` | 330 |
| Nested object adapter | `0x2a05f30` | `0x2a06161` | 561 |
| Position fields | `0x2a3d0a0` | `0x2a3d30a` | 618 |
| Optional float field adapter | `0x29fa3d0` | `0x29fa626` | 598 |
| Float text adapter | `0x2a342b0` | `0x2a343a1` | 241 |

The outer object passes the key `type` and a descriptor whose relocated strings are `FAssetPosition` and `oneWay`, then passes `position` to the nested object adapter. A successful `type` field is required before the latter call. The nested adapter invokes the position-field extent; an error result exits through its error branch. The 11 position keys, key lengths, record offsets and call targets are extracted directly from LEA displacements, immediate lengths and call displacements in `fields.tsv`:

| Fields | Input offsets | Local call role |
| --- | --- | --- |
| `coin` | `+0x20` | other writer |
| `szi` | `+0x48` | shared scalar float writer |
| `leverage` | `+0x38` | other writer |
| `entryPx` | `+0x00` | optional float adapter |
| `positionValue`, `unrealizedPnl`, `returnOnEquity` | `+0x50`, `+0x58`, `+0x60` | shared scalar float writer |
| `liquidationPx` | `+0x10` | optional float adapter |
| `marginUsed` | `+0x68` | shared scalar float writer |
| `maxLeverage`, `cumFunding` | `+0x88`, `+0x70` | other writers |

Before the normal tag comparison, the adapter subtracts its builder's first 64-bit word from zero and branches on signed overflow. That happens for exactly one bit pattern, `0x8000000000000000`: negating signed 64-bit minimum is the sole result outside the signed range. On this alternate route, the authenticated key lengths 7 and 13 both differ from 30, so the code skips the optional tag and reaches a separate indirect-call/return path without taking the direct float-adapter call. `optional-entry-classes.tsv` partitions the full 64-bit word space. This is local control flow; the existence of a reachable builder in this sentinel state is unresolved.

On the normal builder path, after preceding operations return successfully, the optional adapter compares the 32-bit word at its input with 1. Equality loads the eight-byte payload at `+8` into `xmm0` and calls the float text adapter. Any other 32-bit word takes the separate `0x29fa4c5` path and does not make that call. This partitions all 2^32 tag words; it does not establish which tags occur in a valid constructed position or what the downstream representation means. On the equal path the float adapter passes descriptor `0x20ad58` to the shared formatter and then calls the shared trim helper. Its successful carrier uses the tag word `0x8000000000000003` and stores the produced length and pointer. A negative length and a failed nonzero allocation have separate exits. The optional adapter and outer adapter each test their helper result before continuing; `branches.tsv` records the selected encoded edges.

The request bytes are `c5 20 00 00 70 0a 00 00`. Under the independently reconstructed compact-request relation in `RE-001-format-request-controller-94`, tag `0xc5` supplies the options word `0x70000020` and an immediate second quantity of 10, without descriptor-row indirection. The callback slot relocates to the float callback identified by `RE-006-open-order-view-94` and further described in the pending `RE-004-fixed8-float-rounding-94` submission (#1543); that submission identifies option bit `0x10000000` as selecting the second quantity as precision. Thus the same formatter request has precision 10, conditional on those previously established relations. The earlier `RE-006-raw-book-diff-output-94` interprets the shared trim boundary as removing trailing zeroes while retaining `.0`, with `-0.0` becoming `0.0`; its test formatter uses a stub for the format engine. Those shared bodies are dependencies, not new subject functions here. The five other fields reach the same writer that `RE-006-open-order-view-94` maps to float-valued fields; it is an external boundary here, and its complete output behavior is not proved by the optional-field path.

For every field call, a nonzero return reaches the common error block immediately; after the final call, a zero return selects the success block. Assuming each called helper returns, the first nonzero result therefore prevents later field calls. `failure-model.tsv` partitions all 2,048 Boolean success/failure combinations over the 11 calls; its counts describe this local control flow, not reachable application states or a whole-function execution test.

The retained branch table gives encoded condition, taken target and fallthrough. These are the selected decisions beyond the 11 field-result tests; they are not a complete CFG:

| Site | Taken condition | Taken effect | Fallthrough |
| --- | --- | --- | --- |
| `0x2a311ec` | `type` call returns nonzero | outer error block | call the `position` adapter |
| `0x2a31208` | `position` call returns zero | outer success block | outer error block |
| `0x2a05ff1` | nested carrier tag differs from error sentinel | copy carrier | propagate its error |
| `0x29fa3eb` | signed overflow in `0 -` the first builder word | alternate builder path | normal allocation and tag checks |
| `0x29fa5b0` | key length differs from 30 on the sentinel path | alternate indirect-call/return path | compare key bytes |
| `0x29fa47f` | 32-bit optional tag differs from 1 | skip float call | load payload and call float adapter |
| `0x29fa49a` | float carrier tag differs from error sentinel | copy carrier | propagate its error |
| `0x2a34309` | output length is nonnegative | test length for zero | negative-length failure |
| `0x2a34318` | output length is zero | use empty allocation representation | request nonzero allocation |
| `0x2a34326` | allocation returned zero | allocation failure | copy and construct carrier |

### Inferences and reference comparison

The keys and descriptor support interpreting the two tag-1 payloads as position entry and liquidation prices. The code shows their data flow and a format request, not the price unit, the producer, or whether a particular float is reachable. The reference `info_server/f_types/position.rs` describes these as optional floats and its helper uses shortest `to_string`; this is a comparison to an unlicensed hypothesis, not source authority. Under the prior descriptor and trimming interpretation, an injected binary64 approximation to `1e-11` is displayed as `0.0`, while shortest-round-trip rendering distinguishes it from zero. A reconstruction should preserve the ten-place request on this path rather than rely on the reference helper.

`conditional-model.tsv` is a separate exact-rational model of round-to-nearest, ties-to-even at ten decimal places and the stated trim rule. It includes the exact halfway inputs `1/2048` and `3/2048`, negative zero, a subnormal, and a maximum finite input. These are mathematical examples under that model, not captured-node outputs or proof that the existing shared formatter implements the model for every input. The binary bytes establish the request and handoff; the numerical rounding model is conditional on the formatter contract and floating-point environment.

The model also has an exact all-finite-binary64 zero interval in `conditional-zero-region.tsv`: for either sign, every magnitude encoding from `0x0000000000000000` through `0x3dcb7cdfd9d7bdba` rounds to `0.0`; the next encoding formats to `0.0000000001` in magnitude. This is 4,452,789,957,460,213,179 patterns per sign. The midpoint `1/(2*10^10)` has a denominator containing a factor of five, so no binary64 value equals it; positive finite encodings are strictly ordered by value. The generator uses exact rational bisection and verifies the two adjacent encodings, which establishes the interval for the stated model without enumerating its inputs. The count includes each sign of zero. This is a conditional mathematical range proof, not an assertion that the target formatter has been proved to follow the model.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo lock, compiler flags, source build, binary comparison, normalization masks, or target differential execution have been measured. The model does not execute the instruction stream. It uses exact integer ratios for the conditional examples; a separate Python fixed-format comparison checks 2,046 deterministic finite bit patterns. The focused tests also reject an incorrect artifact digest, changed function bytes with digest checking bypassed, a changed field literal or descriptor, a wrong relocation type or float callback addend, a duplicate FDE, invalid branch/call encodings, an unmapped address and NOBITS mapping. No test is skipped.

## Results and limitations

Five FDE extents, 11 field mappings, 21 selected conditional branch records, seven instruction windows, three builder-word partitions, three tag partitions, 15 model values and two conditional zero intervals are retained. The first-error model covers 2,048 Boolean masks; it does not execute the target, prove helper purity or establish reachability of all masks. Nineteen focused unit tests pass. No component progress gate is requested.

The common formatting engine, its complete rounding behavior and exceptional-value handling, allocation/unwind effects, conversion of carrier tags into final JSON, validity of non-1 tags, producer units, and admitted input range remain unresolved. The sample model is not an all-binary64 equivalence proof. FDE coverage is limited to the five selected extents and says nothing about the whole node.

Next question: identify an address-disjoint producer of the two price payloads and its unit and nullability rules, then compare the independently reconstructed formatter with an authorized offline target harness.
