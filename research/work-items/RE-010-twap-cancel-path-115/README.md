# RE-010: node 115 TWAP cancellation from action name to removal and handoff

On node #115, matching table ordinals and call sites connect the `twapCancel` decoder tag `0xa9` to paired removal routines whose compact-row path decrements a count before testing a byte that can lead to internal result `0xd4`, establishing a reconstruction ordering subject to the unresolved runtime handoff.

- Component ID: `action-dispatch`, task `RE-010`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` is a navigation lead only, not implementation source.
- Claim status: static observations below; names assigned to data structures and route meanings are inferences. Runtime object transfer, transaction rollback and unexamined callees remain unresolved.
- Scope included and excluded: one selected name/decoder/dispatch context, the payload parser and thirteen new execution FDEs, both route branches, compact/tree removal, compact shifts, record-index guards and selected error and handoff paths. Other action variants, all called-helper semantics, captured execution and full component reconstruction are excluded.

## Reproduce

From the repository root, with Python 3.12.3 on Linux x86-64:

```sh
python3 tools/re010_twap_cancel_115.py --out research/work-items/RE-010-twap-cancel-path-115
python3 -m unittest tests.test_re010_twap_cancel_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-010-twap-cancel-path-115 && sha256sum -c MANIFEST.sha256)
```

The generator reads `artifacts/node/115/hl-node`, verifies its complete SHA-256 first, and imports `tools/elf_index.py` and `tools/fde_extents.py`. It reads ELF sections, FDEs, unwind-index entries, selected instruction bytes, signed relative displacements, and RELA records directly using the Python standard library. It excludes `SHT_NOBITS` from file-backed VA resolution. It neither runs the captured node nor invokes an external program. GNU objdump 2.42 was used for human inspection only; no generated evidence file or test parses or calls binutils.

The following commands reproduce the two-output comparison with an empty executable search path; choose fresh ignored output directories:

```sh
TASK_PYTHON=$(command -v python3)
mkdir -p work/re010-empty-bin
PATH=work/re010-empty-bin PYTHONHASHSEED=1 TZ=UTC "$TASK_PYTHON" tools/re010_twap_cancel_115.py --out work/re010-twap-a
PATH=work/re010-empty-bin PYTHONHASHSEED=97 TZ=Pacific/Honolulu "$TASK_PYTHON" tools/re010_twap_cancel_115.py --out work/re010-twap-b
diff -r work/re010-twap-a work/re010-twap-b
PATH=work/re010-empty-bin "$TASK_PYTHON" -m unittest tests.test_re010_twap_cancel_115
```

`functions.tsv` contains the selected FDE metadata, complete body bytes and SHA-256 values. `windows.tsv`, `branches.tsv`, `jumps.tsv`, `calls.tsv`, `rip-references.tsv`, `switches.tsv`, `descriptors.tsv`, `relocations.tsv`, and `name-order.tsv` contain the selected bytes and directly decoded coordinates. `record-indexing.tsv` and `record-arithmetic.tsv` record arithmetic immediates, offsets and overflow branches from the selected record paths. `shift-strides.tsv`, `shift-slot-references.tsv` and `shift-dynamic-import.tsv` preserve the shift helpers' element strides and dynamic symbol linkage. `pairs.tsv`, `pair-operands.tsv`, and `pair-diffs.tsv` preserve raw pair comparisons and every explicit mask. `constants.json` contains extracted immediates and the arithmetic certificate; `summary.json` counts only these selections. The manifest covers the README and generated files; the generator updates only the generated files.

## Evidence

All addresses are linked ELF virtual addresses; file offsets are zero-based. Ends are exclusive. The selected parser and core start at file offsets `0x39cff20` and `0x2c2e020`, respectively. Each row below is an unwind-described FDE range corroborated by a recorded entry call and executable bytes. It does not establish a one-to-one original Rust source function.

| Selected role | Start VA | End VA | Bytes |
| --- | --- | --- | ---: |
| Payload parser | `0x39d0f20` | `0x39d1b0a` | 3050 |
| Route core | `0x2c2f020` | `0x2c2f7c2` | 1954 |
| Route 0 removal | `0x2d2c6e0` | `0x2d2d019` | 2361 |
| Route 1 removal | `0x2d2d020` | `0x2d2d959` | 2361 |
| Route 0 first removal | `0x2d2efa0` | `0x2d2f50b` | 1387 |
| Route 1 first removal | `0x2d2f510` | `0x2d2fa7b` | 1387 |
| Route 0 tree removal | `0x243f670` | `0x243f8fe` | 654 |
| Route 1 tree removal | `0x243f3e0` | `0x243f66e` | 654 |
| Route 0 record, other discriminator | `0x2a81140` | `0x2a81545` | 1029 |
| Route 0 record, discriminator one | `0x2a81a70` | `0x2a81f22` | 1202 |
| Route 1 record, other discriminator | `0x2a80cb0` | `0x2a8113f` | 1167 |
| Route 1 record, discriminator one | `0x2a81550` | `0x2a81a68` | 1304 |
| Compact shift, 112-byte elements | `0x24da590` | `0x24da7c6` | 566 |
| Compact shift, 96-byte elements | `0x24dfef0` | `0x24e01e6` | 758 |

The reference file `l1/exchange/handlers/34_twap_cancel.rs` groups a wrapper and removal presentation. It is an agent-created split, not evidence that the original source had that file or those function boundaries. On #115 the table above has distinct FDEs and the recorded calls enter their starts. The previously recorded central dispatchers, matcher and first-call wrappers are re-read only at context sites needed to connect this question; they are not counted among the fourteen newly selected FDEs. The separate route-specific final handoff functions were already referenced by the schedule-cancel packet and are not analyzed as new functions here.

### Name, tag and parser

The name matcher's length-10 entry at `0x799328` selects `0x3661e2d`. On this path the code first tests `spotDeploy`, then tests all ten bytes of `twapCancel`; its equality branch at `0x3661e72` reaches `0x3662625`, which writes ordinal `0x23`. The short path's instruction immediates and the preceding comparison are in `name-order.tsv` and `windows.tsv`. Three separately relocated variant-table slots at index 35 also contain `twapCancel`.

The selected action-decoder table entry `0x79a438` reaches `0x36b9332`. That code references the 16-byte `TwapCancelAction` string and four relocated field descriptors, calls the selected parser at `0x39d0f20`, and on the selected parser-success path writes tag `0xa9` through the shared store at `0x36bae27`. The dispatch bias is `0x86`; `0xa9 - 0x86 = 35`. The selected nested and direct dispatch entries lead to their previously mapped wrappers. Each wrapper has a recorded direct call to the new core, at `0x2a2fbe2` and `0x2c0a868`, respectively. The generator checks that each call lies in the FDE targeted by its corresponding dispatch arm.

This is a static producer/consumer connection. It does not show that a runtime value returned by the name matcher reaches the decoder, or that the resulting decoded object reaches either router without an intervening transformation.

The parser's selected map-like path checks the four strings `a`, `asset`, `t`, and `twapId`, with the first pair selecting field 0 and the second pair selecting field 1. Its internal kind `0x15` enters that path; `0x14` enters a sequence-like path, and other kinds take a separate error-construction route. The map path checks separate presence flags: after the selected value-conversion path returns, a repeated field reaches the duplicate-field formatting path, and at the end a missing `a` flag is checked before a missing `t` flag. The sequence path has separate empty and excess-element branches. The selected 15-way input-kind switch is in `switches.tsv`; these are internal parser kinds, not a complete wire-format specification.

### Wrapper and route decisions

`0x1a2`, `0x154`, `0x108`, and `0xd4` below are observed internal words, not asserted external API codes. Conditions assume the cited calls return normally.

| Ordered condition | Static consequence |
| --- | --- |
| The wrapper's classifier result word is not `0x1a2` | The selected path propagates its result into outer tag `0x0f` and does not call the core. |
| Classifier returns `0x1a2`, and the first payload word is at least `0x0ccccccccccccccc` | The wrapper records `0x154` with outer tag `0x0f`; it does not call the core. |
| Classifier returns `0x1a2`, and the word is below that limit | The wrapper calls the core and then writes outer tag `0x05` after copying its result, without a result-word test on that straight-line portion. The nested result can still contain an error. |
| Core input `rcx == 1` and byte `[state+0x42ac]` is nonzero | The core writes word `0x108` and takes its return path before either selected removal call. |
| Core input `rcx == 1` and that byte is zero | The core calls route 1 removal at `0x2d2d020`. |
| Core input `rcx != 1` | The core computes the unsigned quotient described below, checks it against two lengths, then calls route 0 removal at `0x2d2c6e0`. Either failed length check reaches a separate call and `ud2` path. |
| A removal result begins with dword `1` | The core copies that result and still reaches the corresponding final handoff with the initial empty temporary collection. This alone says nothing about the handoff's effects or rollback. |
| A removal result does not begin with dword `1` | A second discriminator selects one of two recorded record-preparation calls for the route. The core constructs a temporary record, passes byte count `0x2b8` or `0x2c8` to an indirect call, stores internal word `0x1a2`, and reaches the route-specific handoff. |

For the non-one route, the core multiplies unsigned `r8` by `0x346dc5d63886594b`, takes the upper 64 bits, and shifts right by 11. Thus `q = floor(r8 / 10000)` over all unsigned 64-bit inputs. Writing `M = ceil(2^75 / 10000)`, the extracted multiplier satisfies `M * 10000 - 2^75 = 432`; because `(2^64 - 1) * 432 < 2^75`, the reciprocal's excess is too small to carry across the next integer. The two bounds are read at state offsets `+0x3ad0` and `+0x7d0`; the subsequent selected array strides are `0x200` and `0x510`. Their semantic names and the validity of arbitrary input values are not established by this calculation.

### Removal, writes and failures

Each route-specific removal first calls its corresponding first-removal FDE. If that result's selected byte differs from `2`, the caller copies the returned row-shaped value. For byte `2`, it proceeds to a second representation with a 20-byte comparison path and a compact representation. A null root, a failed key lookup, an index outside its recorded count, or the selected missing-ID result can reach the internal `0xd4` result. The same selected branch destinations are separately decoded for both route copies in `branches.tsv`.

On the compact route, the code copies a row at a stride of `0x70`, saves its byte at offset `+0x2a`, calls a shift helper, decrements a count, stores the decremented count, and only later tests the saved byte against `2`. If it is `2`, the selected path continues through the result/representation handling and can return `0xd4`. The first-removal pair has a corresponding shift and count decrement before its own byte-2 check. Intervening calls, caller-level transactions and rollback are not closed; the instruction order does not prove a committed state change after an error.

Human-readable excerpt of selected #115 instructions, inspected with GNU objdump 2.42; the omitted interval contains copies and representation handling:

```text
2d2c9c3  e8 c8 db 7a ff       call 0x24da590
2d2c9c8  49 ff cc             dec  r12
2d2c9cb  4d 89 65 18          mov  [r13+0x18],r12
...
2d2ca4f  40 80 fd 02          cmp  bpl,0x2
2d2ca53  75 07                jne  0x2d2ca5c
...
2d2ccd6  66 41 c7 47 10 d4 00  mov  word [r15+0x10],0xd4
```

The selected tree path compares a key, calls its inner removal helper and decrements the tree count at `0x243f79f`. When the returned flag selects root replacement, it checks a root pointer and a height-like word, installs a child pointer, decrements that word, and calls an indirect slot with size `0x540`. The two failed checks have distinct recorded targets. These are layout and instruction observations; original container type, allocation ownership and error recovery are not established.

### Compact movement and copy ordering

The two removal pairs call separate shift FDEs, at `0x24da590` and `0x24dfef0`. Their instructions scale positions and lengths by 112 and 96 bytes respectively. The caller computes `suffix = length - index - 1`; when `suffix < index` it moves the suffix one position toward the removed row and leaves the head field unchanged. Otherwise it moves the prefix one position forward and stores the next head. Ties therefore take the prefix path. After the helper returns, the caller decrements and stores the length. These names and ring interpretation are inferred from the recorded arithmetic and calls; their validity assumes a valid, representable compact buffer and normal return.

The helper receives a buffer capacity `C`, physical source `s`, physical destination `d` and element count `k`. For nonzero `k` and distinct positions, let `S = C - s`, `D = C - d`, and `delta = (d - s) mod C`. With valid compact-buffer arguments, the complete selected split follows this table. Each triple means `(destination, source, number of elements)`; triples are ordered. For `k = 0` or `s = d`, the function returns without a copy. Each position and count is multiplied by the helper's element stride before the indirect call.

| Condition | Ordered copy triples |
| --- | --- |
| `k <= S` and `k <= D` | `(d, s, k)` |
| `k <= S`, `k > D`, `delta >= k` | `(d, s, D)`, `(0, s + D, k - D)` |
| `k <= S`, `k > D`, `delta < k` | `(0, s + D, k - D)`, `(d, s, D)` |
| `k > S`, `k <= D`, `delta >= k` | `(d, s, S)`, `(d + S, 0, k - S)` |
| `k > S`, `k <= D`, `delta < k` | `(d + S, 0, k - S)`, `(d, s, S)` |
| `k > S`, `k > D`, `delta >= k` | `(d, s, S)`, `(d + S, 0, D - S)`, `(0, D - S, k - D)` |
| `k > S`, `k > D`, `delta < k` | `(S - D, 0, k - S)`, `(0, s + D, S - D)`, `(d, s, D)` |

The recorded branch targets cover both helper bodies. Eighteen selected RIP-relative instructions address slot `0x64df568`; the raw `R_X86_64_GLOB_DAT` relocation and undefined dynamic symbol identify the linked import as `memmove`. Runtime symbol binding is not captured. The model and copy-order interpretation assume normal `memmove` behavior, non-overflowing physical and byte offsets, valid storage and the one-step shift arguments constructed by these callers; the table is not a claim that arbitrary circular copies are safe. The focused test enumerates 6,020 valid caller configurations with capacities 1 through 14, compares the synthetic ordered copies against independent logical removal, and exercises zero through three copies. This does not execute the captured node.

### Record preparation: index and failure branches

On the selected non-error result paths, the core's discriminator selects one of two record constructors per route. Their direct call sites and FDE starts are in `calls.tsv` and `functions.tsv`. These four bodies are separate FDEs, even though the reference presents them together with a higher-level handler.

| Constructor | Selected indexing observation | Out-of-range or group-mismatch path |
| --- | --- | --- |
| Route 0, other | At `0x2a8119d`, computes quotient `q = floor(key / 10000)`, compares it with `[r13+0x50]`, then uses `key - q*10000` as an index bounded by `[r13+0x10]`; rows have stride 32. | Mismatch goes to `0x2a81295`; index at least the bound goes to `0x2a812b9`. The observed `rsi == 0` path initializes selected temporary values, while nonzero reaches an indirect call. |
| Route 0, one | At `0x2a81ac7`, computes the same quotient and remainder and checks `[r8+0x50]` and `[r8+0x10]`; rows have stride 32. | Mismatch goes to `0x2a81be3`; index at least the bound goes to `0x2a81c13`. The `rbp | rsi == 0` path initializes selected temporary values; a nonzero result reaches an indirect call. |
| Route 1, other | The value at `[rsi+0x10]` is compared unsigned against `[rdx+0x10]` at `0x2a80ccc`; in range it selects a row with stride 32. | An index greater than or equal to the bound goes to `0x2a810f0`, which makes two indirect calls followed by `ud2` if they return. |
| Route 1, one | The value at `[rsi]` is compared unsigned against `[rdx+0x10]` at `0x2a8156b`; in range it selects a row with stride 32. | An index greater than or equal to the bound goes to `0x2a81a19`, which makes two indirect calls followed by `ud2` if they return. |

`record-indexing.tsv` derives the multiplier, shift, divisor, member displacements and stride from the pinned instruction windows. The division certificate above also applies to these two route-0 constructors. The input provenance, complete initialized values, all later arithmetic, indirect call behavior and whether an outer transaction commits are still unknown. In particular, the indirect calls on a failed route-0 check are not assumed to return, abort, or commit anything.

Both route-1 constructors also call an indirect slot and inspect the byte returned at stack offset `+0x18`. For a byte `b < 2`, the eight-byte value `v` at stack offset `+0x10` follows the same selected calculation in both bodies. Let `U = 2^64 - 1` and `K = 100000000`: the instructions first compute `n = min(U, 10*v + b)`, then `min(U, n + K) - K`. The multiply-overflow branch sets the intermediate to `U`; carry in each addition selects `U`. The final subtraction follows the recorded join, making the result equivalently `min(10*v + b, U - K)` on this path. For `b >= 2`, the code instead uses the pre-call index and branches separately for zero, values below `K`, and values at least `K`. `record-arithmetic.tsv` and the selected windows preserve both copies, constants, overflow targets and the shared slot address. The source or business meaning of the indirect result and the subsequent formatting are not established. Boundary-vector tests exercise the multiplication and offset limits; they do not execute the node or establish runtime binding of the indirect slot.

### Inferences and unresolved questions

The labels `route 0`, `route 1`, `row`, `group`, `record` and `removal` describe observed data flow, call order and writes; they are not recovered Rust type or source-function names. The `twapCancel` name and `TwapCancelAction` descriptor are literal #115 data. The association of those two producer/consumer contexts with the selected core is supported by their matching table ordinal and the recorded wrapper call sites, but runtime movement of the object and the semantic meaning of every result remain unverified.

### Paired bodies and comparison limits

| Body pair | Raw equal / compared | Different raw positions | Four-byte operand masks | Masked operands with different computed targets |
| --- | ---: | ---: | ---: | ---: |
| Removal | 2322 / 2361 | 39 | 18 | 6 |
| First removal | 1351 / 1387 | 36 | 16 | 4 |
| Tree removal | 638 / 654 | 16 | 7 | 0 |

Each row is one equal-length pair of complete selected FDE bodies. All unmasked byte positions match after masking only the listed four-byte PC-relative displacements in instructions whose opcodes are checked in both bodies. `pair-diffs.tsv` preserves all 91 raw differences, and `pair-operands.tsv` records every masked operand and its computed target in both copies. Masked equality is a structural observation, not helper equivalence: ten selected computed targets differ across the first two pairs. The status of those targets, relocation resolution, referenced data, vtables and indirect-call effects remains separate.

### Historical lead

The retired #94 `RE-010-exchange-handlers` record at repository commit `3324e50333042b391312515e542279ca21f63dc8` reports `twapCancel` at case 34/tag `0x96`, with first call `0x22c4630`. The reference's related helper lead is `0x2724580`; both belong to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The #94 binary was unavailable for a new byte-level comparison. This packet derives the #115 name, tag, call sites, FDEs and branches from #115 itself; it does not claim cross-release body, layout, status-code or behavior equivalence.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependencies, compiler/linker options, two-build results, reconstructed-byte comparisons, complete helper closure, relocation/vtable/data closure and whole-ELF comparison: **not yet measured**. The paired-body comparison above compares two locations in the captured #115 image and is not an implementation comparison.

The focused tests check the digest, selected body hashes, executable-section membership and index linkage, name comparisons, descriptor and import relocation records, branch and call decoding, selected input-kind table, result words, row-write order, compact movement and the full-width reciprocal proof. Negative controls mutate bytes, branch and call operands, the imported symbol, descriptors, FDE metadata and masked/unmasked pair operands; malformed, ambiguous, out-of-range and `SHT_NOBITS` mappings are rejected. Arithmetic, ring and field-spelling models are synthetic checks of the stated interpretation, not execution of the node.

## Results and limitations

The generated selections cover 14 FDEs, 65 pinned windows, 111 selected conditional branches including paired copies, 12 direct jumps, 22 selected calls, 7 RIP references, 19 selected switch entries, 7 descriptor strings, 8 relative relocation records, 4 record-indexing paths, 2 record-arithmetic paths, 18 shift-slot references, one dynamic import and 3 pair comparisons with 41 masked operands. They are selected evidence, not a target-wide function census or coverage denominator. The focused suite passed 44 tests with no skips; two generations under different hash seeds and time zones, using a search path without binutils, were byte-identical. Artifact authentication and the catalogue check passed.

No captured binary, network, keys, chain actions or full repository test suite were run. The matcher-to-router object handoff, argument provenance, complete classifier, remaining record-preparation arithmetic, tree helper, dynamic symbol binding, other indirect slots, allocator/unwind effects, final handoffs and transaction rollback remain open. The #115 `action-dispatch` gate remains 0/4; no gate change is requested. Next: close the final route-specific handoff and its caller-level transaction behavior once the overlapping work is reconciled.
