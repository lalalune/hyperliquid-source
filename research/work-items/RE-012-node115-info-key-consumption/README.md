# RE-012: node115 `info` literal reaches a format-key consumer

Task/component: RE-012 / node-runtime function attribution, resolving the explicit next question in `RE-012-node115-cli-info-literal`. Target node115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. Base `05bc2de303c05525b71e7e257426e741bc66a390`. New analysis/code is independently authored MIT; upstream captured bytes retain their rights.

The earlier packet found `info` but deliberately left its consuming use unresolved. The real selected use passes it as the first string argument alongside format bytes `"%s":%s`, with empty/space suffix selection. This is concrete format-key preparation evidence; the literal match alone does not identify a CLI command or service entrypoint.

## Measured scope

| Role | Complete FDE range, linked ELF VA | Bytes |
| --- | --- | ---: |
| containing owner/context | `[0x63d4bbe,0x63d5428)` | 2,154 |
| immediate literal consumer | `[0x63d3d27,0x63d3d66)` | 63 |

Total retained native evidence: **2 FDEs / 2,217 bytes / 477 contiguous instruction rows**. The interpretation claim is the literal-to-consumer corridor and the entire 63-byte consumer; the large owner's other branches are retained context, not a claim of completely reconstructed behavior. The original literal occurrence/address was already known and is not claimed again as a new discovery.

`evidence.json` retains full raw bodies/FDE/CIE, section-resolved file offsets, every exported RIP reference/direct edge, five selected data slices and the one matching RELATIVE writer. Per-owner LLVM files contain every byte; GNU frame exports independently confirm both FDE extents. No nearest-symbol label establishes either source identity or dependency provenance. The old nearest C++ symbol printed by objdump is not adopted as a function name. Source/dependency ownership and all callers remain unknown.

## The selected producer corridor

At `0x63d4cc3` RBX is set to RSP+0xa0. The owner initializes that local object's dword+0 to1, qword+8 to `0x636c530`, qword+0x10 to its saved R12, and selected later fields to zero. It passes the same object to a prior call with a NUL-terminated `{` slice at `0x44ecd8` (only the two-byte prefix is relevant; following retained bytes are adjacent material, not part of that string).

The selected sequence then does:

```text
0x63d4d18: RSI = &"info\\0" at 0x4312f2
0x63d4d1f: RDI = RBX
0x63d4d22: dword[local_object+0x18] = 1
0x63d4d2d: call 0x63d3d27
```

There is no branch or intervening call between these assignments and the consumer call. This is a specific local use, not an exhaustive xref census or a proof that no other instruction in the ELF treats the string differently. Reachability of the containing path from a CLI input remains unproved.

## Entire immediate consumer

The 63-byte consumer saves incoming RSI in RBP and incoming RDI in RBX, then calls `0x63d3ce2` with the object. Assuming an ordinary ABI-preserving normal return, it reads the **post-helper** object dword at +0 and prepares:

```text
RDI = object
RSI = 0x449912 -> bytes 22 25 73 22 3a 25 73 00  ("%s":%s\\0)
RDX = saved incoming string pointer (here, "info")
RCX = empty string at 0x4376fd if dword[object] == 1,
      otherwise one space at 0x433058
AL = 0
call 0x63d3bd3
byte[object+0x1d] = 1
return through the ordinary epilogue
```

CMP flags survive the intervening MOV/LEA instructions until CMOVE at `0x63d3d4c`. Thus the suffix selection depends on the object after the first opaque helper; it is not guaranteed by the producer's earlier initialization to1. AL=0 is an observed varargs-like convention preparation, not an inferred Rust formatting ABI. The final byte store occurs after normal return from the second helper; it is not asserted on exceptions.

The format and argument bindings support a JSON-like key interpretation. Actual formatting/output is delegated to `0x63d3bd3`, and the first helper may change object state. Their bodies, callback effects, successful serialization, escaping, I/O, arbitrary input grammar, CLI dispatch and original library identity remain unclosed. No concrete output bytes are claimed to have been produced. The evidence specifically replaces the previous unanswered local-use question with measured argument flow.

## Reproduce and controls

From repository root, choose a new directory and installed native tools:

```sh
python3.11 -B research/work-items/RE-012-node115-info-key-consumption/collect.py \
  --output work/info-key-fresh --objdump "$OBJDUMP" --readelf "$READELF"
```

Observed macOS arm64, Python3.11.15, Apple LLVM21.0.0, GNU readelf2.45; exact banners in `validation.json`. Complete input authentication precedes output/native tools, which read a private byte-identical snapshot. Exported bytes and uninterrupted owner coverage are checked against that authenticated image. Only native path labels and surplus terminal newlines are normalized. Two captures reproduced all six outputs exactly.

**27 below-identity controls actually ran:** 19 instruction pins, five selected-data locks, two FDE extents and one parsed relocation-binding lock. They bypass the public image hash to reach the stated obligation checks. They are static operand/data/boundary controls, not arbitrary-byte completeness, execution or string-formatter correctness tests. The one retained relocation belongs to a separate context-table reference in the large owner; the `info` pointer and format strings themselves are direct RIP-addressed, not assigned fabricated relocation writers.

**This contribution remains DRAFT: required full-suite validation is unrun and unmet.** Current default tests include captured-instruction evaluation outside this task's static-only authorization. A maintainer must arrange compliant remaining validation or obtain further authorization before readiness. New-base doctor/verify passed, base catalogue-check was already stale, and separate reproduce passed; integration generation/check results are recorded separately. No tests/workflows are changed to sidestep the full gate.

No captured execution, instruction evaluator, real formatter callback, target file/network action, independent Rust implementation, full owner behavior, source-built node or gate completion is claimed. Next: close the `0x63d3bd3` formatter/callback boundary and establish licensed source provenance before attributing the containing owner to a particular dependency or runtime output API.
