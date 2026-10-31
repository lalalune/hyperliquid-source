# RE-001 / foundation: build-mode-linked name routing

Bounded question: how do the raw mode/flag bytes and the exact name
`run-client` select paths in this source-linked node94 function?

Input `artifacts/node/94/hl-node`: 91774280bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Independent main base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
The exact FDE interval `0x13cd410..0x13cd6cb` is 699bytes; end exclusive.
VA/file-offset mapping, range hash and bytes of every control/literal are in
`observed/records.json`; raw AT&T disassembly, FDE row and RELA row accompany it.

Source attribution: Location slot `0x566a0c0` has RELATIVE addend `0x200676`,
whose bytes are `/home/ubuntu/hl/code_Mainnet/base/src/build_mode.rs`.
This embedded upstream path is target evidence. Inferred reference revision
`999556f6e0a474b8312db96ec3149e1c44e97c23` is pinned but no implementation,
comments or labels from its unlicensed source are copied into this packet.

## Observations

- `0x13cd428..42f`: EAX receives R8D, AL is ORed with CL; zero branches to
  `0x13cd47e`. That route copies the provided name bytes (with explicit
  zero-length/allocation branches), then writes result byte+0x18=0.
- When that OR is nonzero, length must equal10 before comparisons with
  immediate bytes `run-clie` and `nt`. Exact `run-client` branches to
  `0x13cd596`, bypassing the later CL discriminant check and producing a
  separate formatting path, which also joins result byte+0x18=0.
- Other names reach CL comparisons. CL=1 selects five bytes `debug` at
  `0x2194d5`; CL=2 selects seven bytes `release` at `0x2194da`. Other raw CL
  values branch to diagnostic construction at `0x13cd636`, bound to the
  source Location. The complete panic/helper behavior is not reconstructed.
- The debug/release route calls formatting helpers and writes result
  byte+0x18=1 at `0x13cd54d`. Its complete name format and return ABI remain
  unknown; the two result byte values are observations, not a recovered enum.

## Inferences and unknowns

The source-linked path supports a mode-dependent name transformation with a
literal client exception. It does not establish all valid Rust mode/flag
combinations, a complete BuildMode enum, complete command-line syntax, startup,
global construction, full formatting descriptors or helper/allocator closure.
For example, raw CL=0 with nonzero R8B and a non-client name reaches the later
diagnostic; we do not silently treat every raw pair as a legal typed input.
No complete output string or executable command is claimed. No command/node
is run, no Rust code is reconstructed, and all component gates stay false.

## Reproduction

Ubuntu24.04/WSL2, Python3.12.3, GNU binutils2.42, default AT&T.

```text
make doctor verify test catalogue-check reproduce
python3 tools/build_mode_route_static.py
python3 tools/build_mode_route_static.py --output work/repeat
diff -ru work/buildmode-94 work/repeat
```

The producer authenticates full size/digest before local obligations, checks
exact FDE and source binding, and exports bounded instructions. Six tests
cover eight real instruction corruptions, two literal corruptions, actual
source relocation retargeting, exact client name/length variants, decoded
mode comparison and branch destinations, and both result-tag stores.
Corruption controls run below the complete-input identity gate. Local byte
predicates are not target executions or whole-function equivalence tests.

Required checks passed: 437 tests in 152.262 seconds. All four producer exports match
an author rerun byte-for-byte; not independent peer review. Eight identities,
three signatures,37imports and seven pins unchanged. Analysis ready,exact
rebuild unavailable. `required-checks.log` masks local checkout/tool prefixes
and normalizes CRLF toLF; raw disassembly/frame/relocation exports unchanged.
No generated catalogue/progress, imported evidence, pin or gate changes.
No target/emulator execution, Rust build, runtime equivalence or hostedCI claim.
Next close the formatting descriptors and typed caller inputs before implementing
the transformation or asserting its exact string output.
