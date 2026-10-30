# RE-001: node94 API suffix dispatch and caller binding

- Component: `foundation`; bounded function/data attribution, no progress gate.
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`, `base/api_url.rs` supplied address leads only. No inferred implementation was copied, compiled, or treated as authoritative.
- Question: does the actual #94 extent at `0x1450ae0` dispatch the API suffix cases, and what data/caller/source bindings support that attribution?
- Status: instruction/data observations below; type/variant/function names remain inferences.

## Reproduce

Repository root, materialized pinned LFS inputs and submodules. Python 3.12.14,
GNU objdump/readelf 2.47.20260726 on macOS 26.4 arm64. Python checker uses only
standard library plus existing repository parsers. No captured executable runs.

```sh
python3 -B tools/api_suffix_static.py --output work/api-suffix-94
python3 -B tests/test_api_suffix_static.py
cmp work/api-suffix-94/records.json research/work-items/RE-001-api-suffix-dispatch-94/records.json
cmp work/api-suffix-94/function.objdump.txt research/work-items/RE-001-api-suffix-dispatch-94/function.objdump.txt
make doctor
make verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-api-suffix-dispatch-94/MANIFEST.sha256
```

The checker reads/authenticates one input snapshot and supplies a private copy
of those same bytes to both external decoders. Raw disassembly is retained;
all control addresses must be decoded instruction starts. Two FDE ranges are
independently checked with GNU readelf. An additional observed Capstone 5.0.6
cross-check decoded 232 instructions covering all 1,052 bytes and confirmed
all callee control/RIP-reference starts. Capstone is not a runtime requirement.
Setup used task-local verified official native tool bottles; GPG checks use
an isolated public-key home with `--no-autostart`, never a personal keyring.

## Observations

All addresses here and in `records.json` are linked ELF virtual addresses;
each retained byte binding also supplies its exact source-file offset.
No guessed loader/Ghidra base is applied.

- The FDE describes `[0x1450ae0, 0x1450efc)`, 1,052 bytes. Retained raw body
  SHA-256: `29afd0fc30640c79b9c0966c3848fcd746d71743c9883cead54c77086d378ce0`.
  The shared prologue reads `[rsi]`; instructions at `0x1450af1` subtract 2,
  compare the low 16-bit tag to 2, choose index 5 for tags 0/1, and use the
  adjusted low 16 bits otherwise. This packet interprets only observed valid
  tags 0..6, not invalid-enum inputs or a complete source-level enum layout.
- The signed-offset table at `0x219998` has six checked arm starts. Tags 2,
  3, 4, 5, 6 select `0x1450b17`, `0x1450db5`, `0x1450b97`, `0x1450c92`,
  `0x1450b5b`; tags 0/1 share `0x1450df3`. Denominator: seven tag cases,
  six selected arms in this one extent; not a whole-node function census.
- Three arms allocate/store lengths 24, 32 and 18 and copy the exact suffixes
  `s://api.hyperliquid.xyz/`, `s://api.hyperliquid-testnet.xyz/` and
  `://localhost:3001/`. The first combines a 16-byte pool load with an
  eight-byte immediate; the second copies two 16-byte chunks; the third uses
  a 16-byte load plus a two-byte immediate. Both capacity and length stores
  are checked. These observations are stronger than a string occurrence.
- Two other arms load the same relocated global at GOT slot `0x576eb70`
  (`R_X86_64_RELATIVE` addend `0x577a898`) and compare lengths 10/16 against
  `WebSandbox` / `WebSandboxPublic`. The common selected value load at
  `0x1450d84` is a 32-bit load from `[rax+rbx*4+0x110]`, passed through
  formatter callback slot `0x576f6d0` (addend `0x157c730`). Its exact type,
  map contents and callback behavior remain unproved.
- The tag-0/1 arm supplies callback `0x14791a0` and descriptor bytes at
  `0x1f7555`. The descriptor contains `://` and `/`. The map arm supplies
  descriptor `0x1e4df8`, containing `://` and `:3001/`. These compact formatter
  bytes are recorded without claiming a recovered formatter interpreter.
  **The two map keys converge on the same descriptor path in this target.**
  The reference's separate `WebSandboxPublic => "://{ip}/"` narrative is
  therefore not supported by these branches; complete output still needs
  formatter/helper recovery. No reference code is edited.
- The shared lookup failure at `0x1450eba` references Location slot
  `0x566ab28`. Applying its RELA addend gives source path VA `0x1ecd56`,
  length 48, line 90, column 38: the captured build's `base/src/api_url.rs`.
  The on-disk pointer is zero before relocation; it is never interpreted as
  a literal unrelocated address.
- Actual caller instruction `0x2272d10` calls this extent directly. It is
  inside FDE `[0x2272c80, 0x2275a07)`. The next formatting setup references
  compact descriptor `0x2006b7` containing `http`, then calls through slot
  `0x576e040` (RELA addend `0x1344760`). This establishes a concrete caller
  and data edge, not all possible callers or a transitive equivalence claim.

## Controls and limits

Five tests cover the actual capture, deterministic native regeneration, wrong
input admission and ten in-memory corruption cases: selector, table entry,
allocation length, literal, callback target, caller displacement, caller
formatter bytes, source line, shared-arm convergence and FDE end. Semantic corruption tests run below
the whole-file digest gate so they exercise structural checks rather than
only SHA rejection. The actual original files remain unchanged.

No Rust implementation, build comparison, normalized/raw match denominator,
helper closure, live endpoint request, or runtime output is claimed. All
component gates stay false. The concrete next question is the selected map
value formatter at `0x157c730`, including its type and formatting behavior;
that must be recovered before asserting exact dynamic URL outputs.
