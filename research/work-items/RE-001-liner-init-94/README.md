# RE-001 / foundation: liner initializer's sentinel and failure routes

Question: how does this source-linked initializer use its first helper result,
and which object fields are written before returning? This is static partial
RE-001 mapping, not recovery of line I/O or a completed component.

Input `artifacts/node/94/hl-node`:91774280bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Exact FDE `0x13d1720..0x13d1876`:342bytes, exclusive end.
The evidence records linked VAs,file offsets,range hash,raw instructions,
FDE row,literals and actual relocation records separately.

Location slot `0x5666e20` RELATIVE-addend `0x1ecbbe` identifies
`/home/ubuntu/hl/code_Mainnet/base/src/liner.rs`. This path is an embedded
target string. No source/comments/implementation from the unlicensed reference
at pinned `999556f6e0a474b8312db96ec3149e1c44e97c23` are copied.

## Observed path

1. The initializer loads input+8 and input+0x10, passes them to the indirect
   call at `0x13d1741`, and tests RAX. Actual RELA slot `0x576ea68` resolves to
   `0x144c180`; its complete helper behavior and syscall effects remain open.
2. Zero result falls through to store `0x8000000000000000` at stack+0 and
   continues at `0x13d175a`. Nonzero branches to `0x13d17b7`: RAX is saved
   for diagnostic construction, the 43bytes at `0x216f9d` read
   `called Result::unwrap() on an Err value` with literal backticks around
   `Result::unwrap()` and `Err`, and the route ends in an indirect call/`ud2`.
   The actual embedded literal bytes are retained without prose normalization.
3. The normal route loads global pointer slot `0x576eac8`, whose actual RELA
   addend is `0x577a888`. A nonzero dword at global+8 calls a separate helper
   and rejoins; otherwise it loads the binary64 word at global+0 directly.
   No default numeric value, unit or complete lazy-initialization ABI is claimed.
4. Output+0,+8,+0x10 receive preserved input fields. Output+0x18,+0x20,+0x28
   receive words from the stack aggregate. Output+0x38 receives the global
   binary64 value; output+0x40 is reset to dword zero, then output is returned.

The MIN-i64 word is a visible representation sentinel, not sufficient proof
of a complete Rust Option/Result/string/stream layout. Other stack payload
words copied on that route are not established as semantically active or
initialized values by this packet. Their presence does not itself demonstrate
undefined behavior or a runtime defect. Role names such as initializer/error
are interpretations supported by the call pattern and source literal.

## Reproduce and validate

Ubuntu24.04/WSL2,Python3.12.3,GNU readelf/objdump2.42(default AT&T).

```text
make doctor verify test catalogue-check reproduce
python3 tools/liner_init_static.py
python3 tools/liner_init_static.py --output work/repeat
diff -ru work/liner-94 work/repeat
```

The collector first verifies complete size/SHA identity. Five instruction
control ranges, two literals and three RELA bindings are independently checked;
raw disassembly is bounded by the exact FDE. Six tests include actual byte
corruptions for all five ranges/two literals, three RELA retargets, independent
branch/sentinel decoding, output-field writes and diagnostic terminator checks.
Local corruptions run below the whole-input gate to exercise those obligations.

Required checks passed: 437 tests in 151.712 seconds. Four producer exports match an
author repeat byte-for-byte; not independent peer review. Eight artifact
identities,three signatures,37imports and seven pins unchanged. Analysis ready,
exact rebuild unavailable. Logs mask local checkout/tool prefixes and normalize
CRLF toLF; raw instruction/frame/relocation exports unchanged. No generated
progress/catalogue,input,pin or component-gate changes.

No captured target/emulator execution,syscall/open-flag proof,line writing,
flush/concurrency closure,Rust build,runtime equivalence or hostedCI claim.
Next close helper `0x144c180`, caller types and active/inactive aggregate fields
before reconstructing the initializer or claiming actual filesystem behavior.
