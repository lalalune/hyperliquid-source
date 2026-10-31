# RE-001: two downstream callees of node #94 0x1455c00

- Component ID: none (binary-wide function-map input; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: hyperliquid-source
  `1f8c67c63ca4794c9689235471c60297f8a5c985`; can1357-hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23` (not consulted)
- Claim status: observation (extent, bytes, targets); names and semantics remain
  unresolved
- Scope included: the next hop from `0x1455c00`'s direct callee `0x13460a0`
  (`0x1346100`) and from its RELATIVE callee `0x157b480`
  (`0x157b810`). Scope excluded: the remaining call graph, Rust code, runtime
  behavior, gates.

## Reproduce

Windows 11, Python 3.12.10, UTF-8 I/O forced, repository root:

```text
python tools/consumer_downstream.py --check research/work-items/RE-001-consumer-downstream-94/records.json
python -m unittest discover -s tests -p test_consumer_downstream.py -v
```

`records.json` SHA-256 is
`884c1413e5942e6415fc7a864be44e8ccf534583ad36056aca3bcf9714f542ae`.
The tool writes canonical JSON as bytes; no captured byte is executed.

## Evidence

Coordinates are linked VAs; `.text` file offset is `va - 0x1000`.

| Start | Extent | Bytes | Body SHA-256 |
| --- | --- | ---: | --- |
| `0x1346100` | `..0x1346182` | 130 | `028214f931986a61ecaa3537133dab36a7c8f9bbd4500bf55e7ca0beca951985` |
| `0x157b810` | `..0x157b83c` | 44 | `98af620ef076f19db307230ab8e3d5a55a0c8ef100f37d95bb117537bb7b5777` |

Both are FDE starts. Pinned observations:

- **`0x1346100`** (130 bytes): prologue saves r15/r14/rbx and rax; `mov rbx,rdi`;
  `mov r15d,1`; `test rcx,rcx`; `jns +0xa` else `eax=8`, `r14d=0`. Two indirect
  calls: `[0x576e030]` → `0x54c5620` and `[0x576dfd8]` → `0x54c06b0`. The second
  target is the allocator-shaped shim recorded in
  `RE-001-consumer-callees-94`; that shape is not re-claimed here.
- **`0x157b810`** (44 bytes): stores `rdi` at `[rbp-0x10]`, `rsi` at `[rbp-8]`,
  `rdx` at `[rbp-0x20]`, `&[rbp-0x10]` at `[rbp-0x28]` and the word `1` at
  `[rbp-0x18]`, then calls `[0x57706e0]` → `0x4ecdcf0`. The stored layout is an
  observation, not a claimed ABI type.
- Both slots are `R_X86_64_RELATIVE` and both targets are FDE starts.

Byte `E8` candidates inside the bodies: `0x1346100` 0, `0x157b810` 1. The single
`0x157b810` candidate is not a call instruction; no decoded call census is
published.

## Implementation and comparison

No Rust path and no Cargo build. The record is derived only from pinned bytes;
tests bypass the digest gate only to feed mutated copies into the same checks.
Eight tests cover the complete record, committed bytes, digest rejection, an
anchor immediate, RELATIVE addend retarget, RIP-operand retarget and hash-seed
determinism.

## Results and limitations

- Two extents, two anchors sets and three RELATIVE bindings reproduce
  byte-for-byte; `--check` passes.
- No decoded coverage, callee closure of `0x54c5620`/`0x54c06b0`/`0x4ecdcf0`,
  semantic naming, runtime reachability or component gate is claimed.
- The `E8` rows are byte-pattern evidence; one is a known non-instruction.

Next question: decode `0x54c5620` and `0x4ecdcf0`, and compare the
`0x157b810` stored layout with the `core::fmt` argument record before assigning
a formatter/panic API.
