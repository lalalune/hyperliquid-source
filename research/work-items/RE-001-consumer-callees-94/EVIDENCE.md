# RE-001: bound the five callee addends reached from node #94 0x1455c00

- Component ID: none (binary-wide function-map input; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: hyperliquid-source
  `1f8c67c63ca4794c9689235471c60297f8a5c985`; can1357-hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23` (not consulted)
- Claim status: observation (extent, bytes, targets); allocator/panic labelling is
  inference and the high-level names remain unresolved
- Scope included: the five RELATIVE `.text` addends referenced by the eleven
  indirect operands of `0x1455c00` (PR #634): `0x54c8cb0`, `0x1346068`,
  `0x54c06b0`, `0x13460a0`, `0x157b480`. Scope excluded: the other addends'
  callees, semantics, Rust code, runtime execution, gates.

## Reproduce

Windows 11, Python 3.12.10, UTF-8 I/O forced, repository root:

```text
python tools/consumer_callees.py --check research/work-items/RE-001-consumer-callees-94/records.json
python -m unittest discover -s tests -p test_consumer_callees.py -v
```

`records.json` SHA-256 is
`5ecba323d4bad1cb3d61c113c51b5de89db2f7b41a3ff3c6ee649d38c570f406`.
The tool writes canonical JSON as bytes, so output is host-newline independent.
Static only; no captured byte is executed.

## Evidence

Coordinates are linked VAs; `.text` file offset is `va - 0x1000`.

| Start | Extent | Bytes | Body SHA-256 |
| --- | --- | ---: | --- |
| `0x54c8cb0` | `..0x54c8d55` | 165 | `ea8a7868fe44b325da67aac39a27ef77319e7ee05ada7ed6511185542383031d` |
| `0x1346068` | `..0x134607d` | 21 | `a0b0476b2d7d6e58123f84746eabc3bde1ea44130284dc59da7095f6e23df735` |
| `0x54c06b0` | `..0x54c0772` | 194 | `aded10ad2306f8170a39cdab2d13d3a4851893640f9902955db8e78c50d9c949` |
| `0x13460a0` | `..0x13460fb` | 91 | `4109d7360fd82d203c1691c5d459d526aa0f75e9f993c240d3a31c0c2c1e7416` |
| `0x157b480` | `..0x157b499` | 25 | `1942fe4d3c3a14b88f1cc4ad4a627f2c97b5bd6983d5ba6a77dfd50fb8e395e6` |

All five are FDE starts. Pinned observations:

- **`0x54c8cb0`** (`endbr64`): `cmp rsi,0x1000` then `ja` to a slow tail; `test
  edx,edx` + `jne`; `test edi,0xfff`; two RIP LEAs into `.bss`
  `0x59afd00` and `0x59aff40` (SHT_NOBITS, type 8, not file-backed; operand rows
  record the target section name/type/file-backed flag and no table contents are
  read here); TLS reads through `fs:[-0x10a0 + ...]`. This is
  **inferred** to be an allocator deallocate-shaped entry (pointer in `rdi`, size
  in `rsi`, alignment in `edx`); the allocation API name is not proven.
- **`0x54c06b0`** (`endbr64`): `cmp rdi,0x1000` then `ja`; the same two table
  LEAs and TLS reads, with size in `rdi`. Inferred allocator allocate-shaped
  entry; name not proven.
- **`0x1346068`** (21 bytes): `test rdi,rdi`; `jne +6` skips the first call when
  the pointer is nonzero. A zero pointer falls through to `call [0x576e0c0]` ??  `0x1346080` and then `call [0x576e020]` ??`0x1345e2a`; a nonzero pointer jumps
  straight to the second. Both slots are `R_X86_64_RELATIVE` and both targets are
  FDE starts.
- **`0x13460a0`** (91 bytes): computes `max(2*x, 8)` (`cmp rax,9`; `cmovae`), then
  calls `0x1346100` with `rdi=&stack`, `rsi=[arg]`, `rdx=[arg+8]`, `rcx=max`.
  It tests `dword [rbp-0x28] == 1` after the call.
- **`0x157b480`** (25 bytes): `lea rdi,[0x252cf8]`, `mov esi,0x39`, tail call
  `[0x576e098]` ??`0x157b810`. Bytes at `0x252cf8` begin
  `attempt to add with overflow`; the immediate `0x39` covers the start of that
  contiguous message blob. The call's exact message/length semantics are unknown.

Byte `E8` candidates inside the bodies (explicitly not a decoded census):
`0x54c8cb0` 1 (`0x54c8ce5`), `0x54c06b0` 1 (`0x54c06d5`), `0x13460a0` 2
(`0x13460ce` real, `0x13460f4` not an instruction), `0x1346068` 0,
`0x157b480` 0. The two false positives are immediate bytes; no native decode was
performed in this packet, so no call count is published.

## Implementation and comparison

No Rust path and no Cargo build. The record is derived only from pinned bytes;
tests bypass the digest gate only to feed mutated copies to the same checks.
Nine tests cover the complete record, committed bytes, digest rejection, size
threshold, RELATIVE addend retarget, direct-call retarget, RIP-LEA retarget and
hash-seed determinism.

## Results and limitations

- Five extents, one direct call, six pinned RIP targets and two GOT bindings
  reproduce byte-for-byte; `--check` passes.
- No decoded instruction coverage, allocator/panic API naming, callee closure of
  `0x1345e2a`/`0x1346080`/`0x1346100`/`0x157b810`, runtime reachability or
  component gate is claimed. The `.bss` targets `0x59afd00`/`0x59aff40` (NOBITS)
  have unread contents.
- The `E8` rows are byte-pattern evidence and include known non-instructions.

Next question: decode `0x1346100` and `0x157b810`, and read the
`0x59afd00`/`0x59aff40` table contents, before assigning allocator or panic
names.

