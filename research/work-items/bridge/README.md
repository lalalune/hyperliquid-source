# bridge: requestWithdrawal payload hash and signature chain-id selection (node #94)

- Component ID: `bridge` (path rules `l1/bridge2.rs`, `l1/bridge_request.rs`)
- Target release and full SHA-256: `hl-node` #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `6fb86319763b30860f92b9da746cbe4f9b637573`;
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation, with every inference labelled; no acceptance gate claimed
- Scope included and excluded: included are two bounded byte-level questions for
  #94 — how the `requestWithdrawal` payload hash arm is selected and what bytes it
  hashes, and what the inlined signature-chain-id selection computes at the two
  request-building sites. Excluded are `bridge2.rs` state accounting, deposit
  pruning, validator-set votes, nonce lifecycle, signing, serialization of the
  whole `BridgeRequest`, and any execution of the binary.

Task ID `bridge` is new; `docs/TASKS.md` lists bridge only as an extra area, so
nothing in the ready queue is claimed twice. No `Makefile`, catalogue or progress
file is touched ("no gate change").

## Reproduce

All commands run from the repository root on macOS 26.4.1/arm64, offline, with
no captured binary executed.

```sh
python3.12 tools/bridge_inventory.py --out research/work-items/bridge/evidence
```

The tool checks the artifact SHA-256 before parsing, converts between linked VAs
and file offsets through the program headers, and fails on any deviation. It
writes `evidence/bridge-inventory.json` plus the raw excerpt files. Disassembly
excerpts beside this record were produced with Apple LLVM `objdump` 17.0.0:

```sh
objdump -d --start-address=<start> --stop-address=<end> artifacts/node/94/hl-node
```

`evidence/MANIFEST.sha256` pins every retained file; check it from this
directory with `shasum -a 256 -c evidence/MANIFEST.sha256`; its packet-file
entries are also checked by `tests/test_bridge_inventory.py`. Tool inputs are only
`artifacts/node/94/hl-node` and the unwind table parser `tools/elf_index.py`
(`.eh_frame_hdr` only, for function boundaries).

Coordinate system: addresses below are linked virtual addresses (VA). In the
executable segment VA = file offset + `0x1000`; in `.rodata` VA = file offset.
Both values are in the JSON for every reported site.

## Evidence

### Function boundaries

| region | FDE start | next FDE start | note |
| --- | --- | --- | --- |
| field encoder (`struct_hash`) | `0x358de50` | `0x358ea60` | 8-arm dispatch on the payload discriminant |
| request construction (`bridge_request`) | `0x358ea60` | `0x358ed20` | calls the encoder, writes tag, selects chain id |
| action-field state machine | `0x22ae8a0` | `0x22b1080` | inlines the same construction at `0x22af640` |
| shared request builder | `0x3341af0` | `0x3342190` | second inlined chain-id site |

Unwind starts are boundaries, not proven body extents; the three bodies are
large and only the cited windows were decoded.

### `requestWithdrawal` literal and its single xref

- Literal `requestWithdrawal`, 17 bytes, VA/offset `0x595072`, SHA-256
  `0206b4c6b001b408531c6f009ef9c90d45a7c76ed5a6b8cc2f046728cedf36a8`.
  One occurrence in the whole file (`evidence/bridge-inventory.json`,
  `literal_occurrences: 1`).
- One RIP-relative reference, `movups 0x595072(%rip),%xmm0` at VA `0x358e42c`
  (file `0x358d42c`, bytes `0f 10 05 3f 6c 00 fd`), followed by
  `movb $0x6c,0x10(%rax)` at `0x358e436`, which appends the 17th byte `l`.
- The referencing arm is reached only from the 8-entry table at `0x58f650`
  (index 5, target `0x358e40d`). Table and literal map: `tables.txt`.

### Field extraction in the withdrawal arm

`0x358e40d`..`0x358e4b0` (`disasm/02-request-withdrawal-arm.txt`) loads, from the
payload pointer in `%r12`:

| field | source offset | width | copy |
| --- | --- | --- | --- |
| account | `+0x01` | 20 | `movups` + `movl` |
| destination | `+0x15` | 20 | `movups` + `movl` |
| amount | `+0x30` | 8 | `movq %r14` |
| nonce | `+0x38` | 8 | `movq %r15` |

The arm then calls the encoder `0x3c9a570` with a five-slot value slice. That
encoder (`disasm/03-withdrawal-field-encoder.txt`) allocates `0xc8` bytes
(5 × `0x28`), writes tags `6,0,0,4,4` at slots 0..4 — string, address, address,
uint64, uint64 — and passes the 200-byte buffer to the generic finisher
`0x1592160`. Slot order matches the literal followed by account, destination,
amount, nonce.

### Signature chain-id selection

Three identical inlined sequences exist; all compare the chain discriminant with
`3` and conditionally move the mainnet id:

| site VA | bytes | compared | result |
| --- | --- | --- | --- |
| `0x22af76e` (seeded, offset `0x22ae76e`) | `41 80 ff 03 b8 b1 a4 00 00 b9 ee 6e 06 00 48 0f 44 c8` | `%r15b` | `%rcx = 42161` if equal, else `421614` |
| `0x3341cb9` (shared builder) | `40 80 fd 03 b8 b1 a4 00 00 41 be ee 6e 06 00 4c 0f 44 f0` | `%bpl` | `%r14` |
| `0x358ec6b` (request construction) | `40 80 fd 03 c6 00 61 b9 b1 a4 00 00 ba ee 6e 06 00 48 0f 44 d1` | `%bpl` | `%rdx` |

`42161 = 0xa4b1` is Arbitrum One, `421614 = 0x66eee` is Arbitrum Sepolia. The
comparison value is `3`, the fourth variant of the `Chain` enum; the binary
carries the serde names `enum Chain` and `LocalSandboxTestnetMainnet`, and
`variant identifier` nearby, which fixes the order without relying on the
reference tree.

At `0x358ec5b`..`0x358ec7c` (`disasm/04-bridge-request-tag-and-chain.txt`) the
construction is explicit: `__rust_alloc(1)`, `movb $0x61,(%rax)` (ASCII `a`),
then the chain selection, then the byte is stored as a one-element buffer.

### Source attribution

`l1/bridge_request.rs` in the pinned reference supplies the variant order
(`RequestWithdrawal = 5`), the four field names and the `b'a'` tag. All of those
were re-checked against the bytes above; the reference labels in
`bridge-inventory.json` (`reference_label`) remain leads, not authority. No
reference code was copied.

## Implementation and comparison

No Rust implementation and no Cargo manifest are added, so there are no
raw-equal/normalized body counts. The reference tree has no manifest and the
build provenance task (RE-002) is still open; a one-file crate with an invented
dependency set would overstate the evidence.

What the next implementation must satisfy, from the bytes above: payload
discriminant `5` selects the arm; the hashed word sequence is the 17-byte literal,
account, destination, amount, nonce, each padded per the finisher at `0x1592160`;
the request tag is `0x61`; the signature chain id is `42161` only for chain
discriminant `3` and `421614` for every other value. Boundary cases not yet
measured: chain discriminants above `3`, and the `Reserved = 6` arm. That arm
calls `0x37db0d0` through RELATIVE slot `0x5775da0` (`ff 15` at `0x358e592`),
writes the 6-byte name `unlock` from immediates (`0x358e634`/`0x358e63a`, so no
RIP-relative literal load), direct-calls only `0x3c9f240` (`0x358e6e5`) and ends
at `jmp 0x358e920` (`0x358e7af`).

Arm extents: each arm runs to the next arm target, except arm 6, which is last
and ends at that `jmp`, and arm 7 (`InvalidateWithdrawals`), which also owns the
continuation `0x358e7b4..0x358e85b`. Arm 7 reaches it only through `je` at
`0x358e2b6`; it clones the payload's vector of 32-byte elements, stores the
0x15-byte `invalidateWithdrawals` name buffer (filled in arm 7 from `0x595083`)
and calls the encoder `0x3c97be0` at `0x358e856`. The recorded continuation
stops at that call: arm 7 then falls through its own copy of the hash tail to
`0x358e920`, a range with no `e8` calls or RIP-relative literal loads. An
earlier revision scanned arm 6 over a
fixed `0x300` bytes, which ran into this block and credited `0x3c97be0` to
`Reserved` instead of `InvalidateWithdrawals`.

## Results and limitations

Machine-readable metrics, with denominators:

- literal occurrences found: `1/1`; xrefs resolved to it: `1/1`.
- dispatch arms resolved to a target inside the function: `8/8`; arms whose
  literal is loaded in place: `5/8` (1, 2, 3, 5, 7); arm 0 composes `modify` +
  role through `0x1344760`; arm 4 delegates to `0x37db5d0` and jumps to the
  epilogue `0x358e946`; arm 6 calls `0x37db0d0` through the GOT, then hashes
  `unlock` through `0x3c9f240`.
- chain-id sites decoded with matching operands: `3/3`.
- withdrawal-arm field copies pinned: `4/4`; encoder tags pinned: `5/5`.
- function bodies proven complete: `0/3`; the dispatch tables at `0x3d6518` and
  `0x3d6528` inside `0x22ae8a0` were only sampled.

Unknown or unresolved: the exact Rust type names and the 0x88-byte and
0x117-byte structures built around the sites; whether the three chain-id sites
come from one generic function or from duplicated code; the `Reserved` arm
semantics; the finisher's internal word layout (tags are read from the bytes, the
padding rule is inferred from `0x1592460`/`0x15924e0`); and the serializer that
turns the request into the 117-byte buffer. Nothing here proves equivalence, and
no gate is requested.

Corruption control: changing one byte of the artifact, the literal or the
jump-table entries makes `tools/bridge_inventory.py` fail (see
`tests/test_bridge_inventory.py`).

Next question: decode the `0x1592160` finisher's per-tag word rules and the
`0x22b0274` cleanup path, to establish whether the 117-byte buffer is a
`bincode`-style framing of the same five fields.
