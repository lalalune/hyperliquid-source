# RE-015: reconstruct the node #115 user-signed action msgpack encoders, keyed field helpers and newtype tuples

**What this makes reconstructable:** the MessagePack (rmp-serde) path that node #115 uses to encode EIP-712
user-signed actions can now be rebuilt from this record, from the action body down to the leaf writers. A
pure-Python encoder reproduces the exact output bytes, the exact 24-byte result record and every error exit of:

- 17 action bodies that carry `signatureChainId` and `hyperliquidChain` (SendAsset, UsdSend, SpotSend,
  ApproveAgent, UserSetAbstraction, the vote action and the other `user`/`tradingUser` bodies)
- the six keyed `serialize_field` helpers those bodies call (`amount`, `gasLimit`, `destinationChainId`,
  `addressEncoding`, `abstraction`, `data`/`Unvalidated`) and three copies of them
- 17 `serialize_newtype_struct` bodies of the same serializer, with the `_ExtStruct` reserved-name gate and their
  string, integer, address and 2-tuple payloads

The three bodies that call five of the helpers were also run end to end with the helpers' real bytes: the
action-body model and the helper model, composed, predict the bytes of the whole path. The models are checked
against the machine code (interpreted by a concrete x86-64 evaluator; the binary is never executed) in
**45,080 cases with 0 mismatches**, and **190/190 negative controls** (wrong models and corrupted
code bytes) are detected.

- Component ID: `constants` (RE-015 global settings and string references). The action bodies are the callers of
  the `hyperliquidChain` serializer `0x2674b80` reconstructed in `RE-015-chain-codec-115`; the helpers and newtype
  bodies are the rmp writers under them.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: written against main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No reference
  source was used: keys, names and messages come from the immediates and `.rodata` bytes the bodies use.
- Claim status:
  - observation: every byte-level behaviour the tool compares, and the immediates, jump table, key bytes and
    message pointers it reads from the ELF
  - inference: the Rust-level reading (serde `Serialize` impls, `serialize_field`, rmp-serde
    `serialize_newtype_struct`, `Option<String>`, `[u8; 20]` addresses) and the action names, which are taken
    from the keys the bodies write
  - unresolved: listed under "Results and limitations"
- Scope included (all extents from `.eh_frame` FDEs through `tools/fde_extents.py`):
  - signed-action layer: 17 bodies `0x2406120`, `0x2407270`, `0x2407d40`, `0x2408af0`, `0x240ad50`, `0x240ba90`,
    `0x240d140`, `0x240dec0`, `0x240f270`, `0x2410010`, `0x24119f0`, `0x2412830`, `0x2413110`, `0x2d3c1b0`,
    `0x2d3df10`, `0x2d3ea40`, `0x2d400f0` (4,408 instructions)
  - field-helpers layer: `0x24599a0`, `0x2459290`, `0x24585c0`, `0x2458f40`, `0x24596c0`, `0x245b4b0` and the copies
    `0x44f67b0`, `0x44fb0c0`, `0x44fb870` (848 instructions), the jump table `0x5ed130` and the key bytes at
    `0x5ed63d` and `0x5f174d`
  - newtype-tuples layer: 17 bodies `0x226ca20`, `0x226d020`, `0x226e250`, `0x226e3e0`, `0x226f0a0`, `0x226f1e0`,
    `0x2272430`, `0x2274e80`, `0x2274fc0`, `0x2275170`, `0x2275d10`, `0x22767a0`, `0x2276c90`, `0x22771c0`,
    `0x2277a70`, `0x2277b70`, `0x2277cc0` (1,056 instructions)
  - flow layer: bodies `0x2407270`, `0x240dec0` and `0x240f270` with the helpers `0x24599a0`, `0x2459290`,
    `0x24585c0`, `0x2458f40` and `0x24596c0` running real
  - leaf writers that run for real as dependencies: rmp `write_str` `0x25e8bf0`/`0x25e8750`/`0x41c6610`,
    `write_uint` `0x25e9f10`/`0x25e9c70`/`0x3d51450`, array headers `0x25e7c10`/`0x25e7940`, `Compound::end`
    `0x22999e0`/`0x22997f0`, impl-serde `serialize_uint` `0x2631340`, `to_hex` `0x2eabb50` (GOT `0x64e4d08`), the
    chain serializer `0x2674b80`, the bool writer `0x226a340`, `Marker::to_u8` `0x25eab50`, `serialize_none`
    `0x226a3b0`, the keyed String field `0x24586c0`, the keyed u64 field `0x2459630` and the H160 writer `0x24a5850`
- Scope excluded:
  - contract stubs whose arguments are checked: RawVec reserve `0x231e050`/`0x43bd910`, memcpy, the newtype
    serializer `0x22781c0` (the `data` helper's tail-jump target), and in the action layer the helper
    `0x245a590`, which `action-wire-gov-vote-codec-115` already covers
  - the 34 sibling copies of the action bodies (`0x44bxxxx`/`0x44cxxxx`, `0x53xxxxx`/`0x59xxxxx`), the
    `0x59dxxxx` helper copies listed in `RE-001-buffer-grow-963a10-115/callers.tsv`, and the other 565 `_ExtStruct`
    bodies of the binary
  - signing, hashing and the EIP-712 type strings; any #94 coordinates

## Reproduce

From the repository root (Python 3 standard library only; the tool imports `tools/elf_index.py` and
`tools/fde_extents.py`; it never runs the binary and calls no external program):

```
python3 tools/re015_signed_action_rmp_115.py --out research/work-items/RE-015-signed-action-rmp-encoders-115
python3 -m unittest tests.test_re015_signed_action_rmp_115
```

The tool checks the input SHA-256 first and fails on any other file. One full run evaluates 45,080 cases and
190 controls in about 300 s (Python 3.12.3). `--layer signed-action|field-helpers|newtype-tuples|flow`
regenerates one layer's files only. Two full runs, one with the default environment and one with
`PYTHONHASHSEED=12345`, `TZ=Asia/Kolkata` and `PATH=/nonexistent`, produced byte-identical folders. The output
digests are in `MANIFEST.sha256`. The case samples keep every 20th to 50th case; the tool regenerates the rest
from the bytes, and each layer's summary pins `outputs_sha256` over the output bytes and result record of every
case.

## Evidence

Coordinates are ELF virtual addresses of node #115. Code bytes come from `.text`, constants from `.rodata`
(never from SHT_NOBITS sections), GOT slots from `.rela.dyn` RELATIVE addends, extents from `.eh_frame`.

Evidence files (prefix = layer):

- `signed-action-bodies.tsv`, `signed-action-fields.tsv`: each body, its FDE extent, byte and instruction count,
  inferred action and every direct or GOT callee; one row per field with key, key mode, value kind, struct offset
  and value callees. The tool fails if a body calls outside the declared callee set or does not call `0x2674b80`.
- `field-helpers-helpers.tsv`, `field-helpers-abstraction-table.tsv`: each helper, its family (`a` = `0x24xxxxx`,
  `b` = `0x44fxxxx`), key, key test, value kind and callees; the five rel32 entries of the `0x24596c0` jump table
  at `0x5ed130` with the one-letter name each arm stores (`e i z u p`).
- `newtype-tuples-bodies.tsv`: each newtype body, its serializer layout, value shape, header rule and the
  `_ExtStruct` error message pointer and length.
- `flow-bodies.tsv`: the three action bodies that run with real helpers, the helpers they reach and the one still
  stubbed (`0x245b4b0`).
- `*-cases-sample.tsv`, `*-controls.tsv`, `*-coverage.tsv`, `*-summary.json` per layer, and `summary.json` with
  the totals.

Rules observed in the bytes and compared in every case:

1. **Action bodies (signed-action).** Header byte `((flag ^ 1) << 4) | 0x8n`: `0x80|n` in struct-map mode,
   `0x90|n` in array mode, with n = 1 + fields. The serializer flag is byte `+0x1b`. The tag key is written only in
   map mode; the variant name in both. Then `signatureChainId` (`"0x"` + lowercase hex without leading zeros;
   `"0x0"` for zero), `hyperliquidChain` (`Local/Sandbox/Testnet/Mainnet`), and the per-action fields: addresses
   `"0x"` + 40 hex digits, H256 ids `"0x"` + 64, smallest-form uints, fixstr/str8/str16 strings, `c2`/`c3` bools,
   `yes/no/abstain`, `Option<String>` None (`cap = 0x8000000000000000`) as `c0`. Keys appear only in map mode.
2. **Error exits.** write_str returns `rax = 2` for Ok, otherwise the body stores
   `{0x8000000000000000, rax, rdx}`; write_uint writes `[out] = 2` for Ok, otherwise
   `{0x8000000000000000, [out], [out+8]}`; every other fallible callee writes a 24-byte result whose Ok tag is
   `0x8000000000000004`, and the body copies a non-Ok result verbatim. Nothing is written after an error.
3. **Field helpers.** Five helpers write their key when serializer byte `+0x1b` is non-zero (`cmpb $0x0; je`);
   `0x245b4b0` writes `data` only when it equals 1 (`cmpb $0x1; jne`), so mode bytes 2, 0x80 and 0xff give a key
   from the other five but not from `data`. `amount` is `write_str(rdx, rcx)` (the action body passes the `&str`
   pointer and length from struct `+0x68`/`+0x70`); `gasLimit` is `write_uint(rdx)`; `destinationChainId` is
   `write_uint(edx)` (`mov %edx,%edx`: `2^32` encodes as `0x00`); `addressEncoding` writes `base58` only when
   `dl == 1`, else `hex`; `abstraction` takes its key from the caller (`"abstraction"` at `.rodata` `0x5ed60f`) and
   writes the one-letter name selected by the low byte of `r8` through the unchecked 5-entry jump table; `data`
   tail-jumps to `0x22781c0(out, ser, "Unvalidated", 11, rdx)`.
4. **Newtype bodies.** `cmp rcx, 0xa`, then `movabs 0x757274537478455f` and `0x7463` XOR the name: only the exact
   bytes `_ExtStruct` return `(0x8000000000000002, msg, len)` with `expected tuple` (14 bytes, single-value
   bodies) or `expected i8 and bytes` (21 bytes, tuple bodies). Layout a keeps the `Vec<u8>` inline (flag `+0x1c`),
   layout b holds `&mut Vec<u8>` (flag `+0xc`); each layout has its own leaf writers. Values: `str`, `u32`/`u8`
   (layout b's `write_uint` `0x25e9c70` is unsigned), `h160` (`0x` + 40 lowercase hex via the GOT formatter), and
   2-tuples behind a `0x92` header (`optstr2` with `c0` for None, `str2`, `u64x2`), closed by `Compound::end`,
   whose `neg rcx; jo` overflows exactly on the known-length tag and stores Ok without writing.
5. **Composition (flow).** With `0x24599a0`, `0x2459290`, `0x24585c0`, `0x2458f40` and `0x24596c0` running real
   inside their callers, each helper appends exactly the bytes the field-helpers model predicts for the arguments
   the signed-action model says the body passes (and the mode byte the body's serializer carries), returns the
   Ok triple, and leaves the body's own fault positions unchanged.

Readable excerpts (objdump, for humans only; not part of the generated files):

```
2406137: mov 0x40(%rdx),%r14          ; action body: serializer from the tagged context
240613b: movzbl 0x1b(%r14),%r12d      ; struct-map flag
240614c: or  $0x85,%r12b              ; 0x85 map / 0x95 array: 5 entries
24585cb: cmpb $0x0,0x1b(%rsi)         ; destinationChainId: key when non-zero
245b4b8: cmpb $0x1,0x1b(%rsi)         ; data: key only when == 1
2458f9c: cmp  $0x1,%dl                ; addressEncoding: base58 only when 1
```

## Implementation and comparison

Independent Rust path: not yet implemented. The reconstruction is the pure-Python encoder in
`tools/re015_signed_action_rmp_115.py`: the shared MessagePack rules `mp_str`/`mp_uint`; `sa_field_value`,
`sa_segments` and `sa_model` for the action bodies; `fh_model` for the helpers; `nt_is_ext` and `nt_model` for the
newtype bodies; and `fl_helper_bytes`, which plugs `fh_model` into `sa_segments` for the composed path. The models
are written from the rules above, not from traces.

Comparison: one concrete x86-64 evaluator (`Machine`, an instruction subset decoded from the bytes) runs the real
bytes of every body and every real callee. Each case uses fresh regions for the serializer, buffer, context,
struct, result and string pool, and is compared on the output buffer (with a 0..5-byte existing prefix and an
untouched tail), the 24-byte result record, the ordered list of fallible calls, each stub call with its arguments
and buffer length, the reserve requests, and unchanged inputs, callee-saved registers and stack pointer. The
reserve stub fails unless it is called with `cap - len < additional`, then grows `cap` to exactly
`len + additional`, so tight-capacity cases take every growth branch. Each fallible call position is faulted in
turn.

| layer | bodies | cases | mismatches | controls detected | body instructions reached |
| --- | ---: | ---: | ---: | ---: | ---: |
| signed-action | 17 | 10,200 | 0 | 50/50 | 4,408/4,408 |
| field-helpers | 9 | 18,000 | 0 | 40/40 | 848/848 |
| newtype-tuples | 17 | 10,880 | 0 | 73/73 | 1,047/1,056 |
| flow (3 bodies + 5 helpers real) | 8 | 6,000 | 0 | 27/27 | 1,275/1,333 |
| total | | 45,080 | 0 | 190/190 | |

Negative controls (190 in total, all detected; per-layer lists in `*-controls.tsv`):

- signed-action (50): 16 model mutants (padded/empty U256 hex, reversed chain names, fixint at 0x80, `ce`
  for u16, fixstr at 32, `d9` limit, uppercase hex, short H256, flipped bool, reordered choices, map/array swap,
  count off by one, two wrong error-record shapes, None as empty string), 17 field-order swaps, 17 header-immediate
  bit flips
- field-helpers (40): 16 model mutants (string/uint boundaries, key always written, `== 1` and `!= 0` tests
  swapped, key marker/case, error tag, u32 read as u64, `base58` for any non-zero `dl`, `e`/`i` swapped, wrong
  newtype name pointer/length, output kept after an error) and 24 bit flips of every inline marker byte
- newtype-tuples (73): 16 model mutants (boundaries, prefix or case-insensitive ext match, wrong tags and
  length, inverted header flag, `0x93` header, no `0x`, uppercase hex, None as empty string, bytes kept after an
  error) and 57 single-byte corruptions (name length, name bytes, message lengths, inline `0x92`/`c0`)
- flow (27): helpers treated as no-op stubs, 9 helper-rule mutants applied through the composed model, and
  a bit flip of every inline marker byte of the five helpers, evaluated through the action bodies. Two field-helpers
  mutants are not flow controls because this path cannot tell them apart: the bodies only pass mode byte 0 or 1
  (so `nz-as-eq1` is invisible) and a 32-bit destinationChainId (so `u32-full` is invisible); the field-helpers
  layer detects both

The unittest (31 tests) adds a truncated and a bit-flipped binary (digest guard), a non-FDE address, reads
outside `.text` and unmapped, a foreign body that the static check refuses (`0x22781c0`), wrong `_ExtStruct`
message pointers, out-of-range chain (4) and abstraction (5) discriminants refused by the models, a full
regeneration compared byte for byte with this folder and its MANIFEST.

## Results and limitations

- 45,080/45,080 cases match; 190/190 negative controls detected; 31/31 unittests pass.
- Code: the tool has 2,908 lines and the test 314 lines. One evaluator, one ELF reader and one set
  of MessagePack rules serve all four layers.
- Unreached body instructions: 9 of the newtype bodies' 1,056, all error exits after a failing header-writer
  call on the flag == 2 path (`0x226e2d1`, `0x2274ef1`, `0x2276806`, `0x2277d26`, `0x2277226..0x2277236`). Leaf
  writers reach only the arms these values need; they are not claimed as reconstructed.
- Unresolved:
  - `0x22781c0` (the `Unvalidated` newtype the `data` helper tail-calls) and `0x245a590` stay stubs in the
    composed path; only their arguments and result pass-through are proven here.
  - The full names behind the one-letter abstraction tags `e/i/z/u/p` are not in these bytes.
  - Action names and the Rust types behind the newtype bodies are inferred, not proven.
  - Out-of-range discriminants (chain ≥ 4, abstraction ≥ 5) are refused by the models, not modelled.
  - `finish_grow` and allocation-failure panics are not exercised (reserve is a contract stub).
- No progress gate is requested. This is one encoding path inside `constants`, not the whole component.
- Next question: do the 34 sibling copies of the action bodies (`0x44bxxxx`/`0x59xxxxx`) match the same field
  table byte for byte, and which inner value serializers do the 565 other `_ExtStruct` bodies call?
