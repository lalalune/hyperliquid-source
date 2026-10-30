# RE-005: the L1 action signing payload (nonce, vault, expiry suffix and Keccak-256)

- Component ID: RE-005 (serialization/signing), component `action-wire`
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the bindings, the instructions, the callee interfaces and
  the evaluated suffix, hash input and payload behaviour; inference for the names given to
  callees and fields; unresolved items are listed under Results and limitations
- Scope included: the three functions that own a `Location` record naming
  `l1/src/action/rmp_signable.rs`, from the serializer's return to their own return, plus
  the identity of the hash they call and of the serializer configuration they build.
- Scope excluded: the body of the action serializer, the body of the Keccak permutation,
  the callers of the three functions, what consumes the payloads (EIP-712 hashing,
  signature recovery), the nonce validation path, and node #115.

## Reproduce

Platform: Linux x86-64 (Ubuntu 22.04), Python 3.10.12. Disassembly with GNU objdump 2.38
(`-d -M intel --no-show-raw-insn`); the same packet bytes were regenerated with LLVM
objdump 23.1.1 (`OBJDUMP=<path to llvm-objdump>`). Run from the repository root. The
binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/action_signable.py --out research/work-items/RE-005-action-signable-94
python3 -m unittest discover -s tests -p 'test_action_signable.py'
(cd research/work-items/RE-005-action-signable-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x333f240 --stop-address=0x333f686 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes about 10 s.
Outputs: `evidence.json`, `functions.tsv`, `vectors.tsv`, `listing-<va>.txt` (one
normalized listing per function, identical for both objdump flavours) and
`MANIFEST.sha256`. The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. `.rodata` VA equals file offset.

**Bindings.** The path `/home/ubuntu/hl/code_Mainnet/l1/src/action/rmp_signable.rs` occurs
once in `.rodata`, at 0x1f3237. Exactly three `RELATIVE`-relocated `Location` records in
`.data.rel.ro` point at it, all for line 14 column 55, and each is referenced by exactly one
RIP-relative `lea` in `.text`. The owning FDEs (from `.eh_frame_hdr`, 121,299 entries) are:

| Function | Size | Insns | Location | `lea` site | Payload | Serializer call |
| --- | ---: | ---: | --- | --- | --- | --- |
| 0x333f240..0x333f686 | 1094 | 235 | 0x56e9c08 | 0x333f5fd | agent | 0x3351bc0, config built inline |
| 0x37eb2d0..0x37eb702 | 1074 | 232 | 0x56f3b98 | 0x37eb679 | agent | 0x3247b00, a wrapper |
| 0x3984fe0..0x39853ec | 1036 | 228 | 0x570da60 | 0x3985373 | embedded | 0x39853f0, config built inline |

Each function has two direct callers (`functions.tsv`, `evidence.json`); they were not
analysed.

**Callees.** Every call in the three functions resolves either directly, through a
`RELATIVE`-relocated slot, or through the one `GLOB_DAT` import `memcpy`. Each role binds to
one target across all three copies, classified from the registers set up at the call site:

| Role | Target | Bound by |
| --- | --- | --- |
| action serializer | per function, above | the only call before the `Ok` niche compare `movabs rax,0x8000000000000004` |
| grow (reserve) | 0x32d6a00 | direct, three sites each: `(vec*, len, additional, align 1, elem 1)` |
| grow by one | 0x13460a0 via slot 0x576e0c8 | `rdi = rsp` (the `Vec` lives at `rsp`) after a `len == cap` compare |
| hasher absorb | 0x4f59a10 via slot 0x576e1d8 | `rdi` is the state whose rate slot holds 136 |
| hasher finalize | 0x4f59e40 via slot 0x576e1e0 | `rdx = 0x20` |
| `memcpy` | import, slot 0x576dfe0 | the 0xe0-byte state clone before finalize |
| dealloc | 0x54c8cb0 via slot 0x576e010 | `(ptr, cap, 0)` after `test cap,cap` |
| alloc | 0x54c06b0 via slot 0x576dfd8 | `edi = 1`, result tested for null |
| unwrap failed | 0x157aa10 via slot 0x576e048 | `rdi` -> `called \`Result::unwrap()\` on an \`Err\` value` (0x2b bytes), `r8` -> the bound `Location` |
| allocation error | 0x1346068 via slot 0x576dfb8 | `edi = 1, esi = 1` after a null allocation |
| unwind only | 0x5660110 (`_Unwind_Resume`), 0x157b63b, per-function drop helpers | landing pads only |

**Suffix instructions** (copy 0x333f240; the other copies differ only in register
allocation, frame size and the serializer call shape). The context argument is `rcx`
(saved in `r15`), the chain argument is `edx` (saved in `ebp`), the output is `rdi`.

```
0x333f2c6  mov r12,[r15+0x10]        nonce
0x333f2de  bswap r12 ; store 8 bytes at ptr+len ; len += 8
0x333f2f3  cmp byte [r15+0x18],1     vault_address tag
   Some:   0x333f30d store byte 1 ; 0x333f33e/0x333f341 copy 20 bytes from [r15+0x19]
   None:   0x333f36a store byte 0
0x333f34f  cmp dword [r15],1         expires_after tag (also at 0x333f379)
   Some:   0x333f393 store byte 0 ; 0x333f3a0 mov r15,[r15+0x8] ; 0x333f3b5 bswap ; store 8 bytes
0x333f43c  mov qword [rsp+0x110],0x88 ; 0x333f448 mov word [rsp+0x118],0x1   hasher rate 136, delim 0x01, mode 0
0x333f45d  absorb(state, ptr, len) ; 0x333f478 memcpy(copy, state, 0xe0) ; 0x333f48b finalize(copy, out, 32)
0x333f4b8  dealloc(ptr, cap, 0) when cap != 0 ; 0x333f4c3 alloc(1)
0x333f4d2  cmp bpl,0x3 ; sete cl ; mov dl,0x62 ; sub dl,cl ; store the byte     source "a" iff chain == 3
0x333f4e2  zero 24 bytes at out+0x40 ; String{cap 1, ptr, len 1} at out ; 32-byte digest at out+0x18
0x333f519  mov qword [out+0x38],0x539                                            chain id 1337
```

Before any of this, each function grows the `Vec` with `(additional = 8 | 20 | 8, align 1,
elem 1)` when `cap - len` is too small, and with grow-by-one when `len == cap` before a
single byte.

**Context layout** (observed reads): expires tag `u32` at +0x0, expires value at +0x8,
nonce at +0x10, vault tag `u8` at +0x18, 20 vault bytes at +0x19.

**Embedded payload** (0x3984fe0). Instead of the string and chain id, 0x3985275..0x3985291
copy 32 bytes from the second argument at +0x48 into out+0x0, store the digest at out+0x20,
the nonce at out+0x40 and the chain byte at out+0x48.

**Hash identity.** Both hasher functions call 0x4f59480 through slot 0x5777790 (it has no
direct caller). 0x4f59480 is the only function that references the 24-entry table at
0x7d04c8, which equals the Keccak-f[1600] round constants; its rotate immediates cover all
24 rho offsets {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44}. The state
the three functions build is 200 zero bytes, offset 0, rate 136, delim 0x01, mode 0,
cloned as 0xe0 bytes; `.rodata` carries one `tiny-keccak-2.0.2/src/` path. Rate 136 with
delimiter 0x01 is Keccak-256, not SHA3-256 (delimiter 0x06). In tiny-keccak 2.0.2
(`crates.io` archive SHA-256 2c9d3793400a45f954c52e73d068316d76b6f4e36977e3fcebb13a2721e80237)
`KeccakState { buffer: [u64; 25], offset, rate, delim, mode }` has that layout and
`Keccak::v256()` uses rate `200 - 256/4 = 136` and `DELIM = 0x01`.

**Serializer configuration.** 0x333f240 and 0x3984fe0 build the serializer as
`{ wr = &vec, dword 0x01000400 at +0x8, byte 0 at +0xc }` and pass it in `rdx`. In rmp-serde
1.3.0 (archive SHA-256 52e599a477cf9840e92f2cde9a7189e67b42c57532749bf90aea6ec10facd4db,
the only `rmp-serde-*` path string in `.rodata`) `Serializer { wr, depth: u16, config:
RuntimeConfig { is_human_readable: bool, is_named: bool, bytes: BytesMode } }` and
`Serializer::new` sets `depth: 1024`. The bytes `00 04 | 00 | 01 | 00` read as depth 1024,
`is_human_readable = false`, `is_named = true`, `bytes = Normal`: named struct maps, the
`with_struct_map()` form. 0x37eb2d0's wrapper 0x3247b00 (712 bytes) stores the same dword
and calls the same serializer 0x3351bc0 after three other direct calls, so it serializes
the same action type after a transformation; that transformation was not analysed.

**Error path.** When the serializer result is not the `Ok` niche, each copy frees a
non-empty buffer, then calls the unwrap-failed target with `rsi = 0x2b`, `rdi` at the
message `called \`Result::unwrap()\` on an \`Err\` value` and `r8` at its own `Location`
(line 14 column 55), then `ud2`. The evaluator reaches this call for all three copies.

**Evaluated behaviour.** The evaluator runs each function from its entry to its `ret`
with the serializer replaced by an oracle that writes caller-chosen bytes `E` and the
`Ok` tag; growth, hashing, allocation and deallocation callees are modelled by the
interfaces above (the hash model is a pure-Python Keccak-256). It stops on any unmodelled
instruction, undefined register byte, flag or memory byte, or unknown call target. For a
grid of 336 vectors per function (12 encoded lengths 0..300 x 4 vault choices x 5 expiry
choices, plus 12 nonces x 8 chain bytes; each with the buffer either exactly full or with
slack) the observed behaviour is:

```
preimage      = E ++ nonce.to_be_bytes() ++ (0x01 ++ vault | 0x00) ++ (0x00 ++ expires.to_be_bytes() | "")
connection_id = keccak256(preimage)
agent:    source = "a" if chain == 3 else "b" (1-byte String), chain_id = 1337, verifying_contract = 0
embedded: signature_chain_id copied from arg2+0x48, nonce, chain byte
```

| Function | Vectors | Mismatches | Instructions run | Grow calls | SDK vector | Error path bound |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 0x333f240 | 336 | 0 | 46,828 | 327 | yes | yes |
| 0x37eb2d0 | 336 | 0 | 45,820 | 327 | yes | yes |
| 0x3984fe0 | 336 | 0 | 44,920 | 327 | yes | yes |

The hasher is initialised exactly once per call with the parameters above, finalized
exactly once, and the buffer is freed exactly once with its final capacity (and never
freed when empty). The callee-saved registers and the stack are restored at `ret`.

**Production vector.** The public Python SDK test
`test_phantom_agent_creation_matches_production` (hyperliquid-dex/hyperliquid-python-sdk
at 2fdb18f9517675ea03695a0962bd19eece9c83f0, `tests/signing_test.py`) expects
`connectionId = 0x0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908` for one
IOC limit order at nonce 1677777606040 with no vault and no expiry. Feeding the MessagePack
encoding of that action (`evidence.json: sdk_vector.encoded_hex`, 78 bytes) through each
of the three functions produces that digest. The SDK's `action_hash` appends the same
suffix, `construct_phantom_agent` uses `"a"` for mainnet and `"b"` otherwise, and
`l1_payload` uses `chainId 1337` with a zero `verifyingContract`.

**Reference comparison.** The lead `l1/action/rmp_signable.rs` describes the same suffix
order, the same `source` rule on discriminant 3, `L1_ACTION_CHAIN_ID = 1337`, a zero
verifying contract, `Keccak::v256()` and `with_struct_map()`. Differences and additions:

- The lead passes `signature_chain_id` as its own parameter. The embedded copy reads it
  from the second argument at +0x48..+0x68, so it is a field of the value being signed.
- The lead's `RmpSignableContext` field order `(expires_after, nonce, vault_address)`
  matches the observed offsets (+0x0/+0x8, +0x10, +0x18/+0x19).
- The lead's `check_embedded_action_signable`, `try_*` variants and
  `build_canonical_action_signable`'s canonicalizer are not covered by these three
  functions; 0x37eb2d0's wrapper is the only trace of a canonical form.
- The lead's `AgentSignablePayload` field order `(source, connection_id, chain_id,
  verifying_contract)` matches the observed stores (+0x0, +0x18, +0x38, +0x40).

**Inferences (not proved).**

- The three functions are `build_default_action_signable`,
  `build_canonical_action_signable` and `build_embedded_action_signable` from the lead,
  monomorphised for one action type each; line 14 column 55 is the `.unwrap()` on the
  serializer result.
- 0x32d6a00 and 0x13460a0 are `RawVec` growth, 0x54c8cb0 and 0x54c06b0 are the global
  allocator's deallocate and allocate. The third dealloc argument is 0 at every site.
- The chain discriminant 3 is Mainnet, so `"a"` is the mainnet source.

## Implementation and comparison

Rust implementation: not yet implemented. No build comparison exists. The preimage rule
and the payload layouts above are the behaviour a later Rust version must meet;
`vectors.tsv` holds 1008 evaluated digests to seed its tests, and the SDK vector is an
independent oracle.

The evaluator is Python. It interprets objdump text (GNU or LLVM intel syntax, normalized
to one form) for the integer, SSE move and branch subset these functions use, with
per-byte register and memory definedness. The serializer is an oracle; the hasher's
absorb and finalize are modelled, not run, and the digest is computed by the Python model
from the absorbed bytes.

## Results and limitations

Metrics: 3/3 functions bound to the one source path through 3 `Location` records;
1008 grid vectors and 3 production vectors with 0 mismatches; 3/3 error paths reach the
bound `Location`; 24/24 Keccak round constants and 24/24 rho offsets in the one
permutation function reached by both hasher callees; 2 normalized listings per function
(GNU and LLVM) identical.

Negative controls in `tests/test_action_signable.py`: a tampered digest, a tampered path
byte and a retargeted `Location` relocation are rejected; removing either `bswap`,
flipping the vault tag immediate, changing 1337, 0x62, `sete`, the chain compare, the
rate 0x88, the delimiter word, the serializer config dword, or the `Ok` niche each changes
the result or stops the run; an unknown call target stops the run.

Limits:

- The serializer bodies (0x3351bc0, 0x3247b00 and its callees, 0x39853f0) were not
  evaluated; `E` is whatever they produce. The named-map configuration is observed, not
  the encoding itself.
- The Keccak permutation, absorb and finalize bodies were not evaluated; the hash
  identity rests on the constants, the state parameters and the call chain, and the
  model's agreement with the SDK vector.
- Growth is modelled with amortised doubling; the real growth policy and the allocator
  were not examined. The evaluated preimage does not depend on the growth sequence.
- The callers (two per function) and what they do with the payload are unresolved.
- Node #115 is not covered.

No progress gate is requested.

Next question: which of the two callers of each copy performs signature recovery, and
does it hash the agent payload under the EIP-712 domain `{Exchange, 1, 1337, 0}` that the
public SDK uses?
