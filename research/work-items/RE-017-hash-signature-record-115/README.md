# RE-017: reconstruct the node #115 hash signature tracker record path (lines 107/123)

This packet makes the record step of `l1/src/abci/hash_signature_tracker.rs` reconstructable.
That step checks one signed hash message, decides whether the signer is a member, stores the
record and either returns error tag `0x95` or `Ok(replaced)`. `record()` in
`tools/hash_signature_record_115.py` is an executable Python reconstruction of the whole body. The
tool runs the real bytes of both monomorphised copies, `0x27606d0` and `0x2760bc0`, with every
callee stubbed. The reconstruction matches both copies on all 2,763 cases per copy, and the tool
shows that each reachable conditional branch and six deliberately wrong reconstructions change
the result.

- Component ID: `abci` (task RE-017, linked to RE-009 state sync and verification)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `05bc2de303c05525b71e7e257426e741bc66a390` (origin/main). The
  `references/can1357-hl` tree was not consulted; every claim here comes from #115 bytes.
- Claim status: observation (control flow, constants, stores and callee arguments of the two bodies
  are executed from bytes); inference (names such as "signer", "member", "sealed"); unresolved
  (what the six callees compute, see Limits)
- Scope included: complete FDEs `[0x27606d0,0x2760bbc)` and `[0x2760bc0,0x27610ac)`, 260
  instructions each, all normal-return paths, both result tags, all tracker writes and the order
  and arguments of every callee call. Scope excluded: callee bodies, the cleanup landing pads
  (reached only by unwinding), the two rescheduled copies `0x5afa7f0`/`0x5afadd0` that carry the
  same Locations, and the line 174/184 insert pair already mapped by
  `RE-001-node115-tracker-watermark-cutoff` (`0x27604d0`/`0x27605d0`). That pair is only called
  here and its body is not re-described.

## Reproduce

From the repository root, with Python 3.12 and the standard library only (no binutils, no
execution of the target):

```sh
python3 tools/hash_signature_record_115.py --out research/work-items/RE-017-hash-signature-record-115
python3 -m unittest tests.test_hash_signature_record_115
```

The tool checks the target SHA-256 first and fails on any other digest. It writes `cases.tsv`,
`mutants.tsv`, `locations.tsv`, `calls.tsv` and `summary.json`. Output is byte-identical across
runs. The tool exits 0 only when there are 0 mismatches, the twins agree and no reached mutant
survives. A full run takes about 2 minutes on one core, most of it in the mutation pass.

The evaluator is the merged shared #115 evaluator in `tools/decimal_scaled_u64.py` (`Image`,
`decode`, `Machine`), imported the same way as `tools/exchange_freeze_115.py`. The new tool adds
only the opcodes this body needs on top of it: `cdqe`, `push r/m64`, `call reg`, `pcmpeqb`,
`pand` and `pmovmskb`. Section, FDE and relocation reads come from that module.

## Evidence

Coordinates are virtual addresses. `.text` VA minus file offset is `0x1000`, so `mutants.tsv`
gives both.

Locations, read from `.rela.dyn` RELATIVE addends that point at the source path string
(`locations.tsv`): there are 8 `hash_signature_tracker.rs` records. Lines 107:28 (`0x643b2f0`)
and 123:32 (`0x643b308`) are loaded only by the two bodies of this packet; their copies at
`0x64bc860`/`0x64bc878` belong to the `0x5afa` copies.

Callees in call order (`calls.tsv`, slots resolved from RELATIVE relocations):

| role (inferred) | `0x27606d0` | `0x2760bc0` | arguments observed |
|---|---|---|---|
| predicate P | slot `0x64e6470` -> `0x3c3a3f0` | same | (arg6, ecx, msg+0x30), returns `al` |
| recover signer | slot `0x64e4f18` -> `0x3c3d240` | same | (out, arg6, msg+0x30), out byte 1 + 20 bytes |
| memcmp | GLOB_DAT slot `0x64dfb50` via `call rbx` | same | 20-byte keys |
| check | slot `0x64e6478` -> `0x36ca5b0` | same | (out, arg5, msg+0x30, [arg5+0x58]), tag `0x1a2` + 32 bytes |
| drop check error | `0x277e390` | same | (out) |
| prior lookup | `0x2bafce0` | `0x2baff80` | (out, tracker, height, &hash) -> Option<Vec<[u8;32]>> |
| report | slot `0x64e4ea8` -> `0x4524e40` | same | (code, Location); code 10 vs 11 |
| dealloc | slot `0x64df4a0` -> `0x635de30` | same | (ptr, cap*32, 0) |
| insert | `0x28aeac0` | `0x28b2f10` | (out, tracker, height, &hash, &record, &block[0x48], arg5, &vset+0x30) |
| watermark/cutoff | `0x27605d0` | `0x27604d0` | (tracker, height, &slot holding vset+0x30, arg7) |
| drop replaced | `0x277d220` | same | (out) |

Arguments: `rdi` result, `rsi` tracker, `rdx` message (`+0` pointer to a 0x48-byte block, `+8`
u64 height, `+0x10` 32-byte hash, `+0x30` signature bytes), `ecx` u32 passed to P, `r8`
context, `r9` signer-set holder (`+0x30` B-tree root, `+0x38` height), and stack argument 7
(`+0x10` u64 boundary height).

Human-readable excerpt (GNU objdump, not used by the tool):

```
2760742: cmp    BYTE PTR [rbx+0x90],0x0      ; tracker already sealed?
276074b: cmp    r13,QWORD PTR [r12+0x10]     ; height == arg7 boundary
2760750: sete   cl ; test al,cl              ; ... and P
276075c: mov    BYTE PTR [rdx+0x91],0x1      ; seal, then copy 32-byte hash to +0x92
27607fb: movzx  eax,WORD PTR [rax+0xe6]      ; B-tree node len, keys +8 stride 0x14
2760955: jo     2760988                      ; Option<Vec> niche i64::MIN
2760a7e: inc r14 ; cmp rbx,r14               ; insert result niche 0x8000000000000001
2760afe: pmovmskb eax,xmm1 ; cmp eax,0xffff  ; old hash == new hash
2760b40: setne  BYTE PTR [r15+0x2]          ; Ok(replaced)
2760b62: mov    ax,0x95                      ; error tag
```

## Implementation and comparison

The independent Rust path is not yet implemented. The executable reconstruction is `record()`
(Python, about 50 lines):

1. `P = predicate(vset, flag, sig)`.
2. If `tracker[+0x90] == 0`, `height == arg7.boundary` (u64 equality) and `P`, then set
   `tracker[+0x91] = 1` and copy the message hash to `tracker[+0x92..+0xb2]`. This happens before
   any other check succeeds.
3. `signer = recover(vset, sig)`. `member` holds iff `signer` is Some and an exact 20-byte key of
   the B-tree set at `vset+0x30` (standard ordered search with `memcmp`; values are not read).
4. `chk = check(ctx, sig, ctx[+0x58])`: Ok with 32 bytes iff the word tag is `0x1a2`, otherwise
   the error is dropped.
5. If `chk` failed and the signer is not a member: return error `0x95` (byte `+2` untouched) when
   `P` is false, else `Ok(false)` (word `0x1a2`, byte `+2 = 0`). If `chk` failed but the signer
   is a member, continue with an empty check result.
6. `prior = prior_lookup(tracker, height, hash)`. If Some, report `(code, line 107)`, and free
   `cap*32` bytes when `cap != 0`.
7. `old = insert(tracker, height, hash, (Option<[u8;32]> chk, Option<[u8;20]> signer), block,
   ctx, &vset.set)`. The record is 54 bytes: tag, 32 bytes, tag, 20 bytes. A None payload is left
   uninitialised; the evaluator sees unknown bytes there and the reconstruction says None.
8. If `old` is Some: report `(code, line 123)` when the stored 32-byte hash at old `+0x40` differs
   from the message hash, call watermark/cutoff, then drop `old`.
9. Return `Ok(old.is_some())`: word `0x1a2`, byte `+2`.

Comparison (from `summary.json`, per body): there are 2,763 cases. They cross 4 signer-set shapes
(empty root, one leaf, a full 11-key leaf, a 2-level tree of fanout 4) and up to 8 signers (none,
2 absent keys, sorted positions including separator keys). They also cross P, the sealed byte,
height equal or not equal to the boundary, check Ok or Err, prior None, empty or 3 elements, and
old None, same hash or 3 different hashes. 3 extra cases use u64 extreme heights. The result is
**0 mismatches on both bodies**. The outcome tables of the twins are identical
(`result_digest` equal); only the report code differs (10 vs 11, read from the `mov edi, imm32`
bytes before each report call). There are 29 distinct outcomes (word / flag / sealed / call
sequence).

Controls:

- Mutation: each of the 16 conditional jumps per body is inverted in a byte copy (32 mutants)
  and run on 1,913 sampled cases. 30 are killed. The 2 not killed (`0x2760b82`, `0x2761072`) are
  labelled `unreached`: they sit in the cleanup landing pad after the vector deallocation, which
  only unwinding reaches, and no case executes them. No reached mutant survives.
- Wrong reconstructions (`negative_controls`), each caught: `seal_ignores_flag` (345 cases),
  `seal_ignores_predicate` (345), `member_without_recover` (1,080), `error_ignored` (576),
  `no_dealloc` (547) and `always_report` (819).
- Unit tests (14): digest change rejected, non-start and out-of-FDE addresses rejected, sampled
  equality on both bodies, error and `Ok(false)` words, flipped seal and membership branches
  caught, swapped report code caught, corrupted hash input caught.

## Results and limitations

- Metrics: 2,763/2,763 cases match per body (5,526 runs). 30/32 mutants are killed and 2/32 are
  unreached (landing pads). 6/6 wrong reconstructions are caught. 243 of the 260 instructions are
  reached in each body (`instructions_reached`). The 17 unreached are the 16 cleanup
  landing-pad instructions from `0x2760b7c` (twin `0x276106c`) and one alignment `nop` at
  `0x2760857`.
- The callees are stubs. What P, recover and check compute (signature scheme, which key set, what
  the 32-byte check output is) is unresolved. So are the prior-lookup and insert containers and
  what report code 10/11 means (`0x4524e40` is shared by many callers). Role names are
  inferences from argument shapes and branch use.
- Only normal returns of callees are modelled. Panics inside callees and the unwind paths are
  out of scope.
- The `0x5afa7f0`/`0x5afadd0` copies have a different callee structure (extra drop helpers
  `0x5b1b250`, `0x5376540`, `0x5b18960` and a call through slot `0x5c87d50`) and are not
  compared.
- No gate is requested. This packet covers one step of the tracker, not the `abci` component.

Next question: does the `0x5afa7f0` copy implement the same `record()` with its extra drop
helpers, and what does insert `0x28aeac0` do with the 54-byte record when the key already
exists?
