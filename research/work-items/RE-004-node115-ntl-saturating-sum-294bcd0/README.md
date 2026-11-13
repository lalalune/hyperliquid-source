# RE-004: characterise the node #115 saturating u64 sum over 64-byte records at 0x294bcd0

- Component ID: `assets` (`l1/qtys/*`)
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`, 105,896,032 bytes)
- Source commit / reference commit: repository base `a8616af9432b8d8517b2af677880e117b7c28ef3`; no external reference source is used
- Claim status: instruction facts, relocations, source-location record and call sites are **observations**; the arithmetic reading of the loop is an **inference** from those observations; record type, callee result and caller intent are **unresolved**
- Scope included and excluded: one FDE extent, `[0x294bcd0, 0x294bd73)` (163 bytes), its direct callee and reporter slot as call targets only, its two direct call sites, and the argument set-up at those sites. Excluded: the semantics of the callee `0x2a8ae60`, of the reporter behind slot `0x64e4ea8`, of the preceding call `0x29dfea0`, of the 64-byte record, and any Rust reconstruction. No component gate is requested.

## Question

What does the 163-byte node #115 function at `0x294bcd0`, whose source-location record names `l1/src/qtys/impl_ntl.rs`, compute, and what happens when its 64-bit running total overflows?

**Finding (observation, then reading).** The function walks a vector of 64-byte records. For each record it copies the 20 bytes at record `+0x18..+0x2c` to the stack, calls `0x2a8ae60` with a context value and a pointer to that copy, and adds the 64-bit result to a running total that starts at the caller's `rsi`. If the add carries, it calls a reporter through `.got` slot `0x64e4ea8` with `edi = 0` and the address of the `l1/src/qtys/impl_ntl.rs:682:1` location record, then replaces the total with `0xffffffffffffffff` and keeps going. A null vector pointer or a zero length returns the starting total unchanged without calling anything. Apart from pushes and calls, the only memory the function itself writes is 20 bytes of its own stack frame; what the callee and the reporter write is not examined.

## Reproduce

Run from the repository root with the pinned binary materialised (`make setup`, or `git lfs pull --include=artifacts/node/115/hl-node`):

```sh
python3 tools/artifacts.py verify
python3 research/work-items/RE-004-node115-ntl-saturating-sum-294bcd0/verify.py
python3 research/work-items/RE-004-node115-ntl-saturating-sum-294bcd0/verify.py --json
python3 research/work-items/RE-004-node115-ntl-saturating-sum-294bcd0/verify.py --write-listing   # regenerates instructions.tsv
objdump -d -M intel --start-address=0x294bcd0 --stop-address=0x294bd73 artifacts/node/115/hl-node
```

- Tools used for this record: Python 3.11.5, Capstone 5.0.7, GNU objdump 2.47.20260726 (Homebrew binutils). Without a GNU `objdump` on `PATH` the verifier reports the cross-check as skipped rather than passed.
- Platform: Darwin 25.6.0 arm64, reading the Linux x86-64 ELF as data. The verifier is static: nothing from the target is executed or emulated, and there is no network access.
- Inputs: the pinned binary above, `tools/elf_index.py` and `tools/fde_extents.py` for the unwind index. Outputs: `instructions.tsv` (54 rows), checked into this directory and compared with the live decode. File hashes are in `MANIFEST.sha256`.
- Runtime is about 15 seconds. Exit status is 0 only if every check passes and every corruption control is rejected.

## Evidence

Coordinates are ELF virtual addresses in `.text` unless stated. For `.text`, file offset = VA − `0x1000`, so the function occupies file offsets `0x294acd0..0x294ad73`.

**Boundary.** `[0x294bcd0, 0x294bd73)` is an indexed FDE extent: FDE record at `0xd71a28`, CIE `0xca6ed8`, unwind-index row 33521, no LSDA. The 163-byte window has SHA-256 `088105b64593c7f48681cd39c8371b2aeac8b1f7f673b4df555815acd92c541b`. Capstone decodes it linearly into 54 instructions that tile the extent exactly, and GNU objdump reports the same 54 instruction boundaries and bytes. An FDE extent is an unwind-described range, not by itself a validated function boundary; here the entry is also the target of both direct calls below and the last instruction is the only `ret`.

**Structure.** Every branch target is an instruction inside the window. There is one direct call (`0x294bd18` to `0x2a8ae60`, an indexed FDE of 565 bytes), one indirect call (`0x294bd3c` through `.got` slot `0x64e4ea8`) and one `ret` (`0x294bd72`).

| Range | Instructions | Reading |
| --- | --- | --- |
| `0x294bcd0..0x294bcdd` | six `push`, `sub rsp, 0x18` | Frame for `rbp r15 r14 r13 r12 rbx` and a 0x18-byte local area |
| `0x294bcde..0x294bced` | `mov r14, rsi`; `test rdi, rdi`; `je 0x294bd61`; `mov rbp, [rdi+0x10]`; `test rbp, rbp`; `je 0x294bd61` | Total starts as `rsi`. Null `rdi`, or a count of zero at `[rdi+0x10]`, jumps to the early return |
| `0x294bcef..0x294bcfd` | `mov rbx, [rdx]`; `mov r12, [rdi+8]`; `add r12, 0x18`; `mov r15, rsp` | Context value read once from `[rdx]`; record cursor starts at `[rdi+8] + 0x18`; `r15` points at the local copy |
| `0x294bd00..0x294bd18` | `mov eax, [r12+0x10]` and `mov [rsp+0x10], eax`; `movups xmm0, [r12]` and `movaps [rsp], xmm0`; `mov rdi, rbx`; `mov rsi, r15`; `call 0x2a8ae60` | 4 + 16 bytes at cursor copied to the stack; callee called with (context, pointer to the copy) |
| `0x294bd1d..0x294bd31` | `mov r13, rax`; `add rax, r14`; `jb 0x294bd33`; `add r12, 0x40`; `mov r14, rax`; `dec rbp`; `jne 0x294bd00`; `jmp 0x294bd64` | No carry: the sum becomes the total, the cursor advances 0x40, loop while the count is non-zero |
| `0x294bd33..0x294bd5f` | `xor edi, edi`; `lea rsi, [rip+0x3af7f9c]`; `call [rip+0x3b99166]`; `add r13, r14`; `mov rax, -1`; `cmovb r13, rax`; `mov rax, r13`; `add r12, 0x40`; `mov r14, rax`; `dec rbp`; `jne 0x294bd00`; `jmp 0x294bd64` | Carry: report, redo the add, clamp to `0xffffffffffffffff`, advance, loop |
| `0x294bd61` | `mov rax, r14` | Early return value is the starting total |
| `0x294bd64..0x294bd72` | `add rsp, 0x18`; six `pop`; `ret` | Epilogue; result in `rax` |

The full listing with bytes is [instructions.tsv](instructions.tsv).

**Data and relocations.**

- `lea rsi, [rip+0x3af7f9c]` at `0x294bd35` resolves to `0x6443cd8`. The 24 bytes there are `00000000000000001700000000000000aa02000001000000`: a zero pointer slot, length 23, line 682, column 1. An `R_X86_64_RELATIVE` entry for slot `0x6443cd8` points into `.rodata` at the 23 ASCII bytes `l1/src/qtys/impl_ntl.rs`.
- `call [rip+0x3b99166]` at `0x294bd3c` calls through `.got` slot `0x64e4ea8`, whose `R_X86_64_RELATIVE` addend is `0x4524e40`, an indexed FDE of 369 bytes. The same slot and addend are documented from another call site in [RE-001-node115-loc-edge-5393742](../RE-001-node115-loc-edge-5393742/README.md); that site passes `edi = 3` and this one passes `edi = 0`. This packet does not interpret the value.

**Memory effects.** Capstone's operand-access flags give exactly two explicit memory writes, `mov dword ptr [rsp+0x10], eax` and `movaps xmmword ptr [rsp], xmm0`, both at the stack pointer: 20 bytes of the function's own frame. Pushes and calls also write the stack implicitly. Nothing is stored through `rdi`, `rdx` or a record pointer.

**Call sites.** A scan of `.text` for `E8`/`E9` instructions whose displacement targets `0x294bcd0` finds two candidates; decoding each containing FDE from its start confirms both are instruction boundaries decoding as `call 0x294bcd0`. No candidate was rejected, no `jmp` reaches the function, no relocation slot holds its address and no RIP-relative address-of instruction targets it.

| Call site | Containing FDE | Set-up observed (every instruction from the preceding call to the site) |
| --- | --- | --- |
| `0x2c75f4f` | `[0x2c75620, 0x2c7637b)` | `call 0x29dfea0` with `esi = 0`; copy `[rsp+0x30]` to `[rsp+0xa0]`; `rdx = &[rsp+0xa0]`; `rdi = r14`; `rsi = rax`; then `cmp rax, 0x989680` and `jae` on the result |
| `0x2c76e4d` | `[0x2c767d0, 0x2c774c0)` | `call 0x29dfea0` with `esi = 0`; copy `[rsp+0xe0]` to `[rsp+0x70]`; `rdx = &[rsp+0x70]`; `rdi = r13`; `rsi = rax`; result moved to `r12` |

No instruction between `call 0x29dfea0` and the call site writes `rax`, so in both callers the starting total `rsi` is the return value of `0x29dfea0(…, 0)`. The second caller's FDE contains the `l1/spot_meta.rs` location edge documented in [RE-001-node115-loc-edge-2c77455](../RE-001-node115-loc-edge-2c77455/README.md). The callee `0x2a8ae60` is described in [RE-010-node115-schedule-cancel-source](../RE-010-node115-schedule-cancel-source/README.md) as walking the perpetual DEX vector and accumulating payload fields; this packet does not re-verify that.

**Analysis scope.** The analysis is complete for the 163-byte extent and the call-site census over `.text`. Nothing was timed out or limited to a sub-range.

## Reading of the loop (inference)

In SysV x86-64 terms the observed roles are: `rdi` a nullable pointer to a header with the element pointer at `+8` and the element count at `+0x10`; `rsi` the starting total; `rdx` a pointer to one pointer-sized cell whose value is passed to the callee on every iteration; `rax` the returned total. As pseudocode:

```text
total = rsi
if rdi == null or rdi.count == 0: return total
ctx = *rdx
for each 64-byte record r in rdi.elements:
    key20 = r[0x18 .. 0x2c]
    v = callee(ctx, &key20)                  // 0x2a8ae60
    if total + v carries:
        reporter(0, &Location{impl_ntl.rs:682:1})   // through slot 0x64e4ea8
        total = 0xffffffffffffffff
    else:
        total = total + v
return total
```

Consequences read from the instructions, not run: the callee is called for every record, including after the total has saturated; once saturated, every later non-zero result carries again and calls the reporter again, while a zero result does not; the clamp relies on `r13` and `r14` surviving the reporter call, which the SysV ABI guarantees for a normal function (the reporter has an FDE and the same slot is called from other sites). The pseudocode is not recovered source and the names are placeholders.

## Implementation and comparison

Not yet implemented and not measured. There is no Rust path, no `Cargo.lock`, no build, and no raw or normalized byte comparison in this packet. The verifier proves that the retained facts are present in the authenticated artifact; it is not a runtime-equivalence result.

Corruption controls. Each control patches an in-memory copy of the authenticated image and must be rejected by the named stage. The semantic controls skip the packet-wide digest checks, so their rejection exercises the instruction and relocation checks themselves.

| Control | Rejected by |
| --- | --- |
| `jb` at `0x294bd23` flipped to `jae` | facts |
| record stride `0x40` at `0x294bd28` changed to `0x44` | facts |
| `cmovb` at `0x294bd4c` flipped to `cmovae` | facts |
| null-vector guard `je` at `0x294bce4` flipped to `jne` | facts |
| callee call displacement off by one | control-flow |
| reporter slot relocation addend corrupted | relocations |
| source-location line 682 changed to 683 | relocations |
| displacement of the call at `0x2c75f4f` corrupted | callers |
| operand byte of the padding `nop` changed (no semantic effect) | window digest |

## Results and limitations

Metrics, with denominators: 11 checks pass (target digest, window digest, FDE extents for the function, callee, reporter and both callers, 54/54 instructions tiled, 54/54 rows equal to `instructions.tsv`, control-flow, 39 pinned instructions plus epilogue, store census, relocations and location record, call-site census with 2/2 candidates verified and 0 rejected, GNU objdump agreement on 54/54 boundaries); 9/9 corruption controls rejected at the intended stage.

What this does not establish:

- The type of the 64-byte record, and whether the 20 bytes at `+0x18` are an address, key or something else. Only the offsets and the copy width are observed.
- What `0x2a8ae60` returns (units, lanes) or what `0x29dfea0` returns when called with `esi = 0`. The packet therefore does not say what quantity the sum measures.
- What the reporter at `0x4524e40` does, or why callers pass different `edi` values.
- The meaning of `0x989680` in the first caller. It is recorded as a compared constant only.
- Anything about callers beyond the two direct sites: calls through registers or jump tables are not enumerated, and only `.text` was scanned for direct calls.
- That all of the function's code originated in `l1/src/qtys/impl_ntl.rs`. The location record anchors the reporter call to that file and line; it does not prove the origin of the whole body.
- Behavioural equivalence with any reconstruction. No execution or emulation was performed.

No progress gate is requested; `assets` stays at its current state.

## Next question

What is the record type held in the vector that both callers pass in `rdi` (a 64-byte element with a 20-byte field at `+0x18`), what does `0x29dfea0(…, 0)` return, and what does `0x2a8ae60` return for one such key? Together these fix the unit and meaning of the sum, which is the prerequisite for an independently written Rust version and a target-grounded test of the saturation behaviour recorded here.
