# RE-001-node115-shortstring-le-u128-fold: what is the function at 0x15472b0?

This function is **not a leaf** (`records.json` `is_leaf: false`): it pushes
`rbx` and makes three calls — the recursive self-call at `0x15472c6` and the two
panic calls. The directory name keeps the historical `leaf` token only as an
identifier; the prose below calls it "the function" or "the recursive fold".

- Component ID: foundation utilities (`base/src/short_string.rs`). Bounded static
  research; **no reconstruction gate requested** and **no component gate claimed**.
- Target release and full SHA-256: node115, `artifacts/node/115/hl-node`,
  105896032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: none copied. The verification model,
  equations and documentation are independently authored under the root MIT
  licence. No inferred unlicensed implementation (e.g. `can1357` or similar) is
  copied, and no public source revision is asserted byte-equivalent. **No
  `byte-windows.json` entry is registered and no compiler-builtins identity is
  claimed.**
- Claim status: **observation** (ELF digest, FDE extent, body bytes, GOT
  relocations, panic location descriptors) separated from **inference** (the
  decoded fold semantics). No execution of the capture.
- Scope included: the single function `0x15472b0..0x1547309` and the packing
  contract it implements. Scope excluded: the caller's full intern/lookup
  algorithm (FDE `0x1546aa0`), and the two panic location-descriptor edges
  already mapped by open PRs (see **Boundary** below).

## Boundary with open PRs (no overlap)

Two OPEN PRs map panic *location-descriptor edges* of related `short_string.rs`
sites. This packet recovers the function's **packing contract**, which those PRs
do not, and deliberately does **not** create their packet names or touch their
paths:

- PR #4747 maps the overflow `jne` at `0x15472d3` / loc `0x15472fc` (52:28) —
  packet `RE-001-node115-loc-edge-15472fc` (not in this tree).
- PR #4744 maps a loc-edge in the *caller* at `0x1546aa0` (line 29) — packet
  `RE-001-node115-loc-edge-1547205`.

The panic descriptors are cited here only as observed callees of this function;
the contribution is the recovered recurrence, not those edges.

## Reproduce

From repo root with the materialized LFS input and GNU binutils on PATH:

```sh
git lfs pull --include="artifacts/node/115/hl-node"
objdump -d --start-address=0x15472b0 --stop-address=0x1547309 -M intel \
  artifacts/node/115/hl-node                                   # == 15472b0.objdump.txt
# caller tail-call excerpt (== 1546aa0.caller-tailcall.objdump.txt, bytes elided for the len>16 path):
objdump -d --start-address=0x1546aa0 --stop-address=0x1546ac4 -M intel artifacts/node/115/hl-node
objdump -d --start-address=0x1546b02 --stop-address=0x1546b1b -M intel artifacts/node/115/hl-node
python3 -B research/work-items/RE-001-node115-shortstring-le-u128-fold/verify_shortstring_le_u128_fold.py
(cd research/work-items/RE-001-node115-shortstring-le-u128-fold && sha256sum -c MANIFEST.sha256)
```

Observed: the verifier prints `RESULT: PASS`. It decodes the real 89 body bytes
(asserting the exact opcode sequence), **emulates** that decoded body, and shows
`emulated==model==LE 14/14 vectors`, the value-dependent overflow domain, the
panic grid, the bounds edge, and both reproducible byte-patch controls. No
PC/register/memory state of the capture is advanced; the emulator runs only over
the pinned body bytes with a synthetic input buffer. Platform: Linux x86-64;
`objdump` from GNU binutils; Python 3.x. The verifier reads the capture
read-only and **never natively executes, copies, relocates, or writes it**.

## Evidence (observation)

Coordinate system: `.text` VA `0x1419300` / file offset `0x1418300`
(VA − fileoff = `0x1000`). `.rodata` is identity-mapped (VA == offset);
`.data.rel.ro` and `.got` map with VA − offset = `0x2000`.

| Fact | Value | Source |
| --- | --- | --- |
| FDE extent (exclusive end) | `0x15472b0 .. 0x1547309` (89 B) | unwind index 2530, FDE `0xcb5d38` |
| Section / CIE / LSDA | `.text` / `0xca6ed8` (aug `zR`) / none | FDE row |
| Body SHA-256 | `be131836977ceb1a02f296cfff40e71654c16b97ce774faec0f4ebe8f2728456` | `verify_shortstring_le_u128_fold.py` |

Three GOT slots dereferenced by the body, each an `R_X86_64_RELATIVE` (type 8)
relocation (confirmed in `.rela.dyn`):

| Call site | GOT slot | Addend (target) | Role |
| --- | --- | --- | --- |
| `0x15472c6` | `0x64e0fe0` | `0x15472b0` | recursive self-call (also tail-called by caller `0x1546aa0`) |
| `0x15472f6` | `0x64df620` | `0x1680cbf` | slice index-out-of-bounds panic |
| `0x1547303` | `0x64df870` | `0x1681dc0` | arithmetic-overflow panic |

Two panic location descriptors (`.data.rel.ro`, layout `{&str ptr, u64 len, u32
line, u32 col}`; the `ptr` field is itself `R_X86_64_RELATIVE` → the file-name
string at `0x435643` = `"base/src/short_string.rs"`, len 24):

| Descriptor VA | File | line:col | Used by |
| --- | --- | --- | --- |
| `0x63fdc68` | `base/src/short_string.rs` | 52:9 | bounds panic `0x15472e9` |
| `0x63fdc80` | `base/src/short_string.rs` | 52:28 | overflow panic `0x15472fc` |

Raw disassembly is retained in `15472b0.objdump.txt`.

### Decoded control flow (inference, anchored to byte offsets)

```
15472b0 push rbx
15472b1 xor  eax,eax                     ; acc_lo = 0
15472b3 mov  ecx,0                       ; acc_hi = 0
15472b8 cmp  rdx,rsi                     ; index (rdx) vs length (rsi)
15472bb je   15472e4                     ; i == len -> return (rdx:rax) = 0
15472bd jae  15472e9                     ; i >  len -> slice-bounds panic
15472bf movzx ebx,BYTE PTR [rdi+rdx]     ; byte = ptr[i]
15472c3 inc  rdx                         ; i += 1
15472c6 call [rip+0x4f99d14]             ; fold(ptr,len,i+1)  (GOT 0x64e0fe0 = self)
15472cc mov  rcx,rdx                     ; rcx = high 64 of recursive u128 (rdx:rax)
15472cf shr  rdx,0x38                    ; (hi >> 56) != 0  <=>  rest >= 2**120
15472d3 jne  15472fc                     ; overflow panic (<<8 would exceed u128)
15472d5 movzx edx,bl                     ; edx = byte
15472d8 shld rcx,rax,8                   ; (rcx:rax) <<= 8  (high limb)
15472dd shl  rax,8                       ;                   (low limb)
15472e1 or   rax,rdx                     ; acc |= byte   (byte in low 8 bits)
15472e4 mov  rdx,rcx                     ; return u128 in rdx:rax
15472e7 pop  rbx
15472e8 ret
15472e9 lea  rax,[rip+0x4eb6978]         ; 0x63fdc68  loc short_string.rs:52:9
...     call [rip+0x4f98324]             ; GOT 0x64df620 -> 0x1680cbf  bounds panic
15472fc lea  rdi,[rip+0x4eb697d]         ; 0x63fdc80  loc short_string.rs:52:28
1547303 call [rip+0x4f98567]             ; GOT 0x64df870 -> 0x1681dc0  overflow panic
```

The result is a u128 returned in `rdx:rax` (`rdx` = high, `rax` = low). Because
the recursion appends each byte into the low 8 bits *after* shifting the
previous result left by 8, the earliest byte ends up least-significant:

```
fold(ptr,len,i) = 0                               if i == len
fold(ptr,len,i) = panic_bounds                    if i > len
fold(ptr,len,i) = panic_overflow                  if fold(ptr,len,i+1) >= 2**120
fold(ptr,len,i) = (fold(ptr,len,i+1) << 8) | ptr[i]   otherwise
  => result = b[0] | (b[1]<<8) | ... | (b[n-1]<<((n-1)*8))   (little-endian pack)
```

The overflow guard is **value-dependent, not a fixed length cut-off.** It fires
when the recursive *suffix value* is already `>= 2**120` (`rdx >> 56 != 0`),
which happens exactly when some byte at absolute index `>= 16` is nonzero.
Equivalently: **the fold succeeds iff the little-endian value fits in 128 bits
(every byte at index ≥ 16 is zero) and panics otherwise.** So:

- any input of length `<= 16` always folds (no index `>= 16` exists);
- a 17-byte input panics **only if its byte at index 16 is nonzero** — a 17-byte
  input whose last byte is `0` folds without panicking and returns the full
  little-endian pack (the committed vector `bytes(range(1,17)) + b"\x00"`);
- wider all-zero or high-zero inputs (e.g. 20 zero bytes) also fold.

The verifier exercises both sides on the emulated body: `fit_no_panic` vectors
(including the 17-byte last-byte-`0` case) return the LE pack, and `panic`
vectors (any nonzero byte at index `>= 16`) take the overflow call in both the
emulated body and the model. The ABI reading is SysV x86-64: `rdi` = ptr,
`rsi` = len, `rdx` = index; result u128 in `rdx:rax`.

Caller note (context only, not the claim): FDE `0x1546aa0` does
`cmp rsi,0x10; jbe 0x1546b02`; at `0x1546b02` it `xor edx,edx` (index 0), runs
its epilogue, and `jmp QWORD PTR [rip+0x4f9a4c5]`, which dereferences GOT
`0x64e0fe0` (`0x1546b1b + 0x4f9a4c5 = 0x64e0fe0`) — the slot that relocates to
this function. So strings of length ≤ 16 begin the fold at index 0 via a tail
call. The raw bytes are in `1546aa0.caller-tailcall.objdump.txt`; the caller's
full intern/lookup algorithm is **not** claimed here.

## Implementation and comparison

No Rust reimplementation or two-build comparison is attempted (no reconstruction
gate requested). `verify_shortstring_le_u128_fold.py`:

1. authenticates the ELF by SHA-256 **before any other byte interpretation**;
2. pins the 89-byte body length and body SHA-256;
3. confirms the three GOT slots are `R_X86_64_RELATIVE` with addends self
   `0x15472b0`, bounds `0x1680cbf`, overflow `0x1681dc0`;
4. confirms the two location descriptors decode to `base/src/short_string.rs`
   52:9 and 52:28, sharing the file-name string at `0x435643`;
5. **decodes the real 89 body bytes** instruction-by-instruction and asserts the
   exact opcode sequence (`push/xor/mov/cmp/je/jae/movzx/inc/call/mov/shr
   rdx,0x38/jne/movzx/shld/shl/or/mov/pop/ret/lea/call`) over all 89 bytes with
   zero leftover — a byte-level decode check of the body;
6. **emulates** that decoded body with a tiny in-process x86-64 interpreter
   (restricted to exactly those encodings; the recursive self-call is dispatched
   through the recovered GOT slot, the two panic calls raise), and compares the
   emulated u128 (`rdx:rax`) against the Python recurrence model **and** the
   independent little-endian pack `int.from_bytes(buf,'little')` **and** the
   closed-form `sum(b << 8k)`. The **emulated binary is the ground truth**:
   agreement is credited only when all four match. Earlier revisions compared
   only a Python recurrence to `int.from_bytes` (a model-vs-model check that
   proved nothing about the bytes); the emulator removes that gap.

The grid now also contains the value-dependent domain vectors (16-byte max,
17-byte last-byte-`0` that fits, all-zero wide inputs) and a separate panic grid
(any nonzero byte at index `>= 16`); the emulated body and the model are
asserted to agree on which inputs panic. A bounds-edge test feeds `index > len`
directly and both the emulated body and the model take the slice-bounds panic.

### Negative controls (reproduced inside the verifier)

The two byte-patch controls are applied **in memory** to a copy of the body and
**re-decoded and re-emulated on every verifier run** (the verifier is itself
MANIFEST-checked), so the divergence is reproduced, not just asserted in prose.
The captured binary is never modified or executed.

| Control | Mechanism (in `verify_…py`) | Reproduced result |
| --- | --- | --- |
| big-endian pack | `int.from_bytes(buf,'big')` vs the model | diverges on multi-byte, multi-value inputs |
| drop `<<8` | OR successive bytes without the shift | diverges (collapses to a byte-wise OR) |
| `jne`→`je` @`0x15472d3` | patch `75`→`74` in memory, re-emulate | overflow guard inverted: the small input `"AB"` folds to `0x4241` on the real body but **panics** on the patched body |
| `shld`→`5×nop` @`0x15472d8` | patch `48 0f a4 c1 08`→`90 90 90 90 90` in memory, re-emulate | high-limb carry removed: a 15-byte input emulates to only the low 64 bits (high limb `0`), diverging from the little-endian pack |

The committed `control-1-jne-to-je.objdump.txt` and `control-2-shld-to-nop.objdump.txt`
are the static-disassembly view of these exact in-memory patches (base VA via
`--adjust-vma`), kept for readability.

## Results and limitations

- Positive: the **emulated body** agrees bit-exactly with the recurrence model,
  the independent little-endian pack and the closed-form on 14/14 fold vectors;
  emulated body and model agree on every panic/no-panic input of the
  value-dependent domain and on the bounds edge; both model controls diverge and
  both byte-patch controls re-emulate to the altered behavior.
- This is a single function's packing contract, **not** a component gate; no gate
  is requested and no `byte-windows.json` entry is added.
- Identity: the file/line attribution (`base/src/short_string.rs:52`) is read
  directly from the panic location descriptors; this is the first-party source
  file, not a compiler builtin. No public source revision is asserted
  byte-equivalent.
- The emulator covers exactly the encodings in this 89-byte body and dispatches
  the recursion through the recovered GOT slot; it is not a general CPU and is
  not a substitute for whole-program execution, which is not performed.
- Next question: fully map the caller `0x1546aa0` intern/lookup path (the
  `cmp rsi,0x10; jbe; xor edx,edx; tail-jmp` dispatch and the ≥17-byte branch it
  guards) **without duplicating the open loc-edge PRs** (#4744 / #4747) — i.e.
  recover the lookup/hash-table contract, not the panic edges those PRs own.
