# vaults-subaccount-create-94: createSubAccount check order, volume operand and address derivation

- Component ID: `vaults` (path rule `l1/sub_account.rs`; the creator `0x36f3610`
  references the panic `Location` `l1/src/sub_account.rs:69:13` through the lea at
  `0x36f3bcd`). The volume operand's step functions reference `l1/src/scaled_vlm.rs`
  and `l1/src/raw_vlm.rs`, which `docs/COMPONENTS.md` maps to `fees`; they are used
  here only as evidence for what the operand is.
- Target release and full SHA-256: `hl-node` #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository base
  `1f8c67c63ca4794c9689235471c60297f8a5c985` (this packet is one commit on top);
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference files
  read as leads only: `l1/exchange/impl_create_sub_account.rs`,
  `l1/exchange/handlers/06_create_sub_account.rs`, `l1/sub_account.rs`.
- Claim status: observation. Inferences are labelled and unknowns are listed. No
  acceptance gate is requested; the `vaults` gates stay false.
- Scope included: for the action whose dispatcher table index is 6 (exchange tag
  122; the wire name `createSubAccount` for that tag is RE-010's reference label),
  the ordered checks, their constants, decision edges and status stores across the
  handler `0x27e3140` and the callees `0x36f3610` (creator), `0x36f3c20` (deriver)
  and `0x36f43c0` (name helper); every call site of those four functions; what the
  bytes show about the volume operand the creator gates on; and the
  address-derivation mechanism.
- Scope excluded: the internals of `0x2840fb0` and `0x399c7a0` (called before the
  hash-table probes), `0x379a4d0` (called by `0x3596680`), `0x379ec60` (the insert),
  `0x36f57f0` and `0x371b3a0` (the per-user lookups of the volume step), the
  post-success callees `0x1f84840`, `0x1f849b0` and `0x1f84b30`, the slot callees
  `0x54c06b0`, `0x54c8cb0`, `0x1345e2a`, `0x157b7f0`, `0x157b63b`, `0x4ee3b20` and
  `0x32d6350`, and the `0x577ab98` once-init path; a word-by-word proof of the ethabi
  encoder `0x1592160` (only its Int/Uint word writer is decoded); the semantic origin
  of the per-user volume fields; the purpose of the second gate in `0x2766f70`; and
  any execution of the binary.

## Reproduce

Platform: macOS 26.6 (Darwin 25.6.0, arm64), offline, from the repository root.
Python 3.13.18; GNU binutils 2.47.20260726 (`objdump`, `readelf`). The tool is
stdlib only. `objdump` is used only by `--excerpts`, by `verify.py` to regenerate the
excerpts, and by the cross-check tests; `readelf` only by one test. No captured
binary is executed.

```sh
export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:/opt/homebrew/opt/binutils/bin:$PATH"
P=research/work-items/vaults-subaccount-create-94
python3 -B tools/subaccount_create.py --check $P/subaccount-create.json    # exit 0 same, 1 differs, 2 EvidenceError
python3 -I -B $P/verify.py
python3 -O -B $P/verify.py
python3 -B -m unittest tests.test_subaccount_create -v
# rewrite the two generated files:
python3 -B tools/subaccount_create.py --out $P/subaccount-create.json --excerpts $P/objdump-excerpts.txt
```

- The tool checks the artifact SHA-256 before parsing and fails closed
  (`EvidenceError`, exit 2) on the first difference from a pinned fact.
- Output SHA-256 `f0b9e4b9addad4fafaa93e82c5f126b73d81a1b02ad3b4b5d31d70df869d8fe6`,
  identical across runs and under `PYTHONHASHSEED` 0, 7 and 99.
- `subaccount-create.json` and `objdump-excerpts.txt` are written by the tool and
  never hand-edited. The excerpt file records the objdump version and the exact
  `--start-address`/`--stop-address` of each window. Normalisation: objdump's
  leading file/section header lines are dropped and trailing whitespace is
  stripped; nothing else changes. The `<symbol+off>` annotations come from the
  dynamic symbol table and are not evidence. `verify.py` regenerates the excerpts
  and compares them byte for byte when GNU objdump with the recorded version is on
  `PATH`; otherwise it checks the headers and windows only and says so.
- The JSON keeps each panic `Location` path as the bytes in the binary. This README
  cites first-party paths without the build prefix `/home/ubuntu/hl/code_Mainnet/`
  (`l1/src/sub_account.rs` is `/home/ubuntu/hl/code_Mainnet/l1/src/sub_account.rs`).

Coordinate system: linked virtual addresses of instruction starts (REX prefix
included). `@va` marks the address of an instruction; `-> va` is a branch target.
The four `LOAD` segments map as: R (`.rodata`, `.eh_frame`, `.rela.*`) VA = file
offset; RE (`.text`, `.plt`) VA = file offset + `0x1000`; RELRO (`.data.rel.ro`,
`.got`, `.got.plt`) VA = file offset + `0x2000`; RW (`.data`; `.bss` has no file
bytes) VA = file offset + `0x3000`. Function windows are `.eh_frame_hdr` FDEs
(end-exclusive), read with `tools/state_roots.py`. Hash-table buckets are addressed
as hashbrown does: `bucket_end = ctrl - idx*stride`, `bucket = bucket_end - stride`.

Completeness: the analysis is limited to the 27 FDE windows listed in the JSON.
The handler, creator, deriver and name-helper windows were read in full with
objdump (control flow, every 16-bit store, every call). Their 44 call instructions
are all listed in the JSON (`calls`: 25 through a `.got` slot, 16 direct, 3 through
a register), and a test checks with objdump that the list is complete. Inside all
windows the tool re-checks only what is listed under Results. The other 23 windows
were read only around the cited sites, except `0x3743df0`, `0x358dcd0` and
`0x3596680`, which were read in full (whole-window excerpts).

## Observations (from the bytes)

### Dispatch

The dispatcher `0x2759240` computes `index = tag - 0x74` (`lea rcx,[rax-0x74]`,
`cmp rax,0x74`; tags below `0x74` use index 20) and jumps through the table at
`0x3ede28` (88 entries land inside the dispatcher). Exactly one index, 6, reaches
the arm `0x2759d2a`, whose `call` @`0x2759d4d` targets the handler `0x27e3140`:
tag 122. Index 1 (tag 117) reaches `0x27592bd`, which calls `0x1e5f770` (used in the
negative controls).

### Ordered checks, decision edges and status stores

Each callee writes a u16 status to its out pointer (`rdi`): at `[rbx]` in the
creator and the deriver, at `[r12]` in the name helper. The handler's out record
has an outer byte at `[rbx]`, `0xe` on every failure path (`0x27e356e`) and `0x6`
on success (`0x27e371c`), and the u16 status at `[rbx+0x8]`. A byte scan of the four
windows finds 15 16-bit stores, the same 15 objdump lists. 12 of them write the
status field (7 `imm16`, 5 from a register) and 3 do not (`0x36f3980` `[rbx+0x6]`,
`0x36f3b03` `[rsp+0xc]`, `0x36f3dfc` the Keccak delimiter at `[rsp+0x178]`).

| # | owner | decision | condition | failure edge; status store | pass edges |
|---|---|---|---|---|---|
| 1 | handler | `call` @`0x27e317d` (slot `0x5774f40` -> deriver); `jne` @`0x27e31a2` | deriver result != `0x186` | taken -> `0x27e32b5`; `eax` = `movzx [rsp+0x78]` @`0x27e3183`, stored by `mov [rbx+0x8],ax` @`0x27e356a` | fallthrough -> `0x27e31a8` |
| 2 | handler | `je` @`0x27e3284` | derived address is already a key of the table at `exchange+0x740` (probed only if `[exchange+0x758] != 0`; `0x58`-byte buckets) | taken -> `0x27e3348`; `0xd8` imm16 @`0x27e335e` (`[rbx+0x8]`) | `je` @`0x27e31da`, `jne` @`0x27e32a3` -> `0x27e3309` |
| 3 | handler | `call` @`0x27e3317` -> `0x275fee0` | volume operand `0x275fee0(exchange, &master)`; `rax` -> `[rsp+0x110]` @`0x27e331c` -> `r8` @`0x27e33b2` -> creator | none | |
| 4 | creator | `jae` @`0x36f362e` | `r8 < 0x989680` (unsigned); the creator's first test, right after its prologue | fallthrough -> `0x36f3630`; `0xdd` imm16 @`0x36f363d`, payload `(f64)r8 / 100.0` at `[rbx+0x8]` | taken -> `0x36f3658` |
| 5 | creator | `jae` @`0x36f375e` | only if the master has a `user_to_sub_accounts` entry: count `[bucket+0x28]` (Vec len) >= `min(r8*M >> 97, 40) + 10` | taken -> `0x36f39ca`; `0xd6` imm16 there | fallthrough -> `0x36f3764`; with no entry `je` @`0x36f3663`, `jne` @`0x36f3722` -> `0x36f3764` |
| 6 | creator | `call` @`0x36f376f` (slot `0x5774f40`); `jne` @`0x36f3791` | re-derive; result != `0x186` | taken -> `0x36f389f`; `eax` = `movzx [rsp+0x50]` @`0x36f3775`, stored by `mov [rbx],ax` @`0x36f38ed` | fallthrough -> `0x36f3797` |
| 7 | creator | `je` @`0x36f386e` | derived address is already a key of `sub_account_to_master` (tracker+`0x30`; probed only if `[tracker+0x48] != 0`; `0x28`-byte buckets) | taken -> `0x36f39d9`; `0xd8` imm16 @`0x36f39e9` | `je` @`0x36f37d3`, `jne` @`0x36f388d` -> `0x36f3901` |
| 8 | creator | `jbe` @`0x36f3910` | name byte length (`String` len, `[name+0x10]`) > 100 | fallthrough -> `0x36f3916` `mov bp,0x143`; stored by `mov [rbx],bp` @`0x36f39c5` | taken -> `0x36f3a17` |
| 9 | name helper | `ja` @`0x36f43d9` | byte length (`r8`) not in `1..=16`; the helper's first test, right after its prologue | fallthrough -> `0x36f43db`; `0xd9` imm16 there | taken -> `0x36f43e7` |
| 10 | name helper | `je` @`0x36f4537` | `0x1344900`(new name) equals `0x1344900`(name) of a record in the master's Vec (length compare, then `bcmp`) | taken -> `0x36f45ec` `mov bx,0xd7`; stored by `mov [r12],bx` @`0x36f45f4` | four edges -> `0x36f45b9`/`0x36f45bd`/`0x36f45c1`, which stores `bx = 0x186` |
| 11 | creator | `je` @`0x36f3a5e` after `call` @`0x36f3a54` -> `0x379ec60` | the insert (sub -> master) at tracker+`0x30` returned a previous value (tag byte 1) | taken -> `0x36f3bc6` panic, `Location` `l1/src/sub_account.rs:69:13` | fallthrough -> `0x36f3a64` |
| 12 | creator | `call` @`0x36f3a7f` -> `0x3596680` | push the `0x40`-byte record (`shl rcx,0x6`) into the Vec that `0x3596680(tracker+0, &master)` returns | `0x186` imm16 @`0x36f3af4` | |
| 13 | handler | `jne` @`0x27e33df` | creator result != `0x186` | taken -> `0x27e3516`; `eax` = `movzx [rsp+0x78]` @`0x27e33c0`, stored @`0x27e356a` | fallthrough -> `0x27e33e5`, then the tail below; outer byte `0x6` |

So there are 8 status-bearing rows (6 `imm16` stores; 2 register-mediated: `0x143`
loaded @`0x36f3916` and stored @`0x36f39c5`, `0xd7` loaded @`0x36f45ec` and stored
@`0x36f45f4`) and 5 control rows (calls 1, 3 and 6, the assert 11, the success tail
13). The creator returns a non-`0x186` name-helper status through the same `bp`
store: `movzx ebp,[rsp+0x50]` @`0x36f3a31`, `jne` @`0x36f3a3c` -> `0x36f3afe` ->
`0x36f39c5`. An objdump test checks that nothing writes `bp` on either path (only a
call, which preserves `rbp`, lies between).

Rows 1, 6 and 13 pass a callee's status on. In each, the u16 is loaded by
`movzx eax,WORD PTR [rsp+X]` right after the call, where `rsp+X` is the out pointer
the caller passed in `rdi` (`lea rdi,[rsp+X]` @`0x27e3172`, @`0x36f3764`,
@`0x27e339d`), and is compared by `cmp eax,0x186` right before the decision. The
failure paths are pinned: `0x27e32b5..0x27e3309` (ending in `jmp` @`0x27e3304` ->
`0x27e3565`) and `0x27e3565..0x27e356a` for row 1, `0x36f389f..0x36f38ed` for row 6,
`0x27e3516..0x27e356a` for row 13. The tool checks the load, the out pointer, the
compare, and that each path holds no call, conditional branch or `ret`. An objdump
test checks that no instruction on these ranges writes `eax`, either as a
destination or implicitly. The paths only copy the callee's payload (`xmm0..xmm3`,
`ecx`) into the out record.

The deriver's only status store is `0x186` @`0x36f3e8b`, and its only `ret` is
@`0x36f3e9f`. Its other exits are the call through `0x576dfb8` to `0x1346068`, a
21-byte function with no `ret` that ends in a call, and the code at
`0x36f3eb0..0x36f3ed0`, which ends in `call _Unwind_Resume@plt` @`0x36f3ecb` (the
`.plt` stub `0x5660110` jumps through `0x5778db0`, whose `JUMP_SLOT` relocation
names `_Unwind_Resume`). Nothing falls through into `0x36f3eb0`, because the call
before it does not return. So rows 1 and 6 are Result-typed calls to a callee that
only returns `0x186`.

The handler first probes the table at `exchange+0x740` (row 2), not
`sub_account_to_master`. The creator probes `sub_account_to_master` (row 7) after
the volume and cap checks.

Row 12: the creator copies the master to `rsp+0x50` and calls
`0x3596680(rdi = tracker+0, rsi = &master)` @`0x36f3a7f`. It then treats `rax` as a
Vec: it compares len `[rax+0x10]` with cap `[rax]` (growth through slot `0x5774478`
-> `0x32d6350`), writes the record through ptr `[rax+0x8]` and stores len+1 to
`[rax+0x10]` @`0x36f3add`. `0x3596680` (read in full) returns `X - 0x18` on both of
its paths, so `[rax+0x10]` is `[X-0x8]`. On the path where the probe `0x379a4d0`
reports a vacant slot, `X` is the end of a `0x30`-byte bucket: the path writes a
20-byte key at `X-0x30` and a Vec {cap 0, ptr 8, len 0} at `X-0x18..X-0x8`, then
increments the item count. There `[X-0x8]` is `[bucket_end-0x8]`, the field the cap
(row 5) and the deriver read. On the other (occupied) path, `X` is loaded from
`[rsp+0x18]` (@`0x359675c`), a word of the out record `rsp+0x10` passed to
`0x379a4d0`, which nothing in `0x3596680` writes; on the vacant path the same word is
ANDed with the bucket mask for the probe start (@`0x35966bf`) and shifted right by 57
for the control byte (`shr rax,0x39` @`0x35966ef`). That on the occupied path `X`
comes from the undecoded `0x379a4d0` and is the end of the master's bucket is an
inference (below).

Status messages, read from the status formatter `0x37ffd40` (it dispatches on the
u16 through the table at `0x59a8d0`; 390 entries, indices `0..0x185`, land inside it,
and index `0x186` is the first one outside):

| status | arm | message bytes |
|---|---|---|
| `0xd6` | `0x3800660` | "Too many sub-accounts." (`0x59d8d6`, 22 bytes) |
| `0xd7` | `0x3802421` | "Sub-account name already taken." (`0x59d8ec`, 31) |
| `0xd8` | `0x3801ea7` | template `0x1fd63e` "Duplicate sub-account user {}", argument status+2 (the address) |
| `0xd9` | `0x380292e` | "Sub-account name must be between 1 and 16 characters long." (`0x59d90b`, 58) |
| `0xdd` | `0x3800e28` | template `0x1e2b81` "Cannot create sub-accounts until enough volume traded. Required: ${}. Traded: ${}." |
| `0x143` | `0x38011e8` | "Invalid input length" (`0x59e443`, 20) |

The templates are shown with `{}` where the raw bytes hold a `0xc0` argument
marker. The marker encoding (rustc's) is not decoded further, and the raw bytes
are pinned.

### The volume operand

The creator gates on `r8` (row 4) and uses it for the cap (row 5). The bytes show
the following about it.

1. **The message.** The `0xdd` arm builds two format arguments. `args[0]` points at
   `100000.0` (`movabs rax,0x40f86a0000000000` @`0x3800e31`, stored at `[rsp]`; its
   formatter pointer is loaded from `0x57739b0` @`0x3800e47`). `args[1]` points at
   `[rsp+0x40]`, which holds status+8 (`add rdi,0x8` @`0x3800e28`); its formatter is
   `0x37ece50` (@`0x3800e5d`). Status+8 is the f64 the creator writes on the failure
   path: `cvtsi2sd xmm0,r8` @`0x36f3630`, `divsd` by the 100.0 at `0x20a960`, and
   `movsd [rbx+0x8]` @`0x36f3642`. The template text is "Cannot create sub-accounts
   until enough volume traded. Required: $", a marker, ". Traded: $", a marker and
   ".". `100000.0` equals `0x989680 / 100.0` (the tool checks this). If the two
   markers take `args[0]` and `args[1]` in order, which is assumed and not decoded,
   the message prints the threshold / 100 after "Required: $" and the operand / 100
   after "Traded: $".
2. **The producer and the fold.** `0x275fee0(exchange, &master)` probes
   `user_to_sub_accounts` (`exchange+0x37e0` = tracker+0, `0x30`-byte buckets, key
   compared with the master). It builds an iterator state at `rsp+0x20`:
   `[+0x0]=1`; `[+0x8]` = the Vec in the master's bucket (bucket+`0x18`) or 0;
   `[+0x10]=0`; `[+0x20]=0`; and a once(master) tag 1 at `[+0x30]` with the master
   at `[+0x31]`. It then calls the fold, `call 0x258b4e0` @`0x2760033` with
   `rdx = exchange`, followed by `add rsp,0x68; pop; pop; ret`. That is an ordinary
   call, not a tail call. The fold stores `rdx` at `[rsp+0x10]` @`0x258b4f1`. It calls
   the step `0x2773bb0` for the once() address (@`0x258b533`) with `ctx = rsp`, where
   `[rsp] = rsp+0x10`. Because `[state] & 1`, it then calls `0x26b2180(&Vec, acc,
   rsp+0x8)` @`0x258b5e4`, where `[rsp+0x8]` is a copy of `[rsp+0x10]`. Its two slice
   loops are skipped here, since `[+0x10]` and `[+0x20]` are null.
3. **The step** `0x2773bb0(ctx, acc, &user)` reads `exchange = [[ctx]]`
   (@`0x2773bc1`, @`0x2773bc4`) and returns `acc + (L + R)` (`ret` @`0x2773d03`).
   - `R` is the sum, over the `[exchange+0x5c8]` records of `0x2f0` bytes that
     start at `[exchange+0x5c0]` (`imul rbp,rax,0x2f0` @`0x2773bfc`; the loop advances
     by `0x2f0` @`0x2773c49`), of `[result+0x40]`, where `result =
     0x36f57f0(record+0xf8, &user)` (`add r12,0xf8` @`0x2773c03`, call @`0x2773c2c`).
   - `L` is `[result+0x0]` of a lookup of the user at `exchange+0x80` through slot
     `0x5773170` (@`0x2773cd3`).
   - A parallel sum, the `[result+0x48]` values plus the lookup's `[+0x8]`, is only
     overflow-checked (`not` @`0x2773cb1`, then `cmp` @`0x2773ce8` and `ja`
     @`0x2773ceb`) and is not returned.
4. **The Vec fold** `0x26b2180` reads `exchange = [rdx]` (@`0x26b21af`) and walks the
   Vec's `0x40`-byte records (`shl rax,0x6` @`0x26b21d8`). For each record it takes
   the 20 bytes at record+`0x18` (@`0x26b21e9`), the sub-account address field the
   creator writes @`0x36f3abc`/`0x36f3ac5`. For that address it sums
   `[value+0x40]`/`[value+0x48]` over the same table (`[exchange+0x5c8]` records from
   `[exchange+0x5c0]`, `imul rax,rax,0x2f0` @`0x26b2229`), probing the map at
   record+`0xf8` inline (mask `+0x100`, items `+0x110`, hasher state `+0x118`;
   `0x78`-byte buckets, `imul r9,r9,0x78` @`0x26b22cc`), with a default value at
   `0x57862a0` when the key is absent. It then looks the address up at `exchange+0x80`
   through the same slot `0x5773170` (@`0x26b2477`). The tool's link checks that the
   two functions use the same fields, strides and offsets. That this inline probe
   returns the same value as the step's `0x36f57f0(record+0xf8, &user)` is an
   inference (below): `0x36f57f0` is not decoded here.
5. **Overflow.** Every add of these sums is checked for carry with `jb`/`jae`. On a
   carry the code calls slot `0x5773190` -> `0x358dcd0` with a `Location` in `rsi`,
   then saturates the sum to `0xffffffffffffffff` with `cmov`. `0x358dcd0` returns: its
   window (read in full, excerpted) holds exactly two `ret`s, @`0x358dd54` and
   @`0x358de0c`, both pinned. The step reports these `Location`s:
   - `l1/src/scaled_vlm.rs:15:21` for `L + R` (@`0x2773d04`);
   - `l1/src/raw_vlm.rs:17:21` for the parallel sum (@`0x2773d26`);
   - `l1/src/qtys/impl_ntl.rs:664:1` for the per-record sums and `acc + ...`
     (@`0x2773c63`, @`0x2773c91`, @`0x2773d3d`).

   `0x26b2180` references the same three files.
6. **Arithmetic census** (objdump test over both whole windows). The step has one
   multiply, `imul rbp,rax,0x2f0` @`0x2773bfc` (the record-table size). The Vec fold
   has two, `imul rax,rax,0x2f0` @`0x26b2229` (the record-table end) and
   `imul r9,r9,0x78` @`0x26b22cc` (the bucket offset of its map probe). No multiply
   takes a volume value. Neither function has a `jo`, `seto`, `sar`, `idiv`, `movsx`,
   or a signed `jcc`, `setcc` or `cmovcc`.

Signedness: the gate is an unsigned `cmp`/`jae` and the cap uses an unsigned `mul`.
`cvtsi2sd` runs only on the branch where `r8 < 0x989680`, where signed and unsigned
readings agree. The operand is a u64 accumulated with unsigned saturation, so a
value with the high bit set is a large unsigned value, not a negative one.

### The two-tier name limit (byte length)

`r15 = [name+0x10]` (`String` len, @`0x36f3908`); `cmp r15,0x64; jbe` -> else `0x143`.
The creator then passes `r8 = r15` (`mov r8,r15` @`0x36f3a29`) to the name
helper (`call` @`0x36f3a2c` -> `0x36f43c0`). Right after its prologue (and
`mov r12,rdi`) the helper runs `lea rax,[r8-0x11]; cmp rax,0xffffffffffffffef; ja`,
which is valid iff `len` is in `1..=16`. The tool derives the bounds 1 and 16 from
the two immediates. Result: 0 -> `0xd9`, 1..16 pass, 17..100 -> `0xd9`, 101 and up ->
`0x143`. The unit is the UTF-8 byte length (`String` len), even though the `0xd9`
message says "characters".

### The duplicate-name check compares outputs of `0x1344900`

The new name is passed through slot `0x576e050` (-> `0x1344900`) @`0x36f43f8`. For
each record of the master's Vec (name ptr/len at record+`0x8`/`+0x10`), the record's
name goes through the same function (`call r15` @`0x36f4553`, where `r15` was
loaded from `0x576e050` @`0x36f4506`/`0x36f4530`). Then the two output lengths are
compared (@`0x36f4556`) and the bytes are compared with `bcmp` (GLOB_DAT slot
`0x576e378`, @`0x36f4576`). If they are equal, the status is `0xd7`. That
`0x1344900` lowercases, which would make the check case-insensitive, is an
inference (below).

### The cap reciprocal

`movabs rdx,0xdbe6fecebdedd5bf; mul rdx; shr rdx,0x21` is the high word `>> 33`,
that is the full product `>> 97`. Then `cmp rdx,0x28; mov eax,0x28; cmovb` clamps
to 40, and `add rax,0xa` adds 10. The tool takes the magic and the shift from the
bytes and derives the divisor `D = ceil(2^97 / M) = 10^10`. `M` equals
`ceil(2^97 / D)`, and `(M*D - 2^97) * (2^64 - 1) < 2^97` (`M*D - 2^97 = 2912099328`).
So `floor(x*M >> 97) == x // 10^10` holds for every u64. `M - 1` fails on 2 of the 3
controls `x = D`, `2D` and `2^64 - 1`. The cap is `min(operand // 10^10, 40) + 10`, in
`10..=50`. A count must stay below it: q=39 -> 49, q=40 -> 50, q=41 -> 50,
2^64-1 -> 50.

### Address derivation

- Count: the Vec length `[bucket+0x28]` (`[bucket_end-0x8]`, `mov r15,[rcx+r9-0x8]`
  @`0x36f3d0e`) of the master's `user_to_sub_accounts` bucket. It is 0 when the map
  is empty or the master is absent. This is the same field the cap compares
  (`[rsi+r10-0x8]`).
- Label: `movups xmm0,[rip->0x2035a0]` loads `b'createSubAccount'` into a 16-byte
  allocation.
- Tokens (builder `0x3c97900`, which keeps its `rsi` = the deriver's `rsp+0x68` in
  `r15`): a `0x78`-byte allocation holds 3 tokens of `0x28` bytes each. Token 0 is
  tag 6 (the label String, payload at +8). Token 1 is tag 0 at +`0x28` (the 20-byte
  master at +`0x29`). Token 2 is tag 4 at +`0x50` (limbs at +`0x58`: count, 0, 0, 0).
  The 3 tokens are encoded through slot `0x576ed20` (-> `0x1592160`). The tag
  numbering comes from the ethabi `Token` Debug impl `0x15906a0`, whose table
  `0x25fa64` decodes to `0 Address, 1 FixedBytes, 2 Bytes, 3 Int, 4 Uint, 5 Bool,
  6 String, 7 FixedArray, 8 Array, 9 Tuple`. Its arms put the payload at +1 for
  Address and Bool and at +8 otherwise, which matches the builder's stores.
- Uint word: `0x1592160` calls `0x1591f20` (@`0x1592255`), which calls the word writer
  `0x1591cd0` with a Token pointer in `rsi` (@`0x159200d`, @`0x15920d3`). The writer
  dispatches on the tag byte (`cmp rax,0x6; ja`, table `0x25fba4`). Tags 3 (Int) and
  4 (Uint) reach the arm `0x1591d24`, and no other tag does. That arm loads the four
  limbs at token+`0x8..0x28`, byte-swaps each (`bswap` @`0x1591d34..0x1591d3d`) and
  stores them as one 32-byte word (`shl rcx,0x5`): limb 3 at +`0x0`, limb 2 at +`0x8`,
  limb 1 at +`0x10`, limb 0 at +`0x18`. That is a big-endian 256-bit word, so the count
  (limb 0) fills word bytes 24..32 big-endian. The tool decodes the registers of
  these loads, swaps and stores, and the model's third head word is checked against
  this layout. Tags 2 and 6 share the arm `0x1591d03`; the other arms are not decoded.
- Keccak: the state sits at `rsp+0xa0` (`0xe0` bytes). Rate `0x88` is at +`0xd0`,
  the delimiter `0x01` at +`0xd8`, and a 0 byte at +`0xd9`. Update goes through slot
  `0x576e1d8` (-> `0x4f59a10`). The state is copied (memcpy, `0xe0` bytes). Finalize
  goes through slot `0x576e1e0` (-> `0x4f59e40`) and writes `0x20` bytes at
  `rsp+0x20`. Both reach keccak-f `0x4f59480` through slot `0x5777790`. Its loop runs
  24 rounds (`cmp rdx,0xc0`) over the table at `0x7d04c8`, and all 24 entries equal
  the rc(t) LFSR constants.
- Kept bytes: the digest is copied to `rsp+0x40..0x60`. `[out+0x2..0x12]` gets
  digest[0..16] (from `rsp+0x40`) and `[out+0x12..0x16]` gets digest[16..20] (dword
  from `rsp+0x50`). The address is therefore digest bytes `0..20`. The tool derives
  this slice from the eight displacements.

### Post-success tail (row 13)

Two calls go through slot `0x57748f8` (-> `0x3743df0`) with `rsi = exchange+0x5d0`:
first for the master (output `rsp+0x140`, @`0x27e341a`), then for the sub (output
`rsp+0x78`, @`0x27e3438`). `0x3743df0` writes only through its output pointer: every
store in its window goes through `rax = rdi` (read in full, test + excerpt). For
the keys 20 x `0xff` (`0x59c0e4`) and 20 x `0xfe` (`0x59c0f8`), compared as 16 + 4
bytes @`0x3743dfa..0x3743e64`, it returns zeroed fields. Otherwise it returns the
record from an `0xe8`-byte-bucket table at `[rsi+0xc0]` when one is present and
flagged, or a default record (`[rsi+0x48..0x68]`, with 1.0 at +`0x70`). The handler
then compares the two results field by field (`ucomisd`/`cmp` from `0x27e343a`).
Only if a field differs does it call `0x1f84840(exchange+0x690, &sub)`, store qword 1
at `[rax]` and copy the master's `0x78`-byte result to `[rax+0x8..0x80]`. After that
it calls `0x1f849b0(exchange+0x740, &sub)` (the table probed in row 2) and
`0x1f84b30(exchange+0x318, &sub)`. Finally it writes the outer byte `0x6` and the
sub address to `[out+0x1..0x15]`. The callees' semantics are not decoded here. Labels
such as "clearinghouse init" or "get_or_create_user_account" are reference
labels and are not established.

### Library identity (panic `Location` records, each referenced by a lea in the named function)

- ethabi-18.0.0 `src/encoder.rs` 113:65, 113:90 and 115:41 are inside `0x1592160`
  (leas `0x15921a0`, `0x159230b`, `0x1592324`).
- tiny-keccak-2.0.2 `src/lib.rs:312:32` is inside `0x4f59a10` (`0x4f59cfe`) and
  `0x4f59e40` (`0x4f5a04b`).
- alloc `src/str.rs` 415:63 and 416:51 are inside `0x1344900` (`0x1344ab5`,
  `0x1345529`).
- The insert assert's first-party `Location` is `l1/src/sub_account.rs:69:13`
  (`0x56f1c38`). Its message is the 85-byte string at `0x598ead`: "assertion failed:
  self.sub_account_to_master.insert(sub_account_user, user).is_none()".

## Inferences (labelled)

- **Volume operand.** The operand is the traded volume of the master plus that of
  the addresses in its Vec (its existing sub-accounts), not an equity. It is in raw
  units shown divided by 100 as USD (1 raw = $0.01). This rests on the `0xdd`
  message text ("enough volume traded", "Traded: $") and on the assumed
  marker-to-argument order. It also rests on the aggregation over the master and
  the Vec's record+`0x18` addresses (with the Vec fold's inline probe taken to
  return what `0x36f57f0` returns in the step), and on the
  `scaled_vlm.rs`/`raw_vlm.rs` file names. That the returned per-user value is the
  "scaled" volume rests only on its overflow site being `scaled_vlm.rs:15:21`.
  "equity" is the reference's label, and the message text contradicts it.
- **The duplicate-name check is case-insensitive.** This needs `0x1344900` to be
  alloc's `str::to_lowercase`. That rests on the two `str.rs` `Location` records
  inside it and the final-sigma compare `cmp esi,0x3a3` @`0x1344b89`. It is not a
  symbol.
- **The Vec of row 12 is the master's.** `0x3596680` is called with tracker+0 (the
  `user_to_sub_accounts` map that the producer and the deriver probe for the master)
  and `&master`. On its vacant path the result's `+0x10` is `[bucket_end-0x8]` of the
  new bucket, the field the cap reads. On the occupied path `X` comes from
  `0x379a4d0`, which also does the key match; that `X` is the end of the master's
  bucket there rests on that function, which is not decoded.
- **Rows 1 and 6.** Their failure edges are not reached, because the deriver has
  no other status (see above).
- **`0x2840fb0` and `0x399c7a0` are hash functions.** In the objdump reading, their
  results are shifted right by 57 and masked before each SSE group probe, as
  hashbrown does with a hash. They are not pinned or decoded.
- **`0x186` is the Ok niche.** It is the success value, and it is the first index
  outside the formatter's table.
- **Map and record names.** The serde strings
  "user_to_sub_accountssub_account_to_masterstruct SubAccountTracker with 2
  elements" (`0x3b02e5`) and "struct SubAccount with 3 elements" (`0x3afeca`) fit
  two maps at tracker+`0x0`/`+0x30` and a 3-field `0x40`-byte record (name `String`,
  sub address, master address). No xref from these strings to the code is
  established here. "SubAccountEntry" does not occur in the binary.
- **Derivation model.** `address = keccak256(ethabi::encode([String("createSubAccount"),
  Address(master), Uint(count)]))[0..20]`. From the bytes come the literal, the token
  order and tags, the count source and limb, the Uint word layout, the rate, the
  delimiter, the round constants, the digest length and the kept slice. The rest of
  the head/tail layout of `0x1592160` is the standard one and is assumed, not
  proven word by word: which word goes where, the `0x60` offset word, the Address
  word, and the String length and padding. The 160-byte preimage is the model's
  length; it is not read from the binary. No target-produced address vector exists
  offline, so the sample addresses in the JSON are model outputs.

## Negative controls

- **Sibling.** The one sibling examined (1/1), `0x36f40d0`, is the other direct
  caller of the name helper (`call` @`0x36f4250` -> `0x36f43c0`). It has its own
  `cmp r8,0x64` (@`0x36f41d2`), `0x143` (@`0x36f41d8`) and two `0xdc` stores
  (@`0x36f4211`, @`0x36f434c`). Byte scans of its FDE window find no `0x989680`
  immediate and no reciprocal magic (0 and 0). As a positive control, the same
  scans find 1 and 1 in the creator.
- **The gate and the cap are not exclusive to creation.** The producer
  `0x275fee0` has exactly 2 E8 rel32 callers in `.text`: the handler (@`0x27e3317`)
  and `0x2766f70` (@`0x27677d4`). `0x2766f70` uses the same threshold compare
  (`cmp rax,0x989680` @`0x27677e3`) and the same cap formula (@`0x2767860`) to set
  `r9`. Below the threshold `r9` is 0 (@`0x27677eb`); a third path sets 10
  (@`0x27677aa`). It passes `r9` to `0x3421e20` through slot `0x5774dc0`
  (@`0x2767925`). `0x2766f70` is reached from dispatcher index 1 (tag 117; RE-010's
  reference label is approveAgent) through `0x1e5f770` (`call` @`0x1e5f8ec`).
  `0x3421e20` saves `r9` at `[rsp+0x30]` in its prologue (@`0x3421e31`), copies its
  `rdi` to `r15` (@`0x3421e39`) and returns `r15` (@`0x3422345`). It stores the u16
  `0x57` to `[r15]` @`0x3422368` and `r14` to `[r15+0x8]`. Between the copy and
  these uses, `r15` is spilled (@`0x3421f9b`), reused (@`0x3421fe4`) and reloaded
  (@`0x34220a1`, @`0x34221c0`); in the objdump reading (these four sites are not
  pinned) it holds `rdi` again at both stores and at the return. The status
  formatter's arm for `0x57` (`0x3800578`) prints status+8 with template
  `0x1fa4f2`, "Too many extra agents for cumulative volume traded. Current limit is
  {}". Whether the saved `r9` becomes that `r14` is not traced, so the purpose of
  this gate is not established here. Across `.text`, the `0x989680` imm32 pattern
  has 48 hits in 30 FDE windows, and the magic has 7 hits in 7.
- **Tool controls (`tests/test_subaccount_create.py`, 20 tests).**
  - 168 fail-closed controls, each asserting its own error message: 81 single-site
    byte mutations of the target with the digest re-pinned, 1 wrong-digest control,
    51 re-pinned cases, 3 byte patches combined with an in-memory table change, and
    32 unit controls. In the re-pinned cases the binary and the pinned bytes change
    together, so the shape check passes and the semantic check behind it fires on
    its own; one of them also changes the pinned caller lists. The unit controls
    change a pinned table in memory or call a helper directly.
  - Guard inventory: the tool has 94 `raise EvidenceError` lines (besides the one
    inside `link()`) and 18 `link()` calls (21 link checks, since one call runs over
    4 prologue pairs). `test_guard_inventory` maps each of these 112 guard lines to
    one named control (110) or to the defensive list (2: the dispatcher and
    formatter table-termination guards, which would need more than 512 and 4096
    in-function entries).
  - Guard mutants: `test_guard_mutants_killed` applies 122 mutants to the tool
    source in memory, one at a time. 110 turn one guard line into a no-op: the raise
    becomes a discarded call, or the link is skipped. 12 remove one item: each of
    the six `0x186` compares, each of the four prologue pairs, the reciprocal
    error-bound clause and the `alloc_fail` no-ret clause. A mutant counts as killed
    when its named control no longer produces the control's message; 122/122 are
    killed. A guard line often checks many items (every shape, every slot) and its
    control exercises one of them, so this shows a killing control for every guard
    line, not for every item.
  - Objdump and readelf cross-checks (GNU binutils only; with another `objdump` or
    `readelf` they are skipped): instruction boundaries and bytes of every pinned
    shape, the 16-bit stores, slot references and the complete call list, the
    callers, the deriver's exits, the rets of `0x358dcd0`, the register paths of
    rows 1, 6, 8 and 13, the arithmetic census, the excerpts, and the slot and
    `JUMP_SLOT` relocations.
  - `verify.py` is tested on tampered copies: an extra file, a missing MANIFEST line,
    a changed README, a JSON edit with the MANIFEST refreshed, an excerpt window
    edit with the MANIFEST refreshed, and (with the recorded objdump) an excerpt
    body edit with the MANIFEST refreshed.
- **Keccak model.** With delimiter `0x06` the sponge equals `hashlib.sha3_256`:
  11/11 lengths in the tool and 52 distinct lengths in the tests (0..294 in steps of
  7, which includes 273, plus 135, 136, 137, 160, 271, 272, 408, 1000 and 4096 bytes).
  SHA3 and Keccak differ on the empty input. The digest slice `[12..32]` differs from
  the kept `[0..20]` in every sample.

## Related work

Read-only `gh pr diff` of the PRs below; their text was read as data.

- #21 (merged, RE-010) maps index 6 / tag 122 -> `0x2759d2a` -> `0x27e3140` and
  index 1 / tag 117 -> `0x27592bd` -> `0x1e5f770` with the same tag bias. It records
  the FDE windows `0x36f3610..0x36f3c15` and `0x36f3c20..0x36f3ed0`. This packet
  agrees.
- #8 (merged, bridge) has an encoder that writes tags 6, 0, 0, 4, 4 and calls the
  same finisher `0x1592160`. That fits the Token Debug decode here (6 String,
  0 Address, 4 Uint). Its next question, the finisher's per-tag word rules, overlaps
  the open question here; this packet decodes only the Int/Uint word.
- #23 (merged, RE-009) records `0x4f59480` as the only function that references the
  RC table `0x7d04c8`. #145 (open, RE-005) reaches the same keccak-f through slot
  `0x5777790` with rate 136 and delimiter 0x01. Both are consistent with the Keccak
  identity here.
- #117 (open, fees) reads the same per-user lookups for another gate: the
  `0x2f0`-byte records with the map at `+0xf8`, `0x36f57f0` with `+0x40`/`+0x48`, and
  the slot `0x5773170` lookup at `+0x80` with `+0`/`+8`. It also finds that the second
  sum is only checked, and its message has the same "enough volume traded.
  Required: $ ... Traded: $" form. Its scaled/raw labels are its own. #182 (open,
  fees) also calls `0x36f57f0` and `0x371b3a0`.
- #234 (open, RE-004) lists `0x2773bb0` and `0x26b2180` among the users of these
  `Location`s and states that slot `0x5773190` -> `0x358dcd0` starts an FDE and has
  `ret` rows. This is consistent with the two rets pinned here.
- #228 (open, fees) reads `0x3743df0` as a per-address fee "rate row" (20 x `0xff`
  and 20 x `0xfe` give an all-zero row; table at `+0xc0` with `0xe8`-byte buckets;
  default at `+0x48..0x68`). The structure agrees with the reading here. The fee
  reading is a lead and is not adopted.
- #102 (open) names `0x358dcd0` only as an undecoded callee. #260 (open) shows one
  of the 48 `.text` `0x989680` hits (`0x3956628`) and loads of the global
  `0x577ab98` in its own functions. Neither overlaps the code analysed here.

## Implementation and comparison

Not yet implemented/measured. No Rust implementation or Cargo manifest is added, so
there are no raw-equal or normalized body counts and no build result. The
reference tree has no manifest, and the build-provenance task is open. A later
implementation has to reproduce the bytes above:

- the order of rows 2, 4, 5, 7, 8, 9, 10 and 11;
- the cap is skipped when the master has no entry;
- the unsigned u64 operand, with saturation;
- the byte-length tiers;
- the duplicate check on `0x1344900` outputs;
- `0x186` as success, and the propagation of the callees' statuses;
- the `[0..20]` digest slice of the ethabi/Keccak preimage, with a big-endian Uint
  count word;
- the post-success tail.

## Results and limitations (with denominators)

- Function windows (FDE start and end pinned): 27/27.
- Pinned instruction windows: 191 (989 instructions, 4291 bytes). Each is verified
  byte for byte and lies inside its owner window. Under objdump, decoding from the
  FDE start gives the same instruction starts and bytes (test).
- Direct branch and call edges decoded from those bytes: 99. Call targets are FDE
  starts and jumps stay in their function. RIP-relative data references: 24.
  Decoded immediates and displacements: 178. Cross-site link checks: 21.
- 16-bit stores in the four windows: 15 (byte scan = objdump). 12 write the status
  field (7 imm16 + 5 register); 3 do not.
- Check rows: 13 = 8 status-bearing (6 imm16 + 2 register-mediated) + 5 control
  rows. Every decision, pass edge and failure edge is decoded, and its mnemonic and
  target are checked. The 3 propagated statuses (rows 1, 6, 13) are checked from the
  load to the store.
- Calls in the four windows: 44/44 listed (25 through a slot, 16 direct, 3 through
  a register; objdump test). The 25 slot calls use 13 distinct `.got` slots (11
  `R_X86_64_RELATIVE` to FDE starts, 2 `GLOB_DAT`: memcpy, bcmp). The 16 direct calls
  are checked to their FDE start or, for the 3 `_Unwind_Resume` calls, to their
  `.plt` stub and `JUMP_SLOT` symbol.
- Call slots: the five windows (the four plus the builder) make 35 references to
  17 distinct `.got` slots, and all 17 are resolved (15 `R_X86_64_RELATIVE` to FDE
  starts, 2 `GLOB_DAT`: memcpy, bcmp; readelf agrees). 4 more cited slots
  (`0x5777790`, `0x5774dc0`, `0x5773190`, `0x5773170`) are checked the same way.
- `Location` records: 11. All 18 cited lea sites are inside the named functions.
- Status formatter: 7 arms decoded to message or template bytes (the 6 statuses of
  this path and `0x57`); 390 table entries.
- Token Debug: 10/10 variant names. Word writer: 7/7 tag arms, 2 reaching the
  Int/Uint arm.
- Dispatch: 88 entries, 1 index reaching the tag-122 arm.
- Direct E8 callers pinned: the handler has 1, the name helper 2, the producer 2,
  the fold 3, the step 3, the Vec fold 1, `0x3596680` 1, `0x1591f20` 3, the word
  writer 2, `0x2766f70` 1 and `0x1e5f770` 1. The creator, the deriver, `0x358dcd0`
  and `0x3421e20` have 0; each is reached through one RELATIVE slot.
- Keccak: known-answer tests 2/2; round constants 24/24. The model's Uint word
  matches the word writer's layout in 4/4 samples.
- Reciprocal: exact for all u64 by certificate; 7/7 boundary vectors; the tests
  add 20,000 random u64 and boundary points.
- Excerpts: 56 objdump windows.
- Repository checks on this commit:
  - `python3 -B -m unittest discover -s tests`: 375 tests, 20 errors, no failures.
    Base `1f8c67c` gives 355 tests with the same 20 errors (same test names). All 20
    are caused by the `references/can1357-hl` submodule not being checked out in
    this clone: 19 `FileNotFoundError` plus one subprocess that hits the same
    missing file. The 20 tests of this packet pass.
  - `python3 tools/catalogue.py --check`: fails with "Stale catalogue:
    research/catalogue/components.json". The same failure occurs at base `1f8c67c`
    with the same binaries, so it predates this packet, which touches no catalogue
    input.
  - `python3 tools/verify_imports.py`: fails, "Missing pinned source:
    references/can1357-hl". The submodule is not checked out in this clone; same
    at base.
  - `python3 tools/artifacts.py verify` was not re-run for this revision (it can
    start gpg-agent). An earlier run on this branch gave 8/8 SHA-256 OK and 3/3
    signatures valid, then stopped at the pinned-pair check for the same missing
    submodule. This revision changes no artifact.
  - `git diff --check`: clean.

Unknowns:

- what the per-user fields at `[lookup(user)+0x0]`/`+0x8` and at
  `[0x36f57f0(record+0xf8, &user)+0x40]`/`+0x48` hold (the semantic origin of the
  volume);
- what `0x2766f70`/`0x3421e20` use the same gate and cap for, and whether `r9`
  becomes the `0x57` payload;
- the internals of the callees listed under Scope excluded, in particular
  `0x379a4d0` (which bucket `0x3596680` returns on its occupied path), `0x36f57f0`
  (whether it returns what the Vec fold's inline probe reads) and `0x379ec60`;
- the head/tail word layout of the encoder `0x1592160` beyond the Uint word;
- a target-produced address vector.

## Diff against the reference (leads only)

The can1357 files are unlicensed inferred code. No reference code was copied.

`l1/exchange/impl_create_sub_account.rs` disagrees with the bytes on 7 points:

| topic | that file | this binary |
|---|---|---|
| kept hash slice | `hash[12..32]` | digest `[0..20]` |
| preimage | concat `label \|\| master \|\| count_le` | ethabi `[String, Address, Uint]` (count big-endian in its word; model: 160 bytes) |
| count source | a separate `master_to_sub_count` map | the Vec length in the same `user_to_sub_accounts` bucket |
| name limit | one rule, `len > 100 -> 323` | two tiers: `> 100 -> 0x143`, then `1..=16` bytes else `0xd9` |
| outcomes | `AlreadyExists`, `TooManySubs`, `InsufficientEquity` (no numeric codes) and `Error { status: 323 }` | `0xd8` (twice), `0xdd`, `0xd6`, `0x143`, `0xd9`, `0xd7` |
| hash function | "likely keccak256", `todo!()` | Keccak-256 (rate 136, delimiter 0x01, 24 rounds, RC table `0x7d04c8`) |
| first duplicate probe | `sub_to_master` | the table at `exchange+0x740` (handler), then `sub_account_to_master` (creator) |

The file is not consistent with itself on one more point. Its doc comment
(l.136-137) lists the name validation before the second `sub_to_master` check. Its
function body (l.185-197) does the second check first and then the name length,
which is the binary's order (row 7 before rows 8-10).

`l1/exchange/handlers/06_create_sub_account.rs` and `l1/sub_account.rs` already
agree with the bytes on several of these:

- the digest `[0..20]` (`address_from_digest`, `sub_account.rs:462`; `handlers/06`
  leaves the digest abstract);
- the `1..=16`/100 tiers (`sub_account.rs:22-23`, `handlers/06:23-24`);
- statuses 215/217 (`0xd7`/`0xd9`);
- the count as `Vec::len` (`handlers/06:129`);
- the handler's check of a table before any volume work (216, `handlers/06:96`,
  which calls it a global user-account table; that name is the reference's label);
- the order: `sub_account_to_master` collision, then wire length, then canonical
  length and uniqueness (`handlers/06:225-227`).

The threshold `0x989680`, the `/100.0` scaling and the `min(.., 40) + 10` cap
agree in all three files. These differences remain:

| topic | reference (file) | this binary |
|---|---|---|
| gated quantity | "equity" in all three (`user_equity_raw`, `InsufficientEquity`, `SubAccountsNotEligible { equity_raw }`) | the `0xdd` message says "enough volume traded" and prints the operand after "Traded: $"; "equity" is contradicted by the message text (see Inferences) |
| duplicate-name compare | byte-exact in `handlers/06:169` and `sub_account.rs:204` (`entry.name.as_bytes() == name.as_bytes()`); none in `impl_create_sub_account.rs` | both sides pass through `0x1344900` (@`0x36f43f8`, @`0x36f4553`), then `bcmp` |
| address digest | an abstract digest function in `handlers/06` and `sub_account.rs` | ethabi `(String, Address, Uint)` encoding with legacy Keccak-256 (beyond the Uint word, the layout is a model) |
| post-success state | `handlers/06` caches the sub-account's snapshot when the two differ | inserts a copy of the master's lookup result under the sub key at `exchange+0x690`, only when the two differ |
| record type name | `SubAccountEntry` in all three | not a string in the binary; serde says "struct SubAccount with 3 elements" |

## Files

| file | what |
|---|---|
| `subaccount-create.json` | tool output: function windows, pinned instruction windows, decoded edges, immediates, rip references, dispatch, 16-bit stores, check order with the propagation paths, call sites, call slots, callers, `Location`s, literals, formatter arms, Token variants, word writer, byte scans, links, kept digest bytes, constants, layouts, reciprocal proof, cap boundaries, derivation model |
| `objdump-excerpts.txt` | 56 objdump windows covering every pinned instruction window (and the whole of `0x3743df0`, `0x358dcd0` and `0x3596680`), written by the tool |
| `verify.py` | exact manifest file set, regenerated JSON hash and bytes, excerpt windows (and bodies with the recorded objdump), pinned facts |
| `MANIFEST.sha256` | SHA-256 of the four files above |

The tool is `tools/subaccount_create.py`; the tests are `tests/test_subaccount_create.py`.
This packet requests no acceptance gate. It is a bounded static result for node #94 only.

Next question: decode `0x1592160` word by word (the head offsets, the Address word,
the String length and padding), so that the derivation stops being a model; and
trace the saved `r9` through `0x3421e20` to the `0x57` payload, to settle what the
second gate limits.
