# RE-001: node115 program entry point and Rust `main` handoff

- Component ID: node-runtime (startup); contributes to the RE-001 #115 entrypoint/xref map. No acceptance gate requested.
- Target release and full SHA-256: node115, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: analysis against the pinned capture only; new tooling/docs independently authored under the root MIT license. No inferred unlicensed code is copied.
- Claim status: observation (byte-anchored) plus inference (glibc / Rust `std::rt::lang_start` ABI naming).
- Scope included: the ELF entry function `_start`, its `__libc_start_main` call site and arguments, and the Rust `main` shim that tail-calls `std::rt::lang_start_internal`, with the two callee relocations and the resolved user `main` and `&dyn Fn` operands.
- Scope excluded: the `__libc_start_main` body, the `lang_start_internal` body at `0x5c99970`, the user `main` at `0x2cd8370`, runtime side effects, and any Rust reconstruction/equivalence gate.

## Reproduce

macOS/Linux; Python 3; GNU `readelf`/`objdump` (Debian binutils 2.44 used here). From the repo root with the materialized, authenticated node #115 binary (`git lfs pull`):

~~~sh
python3 -B tools/entry_start_static.py --output work/entry-start115
python3 -B -m unittest discover -s tests -p test_entry_start_static.py -v
python3 tools/artifacts.py verify && python3 tools/verify_packets.py && python3 tools/catalogue.py --check
~~~

`generate()` authenticates the full capture (size and SHA-256) before any interpretation or native call; the committed `records.json`, `frames.txt`, `*.objdump.txt` and `selected-relocations.txt` regenerate byte-for-byte. GNU tools read a private byte-identical snapshot. No captured code is executed.

## Evidence

All coordinates are original ELF virtual addresses, half-open. The ELF header `e_entry` (file offset 24) is `0x1419300`, which maps to the executable `_start`.

`_start` — FDE-bounded `0x1419300..0x1419326` (38 bytes, body SHA-256 `cf432d50b96a11a67b03f671fe51599dd44a6b9c5a009eefba514c487d9e23bd`). Canonical glibc PIE entry:

~~~text
endbr64
xor  ebp,ebp
mov  r9,rdx            ; r9 = rtld_fini (entry rdx)
pop  rsi               ; rsi = argc
mov  rdx,rsp           ; rdx = argv
and  rsp,-16
push rax
push rsp               ; stack_end on stack
xor  r8d,r8d           ; r8 = fini = NULL
xor  ecx,ecx           ; rcx = init = NULL
lea  rdi,[rip+0x18d65d1]   ; rdi = main = 0x2cef8f0
call [rip+0x50c6133]       ; __libc_start_main, GOT slot 0x64df458
hlt
~~~

The call GOT slot `0x64df458` carries `R_X86_64_GLOB_DAT` against dynamic symbol `__libc_start_main@GLIBC_2.34` (addend 0). The `lea rdi` displacement resolves to `main` at `0x2cef8f0`.

`main` — FDE-bounded `0x2cef8f0..0x2cef917` (39 bytes, body SHA-256 `c0621248d6ec3fd7ae1ee2df6b09bdd79541219362b313e5567717eb8f59a5c9`). Rust `std::rt::lang_start` lowering of `fn main`:

~~~text
push rax
mov  rcx,rsi               ; rcx = argv
movsxd rdx,edi             ; rdx = argc (sign-extended)
lea  rax,[rip-0x1758e]     ; rax = user main fn = 0x2cd8370
mov  [rsp],rax             ; store fn ptr = &dyn Fn data
lea  rsi,[rip+0x375123f]   ; rsi = &dyn Fn vtable = 0x6440b48
mov  rdi,rsp               ; rdi = &dyn Fn data pointer
xor  r8d,r8d               ; r8 = sigpipe = 0
call [rip+0x37f731b]       ; lang_start_internal, GOT slot 0x64e6c30
pop  rcx
ret                        ; returns i32 exit code in eax
~~~

The call GOT slot `0x64e6c30` carries `R_X86_64_RELATIVE` with addend `0x5c99970`, i.e. the `lang_start_internal` body is internal (not a dynamic import). `rdi`/`rsi` form the `&dyn Fn() -> i32` fat pointer (data = `&main_fn_ptr` on the stack, vtable = `0x6440b48`); `rdx`=argc, `rcx`=argv, `r8`=sigpipe follow the `lang_start_internal(main, argc, argv, sigpipe)` signature. The user `main` at `0x2cd8370` opens with the Rust large-stack probe (`sub rsp,0x1000; mov qword [rsp],0; ...`), confirming an ordinary first-party function body (not analyzed here).

Analysis was complete for both FDE extents; both have exactly one matching FDE in the authenticated index.

## Implementation and comparison

Not applicable: this is a static control/argument map, not a Rust reconstruction. No Cargo build, two-build identity or binary-equivalence claim is made. The producer compares only authenticated file bytes, RIP displacements and dynamic relocations; it performs no execution.

## Results and limitations

Machine-readable metrics in `records.json`. Compared surface: 2 functions, 77 `.text` bytes (0 FDE/boundary disagreements). Positive: `e_entry`, all 24 opcode anchors, 5 resolved RIP targets, 2 callee relocations (one `GLOB_DAT` to `__libc_start_main`, one `RELATIVE` to `0x5c99970`) and both FDE extents all match. Negative controls (`tests/test_entry_start_static.py`): flipping any single anchored opcode byte, any of the five RIP displacement fields, the `GLOB_DAT` `r_info`, the `RELATIVE` addend, or `e_entry` is rejected; a per-function body digest additionally pins operand bytes the opcode/RIP checks skip; and a wrong-size/wrong-release or wrong-digest input is rejected before any output.

Unknown/next: the `__libc_start_main` and `lang_start_internal` bodies, the user `main` body at `0x2cd8370` and its first called subroutines, and whether the `&dyn Fn` vtable at `0x6440b48` is in `.data.rel.ro`. Next question: decode the user `main` at `0x2cd8370` and map its first direct calls to continue the #115 startup path.
