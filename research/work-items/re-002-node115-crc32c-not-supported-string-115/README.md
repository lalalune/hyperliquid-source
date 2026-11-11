# RE-002: node #115 CRC32 support string builder at 0x61c2400

This packet reconstructs one bounded node #115 behavior: the
function at `0x61c2400` (FDE `0x61c2400..0x61c25f0`, cold block
`0x61c23b9..0x61c23f8`) that builds the constant string
`"Not supported on x86"` — and it confirms the vendor census label
`rocksdb::crc32c::IsFastCrc32Supported`: the `B5cxx11` ABI tag in
the mangled name marks a `std::string` return, and the body returns
exactly such a string. A whole-`.text` caller
census finds exactly one direct call site, in
`rocksdb::DBImpl::DBImpl`, where the string is logged as the
`%s` of `"Fast CRC32 supported: %s"`.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the FDE ranges, the body
  hashes and the caller census are observations. The census
  symbol label is confirmed by the bytes (see Census
  confirmation below): the `B5cxx11` tag in the mangled name
  marks a `std::string` return, and the body returns one. The
  constant `"Not supported on x86"` body is the not-supported
  branch of that function — a build without the SSE4.2 fast-CRC
  path — recorded as inference, since the body itself contains
  no CPUID or feature check.
- Scope included: the function body, its cold block and
  landing pads, the three string literals it uses, and the
  caller census with the caller's use of the result.
  Excluded: the exact RocksDB source lines behind the confirmed
  identity, any indirect caller (the scan sees direct calls
  only), and the linked list the caller walks before the call
  site.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61c23b9 --stop-address=0x61c25f0 work/hl-node-115.bin
(cd research/work-items/re-002-node115-crc32c-not-supported-string-115 && sha256sum -c MANIFEST.sha256)
```

The node binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra cross-check
was performed.

## Evidence

### Contract

`f(out: *mut std::string) -> *mut std::string`. The function writes
the constant 20-byte string `"Not supported on x86"` into `*out`
and returns `out`. It takes no other input, has no
data-dependent branch and performs no CPUID or feature check.

### Function body (observed)

The whole function is 496 bytes
(`crc32c_not_supported_string115.hex`,
`crc32c_not_supported_string115.objdump.txt`), plus a 63-byte
cold block at `0x61c23b9..0x61c23f8` (see below):

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61c2400` | `f3 0f 1e fa` | `endbr64` |
| `0x61c2404` | `41 57` | `push   %r15` |
| `0x61c2406` | `41 b8 03 00 00 00` | `mov    $0x3,%r8d` |
| `0x61c240c` | `31 d2` | `xor    %edx,%edx` |
| `0x61c240e` | `31 f6` | `xor    %esi,%esi` |
| `0x61c2410` | `41 56` | `push   %r14` |
| `0x61c2412` | `48 8d 0d be f8 27 fa` | `lea    -0x5d80742(%rip),%rcx` |
| `0x61c2419` | `41 55` | `push   %r13` |
| `0x61c241b` | `41 54` | `push   %r12` |
| `0x61c241d` | `55` | `push   %rbp` |
| `0x61c241e` | `53` | `push   %rbx` |
| `0x61c241f` | `48 89 fb` | `mov    %rdi,%rbx` |
| `0x61c2422` | `48 83 ec 68` | `sub    $0x68,%rsp` |
| `0x61c2426` | `64 48 8b 04 25 28 00 00 00` | `mov    %fs:0x28,%rax` |
| `0x61c242f` | `48 89 44 24 58` | `mov    %rax,0x58(%rsp)` |
| `0x61c2434` | `31 c0` | `xor    %eax,%eax` |
| `0x61c2436` | `48 8d 47 10` | `lea    0x10(%rdi),%rax` |
| `0x61c243a` | `c6 47 10 00` | `movb   $0x0,0x10(%rdi)` |
| `0x61c243e` | `4c 8d 7c 24 10` | `lea    0x10(%rsp),%r15` |
| `0x61c2443` | `48 89 07` | `mov    %rax,(%rdi)` |
| `0x61c2446` | `4c 8d 6c 24 20` | `lea    0x20(%rsp),%r13` |
| `0x61c244b` | `48 c7 47 08 00 00 00 00` | `movq   $0x0,0x8(%rdi)` |
| `0x61c2453` | `4c 89 ff` | `mov    %r15,%rdi` |
| `0x61c2456` | `4c 89 6c 24 10` | `mov    %r13,0x10(%rsp)` |
| `0x61c245b` | `48 c7 44 24 18 00 00 00 00` | `movq   $0x0,0x18(%rsp)` |
| `0x61c2464` | `c6 44 24 20 00` | `movb   $0x0,0x20(%rsp)` |
| `0x61c2469` | `e8 22 e9 22 00` | `call   63f0d90` |
| `0x61c246e` | `4c 8b 64 24 18` | `mov    0x18(%rsp),%r12` |
| `0x61c2473` | `48 8b 44 24 10` | `mov    0x10(%rsp),%rax` |
| `0x61c2478` | `48 8d 6c 24 30` | `lea    0x30(%rsp),%rbp` |
| `0x61c247d` | `4c 8d 74 24 40` | `lea    0x40(%rsp),%r14` |
| `0x61c2482` | `48 89 ef` | `mov    %rbp,%rdi` |
| `0x61c2485` | `4c 89 74 24 30` | `mov    %r14,0x30(%rsp)` |
| `0x61c248a` | `49 8d 74 24 11` | `lea    0x11(%r12),%rsi` |
| `0x61c248f` | `48 89 44 24 08` | `mov    %rax,0x8(%rsp)` |
| `0x61c2494` | `48 c7 44 24 38 00 00 00 00` | `movq   $0x0,0x38(%rsp)` |
| `0x61c249d` | `c6 44 24 40 00` | `movb   $0x0,0x40(%rsp)` |
| `0x61c24a2` | `e8 a9 ea 22 00` | `call   63f0f50` |
| `0x61c24a7` | `48 b8 ff ff ff ff ff ff ff 3f` | `movabs $0x3fffffffffffffff,%rax` |
| `0x61c24b1` | `48 2b 44 24 38` | `sub    0x38(%rsp),%rax` |
| `0x61c24b6` | `48 83 f8 10` | `cmp    $0x10,%rax` |
| `0x61c24ba` | `0f 86 b3 00 00 00` | `jbe    61c2573` |
| `0x61c24c0` | `ba 11 00 00 00` | `mov    $0x11,%edx` |
| `0x61c24c5` | `48 8d 35 32 06 28 fa` | `lea    -0x5d7f9ce(%rip),%rsi` |
| `0x61c24cc` | `48 89 ef` | `mov    %rbp,%rdi` |
| `0x61c24cf` | `e8 6c ea 22 00` | `call   63f0f40` |
| `0x61c24d4` | `48 b8 ff ff ff ff ff ff ff 3f` | `movabs $0x3fffffffffffffff,%rax` |
| `0x61c24de` | `48 2b 44 24 38` | `sub    0x38(%rsp),%rax` |
| `0x61c24e3` | `4c 39 e0` | `cmp    %r12,%rax` |
| `0x61c24e6` | `0f 82 c4 00 00 00` | `jb     61c25b0` |
| `0x61c24ec` | `48 8b 74 24 08` | `mov    0x8(%rsp),%rsi` |
| `0x61c24f1` | `4c 89 e2` | `mov    %r12,%rdx` |
| `0x61c24f4` | `48 89 ef` | `mov    %rbp,%rdi` |
| `0x61c24f7` | `e8 44 ea 22 00` | `call   63f0f40` |
| `0x61c24fc` | `48 8b 54 24 38` | `mov    0x38(%rsp),%rdx` |
| `0x61c2501` | `48 8b 74 24 30` | `mov    0x30(%rsp),%rsi` |
| `0x61c2506` | `48 b8 ff ff ff ff ff ff ff 3f` | `movabs $0x3fffffffffffffff,%rax` |
| `0x61c2510` | `48 2b 43 08` | `sub    0x8(%rbx),%rax` |
| `0x61c2514` | `48 39 d0` | `cmp    %rdx,%rax` |
| `0x61c2517` | `72 7b` | `jb     61c2594` |
| `0x61c2519` | `48 89 df` | `mov    %rbx,%rdi` |
| `0x61c251c` | `e8 1f ea 22 00` | `call   63f0f40` |
| `0x61c2521` | `48 8b 7c 24 30` | `mov    0x30(%rsp),%rdi` |
| `0x61c2526` | `4c 39 f7` | `cmp    %r14,%rdi` |
| `0x61c2529` | `74 0e` | `je     61c2539` |
| `0x61c252b` | `48 8b 44 24 40` | `mov    0x40(%rsp),%rax` |
| `0x61c2530` | `48 8d 70 01` | `lea    0x1(%rax),%rsi` |
| `0x61c2534` | `e8 47 e8 22 00` | `call   63f0d80` |
| `0x61c2539` | `48 8b 7c 24 10` | `mov    0x10(%rsp),%rdi` |
| `0x61c253e` | `4c 39 ef` | `cmp    %r13,%rdi` |
| `0x61c2541` | `74 0e` | `je     61c2551` |
| `0x61c2543` | `48 8b 44 24 20` | `mov    0x20(%rsp),%rax` |
| `0x61c2548` | `48 8d 70 01` | `lea    0x1(%rax),%rsi` |
| `0x61c254c` | `e8 2f e8 22 00` | `call   63f0d80` |
| `0x61c2551` | `48 8b 44 24 58` | `mov    0x58(%rsp),%rax` |
| `0x61c2556` | `64 48 2b 04 25 28 00 00 00` | `sub    %fs:0x28,%rax` |
| `0x61c255f` | `75 2e` | `jne    61c258f` |
| `0x61c2561` | `48 83 c4 68` | `add    $0x68,%rsp` |
| `0x61c2565` | `48 89 d8` | `mov    %rbx,%rax` |
| `0x61c2568` | `5b` | `pop    %rbx` |
| `0x61c2569` | `5d` | `pop    %rbp` |
| `0x61c256a` | `41 5c` | `pop    %r12` |
| `0x61c256c` | `41 5d` | `pop    %r13` |
| `0x61c256e` | `41 5e` | `pop    %r14` |
| `0x61c2570` | `41 5f` | `pop    %r15` |
| `0x61c2572` | `c3` | `ret` |
| `0x61c2573` | `48 8b 44 24 58` | `mov    0x58(%rsp),%rax` |
| `0x61c2578` | `64 48 2b 04 25 28 00 00 00` | `sub    %fs:0x28,%rax` |
| `0x61c2581` | `75 0c` | `jne    61c258f` |
| `0x61c2583` | `48 8d 3d 48 4f 28 fa` | `lea    -0x5d7b0b8(%rip),%rdi` |
| `0x61c258a` | `e8 51 e8 22 00` | `call   63f0de0` |
| `0x61c258f` | `e8 dc e7 22 00` | `call   63f0d70` |
| `0x61c2594` | `48 8b 44 24 58` | `mov    0x58(%rsp),%rax` |
| `0x61c2599` | `64 48 2b 04 25 28 00 00 00` | `sub    %fs:0x28,%rax` |
| `0x61c25a2` | `75 eb` | `jne    61c258f` |
| `0x61c25a4` | `48 8d 3d 27 4f 28 fa` | `lea    -0x5d7b0d9(%rip),%rdi` |
| `0x61c25ab` | `e8 30 e8 22 00` | `call   63f0de0` |
| `0x61c25b0` | `48 8b 44 24 58` | `mov    0x58(%rsp),%rax` |
| `0x61c25b5` | `64 48 2b 04 25 28 00 00 00` | `sub    %fs:0x28,%rax` |
| `0x61c25be` | `75 cf` | `jne    61c258f` |
| `0x61c25c0` | `48 8d 3d 0b 4f 28 fa` | `lea    -0x5d7b0f5(%rip),%rdi` |
| `0x61c25c7` | `e8 14 e8 22 00` | `call   63f0de0` |
| `0x61c25cc` | `f3 0f 1e fa` | `endbr64` |
| `0x61c25d0` | `49 89 c4` | `mov    %rax,%r12` |
| `0x61c25d3` | `e9 e1 fd ff ff` | `jmp    61c23b9` |
| `0x61c25d8` | `f3 0f 1e fa` | `endbr64` |
| `0x61c25dc` | `49 89 c4` | `mov    %rax,%r12` |
| `0x61c25df` | `e9 05 fe ff ff` | `jmp    61c23e9` |
| `0x61c25e4` | `f3 0f 1e fa` | `endbr64` |
| `0x61c25e8` | `49 89 c4` | `mov    %rax,%r12` |
| `0x61c25eb` | `e9 d1 fd ff ff` | `jmp    61c23c1` |

Reading the body: `out` (`*rdi`, saved in `%rbx`) is initialised
as an empty SSO string (`_M_p = out+0x10`, length 0). Stack
string `A` at `rsp+0x10` is built by
`_M_replace(0, 0, "x86", 3)` — the first three bytes of the
`.rodata` literal `"x86"` at `0x441cd7` — so `A = "x86"`. Stack
string `C` at `rsp+0x30` reserves `A.len + 17 = 20`, appends
`"Not supported on "` (17 bytes, `.rodata` `0x442afe`), then
appends `A` (3 bytes), so `C = "Not supported on x86"`. `out`
appends `C` (20 bytes) under the `std::string` `max_size` guard
(`0x3fffffffffffffff` minus the current length, checked against
17, then `A.len`, then `C.len`; a failed guard checks the stack
canary and calls `__throw_length_error("basic_string::append")`
at `0x63f0de0`). The heap buffers are then disposed with the
`_M_dispose` shape: `C` holds 20 bytes, past the 15-byte SSO
limit, so its heap buffer is freed with `operator delete(_M_p,
 _M_capacity + 1)`; `A` holds 3 bytes and stays SSO, so no
delete runs for it. The function returns the `out` pointer in
`%rax`. The three landing pads at the end of the range save the
exception object in `%r12` and jump into the cold block.

### Cold block and landing pads (observed)

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61c23b9` | `48 89 ef` | `mov    %rbp,%rdi` |
| `0x61c23bc` | `e8 ef e9 22 00` | `call   63f0db0` |
| `0x61c23c1` | `4c 89 ff` | `mov    %r15,%rdi` |
| `0x61c23c4` | `e8 e7 e9 22 00` | `call   63f0db0` |
| `0x61c23c9` | `48 89 df` | `mov    %rbx,%rdi` |
| `0x61c23cc` | `e8 df e9 22 00` | `call   63f0db0` |
| `0x61c23d1` | `48 8b 44 24 58` | `mov    0x58(%rsp),%rax` |
| `0x61c23d6` | `64 48 2b 04 25 28 00 00 00` | `sub    %fs:0x28,%rax` |
| `0x61c23df` | `75 12` | `jne    61c23f3` |
| `0x61c23e1` | `4c 89 e7` | `mov    %r12,%rdi` |
| `0x61c23e4` | `e8 67 e6 22 00` | `call   63f0a50` |
| `0x61c23e9` | `48 89 ef` | `mov    %rbp,%rdi` |
| `0x61c23ec` | `e8 bf e9 22 00` | `call   63f0db0` |
| `0x61c23f1` | `eb ce` | `jmp    61c23c1` |
| `0x61c23f3` | `e8 78 e9 22 00` | `call   63f0d70` |
| `0x61c23f8` | `cc` | `int3` |
| `0x61c23f9` | `cc` | `int3` |
| `0x61c23fa` | `cc` | `int3` |
| `0x61c23fb` | `cc` | `int3` |
| `0x61c23fc` | `cc` | `int3` |
| `0x61c23fd` | `cc` | `int3` |
| `0x61c23fe` | `cc` | `int3` |
| `0x61c23ff` | `cc` | `int3` |

The cold block disposes the live strings with
`std::string::_M_dispose` (PLT stub `0x63f0db0`), checks the
stack canary at `0x58(%rsp)`, and rethrows the saved exception
object (`%r12`) with `_Unwind_Resume` at `0x63f0a50`; a canary
mismatch calls `__stack_chk_fail` at `0x63f0d70`. The three
landing pads enter it at staggered points so each disposes
only the strings that exist at its call site: `0x61c25cc` jumps
to `0x61c23b9` (dispose `C`, `A`, `out`), `0x61c25d8` jumps to
`0x61c23e9` (dispose `C`, then fall into disposing `A` and
`out`), and `0x61c25e4` jumps to `0x61c23c1` (dispose `A` and
`out` only — `C` is not yet constructed at that call site). Every
instruction in the cold block is reachable through one of the three
entries; `_Unwind_Resume` never returns, so control never falls
through from it to `0x61c23e9`, but that address is reached by jump
from the landing pad at `0x61c25d8`.

### Census confirmation (observed)

The vendor-census record `node115-vendor-61c2400` labels this
address `librocksdb-sys 0.11.0+8.1.1:
 _ZN7rocksdb6crc32c20IsFastCrc32SupportedB5cxx11Ev` with
`target_body_sha256`
`5e8cffdcbf4b8f146fbc9ea17cd45b15a700af7fce2c54fa6904d35e101bcb6f`.
That hash matches the bytes hashed from the node binary, and the
label is confirmed, not wrong: the `B5cxx11` ABI tag in the mangled
name marks a `std::__cxx11::basic_string` return — a `g++` mangling
check shows `std::string rocksdb::crc32c::IsFastCrc32Supported()`
mangles to exactly this name, while a `bool`-returning sibling
mangles without the tag — and the body does return a `std::string`,
the constant `"Not supported on x86"`. An earlier draft of this
packet claimed the label was wrong on the assumption that
`IsFastCrc32Supported` returns `bool`; that assumption is refuted by
the mangled name itself (slopbot limited review on revision
`98528507f`, corrected in-PR the same cycle). The companion cold
record `node115-vendor-61c23b9` (label
`...IsFastCrc32SupportedB5cxx11Ev.cold`, `target_body_sha256`
`6c1d7659ad52a2360fe662271467420fd7b134452321279fd43ba5e90a234345`)
is likewise confirmed: its hash also matches the bytes hashed from
the node binary, so the cold block belongs to this function.

### Caller census (observed)

A whole-`.text` scan of `work/hl-node-115.bin` (`.text`
`0x1419300..0x63f6a00`, file offset `va - 0x1000`) for `E8 rel32`
calls targeting `0x61c2400`, plus a scan for rip-relative `lea`
instructions resolving to `0x61c2400`, finds exactly one direct
call site, verified by disassembling the surrounding bytes:

| Call site | Caller |
| --- | --- |
| `0x5d87363` | `rocksdb::DBImpl::DBImpl(const DBOptions&, const std::string&)` — census `node115-vendor-5d85480`, FDE `0x5d85480..0x5d878e2` |

No `lea` anywhere in `.text` takes the address `0x61c2400`, so
there is no function-pointer or vtable use, and no direct call
targets the cold entry `0x61c23b9`. Indirect calls through
registers cannot be seen by this scan, so a hidden indirect
caller is not ruled out — a limit, not evidence of one.

At the call site the caller passes the out-pointer from
`[rbp-0x340]` (the only store to that slot before the call, at
`0x5d85899`, is `lea -0x2d0(%rbp)`, so the string object lives
at `rbp-0x2d0`). Immediately after the call the string's data
pointer `[rbp-0x2d0]` is passed as the `%s` argument (in `%rcx`)
to `rocksdb::Log` at `0x5fceda0` (census `node115-vendor-5fceda0`)
with the format string `"Fast CRC32 supported: %s"` (`.rodata`
`0x43f84b`), level 5 and logger `%r12`; the string is then
disposed with `_M_dispose`. The call site sits just after a
list-walk loop in the same constructor (head loaded from global
`0x6507120+0x10`, next at `+0x0`, name at `+0x8`, kind byte at
`+0x28`) that logs `"\t%s supported: %d"` (`.rodata` `0x433f10`)
once per node.

## Check values

- Body SHA-256
  `5e8cffdcbf4b8f146fbc9ea17cd45b15a700af7fce2c54fa6904d35e101bcb6f`
  over the 496 bytes at `0x61c2400..0x61c25f0` (matches the census
  `target_body_sha256`).
- Cold-block SHA-256
  `6c1d7659ad52a2360fe662271467420fd7b134452321279fd43ba5e90a234345`
  over the 63 bytes at `0x61c23b9..0x61c23f8` (matches the census
  cold `target_body_sha256`).
- Result string: `"Not supported on x86"` (20 bytes) —
  `"x86"` (3) + `"Not supported on "` (17), in that order.
- Sole direct caller: `0x5d87363` in `DBImpl::DBImpl`; the logged
  line is `"Fast CRC32 supported: Not supported on x86"`.
- `A` (`"x86"`, 3 bytes): SSO, no heap free. `C` (20 bytes): heap,
  freed with `operator delete(_M_p, _M_capacity + 1)`.
