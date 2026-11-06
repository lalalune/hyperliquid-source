# Raw event-word provenance and copy extent

This corrects the interpretation introduced by merged PR #2427 at base
`05bc2de303c05525b71e7e257426e741bc66a390`. It does not replace the retained
native exports or the slab return-index result. The active RE-006 investigation
could not use the old event description as a reconstruction contract: it
assigned the quantity source to a word whose native reaching definition differs.

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses below are ELF virtual addresses. The two complete owner bodies
are `0x58df360..0x58df78b` and `0x58df790..0x58dfbbb`: 2,134 bytes,
472 instruction rows. These are already retained evidence, not new coverage.

## Definitions reaching the source-frame stores

Let S denote the selector as read from the stack, I the index read when S=1,
L the slab length at the comparison, and Q the qword read from order+0xe0.
The observations require valid, stable, nonaliasing inputs/frame storage and
normal preserving returns from any reached opaque helper. They do not prove
which inputs higher-level callers can produce.

| Event | Owner A | Owner B |
| --- | --- | --- |
| Save Q in [rsp] | 0x58df39b | 0x58df7cb |
| Load S, ordinary arm | 0x58df3a4 | 0x58df7d4 |
| Load S, after overflow helper | 0x58df431 | 0x58df861 |
| Branch when S != 1 | 0x58df3b4 | 0x58df7e4 |
| Branch when I >= L, unsigned | 0x58df3ca | 0x58df7fa |
| RCX := low64(I * 0x110) | 0x58df3d0 | 0x58df800 |
| Branch when slot first qword != 2 | 0x58df3e4 | 0x58df814 |
| RCX := linked slot qword+0xf0 | 0x58df400 | 0x58df830 |
| [rsp+0x50] := RCX | 0x58df49e | 0x58df8ce |
| [rsp+0x58] := RDI | 0x58df4a3 | 0x58df8d3 |

1. **S != 1:** the ordinary branch reaches A447/B877, which loads the
   level pair, clears R8 and reloads Q into RDI. None of those instructions
   assigns RCX. The overflow arm reloads S after its opaque helper and has
   the same fresh fall-through. Thus the source word at +0x50 holds S.
2. **S=1, I>=L:** the unsigned branch reaches A3e6/B816 before the index
   multiplication. Its level-pair loads and R8 clear preserve RCX=1.
3. **S=1, I<L, slot qword=2:** multiplication has replaced RCX by the
   low 64 bits of I*0x110. The qword equality path falls into the same
   level-pair block, which preserves this value. The native address load
   still requires valid storage; wrapping the multiplier is not a claim
   that an arbitrary wrapping index is reachable or safe.
4. **S=1, I<L, slot qword!=2:** the linked arm explicitly replaces RCX
   with the slot qword at +0xf0. The equality is a **qword** comparison,
   unlike the later dword checks in the slab-return path.

All arms join at A45b/B88b. The complete corridor to A49e/B8ce contains
no RCX assignment or call. The next RCX assignment is A4ad/B8dd, after
the raw word has been stored. Q reaches the adjacent source word via RDI:
the selector=1 paths reload it at A3c6/B7f6; other selectors at A457/B887.
Full instruction pins already authenticate these corridors and branch targets.

## Concrete contradiction of the old quantity claim

Consider the registration call sites A caller `0x59119cf` and B caller
`0x5911c6f`, both `push 0`, followed by calls at `0x59119d1`/`0x5911c71`.
Conditionally choose valid preserved storage, Q=7, an initial accumulator
that does not overflow, and spare event capacity. The static source relation
gives [rsp+0x50]=0 and [rsp+0x58]=7. The old claim would put 7 in both.
This is an address-bound manual counterexample, **not an executed fixture**
and not a claim of runtime reachability for the full surrounding operation.

## Source preparation is not destination copy extent

The explicit stores prepare [rsp+0x40, rsp+0x8d), 77 bytes. The first
copy call uses source rsp+0x40, at A4ea/B91a, with EDX=0x2b8/0x2c8,
at A4f6/B926, and calls R12 at A4fb/B92b. R12 was loaded through
slot 0x64df508. A separate raw relocation/symbol check identifies this as
`R_X86_64_GLOB_DAT`, symbol index 7, undefined `memcpy@GLIBC_2.14`,
addend zero. The original relative-relocation map correctly records no
RELATIVE binding; that does not imply absence of an import name. This name
does not identify the runtime-resolved implementation or prove its behavior.
There may first be a call to the event grow helper.

The raw instruction observation is a **full-size copy request**, not an
observed memory transfer. If the helpers return normally, preserve the
prepared frame and implement exact copying over valid disjoint buffers,
the destination contains the prepared prefix and the remaining frame bytes.
The latter contents have not been established here; they are not guaranteed
untouched destination bytes. The original `written_span_bytes` name and
tail statement conflated these two boundaries.

This packet does not assign a Rust Option/enum layout or business meaning
to the fresh-mode word. It does not prove that consumers ignore it, and does
not establish source-language initialization, disclosure, or a vulnerability.
Allocator, copy implementation, exceptional paths, consumer behavior and
whole-operation equivalence remain open. All acceptance gates stay false.
