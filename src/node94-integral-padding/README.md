# Node #94 integral padding requests

This independently authored Rust component recovers the normal callback request
and formatter-header effects of the integral padding helper. It advances the
RE-005 formatting dependency question left behind the numeric selector's opaque
sink. It does not implement the writer's rendering or establish a full component
gate.

The target is node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
ELF virtual addresses, complete FDE extents and fixed helper closure are:

| Role | Half-open ELF VA range | Bytes | Native instruction rows |
| --- | --- | ---: | ---: |
| Integral padding | `0x15723b0..0x15728bf` | 1,295 | 341 |
| Sign/prefix requests | `0x1572350..0x15723a4` | 84 | 37 |
| Long prefix character count | `0x15796c0..0x1579c8b` | 1,483 | 365 |
| Total closed native bodies | | 2,862 | 743 |

The native padding body uses the prefix helper directly and the character
counter through its actual relocated slot. The native sign/prefix helper
dispatches character and string methods. The counter has no calls. The retained
static producer binds all twelve code relocation fields, constants, alignment
destinations and the incoming numeric-selector slot. Correspondence to a
published libcore object identifies a dependency lead; it is not a new source
build or proof of the target's original compiler.

## Chosen safe interface

`pad_integral` receives one borrowed writer state, one `Context`, unique stable
logical `Table` IDs, a full `u32` sign input, an immutable valid UTF-8 prefix,
raw digit bytes and a callback. `Context` and method slots use real `Cell<u64>`
values, so sequential callback mutation remains observable. Logical IDs replace
native pointers; they do not assert pointer or private ABI equivalence.

The initial `tailword` encodes low 32 flag bits, a 16-bit width and 16-bit
precision. This is a chosen value representation of the observed fields, not
the native formatter layout. Width and precision bits remain part of the word
even though precision does not affect this helper's layout.

- Full sign input zero requests `'-'`; nonzero requests `'+'` only with flag
  bit 21. Bit 23 enables the prefix, including a present empty prefix request.
- Content length is raw digit byte length plus sign length and enabled prefix
  Unicode scalar count. The independently authored scalar classifier implements
  the proved native short/long counting relation; it is not a fixed answer or
  an opaque helper stub.
- If width is larger, ordinary padding uses the raw 21-bit fill argument and
  alignment codes `[left, right, center, right]`. Center puts an odd extra fill
  after the content. Each fill remains a separate callback invocation.
- Zero padding (bit 24) requests sign/prefix, zeros, then digits. It installs
  `(initial_flags & 0x9fe00000) | 0x20000030` before the first request. Only
  complete success restores the entire initial 64-bit word. Errors retain the
  current word, including callback changes.
- Every invocation caches initial writer data/table IDs but reloads that
  table's current method cells on every request. Data/table/method changes
  survive the operation. The final no-padding digit callback forwards raw
  `u8`; earlier errors and every padded error return 1.

The domain is x86-64 with 64-bit `usize`, readable nonwrapping prefix/digit
slices of at most `isize::MAX` bytes each, valid stable unique table IDs, and
callbacks that return normally with ordinary call preservation. Input/code/frame
storage remains immutable and separated from inappropriate aliases. The callback
may mutate the supplied cells; no other concurrent mutation is admitted.
Faults, unwind, invalid pointers, arbitrary aliases, source type identity,
hidden registers, physical Unicode/output rendering and whole-node behavior
remain outside this projection. Character requests deliberately carry raw
`u32` arguments, including values that are not Unicode scalars.

## Build and verification scope

There is no root Cargo workspace and no invented dependency graph. The component
builds directly with the admitted official research Rust 1.94.1 provider for
`x86_64-unknown-linux-gnu`. `lib.rs` is `no_std` and forbids unsafe code. The
input-only client uses the provider's real `std`; both fixed helper relations
are implemented in the library. No captured bytes are linked or transplanted.

The independent pre-source authority was sealed before this Rust was authored:
11,150 distinct complete inputs, 1,086,315 individual callback observations,
and 30,343 exact adjacent-event RLE records. Its maximum measured case has
65,536 callbacks; this is not a global call cap. RLE is solely a lossless client
encoding. The Rust still performs each callback and cell action individually.

The input-only client reads only the ten-field input TSV, not expected output.
Expected canonical JSONL remains external to that executable. Unit checks also
cover borrowed context/writer identity and live cell mutation. The full proof
and sealed inputs are in
`research/work-items/RE-005-integral-padding-94/`.

At this source-preservation stage the new Rust has not been compiled. The scoped
validation runner will retain actual compiler/program streams, O0/O3 results,
one same-recipe optimized rebuild, source mutation controls, comparator controls
and exact source/target/pin/provider/linker before/after audits. Results must be
updated from those observed records before any implementation claim is posted.

The expanded repository test suite, captured-instruction evaluators, captured
program execution, hosted CI and a full node build have not run. The authorized
scope is static analysis, pure mathematics and this independently authored Rust.
All unfinished mapped/built/behavior/identity component gates remain false.

New source and documentation are project-authored MIT work. Imported captured
artifacts and published Rust/libcore material retain their original rights and
notices. Existing libcore correspondence provenance/license records supply
attribution; the unlicensed can1357 implementation was not copied.
