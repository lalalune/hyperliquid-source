# RE-005 node 115: which argument builds the build-mode string

Question: PR #2999 pinned the base crate's `std::sync::LazyLock` cell
at `0x64f01c0`, its initializer `0x1568de0`, and the cached value's
24-byte `String` representation. RE-005's lu packet (H11) pinned the
value's source file (`base/src/build_mode.rs`, panic Locations 28:13
and 30:26), the candidate literal block packed beside the assertion
(`/cham/`, `debug`, `release`, `run-client`), and the census of the
accessor `0x1560a40`'s call sites, all of which discard the value.
Neither packet established what the initializer computes: **which
process argument it picks to build the string, in which order, what
the `/cham/` search actually hits, and which of `debug` / `release`
/ `run-client` can survive the lowercase transform as the stored
value** — and whether the artifact names the static or its getter.

This packet answers that question from the node-115 binary alone.
Re-derivation of the bodies the earlier packets pinned agrees with
them (initializer `c87c9590…`, transform `85a51029…`, accessor
`4dd07ff0…`; Locations 28:13 / 30:26), so the answer layers on top
of those packets without contradicting them.

## Observed: the argument source is `std::env::args()`

The initializer's iterator vtable sits at stack `rsp+0x20`. Its
constructor slot `0x64e1290` resolves (`.rela.dyn`, RELATIVE) to
`0x5c9a530`, which reads the process argument cells directly:
the pointer cell `0x6500008` (pin `0x5c9a541`) and the count cell
`0x6500000` (pin `0x5c9a55b`), walks the C array collecting each
entry as a `(capacity, pointer, length)` byte string, and builds
the iterator state from a collection loop whose index starts at 0
(pin `0x5c9a607`: `xor ebx, ebx`). The `next` slot `0x64e1298`
resolves to `0x5caa830`, which pops elements in order, writes the
`None` tag `INT_MIN` over the result when the vector is exhausted
(pin `0x5caa83f`), and converts each element to a checked string
through the UTF-8 validator behind slot `0x64dfca8` (`0x16815e0`),
unwrapping the conversion: the unwrap message
`called \`Result::unwrap()\` on an \`Err\` value` (43 bytes at
`0x949294`) is paired with a `panic::Location` at
`0x64c3240` decoding to
`/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/env.rs:864:51`
— the standard library's own `env::args` conversion site.

So the iterated sequence is the process argument vector itself,
visited once each, in argv order, **argv[0] included** — not the
executable path specially, and not a dedicated flag. There is one
`next` call in the loop (at `0x1568e6b`) and no early exit.

## Observed: the per-argument selection

The accumulator starts as the empty `String` (capacity 0, pointer
1, length 0; pins `0x1568df6`–`0x1568e07`). For each argument:

1. **Flag skip.** An argument of length ≥ 2 whose first two bytes
   are `--` (word compare against `0x2d2d`, pin `0x1568f40`) is
   dropped without contributing anything — no piece, no separator.
2. **The `/cham/` path.** Otherwise the initializer searches the
   argument for the substring `/cham/`, with the search form chosen
   by length: length < 2 cannot contain it; lengths 2–5 fall
   through; length 6 matches only when the argument *is* `/cham/`
   (whole-string word compare, pins `0x1568f62` / `0x1568f6d`);
   lengths 7–20 use an inline scalar scan anchored on the first
   bytes; longer arguments use the verified contains machinery
   (needle `cham/`, 5 bytes at `0x4676f3`, set up at pin
   `0x1568fc5`, with the both-windows verification helper
   `0x156b230`, whose flag-short-circuit is pinned at `0x156b230`).
   A matching argument is replaced by a derived piece:
   - if the argument ends with `/`, the assertion
     `assertion failed: !arg.ends_with('/')` (37 bytes at
     `0x4676f8`) fires with the Location `base/src/build_mode.rs`
     28:13 (call pin `0x1569676`);
   - otherwise the piece is the component after the argument's
     last `/` (backward scan `0x15692d6`–`0x15693d4`; the boundary
     check on the component's first byte at pin `0x15693f0` pairs
     with the bounds panic carrying the line-30 Location,
     `base/src/build_mode.rs` 30:26, call pin `0x156969b`);
   - the component is then cut at its **last** `-`: the `memrchr`
     behind slot `0x64e12a0` (`0x1681990`; setup pin `0x15694a5`,
     call pin `0x15694ad`) returns `(found, index)`, and when a
     `-` is found (test pin `0x15694b3`) the piece is the prefix
     before that last `-` — empty when the `-` is the component's
     first byte.
3. **Plain arguments** (no `/cham/`) contribute themselves whole;
   the `-` cut does not apply to them.

Each piece is lowercased by the transform `0x150caf0` (call pin
`0x1568e9c`) and merged into the accumulator through the
packed-format `format` behind slot `0x64df6e8` (`0x141e3a0`; call
pin `0x1568ef2`). The format machinery is this toolchain's packed
form (`format`'s own `(len << 1) | 1` single-string fast path,
pins `0x141e3b8` / `0x141e456`, and its error message at
`0x456d84` identify `core::fmt`; the paired `write` body
`0x1680500` walks the same encoding, placeholder tag `0xc0`, pin
`0x1680594`). The format string at `0x444a44` decodes under that
encoding to **`{0} {1}`**, with argument 0 the accumulator (via the
String `Display` shim `0x155c6e0`, setup pin `0x1568eb9`) and
argument 1 the piece (via the `&str` shim `0x15ebba0`, setup pin
`0x1568ed2`). The merge is therefore
`acc = format!("{} {}", acc, lowercased_piece)` — one literal
space per contribution, including the first.

After the last argument, the accumulator is lowercased once more
by the same transform (pin `0x15695bb`) and stored as the cached
value with equal capacity and length (store pins
`0x1569609`–`0x1569615`).

## Observed: which candidates are reachable

`records.json` carries a simulation of exactly these semantics
over synthetic argument vectors, each entry re-derived by the
tool. The decisive ones:

| argv | stored value |
| --- | --- |
| `['/opt/hl/cham/release']` | `' release'` |
| `['/opt/hl/cham/debug']` | `' debug'` |
| `['/opt/hl/cham/run-client']` | `' run'` |
| `['/opt/hl/cham/run-client', '--chain', 'Mainnet']` | `' run mainnet'` |
| `['--chain', 'Mainnet']` | `' mainnet'` |
| `['/srv/cham/release/bin/hl-node']` | `' hl'` |
| `['rel-ease']` | `' rel-ease'` |
| `['/a/cham/x-y-z']` | `' x-y'` |
| `['/a/cham/-x']` | `' '` |
| `['--version']` | `''` |
| `['/cham/']`, `['/a/b/cham/']` | panic at `build_mode.rs:28:13` |

Two consequences are pinned by construction, not by sampling:

- **The stored value is never exactly `debug`, `release` or
  `run-client`.** Every contribution prepends a space (the format
  is `{0} {1}` over an initially empty accumulator), and *every*
  non-flag argument contributes — the value is the space-joined,
  lowercased pieces of the whole argv, so even a single matching
  deployment path yields `' release'`, not `'release'`.
- **`run-client` is unreachable even as a piece.** Through the
  `/cham/` path its component is cut at the last `-`, leaving
  `run`; as a bare argument it would survive whole, but then it
  is one piece among the joined pieces, never the whole value.
  Only `debug` and `release` can appear as whole pieces.

The literal census agrees: a whole-`.text` scan for RIP-relative
references finds **zero** references to `/cham/` itself (the
contains path references its 5-byte tail `cham/` exactly once,
from the initializer), one to the assertion text, and exactly one
`lea` per candidate literal — `debug` and `release` in the
neighbouring 699-byte body at `0x1564870` (pins `0x15648f2` /
`0x15648d0`), which also matches an input against `run-client` by
immediate compare, dispatches on a tag byte, and formats with the
packed strings `{0}/{1}` (`0x43aa84`) and `{0}/aws_build/{1}`
(`0x449a91`); and `run-client` in the 258-byte body at `0x155f8d0`
(lea pin site `0x155f937`), where it is used as a key. The
initializer itself never loads any candidate literal: the
vocabulary is live on the enum/key side of the module, while the
cached string is an accumulated by-product of the launch command
line.

## Observed: the static's and getter's names are not in the artifact

A byte-exact census of the artifact finds no `BUILD_MODE`, no
`BuildMode`, and no `build-mode` string anywhere; the substring
`build_mode` occurs only inside the panic-Location file string
`base/src/build_mode.rs`. The naming evidence the binary carries
is therefore exactly: the module path `base/src/build_mode.rs`,
and the assertion's local name `arg` (in
`assertion failed: !arg.ends_with('/')`). Any richer name for the
static or its accessor would be a guess, and this packet makes
none.

## Boundary

- The simulation is exact for the ASCII vectors in
  `records.json`. The transform is the full Unicode lowercase
  mapping (the table-driven body PR #2999 pinned), so non-ASCII
  pieces follow Unicode rules the vectors do not enumerate;
  context-sensitive mappings (e.g. final sigma) are the standard
  library's, applied per piece and once to the whole.
- The semantics assume the `args()` conversion succeeds. A
  non-UTF-8 argument makes `next()` panic at the std site above
  before any selection happens; the initializer stores nothing in
  that case.
- The neighbouring bodies at `0x1564870` and `0x155f8d0` are
  characterized only as far as their use of the candidate
  literals; their full behaviour is a different question, only
  bounded here so the literal census has named owners.
- No process was executed and no captured launch command line is
  used: the argument sequence is the binary's own constructor
  reading the C `argv` cells, and every claim is pinned to bytes,
  relocations, FDE extents and decoded records that
  `tools/build_mode_arg_selection.py` re-derives and
  `tests/test_build_mode_arg_selection.py` checks, including
  byte-mutation controls on the merge format, the flag-prefix
  immediate and a candidate literal.
