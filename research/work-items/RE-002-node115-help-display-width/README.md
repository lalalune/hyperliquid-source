# Display width in node #115 command help and text wrapping

The selected command-help and text-wrapping callers measure Unicode strings
with the non-CJK option of `unicode-width` 0.1.13. For example, a middle dot
counts as one column at the observed call sites. The same library returns two
columns under its CJK option. It counts `한글` as four columns and treats CRLF as
one column. These measurements describe how the selected code lays out text.
An individual terminal's rendering can differ.

## Which callers choose the policy?

The [vendor census](../RE-002-node115-vendor-overflow-census/) previously
matched the complete 821-byte string-width function at
`[0x5d01bc0,0x5d01ef5)` to a published crate build. This packet rechecks
the 781 fixed bytes and resolves GOT slot `0x64e1d40` to that function.

Scanning `.text` for RIP-relative indirect calls to that slot finds 19 sites
in nine FDEs. Decoding from each FDE start shows an immediately preceding
`xor edx, edx` at all 19 sites. This sets the third argument, the CJK option,
to false. The owner at `0x1648390` also references a native source-location
record for `z_vendor/clap/src/app/help.rs` at line 475, column 24. The owner
at `0x165bcd0` references `z_vendor/textwrap/src/lib.rs` at line 559,
column 34. The remaining owners are listed by address. These observations
cover this concrete call shape. Indirect calls through other registers and
other display components are outside the census.

## Linked Unicode data

The function loads three tables through relative relocations and two directly
using RIP-relative addresses. Their full contents match the initializers
from the checksum-pinned 0.1.13 release. The eleven entries of its emoji
dispatch jump table are checked against instruction addresses within the same
FDE. [results.json](results.json) retains the source locations, every
call address, the full table hashes and the semantic comparison.

| Object | Target VA | Bytes |
| --- | --- | ---: |
| Width lookup, level 0 | `0x94e500` | 256 |
| Width lookup, level 1 | `0x94e600` | 2,432 |
| Two-bit width values | `0x94ef80` | 3,808 |
| Emoji presentation leaves | `0x94e200` | 768 |
| Text presentation leaves | `0x94e000` | 512 |

The reference program compiles the original public releases 0.1.12, 0.1.13 and
0.1.14 separately. Each declares Unicode 15.1.0. For every one of the 1,112,064
Unicode scalar values it measures the string alone, with the text presentation
selector U+FE0E, and with the emoji selector U+FE0F. Each shape is measured
with both public width options, giving 6,672,384 observations per release.
An independently written lookup reads the five linked tables and compares
all six columns byte-for-byte.

| Release | Scalar narrow / CJK differences | Text selector narrow / CJK differences | Emoji selector narrow / CJK differences |
| --- | --- | --- | --- |
| 0.1.12 | 72 / 278 | 222 / 278 | 72 / 278 |
| 0.1.13 | 0 / 0 | 0 / 0 | 0 / 0 |
| 0.1.14 | 18 / 25 | 18 / 25 | 18 / 25 |

The additional sequence examples record the public releases' behavior before
and after the linked release. In narrow mode, 0.1.13 measures the woman
technologist sequence as four columns while 0.1.14 measures two. The
Lisu tone pair U+A4F8 U+A4FC measures one column in 0.1.13 and two in
0.1.12. Both the source-qualified function and the full linked tables are
necessary for contextual behavior. The neighboring-release controls narrow
the tested candidates. The original dependency lockfile remains unresolved.

The [public 0.1.13 implementation](https://github.com/unicode-rs/unicode-width/tree/612877a5d70bfc7c93b4bc70b740aa292dd4f48a)
describes its display-width policy. Existing [clap argument display work](../node-runtime-clap-arg-display-115/)
covers individual argument formatters and method tables. The evidence here
covers the caller's width selection and the dependency's data.

## Reproduce

Install Python 3.12+, Capstone 5.0.7 and the rustup 1.95.0 host toolchain.
Materialize the repository's pinned node artifact. The first invocation
provisions and verifies the three archives. The second runs offline.

```sh
packet=research/work-items/RE-002-node115-help-display-width
cache=$(mktemp -d)
python3 "$packet/verify.py" --cache "$cache" --fetch
python3 "$packet/verify.py" --cache "$cache"
```

The files in the chosen cache are the three original public crate archives.
Builds use a temporary directory. Only host builds of the public width
library and [its measurement client](widths.rs) execute. The captured ELF
is read as data throughout.
