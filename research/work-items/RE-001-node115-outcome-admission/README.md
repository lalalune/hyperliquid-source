# RE-001: node115 user-outcome handler admission and amount preprocessing

Component: `action-wire`, bounded static research under RE-001. Question:
which checks run before an outcome descriptor reaches its operation-specific
helpers, and when does an absent amount bypass the initial parser?

Target Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No unlicensed reference code
was used. New analysis/code is independently authored under root MIT; imported
inputs retain their rights. This is an internal handler, not a wire decoder.

## Evidence and newly resolved behavior

The complete FDE `0x283b5b0..0x283bf9d` contains **2,541 bytes / 522
instructions**, independently decoded by GNU and LLVM. Addresses are ELF VAs;
ends are exclusive. `records.json` retains file offsets, body hash, actual
FDE/CIE identity, call bindings, source Locations and incoming references.
The denominator describes retained evidence, not reconstructed matching bytes.

Source Locations bind `l1/src/action/user_outcome.rs:55:56` and `59:26`.
Two qualified E8 calls enter the handler: `0x2bdbbaf` in `0x2bdbaa0`, and
`0x2c1a255` in `0x2c19f20`. There are no RELATIVE slots naming this entry.
The incoming census covers E8 and RIP-relative FF15/FF25 in `.text`, not all
dynamic dispatch or reachability. Other handler copies are not claimed here.

Let S be incoming RCX, A incoming RSI, and O incoming RDI. Observed order:

1. If byte S+0x2a9 is zero, store WORD 0x92 at O+0x10 and BYTE 0x0f at O.
2. Otherwise, nonzero byte S+0x2a8 stores WORD 0x193, BYTE 7 at O+0x12,
   and BYTE 0x0f at O. The preceding condition takes precedence.
3. The structure at S+0xa18 is selected by the signed-overflow test on
   `0 - first_word`: exactly the min-i64 sentinel selects the tree route.
   An empty tree root bypasses lookup. A nonempty tree calls `0x1d65fc0`
   and requires its first result byte nonzero. The other representation calls
   `0x24cd450` and requires nonzero RAX. Either failed test returns raw WORD
   0x15 with output BYTE 0x0f. Lookup membership meaning remains opaque.
4. Decode a local tag from A's first word w: nonnegative w gives t=3;
   negative w gives t=w XOR 2^63. This packet measures t=0..3 only.

| t | Dispatch target | Initial amount descriptor | Absence bypass |
| ---: | --- | --- | --- |
| 0 | `0x283b6fb` | A+8 | none |
| 1 | `0x283b94a` | A+8 | first word at A+8 equals 2^63 |
| 2 | `0x283b991` | A+8 | first word at A+8 equals 2^63 |
| 3 | `0x283b9d5` | A | none |

The four signed-relative entries at `0x5f7478` authenticate these destinations
against instruction boundaries. There is no local full-domain range check;
four measured entries do not establish a public enum domain or variant names.
For t=1/2, absent amounts jump directly to their branch, skipping both the
initial parser and precision check. Their later optional-amount handoff uses
zero R8. This is absence, not a zero-valued decimal.

For a present amount, its descriptor+0x10 length must be **below 101**.
Length 101 or larger returns WORD 0x158 and the selected descriptor pointer
at O+0x18. Parser slot `0x64e4e60` binds `0x43099f0`. WORD 0x1a2 permits
the next call through `0x64e6468` to `0x421e9d0`, with RDX=0 and ECX=5.
The second call must also return WORD 0x1a2. The parser's decimal syntax,
the converter's units and admissible returned values remain unclosed.

For the returned u64 N, the local arithmetic accepts exactly:

```text
ROR64((N * 0x5d4e8fb00bcbe61d) mod 2^64, 5) < 0xa7c5ac471b48
    iff N % 100000 == 0
```

`relations.py` proves this for the full u64 domain by inverting the bijective
multiply/rotate mapping. The multiplier is the modular inverse of 3125;
accepted rotated values are exactly 0..floor(UINT64_MAX/100000). Their inverse
images are 100000 times those values without wrap. Boundary/random probes
provide supplementary checks. Failed divisibility stores WORD 0x154; inactive
error payload bytes are not assigned meaning. Zero passes this local test;
the opaque parser/converter or later helpers may reject it.

## Prior-work boundary

PR #393 (also in integration #1151) identified these handler addresses, source
Locations and dispatch association, and explicitly excluded handler semantics.
PR #460 studies node94 operation-specific amount gates and explicitly excludes
the handler's first parse. PR #2275 studies downstream `0x2c269b0`, not this
frontend. These are credited context, not rediscovered claims. #2270's separate
exchange handoff has a different divisor (10000) and #2289 studies metadata-
dependent decimal divisibility; neither covers this handler or absence routing.
`scope-check.json` records the all-state PR and main-history audit and its limits.

## Reproduce and validation

From the repository root, Python 3.14.7, Capstone 5.0.7, GNU binutils
2.47.20260726 and LLVM 18.1.4 on macOS arm64:

```sh
python3 research/work-items/RE-001-node115-outcome-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-outcome-admission/verify.py --controls
python3 research/work-items/RE-001-node115-outcome-admission/relations.py
python3 -m unittest discover -s tests -p test_node115_outcome_admission.py -v
make doctor verify test catalogue-check reproduce
```

GNU/LLVM must be on PATH (`/opt/homebrew/opt/binutils/bin` and
`/usr/local/opt/llvm/bin` on this host). Export regeneration authenticates the
whole capture before writing a private static input copy. No captured code is
executed or emulated. `--write` regenerates checker/relations JSON.

The checker independently binds instruction spans, RELA records, source text,
Location fields, table data and unwind ranges. **36 corruption controls** bypass
whole-image/body/export guards to exercise those obligations. Four actual
arithmetic operand/branch mutations change the projected relation; a fifth
length mutation makes 100 fail. `validation.json` records actual repository
checks, baseline provenance and known environment skips. Passing these tests
does not establish parser or whole-action equivalence.

The complete body is retained, but later ID resolution, operation-specific
admission, leg construction and final state effects remain outside the claim.
No recovered Rust, build equivalence, public ABI, hosted CI or container run is
claimed; progress gates remain unchanged. Next close the parser/converter's
returned-value contract before assigning decimal units to this precheck.
