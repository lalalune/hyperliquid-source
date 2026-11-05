# RE-001: close the node115 staking checked weight comparison

- Component: staking; bounded static support for the existing comparison caller.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: byte-backed observations and a stated arithmetic interpretation.
  No Rust reconstruction, captured execution, emulation or gate is claimed.

The [previous packet](../RE-001-node115-staking-nested-comparison/README.md)
leaves the relation at `0x422e0f0` opaque. This packet follows that complete
callee and its four local dependencies. It identifies checked selected-key
lookup accumulation, checked total accumulation and the strict unsigned
wide-product comparison. The existing caller is retained as provenance,
including its same-materialization connection; it is not new coverage.

| Role | Complete unwind extent | Bytes |
| --- | --- | ---: |
| Comparison | `0x422e0f0..0x422e273` | 387 |
| Selected-key/map fold | `0x4351520..0x43516c2` | 418 |
| Key cursor | `0x37c9490..0x37c96b1` | 545 |
| Weighted cursor | `0x37cb190..0x37cb3b8` | 552 |
| Flat 32-byte-key lookup | `0x455abb0..0x455ad9c` | 492 |
| Prior caller, reused | `0x36c7f70..0x36c8424` | 1,204 |

The five newly interpreted scopes total **2,394 bytes**. All six exports total
**3,598 bytes**. These are static evidence extents, not reconstructed,
source-built, matched-window or whole-component coverage. An FDE alone is not
a source-function boundary; direct entry/call evidence and the retained
instructions corroborate the selected callable scopes, while split cold code
and diagnostic closure remain limits.

## Reproduce

With authenticated inputs and GNU objdump/readelf on PATH:

```sh
python3 -B research/work-items/RE-001-node115-staking-row-comparison/collect.py \
  --output work/staking-row-comparison --check
python3 -B -m unittest discover -s tests -p test_node115_staking_row_comparison.py -v
make verify
make catalogue-check
```

The collector checks the complete target digest before native queries/output,
independently decodes ELF/FDE/RELA records, checks each complete range with GNU
unwind output, and matches every exported instruction byte to the input.
Source Location `0x6468cb0` binds `l1/src/staking.rs:185:9` through the
caller's actual LEA. Imported nearest-symbol labels in objdump are presentation,
not recovered function names.

The framework is adapted from the prior packet's MIT collector at the base
above. Its original files and negative results are unchanged. New snapshots
use UTF-8/LF explicitly so Windows text translation cannot invalidate committed
manifest hashes. The temporary input pathname is replaced by the canonical
artifact pathname and trailing display whitespace is removed; instruction
addresses/bytes and operands are not masked. Tool versions are retained.

## Checked lookup sum B

The comparison first calls `0x4351520`. That helper takes the map reference
from its first input at `+0x48`, obtains 32-byte key views through
`0x37c9490`, and looks each key up in that map. Missing keys contribute
nothing and iteration continues. This is not an all-or-nothing materializer.

The min-i64 descriptor tag selects tree lookup. Tree keys are compared in
32-byte units using imported `memcmp`; equal keys select the u64 value view
at node `+0x168 + index*8`. The node count is a u16 at `+0x1c2`;
children are read at `+0x1c8 + index*8`. A height borrow or missing root
leaves that key without a contribution. Construction, global ordering and
valid node-count/extents are preconditions, not established by this helper.

The alternate map representation calls `0x455abb0`. Its descriptor fields
are capacity/storage/start/length at offsets 0/8/16/24. Rows are 40 bytes,
with a 32-byte key and a value at `+0x20`. The helper returns a low-bit
miss flag and a logical index; the fold additionally checks index < length.
Physical indexing adds the start and subtracts capacity once when needed.

The flat lookup normalizes the start once, chooses a segment using the
physical-zero seam key when wrapped, and returns immediately on seam equality.
Within the selected sorted segment, the greater-only midpoint rewind and final
equality check select the last equal entry. These observed duplicate choices
are not a claim that duplicate keys are reachable under the original
collection's construction invariants.

Each included value uses a 64-bit ADD with carry rejection. Ordinary completion
returns raw RAX tag 1 and RDX sum B; overflow returns tag 0 with the wrapped
partial payload in RDX. No saturation is performed. Original Option/Result
source types are not inferred from those raw return words.

## Total sum S and final byte

After the first fold returns, the comparison copies **72 bytes** of its second
iterator to local stack storage. It traverses that copy even when the first
fold has returned tag 0. Only after ordinary second-traversal termination does
it require the first tag to equal 1. Replacing that sequence with an early
first-failure return would lose the observed traversal/diagnostic ordering.

Tag 2 selects the optimized flat path: 40-byte steps, u64 value at row +32,
then active/deferred range handoff. Other paths call the weighted cursor.
Both additions reject carry and immediately take the false exit on overflow.
The original second iterator is not updated by these local-copy stores.

At `0x422e23d`, after both folds ordinarily complete, the code implements:

```text
accept_byte = (first_raw_tag == 1) AND (2 * S < 3 * B)
```

The two accumulated values must each fit u64. The products are compared as
unsigned 128-bit values: a shift preserves the high bit of 2*S, unsigned MUL
forms 3*B, and CMP/SBB/SETB perform a strict comparison. Only **AL** is the
normalized result byte; upper RAX is not normalized by SETB. False exits clear
EAX. This differs from the distinct saturating 20-byte-key predicate discussed
in [#2750](https://github.com/lalalune/hyperliquid-source/pull/2750).

In the reused caller, R14 holds the materializer output at caller RSP.
The key-fold input stores that reference at caller RSP +0x68, exactly
first-input +0x48. The total iterator at caller RSP +0x90 is built from the
same output descriptor. The new result therefore connects selected-key
contributions and total weights from that materialization; original key
identity, stake units and application policy remain unassigned.

## Cursor and failure boundaries

Both cursor helpers first inspect the remaining count at iterator +0x40.
Zero returns a null item without following the descriptor tag. Otherwise they
decrement it and require tree tag 1. They support initial leftmost descent,
parent ascent and preparation of the next right-subtree position.

The key node layout uses parent/parent-index/count/children offsets
`0x160/0x168/0x16a/0x170`, and returns a 32-byte key view. The weighted
layout uses `0x160/0x1c0/0x1c2/0x1c8`, with u64 value views from
`0x168 + index*8`. Full record ownership, allocation, lifetimes, concurrent
mutation, global cardinality and constructor-established invariants are open.

The relevant RELA binding names `memcmp` at slot `0x64dfb50`
(GLOB_DAT, symbol 12). Register-indirect calls in the flat search load that
same slot; ordinary ABI-preserving library behavior is a stated assumption.
Missing-ancestor and invalid-tag branches call slot `0x64df830`, bound
to `0x1680c10`, then reach UD2. That target's behavior/unwinding is not
closed here; these paths are not reclassified as an ordinary false result.

## Controls and remaining work

`binding-config.json` ties 69 instruction groups to the observations.
Tests corrupt the first and last byte of every group, independently of the
whole-input digest guard; they also reject damaged/truncated/duplicated export
rows and a wrong target before native tools/output. These are evidence
integrity controls, not runtime equivalence tests.

`math-witnesses.json` contains hand-derived, value-only arithmetic checks:
strict equality, both checked-sum overflows, high-bit values, and wide-product
cases that distinguish inclusive comparison, saturation and u64 truncation.
They are not captured outputs, instruction evaluations, a lookup oracle, or
proof that every supplied scalar pair is a reachable staking state.

No Rust implementation, native ABI reconstruction, captured execution or
emulation, wire/key-domain identity, full helper/diagnostic closure, source
build or gate change is requested. All 92 full-scope gates remain false.
The next question is to recover construction/validity of the materialized map
and caller-supplied key cursor before composing an independently authored
implementation under an actual object contract.
