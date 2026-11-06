# Fixed input-literal qualification probe

The child receives no expected outputs, paths or native data. Its source embeds
only the 42 frozen small input cases and four real repeated-group input plans.
It rejects command-line arguments and emits exactly 46 records in the frozen
case order. This is not a general stdin client or a native execution trace.

Each record is ASCII terminated by a literal LF. CR is forbidden. Fields are
separated by one TAB, IDs are exact and unique, and no blank/trailing records are
allowed. A success has exactly four fields:

```text
ID<TAB>O<TAB>USED<TAB>ENTIRE_BUFFER_HEX<LF>
```

A refusal has exactly seven fields:

```text
ID<TAB>E<TAB>KIND<TAB>MAP<TAB>INDEX<TAB>REQUIRED<TAB>ENTIRE_BUFFER_HEX<LF>
```

Decimals are canonical unsigned decimal (`0` or a nonzero first digit), at most
u64::MAX. Hex is lowercase, even-length, with no prefix; the global record
buffer bound is 4096 bytes. `MAP` is `P`, `S` or `-`. Unit kinds UsedBounds and
LengthOverflow require all three contextual fields `-`. GroupCount and
Representation require P/S and `-` for index/required. InvalidOrdinal,
EmptyValues and DuplicateName require P/S, a decimal index and required `-`.
Capacity requires map/index `-` and a decimal required length.

Syntax checks must not turn a wrong but well-formed result into protocol
failure: returned used/count/index/required values, complete buffer bytes and
success-versus-error are semantic observations. Baseline comparison requires
every full record to equal its separately retained literal expected record.
Mutant qualification requires process exit 0, complete canonical output, a
semantic mismatch and a mismatch at that variant's named frozen witness.
Always retain raw output before parsing. Strictly parse expected rows too.

There are nine native-value mutations and three host-policy mutations; report
these separately. Counts, first-failure details and all observed mismatch IDs
come from actual receipts, never from the existence of this protocol document.
