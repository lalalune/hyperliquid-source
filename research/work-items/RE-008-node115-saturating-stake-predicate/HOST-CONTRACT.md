# Proposed safe host interface and validation transport

This fixes host policy for the conditionally selected stake predicate. It is not
source admission, a recovered native ABI, or a claim about native malformed-input
behavior. The target/native proof remains a separate document.

## Library

Use a dependency-free, allocation-free Rust library over borrowed inputs:

`predicate(rows: &[Row], head: usize, live: usize, selected: &[[u8; 20]])`

returns `Result<Observation, InvalidView>`. `Row` contains an actual twenty-byte
key and u64 weight. `Observation` exposes `selected_sum: u64`, `total_sum: u64`
and `passes: bool`; the sums are chosen observations of native intermediate
values and only the boolean corresponds to native AL. No original layout or
calling convention is promised. `rows.len()` is the capacity.

Admission is deterministic and precedes computation:

1. `live <= rows.len()`.
2. Empty backing storage requires `head == 0` and `live == 0`.
3. Nonempty backing storage requires `head < rows.len()`, including when live
   is zero. This empty-live rule is a stricter canonical host policy; the
   native zero-live route does not read head to find a row.
4. Logical live keys must be nondecreasing by unsigned comparison of all twenty
   bytes. Equality is admitted. Inactive rows are not checked for ordering.

Any bounds failure returns `InvalidView::Bounds`; otherwise the first logical
ordering failure returns `InvalidView::Order`. These are chosen safe errors.
There are no sorting or uniqueness restrictions on `selected`: it is the
complete supplied key-value sequence corresponding to the conditional native
tree traversal. Every occurrence is preserved. The library sets no artificial
row/query count limit beyond valid addressable Rust slices. Ring indexing must
avoid overflowing `head + logical_index`.

After admission, perform actual seam-sensitive key lookup for each selected
occurrence, skip misses, and saturate its found weights into selected_sum.
Independently saturate all live row weights into total_sum. Compare the wide
products strictly: `2 * total_sum < 3 * selected_sum`. Preserve complete
iteration in the implementation; no helper-effect or timing equivalence follows
from the returned value relation. No weight callbacks, native pointers or
precomputed fold sums are accepted as inputs.

## Stdin driver

This transport exists to exercise the library with inputs only. It is not a
native wire codec. The executable accepts zero user command-line arguments.
Any argument exits status 2 with empty stdout before reading stdin; arguments
cannot carry expected values or select an alternate input source. Use one ASCII
TSV record per LF-terminated line, exactly six
fields:

`id<TAB>capacity<TAB>head<TAB>live<TAB>physical_rows<TAB>selected_keys<LF>`

- ID: 1 through 64 characters from ASCII letters, digits, underscore or hyphen.
  IDs must be unique within the complete input by exact case-sensitive byte
  equality. They carry no expected value.
- Integers: canonical unsigned decimal (`0` or a nonzero first digit followed
  by digits), with no sign, whitespace or leading zero. Capacity, head and live
  fit u64; library metadata must fit the target 64-bit host usize. Capacity
  additionally must equal the parsed physical row count.
- Physical rows: `-` for none, otherwise a comma-separated list of
  `key_hex:weight`. Keys are exactly forty lowercase hexadecimal characters;
  weights fit the complete u64 range. Rows are supplied in physical order.
- Selected keys: `-` for none, otherwise comma-separated forty-character
  lowercase hexadecimal keys. Preserve repeats and their input order.
- No blank lines, comments, BOM, CR, embedded NUL, extra fields, missing final
  LF or non-ASCII bytes are admitted. Empty input is a valid zero-record stream.

Chosen transport resource limits: at most 16 MiB input bytes, 8,192 records,
4,096 physical rows per record and 4,096 selected keys per record. These limits
do not restrict the library or claim native maxima. Head/live values above
capacity are structurally parseable and produce the library's bounds outcome;
they are not transport errors. A capacity exceeding 4,096 is a transport error.

Parse and validate the entire stream, including unique IDs, before writing any
stdout. Any lexical/structural/resource error exits status 2 with empty stdout
and a short stderr diagnostic. A stdin read failure also exits status 2 without
stdout. No environment variable or file may supply
expectations. Do not open a network connection or an input filename.

For a valid transport stream, write one LF-terminated result per input record,
in the same order, exit zero, and leave stderr empty:

- Success: `id<TAB>ok<TAB>selected_sum<TAB>total_sum<TAB>0_or_1<LF>`.
- Bounds refusal: `id<TAB>bounds<LF>`.
- Ordering refusal: `id<TAB>order<LF>`.

Echo each ID byte-for-byte with case preserved. Both sum fields use canonical
unsigned decimal as defined for input integers; the boolean is exactly the
single ASCII character `0` or `1`. No alternate number encodings are accepted.

An output I/O failure exits status 1 with a short stderr diagnostic. It may
leave partial stdout after a valid input; the no-partial-output guarantee is
specifically for rejected arguments/input, not an atomic stdout transaction.
Reported successful runs require actual complete output and no I/O failure.

## Independent qualification obligations

The mathematical reference must use linear order-statistic lookup with the
explicit seam exception and exact unbounded sums clamped only after summing,
separate from the intended Rust binary search and stepwise saturating folds.
Manual native-grounded examples must qualify it before corpus freezing.
Repeated generator runs must reproduce the frozen inputs and expectations.
Freeze them before Rust implementation authorship.

The comparison runner must distinguish a semantic mismatch from process,
transport, missing/extra/duplicate row, ID or malformed-output failure. Compiled
wrong implementations must build, exit zero and return complete valid output
before their semantic mismatches count. Boundary controls must cover the exact
transport limits, late malformed records and no partial stdout.

Validation is finite and conditional. It neither executes captured instructions
nor proves original constructors, native error behavior, effects, ABI, Linux
runtime execution or full-node equivalence. All full-scope gates remain false.
