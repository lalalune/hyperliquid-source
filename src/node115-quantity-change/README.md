# Node115 quantity-change observations

Independent Rust for RE-004's counter-update entry and an independently fresh
post-lookup point in `0x4206f70..0x4207104`. This is a conditional observation
API, not the original ABI, a complete hook or a recovered account type.

`entry` observes the zero/nonzero occupancy update. Insert saturates at u64MAX;
removal decrements only a nonzero counter. A saturated insertion still stores,
while removal from zero does not. If an optional total is selected, the API
stops at `Lookup`. It supplies no lookup result. Otherwise it observes the
normal return or notification boundary, preserving the raw nonzero descriptor
word, new raw word and20 copied bytes. The native meaning of that word remains
unclosed.

`post_lookup` begins from a newly supplied total cell and old/new signed words.
It is not wired to a fabricated return from `entry`'s opaque lookup. It records
each actual total store in order. Old INT64MIN reaches an absolute diagnostic
before storing; new INT64MIN can reach that boundary after the first store.
Subtract/add overflow stops before the diagnostic helper with a pending signed
endpoint. The endpoint's next store has not executed. The API never assumes that
helper returns. `Returned` only denotes the observed native RET; the `value`
field is memory, and no native numeric return value is asserted.

The observation record, Vec of stores and boundary labels are owned analysis
representations. They do not infer original layouts, atomicity, rollback,
error enums, callback effects or live quantity policy. Raw signed words have
unknown economic units. The optional lookup, notification and diagnostic
helpers remain unresolved.

Reproduce with Python/Capstone5.0.6 and Rust1.94.1 from the repository root:

```sh
python3 research/work-items/RE-004-quantity-change-115/build.py \
  --rustc /absolute/path/to/rustc --output work/quantity-change-owned
python3 -m unittest discover -s tests -p test_node115_quantity_change.py -v
```

The output directory must be new. The builder regenerates the pre-Rust original
streams, compiles owned libraries/clients at opt0/3, compares stdin-only outputs,
executes ordinary source tests and compiled semantic variants. Expected values
are comparator-side and, separately, under cfg(test), absent from the ordinary
library/client. Clients run in an empty cwd and read no expected files or env.
Research builds execute on macOSarm64; no Linux-node build or byte identity is
claimed. New work is MIT. The original mapping from #2204 is credited, and no
previously mapped bytes are recounted. All component gates remain false.
