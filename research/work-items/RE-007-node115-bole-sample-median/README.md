# RE-007 — Node #115 borrow/lend refresh sample median

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [index writer packet](../RE-007-bole-index-writer-115/) lists the median helper as open.

At `0x369aef5`, the refresh calls `0x452aec0` with the sample pointer and count. This helper returns zero for an empty sample. For a nonempty sample it allocates and copies eight bytes per item, then orders the copy. Counts 2 through 20 take the inline unsigned insertion sort. Counts of at least 21 use the sort slot at `0x64e91d0`, whose relocation resolves to `0x36eeba0`. Count 1 bypasses sorting.

Odd counts select the sorted element at floor(count / 2). Even counts load the two middle unsigned words and return `(lo & hi) + ((lo ^ hi) >> 1)`, equal to the floor of their mean without overflowing a 64-bit sum. The temporary buffer is freed before returning the selected word. The refresh tests that word against zero and takes a distinct branch when it is zero.

This packet covers median selection and the refresh handoff. The large-list sort body and business interpretation of the zero branch remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-007-node115-bole-sample-median/verify.py` from the repository root to verify static windows, the sort relocation and the small-sample model.
