# Node115 fee-associated ordered-increase scan

Independent MIT safe no_std library for the normal-return paths of
`0x36e1b10..0x36e1b81` (node115). The source API accepts raw binary64 words and
width; it returns an owned found/consumed/remaining coordinate, not originalABI.

It compares only the next value with its predecessor in each admitted window,
consuming one element before each test. QuietNaN, equality and decreases continue;
an ordered increase stops true. Width governs remaining-window count, including
widths>2, without claiming those widths occur in the measured width2 caller.

`None` is an own refusal for signalingNaN or nonemptywidth0/1, not nativeerror.
Ordinary comparisons with DAZclear and masked denormal exceptions are premises,
not recovered target settings. See the [contract and packet](../../research/work-items/RE-004-fee-window-scan-115/README.md).
No root Cargo graph, dependencies, original compiler recipe, Linux execution,
whole fee-table acceptance or target-byte equivalence is claimed.
