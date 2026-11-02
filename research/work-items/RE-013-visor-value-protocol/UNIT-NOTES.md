# Visor unit-literal corridor: addressed conditional argument

## Unit literal corridor, manual forward reading

Assume stable disjoint valid storage, state+18 is a byte pointer, state+20 is length n, state+28 is cursor i with `0 <= i <= n < 2^63`, and no intervening changes. These are proof premises, not recovered original Rust ABI guarantees.

`4ab530..4ab65a` scans bytes from i, advancing over9/10/13/32. The rolling RAX starts at i+2 and reads `[pointer+RAX-2]`; each whitespace advances the stored cursor to RAX-1. Exhaustion reaches an opaque error constructor. When the first non-whitespace byte is `n`, the code advances the stored cursor past that byte and uses separately checked bounds before comparing `u`, `l`, `l` at `4ab5c7`, `4ab5df`, and `4ab5f7`. Matching all four bytes reaches `xor eax,eax` at `4ab5fc`, then returns. It has consumed only the four-byte prefix and does not itself validate a following delimiter: that is the caller's closing-brace corridor. The guard also excludes cursor arithmetic wrap under the stated length premise. Mismatch and other-token paths construct or propagate the nonzero normal diagnostic pointers established in MANUAL-PROOF.md. Numeric values and diagnostic contents remain opaque. Thus zero discriminates the four-byte null prefix under the admitted frame/call premises; the caller separately validates the closing brace.
