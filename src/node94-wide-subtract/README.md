# Node94 wide subtraction

`subtract_words(left, right)` preserves the existing numeric API: two arrays
of four little-endian u64 words produce their wrapping 256-bit difference and
borrow Boolean. Its existing 1,352 frozen unit vectors remain unchanged.

`image::subtract_into_image(image, destination, left, right)` additionally
implements the ordered memory behavior of `[0x32d8310,0x32d8361)`. Early
minuend stores can alter later subtrahend reads. The subsequent 16/8/8-byte
copy can likewise alter its later source reads. The result is the final live
qword loaded into raw RAX, and the final borrow is stored at destination+32.
All partial and exact data overlaps are allowed within the checked image.
Missing spans return `Unavailable` before any write; this is new safe policy.

The complete [proof and evidence packet](../../research/work-items/RE-004-wide-subtract-alias-rust-94/README.md)
defines ordinary stable memory, nonwrapping addresses and excluded native fault/
ABI behavior. Its pinned direct-rustc build compiles this dependency-free
`no_std` library, the input-only image client, and the old/new unit tests.
