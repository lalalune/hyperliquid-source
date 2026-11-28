# RE-004 — Node #115 decimal coefficient digit extraction

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the magnitude helper call identified by #7451 into its decimal digit extraction loop.

The helper reads the unsigned 96-bit coefficient as high, low and middle dwords at input +4, +8 and +0xc respectively. Zero bypasses the loop. For each nonzero iteration it divides the high limb by ten using `0xcccccccd` and shift 35. It concatenates each carried remainder with the next limb and takes the high half of a product with `0x199999999999999a` for the middle and low divisions. Each widened dividend is bounded by `9 * 2^32 + 2^32 - 1`.

The remainder of the final limb becomes an ASCII digit after adding 0x30. It is stored as a dword in the scratch array at stack +0x48. The three quotients become the next coefficient, so digits are generated least significant first. The selected window ends as the helper starts to compare the extracted count with the scale byte. The later scale placement, padding and emitted wire text remain open.

Run `PYTHONPATH=tools python3 research/work-items/RE-004-node115-decimal-coefficient-digits/verify.py`. It verifies the static instructions and compares the recovered reciprocal arithmetic with decimal digits from an independent integer-to-string reference.
