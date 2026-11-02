# Visor quoted-string dependency: conditional addressed proof

Target `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`. These are independently authored manual notes over retained native listings. No binary execution, instruction/register evaluator, original source-language ABI assumption or Rust implementation is involved. Native/raw agreement and abstract arithmetic checks do not close the whole visitor.

## Scanner question and byte predicate

The complete scanner FDE is `64f0d0..64f229`, with scalar tail `64f2f0..64f33a`. Treat a byte as special iff it is below32, quote34 or backslash92. Valid stable slice/state storage and `0 <= i <= n < 2^63` are premises.

At `64f0db..64f10e`, the scanner reads length and cursor, returns unchanged for i=n, takes a bounds diagnostic for i>n, and returns unchanged when the first current byte is special. Otherwise `64f11e..64f13a` advances one byte and computes `q=(n-i-1)&0x7ffffffffffffff8`. The word pointer starts at p+i+1 and the loop offset starts0. Every complete qword load at `64f175` is therefore within the remaining q bytes. No load past the slice is needed under the stated bounds.

The constants and operations at `64f114`, `64f147..64f15b`, and `64f179..64f1ad` implement the mathematical word mask

```
F(w) = ((w + dfdfdfdfdfdfdfe0)
       | ((w xor 2222222222222222) + fefefefefefefeff)
       | ((w xor 5c5c5c5c5c5c5c5c) + fefefefefefefeff))
       & ~w & 8080808080808080
```

Additions use64-bit wrapping arithmetic. The required theorem concerns the *least flagged lane*, not whether every later flag is exact. In the low lane the equality additions add255, while the control addition adds224. If a byte is ordinary, the equality XOR operands are nonzero and all three additions carry1 to the next lane. The higher-lane constants254 and223 plus that carry again become255 and224. Inductively, before the first special lane, every high-bit test is zero and the next carries remain1. In the first special lane, the equality test or control test has its high bit set with the input high bit clear. Later carry artifacts cannot change that lowest flag. All bytes>=128 have their high-bit result cleared by `~w` and carry1 forward. The finite byte lemma checks all256 bytes under this induction premise. Additional73,728 word scenarios support, but do not replace, that argument.

The nonzero mask branch reaches TZCNT at `64f1b2`. Thus its zero-input behavior is not used. After chunk k, the offset arithmetic at `64f1a5..64f1c5` yields `i+1+8*k+lane`, and the guard compares that result with the start of the current chunk. The result cannot precede that start for lane0..7. On no flag, `64f1d8..64f1fa` sets the cursor to `i+1+q` and tail-jumps to the scalar FDE. The scalar tail tests the same three special classes and advances only past ordinary bytes. This gives the intended first-special/end cursor relation under the premises. The scanner itself does not validate UTF-8.

## String result framing

`64f440..64f6a6` saves the current segment start, calls the scanner, then distinguishes end, backslash, quote and other special byte. The quote/no-scratch corridor `64f5b6..64f5df` advances past the quote and writes qword tag0 plus a borrowed pointer/length. The nonempty-scratch corridor appends the last ordinary segment, advances the cursor and writes tag1 plus scratch pointer/length at `64f584..64f59f`. A returned nonzero escape-helper result writes tag2 and the error payload at `64f5a5..64f5ad`. End-of-input and raw control-byte paths invoke diagnostic wrappers. The wrappers' normal nonzero/error origin is established separately in MANUAL-PROOF.md. Empty-scratch status is checked by length, not by an independently proven ownership enum.

Slot `7e4b68` binds imported `memcpy`. Slot `7e4bc0` binds image-relative `2be910`; `6500f0` is also a capacity-related call site. Allocation/copy/frame preservation, absence of aliases, and normal-return behavior are explicit remaining premises, not established heap or panic behavior. No claim that all unsuccessful paths restore the cursor is made.

## Escape dispatch

`64ea20..64ebd8` consumes one post-backslash byte, normalizes it by34 and uses an unsigned84-entry dispatch at `bb970` for the range34..117. The independent expected map and all256 input classifications agree with the retained table. Exactly eight simple mappings append one byte: quote->34, slash->47, backslash->92, b->8, f->12, n->10, r->13, t->9. Each has an immediate native store and the shared length increment / zero return at `64eb54..64eb64`. The u byte tail-jumps at `64ebd3` to `64ebe0`. The other247 byte values route to a diagnostic constructor; its normal nonzero diagnostic origin is covered in MANUAL-PROOF.md. The absent-byte path also remains a separate diagnostic case.

## Four hexadecimal bytes

`64f7f0..64f8c5` checks remaining length>=4 and cursor+4 overflow before reading exactly four bytes. It advances the cursor by4 before validating their values. A shorter slice instead sets cursor=length before a diagnostic call; malformed hex is therefore not a no-consumption error on these native paths.

Slots `7e7a48` and `7e7a50` bind two512-byte tables at `bbe10` and `bbc10`. All512 signed words equal the independently specified ASCII digit map: valid hex characters have nibble<<4 in the first table, nibble in the second, and every other byte maps to-1. There are22 accepted ASCII byte values because uppercase/lowercase A..F both appear.

At `64f847..64f865`, the first two digits form `(high[b0] | low[b1]) <<8`; the remaining two form `high[b2] | low[b3]`. All-valid digits therefore produce the ordinary16-bit positional value, nonnegative as a32-bit result. An invalid first or second digit makes the signed16-bit intermediate negative and keeps bit31 set after shift8. An invalid third or fourth digit sign-extends-1 into the final OR. Thus the JS edge at `64f867` detects every non-hex four-byte tuple, conditional on the bound tables; the valid corridor writes tag0 and the16-bit value at `64f869..64f86d`. The word-error tag/nonzero payload constructor at `64f070` is covered in MANUAL-PROOF.md. A pure ASCII/positional check covers all234,256 mixed-case four-digit combinations; that is abstract evidence, not native execution.

## Unicode assembly under the admitted frame contracts

`64ebe0..64ef08` reads a first16-bit unit through `64f7f0`. It rejects a first low surrogate with `(u & fc00)==dc00` at `64ec19..64ec23`. The wrap16 comparison `(u+2400)>=fc00` at `64ec29..64ec38` isolates high surrogates d800..dbff. A high surrogate requires the next literal backslash and u, then a second unit. At `64ece9..64ecf9`, `(v+2000) mod65536 >=fc00` admits only dc00..dfff. The reconstruction is `10000 + ((u-d800)<<10) + (v-dc00)`.

For nonsurrogate BMP units, the code chooses one/two/three-byte encoding at thresholds80 and800; the one-byte path can append a NUL. The pair path constructs four bytes using literal SIMD data at `6dea0` (`ff3f3f3f...`) and `6cd60` (`f0808080...`). Those exact32 bytes are retained. The surrogate guard and packed-byte formulas are independently checked over all65536 units, all1112064 scalar values and all1048576 high/low pairs. The addressed data/control bindings are tested separately; normal capacity/copy/frame contracts remain premises. This does not establish heap safety or a target runtime comparator.

## Reproduction and limits

This dependency is included in the39-FDE packet. See VALIDATION.json for fresh
native/FDE/CIE/data/RELA/call/tail exports, ordinary/optimized identical receipts
and meaningful below-image-identity controls. The counts are retained evidence,
with zero new recovered-byte credit. MANUAL-PROOF.md closes the distinct
result-name/index and normal diagnostic-origin obligations. Buffer/alias/call
preservation and normal allocation remain explicit premises; no unwind, ABI,
complete JSON/configuration, numeric-value or whole-program claim is made.
