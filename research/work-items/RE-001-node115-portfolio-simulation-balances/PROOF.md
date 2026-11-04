# Native relations and their premises

All addresses are node115 ELF virtual addresses and ranges have exclusive ends. Original source-line records provide attribution, not a reconstructed source listing.

## Identity and source binding

The complete FDE is `0x2c64870..0x2c6597a` (4362 bytes), body SHA-256 `329dab1fd2ec234b39ab7fd55495231baeb0bb6168dfb986e02cfc2b1431e936`. Its readelf record and parsed FDE are retained. The source bytes at `0x43e0eb` are `l1/src/exchange/simulate_portfolio_margin.rs`, length 44. Five RELATIVE relocations bind Location-shaped records to those bytes:

| Record VA | Source line:column | Native use |
| --- | --- | --- |
| `0x644d900` | 66:33 | Both per-entry seed requests |
| `0x644d918` | 110:49 | Residual surplus request in R9B=0 path |
| `0x644d930` | 113:30 | Residual shortfall request in R9B=0 path |
| `0x644d948` | 127:53 | Other mode, context only |
| `0x644d960` | 130:48 | Other mode, context only |

There are four qualified E8 incoming sites: `0x296a561`, `0x296b494`, `0x2c61668`, `0x2c65a53`. Their owning FDEs and instruction bytes are recorded. No RELATIVE pointer directly targets this body. The census excludes arbitrary register-indirect dispatch and does not prove the callers' input invariants.

## Inputs and seed loop

The prologue saves incoming RDI as output pointer, RSI as state pointer, RDX as a pointer to 20 copied bytes, ECX as a mode value, R8B as a later transform flag and R9D as a later mode value. Only the low bytes of ECX and R9D select the branches described here; these are machine-level argument observations, not a recovered public ABI.

The seed collections occupy local `[rsp+0x2b0..0x2d0)` and `[rsp+0x2d0..0x2f0)`. Each receives qwords `(0,8,0,0)`. At `0x2c648e4`, state+`0x1340` supplies an entry count; zero bypasses the loop. State+`0x1338` supplies the backing pointer, with stride `0x510`. The loop reads key A at entry+`0x50` and key B at entry+`0x58`.

| Incoming CL | Value acquisition | Rejected result |
| --- | --- | --- |
| zero | Slot `0x64e7178` → `0x447c3b0`, arguments entry, copied 20 bytes, raw code 4, byte entry+`0x509`; result RAX | No local result-tag test |
| nonzero | `0x2a83ae0`, arguments output, state, key A, copied 20 bytes, raw code 2 | Output u16 must equal `0x1a2`; otherwise copy the 112-byte record to cleanup `0x2c94f00`, advance the entry, and continue |

For the tagged mode, the admitted value is a qword at result+`0x18` (`rsp+0x308`). In either mode, `0x2db0a80` is requested with local collection+`0x2d0` and key B; `0x2423690` yields the qword pointer to update. This is called a grouped lookup/entry request from its usage; its internal default and key policy are not claimed. The qword update precedes the call to `0x2dafc10` with collection+`0x2b0`, key A, the original provider value and Location 66:33. Thus the per-entry request receives the provider value, not the newly accumulated group value.

The direct loop advances the pointer and decrements remaining bytes by `0x510`; the tagged loop advances an offset by `0x510`. Its rejected-result path rejoins that increment before the next entry; it does not return from the function or insert that result into either seed collection.

## Signed saturation, conditional on overflow-hook return

At `0x2c64990` and `0x2c64b1c`, the addition uses ADD followed by **JO**, so the overflow criterion is signed. Without overflow, the sum is stored. On overflow, a call through `0x64e4ea8` → `0x4524e40` occurs with code zero and context `0x6432f70`. If that helper returns, the wrapped sum's sign is extended with SAR 63, XORed with `0x8000000000000000`, and selected when a repeated ADD still overflows.

For positive overflow, the wrapped result is negative: all-one sign extension XOR the sign bit gives `i64::MAX`. For negative overflow, the wrapped result is nonnegative: zero XOR the sign bit gives `i64::MIN`. Thus the local normal-return relation is `clamp_i64(old + provider_value)`, not unsigned saturation or wraparound. The side effect and possible non-return of the hook remain outside the claim.

## Preparation and R9B=0 residual split

After the seed loop, a helper at slot `0x64e6498` → `0x369a210` receives state+`0x670` and copied 20 bytes. Its returned representation is copied/transformed into local context at `rsp+0x30`. Another local context contains a newly initialized collection at `rsp+0x118` and a borrowed pointer to state+`0x6c8` at `rsp+0x138`.

The call to `0x4716cc0` receives state+`0x3f0` and copied 20 bytes. The returned representation, with a fallback object and iterator construction, feeds `0x2cfd720`; the saved R8B is passed by address as transform context. Slot `0x64e7e68` → `0x3f10c10` then consumes the grouped seed representation and the transformed result, producing two 32-byte representations copied to locals `rsp+0xf0` and `rsp+0x80`. Their economic meanings and transformation internals are unknown.

Incoming R9B controls both `0x2c64e8f..0x2c64e98` (skip a preprocessing helper loop) and `0x2c650ed..0x2c650f6` (enter the selected residual path). **When R9B is zero**, the first representation is iterated as key/qword pairs. This scope assumes a valid yielded pair; it does not reconstruct container allocation or iteration internals.

At `0x2c65705..0x2c65713`, EAX receives 100 and `MUL qword [rdx]` produces the unsigned 128-bit product. JO here tests MUL overflow: the high half is nonzero. That branch goes directly to the next iteration. Hence accepted quantity `q` is at most **184467440737095516**; the next value is skipped, not clamped.

For an accepted product `scaled=100*q`, `0x2dcc210` receives local `rsp+0x80` and the key. Its AL low bit indicates whether returned RDX contributes; `TEST AL,1` plus CMOVE selects zero otherwise. Define `have = RDX` if AL is odd, otherwise zero. These are raw helper output premises, not a recreated lookup implementation.

At `0x2c6572e..0x2c6575c`, native subtraction and CMOVB yield the following request to `0x2daed00`:

| Relation | Destination local | Value | Location |
| --- | --- | --- | --- |
| `have >= scaled` | `rsp+0x80` (surplus) | `have-scaled` | 110:49 |
| `have < scaled` | `rsp+0x240` (shortfall) | `scaled-have` | 113:30 |

The first SUB computes `have-scaled`; its borrow selects destination and Location with CMOVB. The second SUB computes `scaled-have`; its new borrow selects the first difference as magnitude. At equality neither subtraction borrows, so the request is **surplus, value zero, line 110**. There is no explicit zero-result skip at this call site. The update helper's internal overwrite/removal behavior is unknown.

For values through `u64::MAX`, the absolute difference fits a qword. Only the preceding multiplication needs an explicit overflow skip. The scale 100 is observed; interpreting it as percent, basis points or a currency conversion would require additional unit evidence.

## Returned representation and excluded mode

On the normal return path `0x2c65768..0x2c6585f`, the saved output pointer receives:

| Output range | Local source | Status |
| --- | --- | --- |
| `+0x00..+0x20` | seed at `rsp+0x2b0` | per-entry requests |
| `+0x20..+0x58` | `rsp+0x30` | opaque context |
| `+0x58..+0x78` | `rsp+0x118` | opaque context collection |
| `+0x78..+0x80` | `rsp+0x138` | pointer to state+`0x6c8` |
| `+0x80..+0xa0` | `rsp+0x80` | surplus-side requests |
| `+0xa0..+0xc0` | `rsp+0x240` | shortfall-side requests |

RAX returns that same output pointer. No stable Rust struct name/layout beyond these stores is asserted. The R9B-nonzero mode additionally uses `0x2c619b0`, `0x2c62820`, result tags and context replacements; its behavior is not summarized by the simpler table above. All its bytes/calls are retained so that this boundary is reviewable.

## Checks and falsification

The algebra checker uses independent integer clamping as a reference for 1875 selected signed input pairs per mode, all 65536 tags for four representative mode bytes, 9216 unsigned residual/presence combinations, and explicit multiply/equality/end-point cases. Finite checks support the general arithmetic argument above; they are not target runtime tests.

Seven real operand-byte counterfactuals change accepted tag, multiplier, presence mask, equality routing/Location, or each signed endpoint. Each changes the derived observation and fails an instruction obligation with outer hash/export guards disabled. Forty-eight separate corruptions attack instruction spans, Location/source bytes, RELATIVE addends, and the FDE extent. Exact body digests and independent native exports supply additional guards in ordinary verification.
