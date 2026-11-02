# Selected custom-table leverage-increase gate: native intake

Native freeze50bd47d389dfe04e89076ad99dabe8a22565d905eb66453839cb2d7b8cad3d1a
precedes any new decision oracle or Rust. Complete caller FDE is
0x37098a0..0x370a3c1:2849bytes/600 GNU=LLVM byte partitions,131 syntactic CFG
blocks,33 calls,15 coordinate identity windows. Body SHA256
73da7c07d5d63895ea8a6b6596ba224a2a0fab018342e8733e6583bcd5a845a2.
Full FDE/CIE/LSDA/header identity is retained. The CFG is static: each call has
an ordinary-return edge, not an invented noreturn/exception interpretation.

Existing RE-004-update-leverage-path-94 owns the original caller's static gate
and row-update observations. The new question is a Rust composition of that
caller gate with #1460's actual cap, not new ownership of the caller body.
No existing emulator/harness is executed; only raw bytes, disassembly and CFG
are used here. Main is56c0ec67;234 open PR full bodies at intake have no exact
caller/updateLeverage claim except own#1460's credited cap caller site.

## Domain before entry to the selected gate

D is a readable stable dex record. Asset division/index and price-index checks
must pass. Cross request is canonical0/1. Selected metadata table id is>=50,
its custom registry search succeeds, and the resolved holder has the existing
validated nonempty1..3 logical MarginTable with stable ordered tree links.
The user lookup returns an active existing position, its table id equals the
selected metadata id and requested u32>=old leverage u32. Resolved row/holder,
metadata and relevant global default/callback storage are assumed nonaliasing
and stable through the gate. Runtime source admission and table registration
are not established. No raw Rust holder/iterator ABI is reconstructed.

## Table provenance and unchanged holder

Metadata uses48-byte records fromD+8, countD+10; table id is record+18.
At3709982..998a unsigned id>=50 chooses custom lookup. D+38 supplies registry
root andD+40 height at3709a47/9a59. u32 keys start atnode+270, node count is
u16 at+29e and child edges+2a0. Each56-byte value starts node+8+56*i:
at equality3709ac7 subtracts the negative56-byte scan displacement and adds-48,
yielding that exact address inR15. Missing id takes the existing panic path;
that condition is outside the selected normal domain.

The SAME R15 holder supplies its tier root at+18 and height at+20. The first
leftmost tier byte atleaf+18 (3709b88) becomes the overall maximum; an absent
root/empty first leaf uses3. Valid nonempty first-lower0 tables exclude that
fallback here. R15 remains the holder whileRCX traverses the tier tree. It is
passed asRDI at3709ef6, so the overall-maximum and size-cap checks use the
same resolved table, not separately supplied unconstrained maxima.

Builtin id<50 enters3398f50 and a temporary table: intentionally excluded.
The custom registry's producer/registration and broad ownership remain open.

## Read widths, order, and initialized refusal fields

Requested level is stored fromR9D at37098b1 and read asu32 throughout. It is
not truncated to the cap byte. Cross-kind rejection is earlier at3709911/9918
when canonical cross=true and perp kind byte!=0: only statusu16=0x44.
After table resolution,3709b8c/9b90 unsigned level<=overall maximum passes;
otherwise3709b97 writes onlyu16tag0x43.

The active size is the signed raw word from position+10 at3709ca3; zero bypasses
the gate and is outside this selected active-position domain. Position mode is
compared asDWORD==0 at3709cad (not the byte-mode reader of another component
helper). SETE then XOR with the cross byte accepts exactly(mode_word==0)==cross.
Mismatch writes onlyu16tag0x45 at3709cc5 before the cap or price lookup.

Price-index bounds at3709ec0..9ec7 must pass. The local index was multiplied
by3 and saved atstack+120 at370995e..9969;3709ee5/9eed multiplies it by32.
The raw unsigned price word at3709ef1 is[D+68 +96*local +20]. The signed size
inRDX survives unchanged from3709ca3 to the cap call at3709ef9. RDI=R15 binds
the already selected table; slot5775998 is the proven3333580 cap helper.

3709eff MOVZX EAX,AL establishes u32 cap. CMP at3709f02 and unsignedJBE at
3709f06 accept exactly requested<=cap, including equality. The reject path
writesu16tag0x50 atout+0 (3709f11), u32cap atout+4 (3709f16), then shared
cleanup/return. Padding+2/+3 and other status bytes are not initialized here
and must not be fabricated by the safe Rust decision representation.

## Why the selected increase avoids unresolved margin checks

A passing cap enters370a07d. R13D retains the old position's table id loaded
at3709edc; EBP is the metadata table id. CMP370a083/JNE370a086 goes to clone
setup370a096 only if ids differ. In the selected matching-table path it falls
through370a088, loads the old u32 leverage saved atstack+5c from3709ed3/9ed8,
then unsignedCMP370a08c/JAE370a090 jumps directly to3709cfa when
requested>=old leverage. Both direct selected edges are in the full CFG.

The only two calls via57746f0 to unresolved37d77e0 are370a249 (table-change
mode2) and370a27a (leverage-decrease mode1). Neither site is on that selected
normal branch. A lower request or different table is not represented as a
native rejection: it leaves this proved domain and needs those helper results.

3709cfa starts the actual commit sequence: copies the20-byte user key,
3596940 first resolves the account at3709d1b;339b590 then inserts its key
intoD+188 at3709d4c;33bd420 finds/creates the position at3709e29, then
table id/mode/leverage fields are written and later accounting/index helpers
run. The gate itself returns no Success tag before these calls. After ordinary
returns the caller writes successu16tag0x186 at3709fbe. This intake claims
only `EnterCommit`, not whole action success or effects of those helpers.

## Candidate independent decision interface, not yet authored

A minimal checked safe interface can restrict custom id>=50, active existing
position, matching table id and requested>=old leverage. Those are explicit
API domain refusals, not native status errors. Inside that domain, preserve
native decision order: cross-kind0x44, overall maximum0x43, DWORD-mode0x45,
cap0x50(with capu32), otherwise EnterCommit. Supply one resolved MarginTable
and derive BOTH maxima/cap from it. Do not accept an unrelated external maximum.

Unknowns: builtin builder, table producers and row lookup admission/lifetime,
general decrease/table-change margin checks, subsequent mutation helpers and
full action/financial behavior. No live state, target execution or progress gate.
