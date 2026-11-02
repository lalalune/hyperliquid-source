# Node94 fresh configured endpoint to first connect request

Working local manual argument, not yet a qualified/submitted evidence packet.
Task RE-012 / transport under current startup/peer integration priorities.
Base966865f1637a29ce75b019e1bf11d5529cc6f519; target node94,91774280bytes,
SHA-2563b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
All addresses are linked ELF VAs; FDE ends are exclusive. No captured code,
instruction/register/branch evaluator or network call is run by this research.

## Credited work and bounded new question

`transport-node-port-94` already derives ten port arithmetic/overflow sites,
including2037ac0 and six base-port values. `transport-socket-calls-94` already
binds imported socket/connect/bind/listen/options calls and the call chain
2037ac0→20487f0→3cd6330. Its explicit remaining question is the address data
flow; its call edges alone do not prove that arithmetic feeds the actual
socket-address request. `RE-001-transport-integration-review-94` supplies
complete native context for20487f0 and identifies the earlier orphan byte.
Those observations are credited, not rediscovered or given new byte credit.

The new contract is one fresh normal path: which exact IPv4 destination and
port the first connect request receives from the configured packed endpoint,
and how the immediate adapter's ordinary return/close request differs for
socket failure, connect success, errno115 and other connect errors. It does
not recover service names, arbitrary caller states, retry scheduling, later
readiness/polling, successful TCP connection or the whole async future.

## Premises

The image/relocations/tables are immutable and admitted. Caller, output,
state/input/stack storage is valid, stable, appropriately sized, disjoint
and nonwrapping. The parent phase byte at+1fa is0 and the port selector at
+1fb is in0..5. TLS initialization before parent dispatch returns normally
and preserves the state and nonvolatile registers. Exact initialization,
TLS values and external runtime behavior remain opaque. The chosen arithmetic
does not overflow; the already credited panic paths are excluded, not modeled
as successful requests. Calls conform to the ordinary selected frame and
preserve nonaliased storage. Copies preserve the exact source byte sequence.
Unobserved padding bytes can have arbitrary physical values; they are never
promoted to meaningful address fields or claimed zero.

For result framing only, imported socket/connect calls return admitted signed
32bit values, errno points to an admitted32bit error word, and close returns
normally. The imported request and close counts are observations at the call
boundary, not proofs about actual Linux operations or descriptor lifetime.
Any allocation abort, reentry, foreign state mutation or unwind is excluded.

## Parent phase, configured bytes and port arithmetic

The full parent FDE is2037ac0..2039053 (5523bytes/963rows). Entry retains its
state pointer inRBX.2037b41..2037b45 saves the address of parent+78 at the
private stack slot+128. The seven-entry rel32table3c3b70 maps parent phase0
to2037b69; there is no arbitrary or guessed dispatch target.

Let b0..b4 be the five configured bytes at parent+1fc..+200, and d be the
byte at+1fb.2037b7e..2037b91 copies b0..b3 and b4 into+1f2..+1f6;2037b97
loads d. The adjacent option bytes are not address data in this theorem.
2037cf6..2037d0a forms q=(LE32(b0..b3) OR (b4<<32))>>8. Thus its low32
bits are exactly LE32(b1..b4), independent of all bits of b0.

The table load2037d11..2037d18 supplies B[d], where B is
[4001,4002,4003,4004,3998,3999]. Those values and the generic arithmetic
already belong to the credited port packet.2037d1c tests only bit0 of b0:

* If bit0 is1,2037d21 selects b1 as the unsigned8bit index; the checked
  multiply supplies1000*b1, and2037d31/2037d36 supplies raw IP word0100007f.
  The admitted no-overflow indices are0..61. Indices62..65 take the credited
  addition panic and66..255 the multiplication panic.
* If bit0 is0,2037d3d..2037d48 takes low32(q), preserves its upper24bits,
  isolates the low8bits, and supplies arithmetic offset0. Their OR therefore
  reconstructs the exact IP bytes b1,b2,b3,b4 without reversal.

2037d4a performs the checked base-plus-offset addition.2037d53..2037d5c
stores the combined raw IP at parent+7a, the resulting host-order u16 portP
at+7e, and a zero16bit tag at+78. The first8semantic bytes at parent+78 are
therefore LE16(0)||IP4||LE16(P). For the local arm IP4=7f000001; for the
other arm IP4=b1b2b3b4. The high seven bits of b0 do not change this selected
bit0 contract. No original Rust enum/source identity is inferred from that.

## Full32byte copy corridor into the connect adapter

2037d62 reloads the exact saved pointer parent+78.2037d6a..2037d78 copies
32physical bytes to parent+208..+227;2037d7f writes the nested phase byte at
parent+2f0 to0.2037d86..2037d9b calls20487f0 with its state pointer equal
to parent+208. The nested phase relative offsete8 is therefore the same
parent+2f0 byte just initialized to0. No caller-selected phase is assumed.

The full future FDE is20487f0..2048f05 (1813bytes/410rows). Its phase table
3c3cd0 maps0 to2048823. The initial copies at2048823..2048841 move the
original32bytes from future+0 first to+20 and then+40.204884e initializes
the iterator phase at+60 to0 and continues directly at204887d.2048883..
2048892 copies the same32bytes from+40 to+68.2048896 loads the original
tag0 before204889a writes the consumed sentinel4 at+68. The old tag0 avoids
the tag4 diagnostic and tag3 error paths. Payload IP and port are saved at
20488aa..20488ba before state-field reuse.

20488dc..2048904 puts the original0tag and payload into+c8..+e7.204890e
writes sentinel2 at+c8 only after retaining the old tag inAX. Since oldtag0
is not2,204891b reaches2048aa5.2048aa5..2048abb reconstructs a32byte
address value at future+70..+8f, restoring oldtag0 and the payload byte order.
2048ac9 sets the following nested phase0 and continues at2048ad0.

2048ad0..2048af9 copies the first16bytes to the private stack+40..+4f;
2048adf/2048ae6 copies the remaining16bytes to+50..+5f. These loads/stores
partition the same32byte value without changing any byte of its tag, IP or
port.2048b06 supplies that stack+40 pointer asRSI.2048b0b calls through
57737f8, whose zero-symbol RELATIVE relocation names3cd6330. Thus the
calculated first8semantic bytes reach the real adapter, not just another
unrelated call in the same owning function. The optional payload bytes8..31
are copied physically but cannot influence the selected tag0 adapter fields.

No claim about future resume, iterator yields after the first address,
registration helper1ffea80, eventual poll results, retries or completion
cleanup is needed or established. Their complete native bodies remain context.

## Exact imported IPv4 request and ordinary local result

The complete adapter3cd6330..3cd6427 has247bytes/69rows.3cd6340 loads the
leading16bit tag0.3cd6344..3cd6353 requests socket(domain2,type80801,protocol0)
through slot5775210, bound to imported`socket`. These numeric arguments are
already identified in the socket census and receive no new import discovery
credit. A signed-negative return bypasses connect and close, storing tag1 and
payload `(uint32(errno)<<32)|2` at output+8 via3cd6385..3cd6399.

A nonnegative socket result is retained inEBP. Because tag0's low byte is0,
3cd635f/3cd6362 selects3cd63a1. It reads the port at input+6, rotates its
16bits by8, selects length16/family2 and zeroesXMM0.3cd63ba reads the four
IP bytes at input+2.3cd63bd..3cd63cb creates exactly the16byte native frame:

LE16(2) || BE16(P) || IP4 || eightZeroBytes.

The16byte zero store also writes8bytes beyond that observed16byte request;
the later ECX store is still farther beyond it. No claim is made about ECX
or the unrequested tail. The imported connect call3cd63db receives the saved
fd, pointer to that frame and length16 through slot576f150 (`connect`).
The port becomes network-byte-order; IP bytes retain the order above.

At3cd63e1..3cd63f2, signed-nonnegative connect returns success. A negative
connect return reads errno through576e8d8 (`__errno_location`); exact signed
value115 (hex73) reaches the same success corridor.3cd63f4..3cd63f7 writes
tag0 and the saved fd at output+4, with no close request. This is an admitted
nonblocking/in-progress fd, not proof of an established connection.

Every other signed32bit errno maps at3cd640b..3cd6417 to tag1 plus packed
payload `(uint32(errno)<<32)|2`. The sign extension before the comparison
does not change that final low32bit shifted representation.3cd641d..3cd641f
requests close(fd) once through576e708 (`close`) and ignores its return.
The returned output pointer is the original result address. Actual errno
availability, descriptor reuse, OS/resource lifetime and unwinding stay opaque.

## Supporting checks still required

The manual argument must be bound to complete admitted native/FDE/CIE/RELA
and table records with independent decoders and nonneutral below-image
controls. Expected request bytes and result transcripts must be independently
frozen before any checker/model. Port overflow cases are credited context;
wrong bit0, port-endian, IP-byte-order and errno115/close rules should be
distinguished. No model fixture is an observed target run. Root checks and
fresh ownership review are still required before any PR. No Rust/compiler,
captured execution, network operation, full acceptance gate or byte credit.
