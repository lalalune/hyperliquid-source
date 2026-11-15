# Canonical traces

Each trace is one emulator run of the dispatcher; the model predicts the same call list and output.

## arm 0, small id

- input: T=0x800000000000000d cap=0x3 len=0x4 script=A1B1C1D1G1H1Z1 v=0x7 s=1
- call S(cc05fcfe02765cce04000000..(41))
- call A(0x7c0, 0xce5c7602fefc05cc, 0xff986f611f)
- call B(0xce5c7602fefc05cc, 4, 0x8a41080afd7b)
- call W(350000000000000007000000..(13), 0)
- call FREE(0xce5c7602fefc05cc, 3, 0)
- result: ret, tag 0x1a2

## arm 0, first offset id

- input: T=0x800000000000000d cap=0x0 len=0x4 script=A1B1C1D1G1H1Z1 v=0x2710 s=0
- call S(149600fb4a312d9304000000..(41))
- call A(0x7c0, 1, 0)
- call B(0x932d314afb009614, 4, 0x403a9062e6c7)
- call W(3500000000000000b0ad0100..(13), 0)
- result: ret, tag 0x1a2

## arm 0, last offset id

- input: T=0x800000000000000d cap=0x0 len=0x4 script=A1B1C1D1G1H1Z1 v=0x5f45a5f s=0
- call S(0acd313cfa66ffba04000000..(41))
- call A(0x7c0, 1, 0)
- call B(0xbaff66fa3c31cd0a, 4, 0x609c24feae2b)
- call W(3500000000000000ffe0f505..(13), 0)
- result: ret, tag 0x1a2

## arm 0, id out of range

- input: T=0x800000000000000d cap=0x0 len=0x4 script=A1B1C1D1G1H1Z1 v=0x5f45a60 s=0
- call S(f0974b123896159c04000000..(41))
- call A(0x7c0, 1, 0)
- call B(0x9c159638124b97f0, 4, 0xf3107cfc4d1)
- call W(3500000000000000ffffffff..(13), 0)
- result: ret, tag 0x1a2

## arm 0, name too long

- input: T=0x800000000000000d cap=0x9 len=0x65 script=A1B1C1D1G1H1Z1 v=0x0 s=0
- call FREE(0xdd1e15b2a5ec504b, 9, 0)
- result: ret, tag 0x158

## arm 0, first callee fails

- input: T=0x800000000000000d cap=0x9 len=0x4 script=A0 v=0x0 s=0
- call S(81360d39e4bdd5f904000000..(41))
- call A(0x7c0, 1, 0)
- call FREE(0xf9d5bde4390d3681, 9, 0)
- result: ret, tag 0x186

## arm 1

- input: T=0x800000000000000e script=A1B1C1D1G1H1Z1
- call W(2d0000000000000065bcb7e6..(29), 0)
- result: ret, tag 0x1a2

## arm 2, success

- input: T=0x800000000000000f script=A1B1C1D1G1H1Z1
- call C(050000000000000099b2849d..(24))
- call X(0x338, 050000000000000099b2849d..(24), 0x20)
- result: ret, tag 0x1a2

## arm 2, failure

- input: T=0x800000000000000f script=C0
- call C(05000000000000009c2cf7ca..(24))
- call FREE(0xf1e65afccaf72c9c, 5, 0)
- result: ret, tag 0x18a

## arm 3, flag set, 3 ids

- input: T=0x8000000000000010 cap=0x3 len=0x4 flag=1 script=A1B1C1D1G1H1Z1 sent=0 end=0x3 scale=0x7 fail=0
- call D(0x7c0, 0x82c17ea9cffab688)
- call ALLOC(0x18)
- call VIS(0x11170)
- call VIS(0x11171)
- call VIS(0x11172)
- call FREE(0x600100000, 0x18, 0)
- call FREE(0x82c17ea9cffab688, 3, 0)
- result: ret, tag 0x1a2

## arm 3, flag clear

- input: T=0x8000000000000010 cap=0x3 len=0x4 flag=0 script=A1B1C1D1G1H1Z1 sent=0 end=0x0 scale=0x0 fail=0
- call D(0x7c0, 0x9449fa14a14ec78)
- call FREE(0x9449fa14a14ec78, 3, 0)
- result: ret, tag 0x1a2

## arm 3, sentinel record

- input: T=0x8000000000000010 cap=0x3 len=0x4 flag=1 script=A1B1C1D1G1H1Z1 sent=1 end=0x0 scale=0x0 fail=0
- call D(0x7c0, 0xc358dee2f0d1ccac)
- call FREE(0xc358dee2f0d1ccac, 3, 0)
- result: ret, tag 0x156

## arm 3, multiply overflow

- input: T=0x8000000000000010 cap=0x0 len=0x4 flag=1 script=A1B1C1D1G1H1Z1 sent=0 end=0x2 scale=0x68db8bac710cc fail=0
- call D(0x7c0, 0xfdd7509ff423a567)
- call ALLOC(0x10)
- call MULP()
- result: panic:mul, -

## arm 4, flag clear, mode 2

- input: T=0x8000000000000011 flag=0 script=A1B1C1D1G1H1Z1 sent=0 next=0 al=1 w=0x1e240
- call H(050000000000000085505056..(24))
- call FREE(0xf4c2cf2556505085, 5, 0)
- result: ret, tag 0x1a1

## arm 4, flag set, selector 2

- input: T=0x8000000000000011 flag=1 script=A1B1C1D1G1H1Z1 sent=0 next=0 al=2 w=0x4e20
- call H(0000000000000000ba3dfe60..(24))
- result: ret, tag 0x1a1

## arm 4, flag set, selector not 2

- input: T=0x8000000000000011 flag=1 script=A1B1C1D1G1H1Z1 sent=0 next=0 al=1 w=0x12448838e34afc8
- call H(0000000000000000c02c8b65..(24))
- result: ret, tag 0x1a1

## arm 4, second word mismatch

- input: T=0x8000000000000011 flag=1 script=A1B1C1D1G1H1Z1 sent=0 next=0 al=199 w=0xb5c9ef39f8a30cb
- call H(0500000000000000c08aca5b..(24))
- call FREE(0xd3672ca45bca8ac0, 5, 0)
- result: ret, tag 0x1a1

## arm 5

- input: T=0x0 script=A1B1C1D1G1H1Z1
- call MEM(0, 0xb0)
- call Z(000000000000000000000000..(196))
- call DROP(00000000000000002cd3a603..(176))
- result: ret, tag 0x1a2

## arm 6, below the limit

- input: T=0x8000000000000013 script=A1B1C1D1G1H1Z1 v=0x3 lim=4
- call Y(03000000000000005fa0d6c7..(88))
- result: ret, tag 0x1a2

## arm 6, at the limit

- input: T=0x8000000000000013 script=A1B1C1D1G1H1Z1 v=0x4 lim=4
- result: ret, tag 0x0fa

## arm 7, outside the FDE

- input: T=0x8000000000000014 script=A1B1C1D1G1H1Z1
- result: trap:0x291d6c7, -

