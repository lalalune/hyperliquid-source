# Decoder contract before implementation

Target node94 SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Base b01cbf3c5c80391cdb9ee963d5d483039868e563. All addresses are linked ELF VAs.
This is a mode-1 wire/value projection. Original Rust types, memory layout,
allocator behavior, B-tree node/split identity and peer-acceptance policy are
not claimed. Integer fields below are unnamed unsigned wire values.

`0x25618f0` charges 4, reads a u32 selector, accepts 0..5. Selectors 2..5
have no payload. Selector 1 reads three u64 fields, each charged 8; the wire
order is first/second/third, while observed output stores second/third/first.
Selector 0 reads a byte vector, a charged u64, then `0x255eba0`.

The byte vector `0x2891c30` charges 8 and reads u64 length, charges length,
then checks length <= remaining. Shortage at this pre-allocation check is
kind 1, with no payload cursor advance. Success copies length raw bytes.

`0x255eba0` charges 4 and reads a u32 selector 0..2. Selector 0 reads 32 raw
bytes then map `0x2890b60`. Selector 1 calls `0x1f646e0`: 32 raw bytes,
map `0x28916c0`, map `0x2890ea0`. Selector 2 calls `0x21cca20`: exactly three
records, each two kind-5 u64 words charged 8 apiece and 2048 raw bytes charged
2048 before availability. The arrays preserve every byte. Records consume
6150..6198 wire bytes but contribute 6192 to the logical charge.

All three maps read u64 count (charge 8), reserve 96*count with checked
multiplication/addition, then for each original row refund 96, read raw key20
(charge20), read four u64s after one charge32, read another four after one
charge32, and a raw byte (charge1). Rows are consumed even when keys repeat.
The logical result is lexicographic key order with the last supplied value
for a repeated key. This uses the public map abstraction; target B-tree node
allocation/split/layout equivalence is outside the wire decoder claim.

Each successful fixed-width read charges before checking availability. It
consumes none on shortage (kind0, needed = width - remaining). Byte accepts
all 256 values. Overflow does not update the charge; exceeding limit retains
the increment. Reservation/refund effects remain distinct from encoded width.

Uncharged four-word scalar reads and charged ordinary u64s select the fast
path for remaining >8; invalid FE/FF are unconsumed, expected code2. The slow
Reader consumes the marker, expected code3. Kind-5 record words use expected
code5 on both paths (0x2558d80 and its distinct Reader relocation). u32 tags
switch at remaining >4 and reject FD/FE/FF with expected2; only the slow path
consumes the marker. FB/FC/FD widths are 3/5/9 where allowed; nonminimal
encodings are accepted. Short extensions consume only their marker; empty
input consumes none. Found codes for FD/FE/FF are 3/4/12.

Return state contains actual consumed bytes and logical charge, including on
error. Successful suffix bytes are allowed (0x28bdc00). The wrapper's error
consumed diagnostic is zero, separate from actual cursor progress. No parser
success is an assertion that a peer should be trusted or accepted.

Credits: canonical stream-msg/varint/slow-width packets; PR1723 envelope,
PR1742 value words, PR1779 selected map, PR1816 three records. Those were read
as evidence leads; no implementation from them or can1357 is copied.
