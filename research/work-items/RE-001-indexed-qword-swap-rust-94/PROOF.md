# Indexed qword addressing and ordered overlap proof

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, complete linked ELF VA `[0x4fa90a0,0x4fa9109)`, 105 bytes. The 25-instruction body includes one unreachable nine-byte NOP; seven following INT3 bytes are outside its FDE. Source-level table types, index validity and element meanings are unknown.

## Complete four-way selection

Entry RDX and RCX supply first table address A and first u64 index i. Entry RDI and RSI supply second table address D and second u64 index j. Both threshold comparisons are unsigned. For either table T/index k, define the entry-memory base value

```
b(T,k) = LE64(M[T+264..T+272])  if k <= 31
         LE64(M[T+272..T+280])  if k > 31
p(T,k) = (b(T,k) + 8*k - (0 if k<=31 else 256)) mod 2^64
```

The full 64-bit index chooses the field before scale truncation. In particular, k=2^61+31 is high, even though scale-by-eight discards its top three bits. Its high-field offset is -8 modulo 2^64; it cannot be replaced with low-field index 31. The high expression also equals `b+8*(k-32)` modulo 2^64 because k>31. LEA retains low 64 address bits. No guessed table length or signed-index restriction is imposed.

The first branch selects the first table field. The next comparison selects the second field, with the low-first/high-second case using a backward join at `0x4fa90ef` to `0x4fa90bb`. This does not loop: both terminal paths read/store and return. All four threshold combinations reach one of two byte-identical swap blocks.

## Loads, stores and RAX

Let P=p(A,i), Q=p(D,j), and entry snapshots X=M[P..P+8], Y=M[Q..Q+8]. Both table field loads and both qword loads occur before either store. The target writes X at Q first, then Y at P. RAX continues holding P at every return; it is not either data value.

For every byte address x, the final ordinary-memory relation is

```
M'(x) = Y[x-P]   if P <= x < P+8
        X[x-Q]   if Q <= x < Q+8
        M(x)     otherwise
RAX = P
```

The first range has final-write priority. This is a usual swap only when ranges are disjoint or identical. With partial overlap, replacing it by simultaneous exchange, reversing store order, loading the second value after the first store, or swapping one byte at a time can change bytes. The formula also preserves aliases between table pointer fields and either qword: all pointer values and snapshots were already loaded before stores. Unaligned ranges are allowed.

## Safe domain

`swap_indexed` takes one mutable byte image, an abstract u64 image base, two table-address values and two full u64 indices. It returns P, representing raw RAX. It does not dereference those integers as host pointers or reconstruct a source-language pointer ABI.

The image itself must not wrap. Selected table-field address formation must be nonwrapping and the selected eight bytes must fit; the alternate field need not be mapped. Table bases loaded from those fields need not themselves be in the image. Index scaling/addition uses the exact modular expression above, including loss of high scaled bits and wrapping addition; the resulting P and Q each must name eight nonwrapping available bytes within the image. No blanket table/index bound is inferred. For native correspondence, these checked final byte ranges represent valid ordinary readable/writable target memory, with valid instruction/control storage. Abstract u64 mappings are a value model, not a promise that every address is mappable on Linux/x86-64.

All used ranges are checked before writes. Refusals leave the image unchanged; this is additional safe behavior, not native fault emulation. Partial access faults, page permissions, instruction/control aliases, concurrency, MMIO, an eight-byte access crossing address wrap, and arbitrary invalid raw-pointer ABI behavior are excluded. Modular index/address calculation inside the proved formula remains in scope; it is not silently replaced by checked index multiplication or ordinary unbounded addressing.

## Independent oracle and closure

The oracle uses arbitrary-precision arithmetic for the closed-form address polynomial and constructs final bytes with the priority formula from an immutable image. It does not execute the machine or replay loads/stores. All fixture bytes and expectations are frozen before Rust source exists. Rust independently computes field selection and wrapping stride arithmetic, then snapshots and performs ordered stores.

The body has no calls, no transfer outside its bound leaf and no RIP-relative static-data operand. Full-target and exact FDE/CIE bindings establish all immediate offsets and branch bytes. Full `.text` scanning finds exactly four direct E8 candidates in `[0x4fabb90,0x4fac29f)`, all instruction boundaries in the complete caller decoded by GNU and LLVM. For example `0x4fabc6b..0x4fabc77` passes the same table in RDI/RDX, different index registers RSI/RCX, then overwrites RAX at `0x4fabc7c`. The other three sites join that post-call path. This supports concrete incoming edges and same-table use; it does not identify caller purpose, table bounds or all callers. Other caller calls/logic are unclaimed.

The full 80,300-entry RELA scan finds no addend equal to this entry. Direct-pattern and addend scans do not close indirect/computed references. No inferred implementation, target execution, instruction emulator, whole-node equivalence or progress gate is used or claimed.
