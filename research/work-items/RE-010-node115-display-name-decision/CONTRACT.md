# Frozen Node115 display-name decision contract

Task RE-010. Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All native addresses are unrebased ELF virtual addresses.

Source evidence:

- display wrapper: `0x2392200..0x2392308`, 264 bytes, SHA-256
  `483533a7ffcc753a1eca1d168a2e937f8523919de2a2d23a06e0c453a44be3a5`;
- display core: `0x2c76380..0x2c766dc`, 860 bytes, SHA-256
  `c62228768dba0728cc302de45383c29ed52c692c394939651959ca7e905dc677`.

Inputs are an unsigned 64-bit display-name length, an already-evaluated
duplicate-value predicate, and an already-evaluated prior-key-rejection
predicate. The selected decision order is:

1. prior key rejection: error tag `15`, result word `288`, no mutation;
2. length at least `101`: error tag `15`, result word `344`, no mutation;
3. length zero: success tag `14`, result word `418`, erase;
4. length greater than `20`: error tag `15`, result word `226`, no mutation;
5. length less than `3`: error tag `15`, result word `227`, no mutation;
6. duplicate predicate true: error tag `15`, result word `228`, no mutation;
7. otherwise: success tag `14`, result word `418`, upsert.

The selected native branch order establishes precedence, but the existing
runtime-vector table is not a complete cross product. In particular,
`length=0` with prior rejection, and duplicate predicates for lengths 1-2 or
21-100, are inferred from the verified branch order and synthetic boundary
controls. They are not claimed as captured target observations.

The booleans are logical summaries of conditions observed by the native core.
The contract does not reconstruct the JSON decoder, account keys, container
scan, allocator, erased/upserted value ownership, actual mutation helper,
transaction rollback, wire response or malformed native tree behavior.
