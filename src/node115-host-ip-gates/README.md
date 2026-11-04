# node115 host-IP IPv4 parser and admission

Independently authored MIT Rust projection of the pinned node115 IPv4 prefix
parser and selected host-IP caller gates. See
[the evidence packet](../../research/work-items/RE-014-host-ip-gates-115/README.md)
for digest, pre-source freezes, complete FDE bytes, authentic CALL/RET replay,
normalization, reproducible input-only builds and limitations.

`read_ipv4` accepts an IPv4 prefix and advances its input slice only on success.
`admission` and `should_probe` expose selected raw boundary observations using
project-owned types. No command, service, reader or whole caller is implemented.
No original Rust API/ABI or compiler identity is asserted. This standalone
research component deliberately has no fabricated Cargo dependency graph.
