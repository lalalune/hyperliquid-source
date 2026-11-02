# Node94 firewall-cycle decision projection

Independently authored safe `no_std` Rust for the selected control decisions
before the loader call in node94 `0x28f6960`. Only raw skip-byte value 1 skips
the sections. An absent timestamp tag bypasses the elapsed-time throttle;
otherwise elapsed must be strictly greater than interval. Compute/check still
run when maybe-update is throttled. Any supplied unequal collection comparison
requests update, and the normal loader flag is 1.

Build directly with rustc 1.94.1, edition 2021; no dependencies or recovered
workspace are claimed. The new API receives the time-helper return and three
equality results. It does not compute IP sets, call locks/helpers, write the
timestamp, load state or alter a firewall. Floating comparison results are
covered; original exception flags and input reachability are not.

Evidence and reproduction: `research/work-items/RE-012-firewall-cycle-rust-94/`.
