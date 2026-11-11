# Selected oracle entry lifecycle

This crate models the two observed variant-zero selector keys in a valid ordered flat ring, including normal spare-capacity insertion/removal shifts and the caller's first/latest 12-byte field writes. It accepts preexisting valid variant-one rows as an input premise, so moves preserve opaque existing values. The earlier ratio/threshold gate, tree paths, growth, allocator, diagnostics and inactive raw storage are outside scope. Original evidence and precise boundaries are in `research/work-items/RE-001-node115-oracle-entry-lifecycle`.
