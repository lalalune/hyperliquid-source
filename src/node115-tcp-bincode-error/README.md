# Selected TCP bincode error formatting

For already-decoded tags 0–3, this crate maps the observed raw fields to the selected non-alternate owned error text. It models a logical error owner with cached backtrace state 1 and releases the input frame only after creating the message. Other tags, invalid raw values, allocation failure and native pointer layouts are outside scope. Evidence and exact premises are in `research/work-items/RE-001-node115-tcp-bincode-error-format`.
