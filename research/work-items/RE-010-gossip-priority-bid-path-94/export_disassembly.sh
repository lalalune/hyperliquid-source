#!/bin/sh
# Regenerate the retained disassembly from the repository root. Static only: the
# target is parsed by objdump and never executed. Set GNU_OBJDUMP and LLVM_OBJDUMP
# when the defaults on PATH are not those decoders.
set -eu
TARGET=artifacts/node/94/hl-node
PACKET=research/work-items/RE-010-gossip-priority-bid-path-94
GNU_OBJDUMP=${GNU_OBJDUMP:-objdump}
LLVM_OBJDUMP=${LLVM_OBJDUMP:-llvm-objdump}
SPANS='
arm_a 0x2759865 0x2759892
arm_b 0x4d83675 0x4d83691
arm_c 0x4d84795 0x4d847b1
wrapper 0x1e60bb0 0x1e60cf2
sibling_b 0x4c8c0a0 0x4c8c170
sibling_c 0x4c8c3f0 0x4c8c4c0
sibling_b_ip_error 0x4c8c290 0x4c8c29e
sibling_c_ip_error 0x4c8c5e0 0x4c8c5ee
price_compare 0x2727ca4 0x2727cac
dispatcher_tag 0x2759298 0x27592b4
decoder_tag_store_a 0x3358a4e 0x3358a51
decoder_tag_store_b 0x335caf5 0x335caf8
decoder_duplicate_slot 0x3b6c702 0x3b6c70b
decoder_duplicate 0x3b6ca03 0x3b6ca31
decoder_duplicate_max_gas 0x3b6ce42 0x3b6ce54
decoder_duplicate_ip 0x3b6ce93 0x3b6cea5
decoder_caller_a 0x3357671 0x33576ae
decoder_caller_b 0x335b718 0x335b755
decoder_map_start 0x3b6c665 0x3b6c6dd
decoder_field_max_gas 0x3b6c7e5 0x3b6c854
decoder_field_ip 0x3b6c868 0x3b6c8f6
decoder_end 0x3b6ca42 0x3b6ca9e
decoder_missing_slot 0x3b6cac1 0x3b6cafd
decoder_build 0x3b6cc4e 0x3b6cc7d
serializer 0x1e971d0 0x1e97502
name_site 0x28241f2 0x2824265
'
: > "$PACKET/gnu.txt"
: > "$PACKET/llvm.txt"
printf '%s\n' "$SPANS" | while read -r name start stop; do
    [ -n "$name" ] || continue
    printf '## %s %s %s\n' "$name" "$start" "$stop" >> "$PACKET/gnu.txt"
    "$GNU_OBJDUMP" -d -Mintel --wide --insn-width=15 --start-address="$start" --stop-address="$stop" "$TARGET" \
        | sed 's/ *<[^>]*>//g' | grep -E '^ +[0-9a-f]+:' >> "$PACKET/gnu.txt"
    printf '## %s %s %s\n' "$name" "$start" "$stop" >> "$PACKET/llvm.txt"
    "$LLVM_OBJDUMP" -d --x86-asm-syntax=intel --start-address="$start" --stop-address="$stop" "$TARGET" \
        | sed 's/ *<[^>]*>//g' | grep -E '^ +[0-9a-f]+:' >> "$PACKET/llvm.txt"
done
