#![no_std]
#![forbid(unsafe_code)]
/// Node94 [0x5229860,0x522987c): ESI==1 and EDI==4 selects eight;
/// every other low-dword pair selects nine. The full returned RAX is clean.
pub fn nine_eight(rdi: u64, rsi: u64) -> u64 {
    if rsi as u32 == 1 && rdi as u32 == 4 {
        8
    } else {
        9
    }
}
