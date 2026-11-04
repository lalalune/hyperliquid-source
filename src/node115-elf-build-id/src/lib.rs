//! Logical ELF64 little-endian GNU build-id scan bound to node #115.
//! Inputs are already selected borrowed file bytes and complete section records.
#![no_std]
fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four bytes"))
}
fn wide(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
}
fn aligned(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}
/// Return the first matching descriptor, including a valid empty descriptor.
/// Malformed note spans abandon that section; later sections remain eligible.
/// This is not an ELF/Object constructor, native ABI or invalid-pointer model.
pub fn build_id<'a>(file: &'a [u8], section_headers: &[[u8; 64]]) -> Option<&'a [u8]> {
    for header in section_headers {
        if word(&header[4..8]) != 7 {
            continue;
        }
        let raw_alignment = wide(&header[48..56]);
        let alignment = if raw_alignment <= 4 {
            4
        } else if raw_alignment == 8 {
            8
        } else {
            continue;
        };
        let Ok(offset) = usize::try_from(wide(&header[24..32])) else {
            continue;
        };
        let Ok(size) = usize::try_from(wide(&header[32..40])) else {
            continue;
        };
        let Some(end) = offset.checked_add(size) else {
            continue;
        };
        let Some(mut notes) = file.get(offset..end) else {
            continue;
        };
        while notes.len() >= 12 {
            let name_length = word(&notes[..4]) as usize;
            let descriptor_length = word(&notes[4..8]) as usize;
            let kind = word(&notes[8..12]);
            if name_length > notes.len() - 12 {
                break;
            }
            // u32 sizes plus at most seven padding bytes fit selected 64-bit domain.
            let descriptor = aligned(12 + name_length, alignment);
            if descriptor > notes.len() || descriptor_length > notes.len() - descriptor {
                break;
            }
            let descriptor_end = descriptor + descriptor_length;
            let mut name = &notes[12..12 + name_length];
            while name.last() == Some(&0) {
                name = &name[..name.len() - 1];
            }
            if name == b"GNU" && kind == 3 {
                return Some(&notes[descriptor..descriptor_end]);
            }
            // A matching descriptor may end before absent final padding.
            let next = aligned(descriptor_end, alignment);
            if next >= notes.len() {
                break;
            }
            notes = &notes[next..];
        }
    }
    None
}
