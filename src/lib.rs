#![no_std]
#![forbid(unsafe_code)]
//! Metadata-type bits recovered from node115 predicates `0x1500a60` and
//! `0x1500d20`.

pub const FILE_TYPE_MASK: u32 = 0xf000;
pub const DIRECTORY_TYPE: u32 = 0x4000;
pub const REGULAR_FILE_TYPE: u32 = 0x8000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataKind {
    Directory,
    RegularFile,
    Other,
}

pub fn classify(mode: u32) -> MetadataKind {
    match mode & FILE_TYPE_MASK {
        DIRECTORY_TYPE => MetadataKind::Directory,
        REGULAR_FILE_TYPE => MetadataKind::RegularFile,
        _ => MetadataKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{MetadataKind, classify};

    #[test]
    fn matches_directory_mode_and_ignores_permission_bits() {
        assert_eq!(classify(0o040000), MetadataKind::Directory);
        assert_eq!(classify(0o040755), MetadataKind::Directory);
        assert_eq!(classify(0o041777), MetadataKind::Directory);
    }

    #[test]
    fn matches_regular_file_mode_and_ignores_permission_bits() {
        assert_eq!(classify(0o100000), MetadataKind::RegularFile);
        assert_eq!(classify(0o100644), MetadataKind::RegularFile);
        assert_eq!(classify(0o100600), MetadataKind::RegularFile);
    }

    #[test]
    fn rejects_other_file_type_nibbles() {
        assert_eq!(classify(0), MetadataKind::Other);
        assert_eq!(classify(0o010644), MetadataKind::Other);
        assert_eq!(classify(0o120777), MetadataKind::Other);
        assert_eq!(classify(0o140777), MetadataKind::Other);
        assert_eq!(classify(0o060644), MetadataKind::Other);
    }

    #[test]
    fn masks_high_bits_above_the_mode_word() {
        assert_eq!(classify(0xffff_4000), MetadataKind::Directory);
        assert_eq!(classify(0xffff_8000), MetadataKind::RegularFile);
        assert_eq!(classify(0xffff_c000), MetadataKind::Other);
    }
}
