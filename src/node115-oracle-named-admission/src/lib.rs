//! Project the four named count lanes from a successfully decoded node #115 payload.
//! Raw descriptors and action tags are modeled only on the selected valid path.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub oracle_pxs: u64,
    pub external_perp_pxs: u64,
    pub usdt_usdc_px: Option<u64>,
    pub native_px: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    Truncated,
    WrongTag,
}

fn word(bytes: &[u8], offset: usize) -> Result<u64, ProjectionError> {
    let bytes = bytes
        .get(offset..offset + 8)
        .ok_or(ProjectionError::Truncated)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("eight-byte slice"),
    ))
}

/// Project named counts from the decoded 0x70-byte payload.
/// The caller must supply a successfully decoded descriptor representation.
pub fn project_payload(payload: &[u8]) -> Result<Counts, ProjectionError> {
    if payload.len() < 0x70 {
        return Err(ProjectionError::Truncated);
    }
    let optional = |base| -> Result<Option<u64>, ProjectionError> {
        if word(payload, base)? == 1_u64 << 63 {
            Ok(None)
        } else {
            Ok(Some(word(payload, base + 0x10)?))
        }
    };
    Ok(Counts {
        oracle_pxs: word(payload, 0x18)?,
        external_perp_pxs: word(payload, 0x38)?,
        usdt_usdc_px: optional(0x40)?,
        native_px: optional(0x58)?,
    })
}

/// Project from the selected 0x9e tagged action allocation, whose payload begins at +8.
pub fn project_tagged_action(action: &[u8]) -> Result<Counts, ProjectionError> {
    if word(action, 0)? != 0x9e {
        return Err(ProjectionError::WrongTag);
    }
    project_payload(action.get(8..).ok_or(ProjectionError::Truncated)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(b: &mut [u8], at: usize, n: u64) {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    #[test]
    fn separate_count_lanes_and_tagged_offset() {
        let mut action = [0xa5; 0x78];
        put(&mut action, 0, 0x9e);
        for (offset, value) in [
            (0x18, 101),
            (0x38, 202),
            (0x40, 1),
            (0x50, 303),
            (0x58, 2),
            (0x68, 404),
        ] {
            put(&mut action, 8 + offset, value);
        }
        let expected = Counts {
            oracle_pxs: 101,
            external_perp_pxs: 202,
            usdt_usdc_px: Some(303),
            native_px: Some(404),
        };
        assert_eq!(project_tagged_action(&action), Ok(expected));
        assert_eq!(project_payload(&action[8..]), Ok(expected));
    }
    #[test]
    fn absent_and_present_empty_are_distinct() {
        let mut payload = [0; 0x70];
        put(&mut payload, 0x40, 1 << 63);
        put(&mut payload, 0x50, u64::MAX);
        assert_eq!(project_payload(&payload).unwrap().usdt_usdc_px, None);
        assert_eq!(project_payload(&payload).unwrap().native_px, Some(0));
        put(&mut payload, 0x40, (1 << 63) + 1);
        assert_eq!(
            project_payload(&payload).unwrap().usdt_usdc_px,
            Some(u64::MAX)
        );
    }
    #[test]
    fn rejects_wrong_tag_and_each_truncation() {
        let mut action = [0; 0x78];
        assert_eq!(
            project_tagged_action(&action),
            Err(ProjectionError::WrongTag)
        );
        put(&mut action, 0, 0x9e);
        for length in 0..action.len() {
            assert_eq!(
                project_tagged_action(&action[..length]),
                Err(ProjectionError::Truncated),
                "{length}"
            );
        }
    }
}
