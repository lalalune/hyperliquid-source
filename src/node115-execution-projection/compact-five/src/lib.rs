#![no_std]
#![forbid(unsafe_code)]
//! Safe 80-byte to five-byte projection recovered from node115 execution state.

pub const SOURCE_ROW_BYTES: usize = 0x50;
pub const PACKED_ROW_BYTES: usize = 5;
pub const PROJECTION_START: usize = 0x45;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    OutputTooSmall,
}

pub fn project_row(row: &[u8; SOURCE_ROW_BYTES]) -> [u8; PACKED_ROW_BYTES] {
    let mut packed = [0; PACKED_ROW_BYTES];
    packed.copy_from_slice(&row[PROJECTION_START..PROJECTION_START + PACKED_ROW_BYTES]);
    packed
}

pub fn project_rows(
    rows: &[[u8; SOURCE_ROW_BYTES]],
    output: &mut [[u8; PACKED_ROW_BYTES]],
) -> Result<(), ProjectionError> {
    if output.len() < rows.len() {
        return Err(ProjectionError::OutputTooSmall);
    }
    for (row, target) in rows.iter().zip(output.iter_mut()) {
        *target = project_row(row);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PACKED_ROW_BYTES, ProjectionError, SOURCE_ROW_BYTES, project_row, project_rows};

    fn row(seed: u8) -> [u8; SOURCE_ROW_BYTES] {
        let mut row = [0; SOURCE_ROW_BYTES];
        for (index, byte) in row.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        row
    }

    #[test]
    fn projects_only_offsets_45_through_49() {
        let source = row(7);
        assert_eq!(project_row(&source), source[0x45..0x4a]);
    }

    #[test]
    fn projects_rows_in_order_and_rejects_short_output() {
        let rows = [row(0), row(1), row(2)];
        let mut output = [[0; PACKED_ROW_BYTES]; 3];
        assert_eq!(project_rows(&rows, &mut output), Ok(()));
        for (source, packed) in rows.iter().zip(output) {
            assert_eq!(packed, source[0x45..0x4a]);
        }
        assert_eq!(
            project_rows(&rows, &mut [[0; PACKED_ROW_BYTES]; 2]),
            Err(ProjectionError::OutputTooSmall)
        );
    }
}
