#![no_std]
#![forbid(unsafe_code)]

//! Three node94 keyword classifiers with one shared memory/output contract.

use core::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classifier {
    UntilRequiredMatches,
    VipMm,
    InputGasLimit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    ImageRange,
    Input,
    Output,
}

fn span(image: &[u8], base: u64, address: u64, width: usize) -> Option<Range<usize>> {
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let end = start.checked_add(width)?;
    (end <= image.len()).then_some(start..end)
}

/// Classify the selected input and store `[9, tag]`, returning numeric RAX.
///
/// `image[j]` represents `image_base + j` in one nonwrapping image. Only
/// matching full-u64 lengths read input bytes. All necessary ranges are checked
/// before writes; every error leaves the image unchanged. Input/output overlap
/// is permitted. Stable ordinary memory is required; see the proof for limits.
pub fn classify(
    image: &mut [u8],
    image_base: u64,
    output: u64,
    input: u64,
    length: u64,
    classifier: Classifier,
) -> Result<u64, AccessError> {
    if !image.is_empty() {
        let last = u64::try_from(image.len() - 1).map_err(|_| AccessError::ImageRange)?;
        image_base
            .checked_add(last)
            .ok_or(AccessError::ImageRange)?;
    }
    let (zero, one): (&[u8], &[u8]) = match classifier {
        Classifier::UntilRequiredMatches => (b"until", b"required_matches"),
        Classifier::VipMm => (b"vip", b"mm"),
        Classifier::InputGasLimit => (b"input", b"gas_limit"),
    };
    let selected = if length == zero.len() as u64 {
        Some((zero, 0_u8))
    } else if length == one.len() as u64 {
        Some((one, 1_u8))
    } else {
        None
    };
    let input_span = if let Some((word, _)) = selected {
        Some(span(image, image_base, input, word.len()).ok_or(AccessError::Input)?)
    } else {
        None
    };
    let output_span = span(image, image_base, output, 2).ok_or(AccessError::Output)?;
    let tag = match (selected, input_span) {
        (Some((word, tag)), Some(range)) if &image[range.clone()] == word => tag,
        _ => 2,
    };
    image[output_span.start + 1] = tag;
    image[output_span.start] = 9;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_is_classified_before_overlapping_output() {
        let mut image = *b"required_matches";
        assert_eq!(
            classify(&mut image, 0, 0, 0, 16, Classifier::UntilRequiredMatches),
            Ok(0)
        );
        assert_eq!(&image[..2], &[9, 1]);
        assert_eq!(&image[2..], b"quired_matches");
    }

    #[test]
    fn full_width_other_length_skips_unmapped_input() {
        let mut image = [0_u8; 2];
        assert_eq!(
            classify(
                &mut image,
                u64::MAX - 1,
                u64::MAX - 1,
                0,
                (1_u64 << 32) + 3,
                Classifier::VipMm
            ),
            Ok(u64::MAX - 1)
        );
        assert_eq!(image, [9, 2]);
    }

    #[test]
    fn refused_output_preserves_image() {
        let mut image = *b"input";
        assert_eq!(
            classify(&mut image, 0, 4, 0, 5, Classifier::InputGasLimit),
            Err(AccessError::Output)
        );
        assert_eq!(&image, b"input");
    }
}
