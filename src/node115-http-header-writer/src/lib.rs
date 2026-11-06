//! Conditional node115 logical header-byte append; not an HTTP grammar validator.
#![no_std]
#![forbid(unsafe_code)]

/// Builtins and custom byte strings are distinct even when they render equally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name<'a> {
    Builtin(u8),
    Custom(&'a [u8]),
}

/// An ordered group contains at least one value occurrence, which may be empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group<'a> {
    pub name: Name<'a>,
    pub values: &'a [&'a [u8]],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Map {
    Primary,
    Spelling,
}

/// These are ordered safe-host policies, not native error variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UsedBounds,
    GroupCount(Map),
    InvalidOrdinal { map: Map, index: usize },
    EmptyValues { map: Map, index: usize },
    DuplicateName { map: Map, index: usize },
    Representation(Map),
    LengthOverflow,
    Capacity { required: usize },
}

// Exact ordinal data from the credited node115 table; no runtime hash provider.
const BUILTINS: [&[u8]; 81] = [
    b"accept",
    b"accept-charset",
    b"accept-encoding",
    b"accept-language",
    b"accept-ranges",
    b"access-control-allow-credentials",
    b"access-control-allow-headers",
    b"access-control-allow-methods",
    b"access-control-allow-origin",
    b"access-control-expose-headers",
    b"access-control-max-age",
    b"access-control-request-headers",
    b"access-control-request-method",
    b"age",
    b"allow",
    b"alt-svc",
    b"authorization",
    b"cache-control",
    b"cache-status",
    b"cdn-cache-control",
    b"connection",
    b"content-disposition",
    b"content-encoding",
    b"content-language",
    b"content-length",
    b"content-location",
    b"content-range",
    b"content-security-policy",
    b"content-security-policy-report-only",
    b"content-type",
    b"cookie",
    b"dnt",
    b"date",
    b"etag",
    b"expect",
    b"expires",
    b"forwarded",
    b"from",
    b"host",
    b"if-match",
    b"if-modified-since",
    b"if-none-match",
    b"if-range",
    b"if-unmodified-since",
    b"last-modified",
    b"link",
    b"location",
    b"max-forwards",
    b"origin",
    b"pragma",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"public-key-pins",
    b"public-key-pins-report-only",
    b"range",
    b"referer",
    b"referrer-policy",
    b"refresh",
    b"retry-after",
    b"sec-websocket-accept",
    b"sec-websocket-extensions",
    b"sec-websocket-key",
    b"sec-websocket-protocol",
    b"sec-websocket-version",
    b"server",
    b"set-cookie",
    b"strict-transport-security",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"user-agent",
    b"upgrade",
    b"upgrade-insecure-requests",
    b"vary",
    b"via",
    b"warning",
    b"www-authenticate",
    b"x-content-type-options",
    b"x-dns-prefetch-control",
    b"x-frame-options",
    b"x-xss-protection",
];

fn fallback<'a>(name: Name<'a>) -> &'a [u8] {
    match name {
        Name::Builtin(ordinal) => BUILTINS[ordinal as usize],
        Name::Custom(bytes) => bytes,
    }
}

fn spellings<'a>(name: Name<'_>, groups: &[Group<'a>]) -> Option<&'a [&'a [u8]]> {
    groups
        .iter()
        .find(|group| group.name == name)
        .map(|group| group.values)
}

fn chosen<'a>(name: Name<'a>, spelling: Option<&'a [&'a [u8]]>, index: usize) -> (&'a [u8], bool) {
    match spelling.and_then(|values| values.get(index)) {
        Some(value) => (*value, false),
        None => (fallback(name), true),
    }
}

fn representation(
    groups: &[Group<'_>],
    map: Map,
    row_stride: usize,
    extra_stride: usize,
) -> Result<(), Error> {
    let limit = isize::MAX as usize;
    let rows = groups
        .len()
        .checked_mul(row_stride)
        .ok_or(Error::Representation(map))?;
    if rows > limit {
        return Err(Error::Representation(map));
    }
    let mut extras = 0usize;
    for group in groups {
        // EmptyValues was checked globally before this pass.
        extras = extras
            .checked_add(group.values.len() - 1)
            .ok_or(Error::Representation(map))?;
    }
    let bytes = extras
        .checked_mul(extra_stride)
        .ok_or(Error::Representation(map))?;
    if bytes > limit {
        return Err(Error::Representation(map));
    }
    Ok(())
}

/// Append complete header lines, preserving prefix and unused suffix on success.
/// Every error preserves the entire output slice. All validation precedes writes.
/// Duplicate and unused-group validation is eager safe-host policy.
pub fn append(
    primary: &[Group<'_>],
    spelling: &[Group<'_>],
    capitalize: bool,
    output: &mut [u8],
    used: usize,
) -> Result<usize, Error> {
    if used > output.len() {
        return Err(Error::UsedBounds);
    }
    let maps = [(Map::Primary, primary), (Map::Spelling, spelling)];
    for (map, groups) in maps {
        if groups.len() > 65_535 {
            return Err(Error::GroupCount(map));
        }
    }
    for (map, groups) in maps {
        for (index, group) in groups.iter().enumerate() {
            if matches!(group.name, Name::Builtin(ordinal) if ordinal > 80) {
                return Err(Error::InvalidOrdinal { map, index });
            }
        }
    }
    for (map, groups) in maps {
        for (index, group) in groups.iter().enumerate() {
            if group.values.is_empty() {
                return Err(Error::EmptyValues { map, index });
            }
        }
    }
    for (map, groups) in maps {
        for (index, group) in groups.iter().enumerate() {
            if groups[..index]
                .iter()
                .any(|earlier| earlier.name == group.name)
            {
                return Err(Error::DuplicateName { map, index });
            }
        }
    }
    representation(primary, Map::Primary, 104, 72)?;
    representation(spelling, Map::Spelling, 96, 64)?;

    let mut required = used;
    for group in primary {
        let spelling = spellings(group.name, spelling);
        for (index, value) in group.values.iter().enumerate() {
            let (name, _) = chosen(group.name, spelling, index);
            required = required
                .checked_add(name.len())
                .ok_or(Error::LengthOverflow)?;
            if value.is_empty() {
                required = required.checked_add(3).ok_or(Error::LengthOverflow)?;
            } else {
                required = required.checked_add(4).ok_or(Error::LengthOverflow)?;
                required = required
                    .checked_add(value.len())
                    .ok_or(Error::LengthOverflow)?;
            }
        }
    }
    if required > isize::MAX as usize {
        return Err(Error::LengthOverflow);
    }
    if required > output.len() {
        return Err(Error::Capacity { required });
    }

    // The immutable second traversal has exactly the planned length. No fallible
    // operation remains, and every endpoint is <= required <= output.len().
    let mut position = used;
    for group in primary {
        let spelling = spellings(group.name, spelling);
        for (index, value) in group.values.iter().enumerate() {
            let (name, is_fallback) = chosen(group.name, spelling, index);
            let mut previous = b'-';
            for &byte in name {
                let emitted =
                    if capitalize && is_fallback && previous == b'-' && byte.is_ascii_lowercase() {
                        byte - (b'a' - b'A')
                    } else {
                        byte
                    };
                output[position] = emitted;
                position += 1;
                previous = emitted;
            }
            output[position] = b':';
            position += 1;
            if !value.is_empty() {
                output[position] = b' ';
                position += 1;
                output[position..position + value.len()].copy_from_slice(value);
                position += value.len();
            }
            output[position..position + 2].copy_from_slice(b"\r\n");
            position += 2;
        }
    }
    Ok(position)
}
