//! Complete logical ISO-week to packed-date constructor observed in node #115.
//! Independent Gregorian mathematics, no clock, allocation or native execution.
#![no_std]

#[derive(Clone, Copy, Debug)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}
impl Weekday {
    pub fn from_monday_index(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Monday,
            1 => Self::Tuesday,
            2 => Self::Wednesday,
            3 => Self::Thursday,
            4 => Self::Friday,
            5 => Self::Saturday,
            6 => Self::Sunday,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Date {
    pub packed: i32,
    pub year: i32,
    pub ordinal: u16,
    pub flags: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct YearOverflow;
fn leap(y: i32) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}
fn year_days(y: i32) -> i32 {
    if leap(y) { 366 } else { 365 }
}
fn january_monday_index(y: i32) -> i32 {
    let n = i64::from(y) - 1;
    (n + n.div_euclid(4) - n.div_euclid(100) + n.div_euclid(400)).rem_euclid(7) as i32
}
/// Invalid week returns None before year adjustment. The typed weekday is an
/// explicit safe domain, not a claim about arbitrary native u8 representations.
/// i32 arithmetic failure on crossing a year is distinct from a final supported
/// date-range refusal. This API does not reproduce the native panic payload.
pub fn from_iso_week(
    iso_year: i32,
    week: u32,
    weekday: Weekday,
) -> Result<Option<Date>, YearOverflow> {
    let jan1 = january_monday_index(iso_year);
    let weeks = if jan1 == 3 || (jan1 == 2 && leap(iso_year)) {
        53
    } else {
        52
    };
    if week == 0 || week > weeks {
        return Ok(None);
    }
    let mut year = iso_year;
    // ISO week one contains January fourth; the Monday can lie in December.
    let mut ordinal = 4 - (jan1 + 3) % 7 + 7 * (week as i32 - 1) + weekday as i32;
    if ordinal <= 0 {
        year = year.checked_sub(1).ok_or(YearOverflow)?;
        ordinal += year_days(year);
    } else if ordinal > year_days(year) {
        ordinal -= year_days(year);
        year = year.checked_add(1).ok_or(YearOverflow)?;
    }
    if !(-262143..=262142).contains(&year) {
        return Ok(None);
    }
    let flags = (((january_monday_index(year) + 5) % 7 + 1) as u8) | if leap(year) { 0 } else { 8 };
    let packed = (year << 13) | (ordinal << 4) | i32::from(flags);
    Ok(Some(Date {
        packed,
        year,
        ordinal: ordinal as u16,
        flags,
    }))
}
