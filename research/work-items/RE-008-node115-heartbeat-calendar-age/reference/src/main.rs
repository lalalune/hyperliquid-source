//! Compare the production path with the public Chrono calendar implementation.
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use node115_time_producer::heartbeat::{
    HeartbeatClass, HeartbeatError, HeartbeatTime, TimedSample, classify_at,
};
use node115_time_producer::{DateTime, from_ce_day};
use std::error::Error;
use std::io::{self, BufRead};

fn times(
    day: i64,
    seconds: i64,
    nanos: i64,
) -> Result<(HeartbeatTime, NaiveDateTime), Box<dyn Error>> {
    let day = i32::try_from(day)?;
    let seconds = u32::try_from(seconds)?;
    let nanos = u32::try_from(nanos)?;
    let original = DateTime {
        date: from_ce_day(day).ok_or("day outside target range")?,
        seconds_of_day: seconds,
        nanoseconds: nanos,
    };
    let model = HeartbeatTime::from_datetime(original).ok_or("invalid heartbeat time")?;
    let date = NaiveDate::from_num_days_from_ce_opt(day).ok_or("invalid reference date")?;
    let time = NaiveTime::from_num_seconds_from_midnight_opt(seconds, nanos)
        .ok_or("invalid reference time")?;
    Ok((model, date.and_time(time)))
}

fn main() -> Result<(), Box<dyn Error>> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields = line
            .split_whitespace()
            .map(str::parse::<i64>)
            .collect::<Result<Vec<_>, _>>()?;
        let [today, now_secs, now_ns, prev_day, prev_secs, prev_ns, mode]: [i64; 7] =
            fields.try_into().map_err(|_| "expected 7 fields")?;
        let (now, calendar_now) = times(today, now_secs, now_ns)?;
        let (previous, calendar_previous) = times(prev_day, prev_secs, prev_ns)?;
        let delta = calendar_now.signed_duration_since(calendar_previous);
        let age = (delta.num_seconds() as f64 + f64::from(delta.subsec_nanos()) / 1e9).max(0.0);
        let (found, numerator, denominator, threshold, config) = match mode {
            0 => (true, 0.0, 1.0, 0.0, false),   // age
            1 => (false, 0.0, -1.0, 1.0, false), // missing before diagnostic
            2 => (true, 8.0, 2.0, 3.0, false),   // ratio before age
            3 => (true, 8.0, 2.0, 3.0, true),    // config routes to age
            4 => (true, 8.0, -1.0, 1.0, true),   // denominator diagnostic
            5 => (true, 8.0, 0.0, 0.0, false),   // zero denominator
            _ => return Err("unknown test mode".into()),
        };
        let sample = found.then_some(TimedSample {
            numerator,
            denominator,
            recorded_at: previous,
        });
        let output = classify_at(now, sample, threshold, config);
        let expected = match mode {
            1 => Ok(HeartbeatClass::Missing),
            2 => Ok(HeartbeatClass::Ratio(4.0)),
            4 => Err(HeartbeatError::DenominatorNotPositive),
            _ if age > 180.0 => Ok(HeartbeatClass::Age(age)),
            _ => Ok(HeartbeatClass::Skip),
        };
        if output != expected {
            return Err(format!("input {line}: {output:?} differs from {expected:?}").into());
        }
        let (tag, payload) = match output {
            Ok(HeartbeatClass::Missing) => ("missing", 0),
            Ok(HeartbeatClass::Skip) => ("skip", 0),
            Ok(HeartbeatClass::Age(v)) => ("age", v.to_bits()),
            Ok(HeartbeatClass::Ratio(v)) => ("ratio", v.to_bits()),
            Err(HeartbeatError::DenominatorNotPositive) => ("denominator", 0),
        };
        println!(
            "{tag} {payload} {} {}",
            delta.num_seconds(),
            delta.subsec_nanos()
        );
    }
    Ok(())
}
