use node115_base::runtime_utils::{LinerBucket, daily_liner_path};
use node115_base::time::HourDecodeError;
use std::path::Path;

#[test]
fn resolves_the_registered_stream_before_the_date_and_hour() {
    let root = Path::new("hl/data");
    let dir = root.join("abci_hashes");
    let day = LinerBucket::daily("20261128");
    let h0 = LinerBucket::hourly("20261128", 319).unwrap();
    let h23 = LinerBucket::hourly("20261128", 86_399).unwrap();
    let next = LinerBucket::hourly("20261129", 0).unwrap();
    assert_eq!(
        daily_liner_path(root, "20261128", "abci_hashes"),
        dir.join("20261128")
    );
    assert_eq!(h0.path(&dir), dir.join("hourly/20261128/0"));
    assert_eq!(h23.path(&dir), dir.join("hourly/20261128/23"));
    assert_eq!(
        h0.path_if_changed(&dir, Some(LinerBucket::hourly("20261128", 3599).unwrap())),
        None
    );
    assert_eq!(
        next.path_if_changed(&dir, Some(h0)),
        Some(dir.join("hourly/20261129/0"))
    );
    assert_eq!(
        h0.path_if_changed(&dir, Some(h23)),
        Some(dir.join("hourly/20261128/0"))
    );
    assert_eq!(day.path_if_changed(&dir, Some(day)), None);
    assert_eq!(day.path_if_changed(&dir, None), Some(dir.join("20261128")));
}

#[test]
fn covers_all_seconds_in_the_observed_hour_helper_domain() {
    let directory = Path::new("logs");
    let mut previous = None;
    let mut changed = 0;
    for second in 0..90_000 {
        let current = LinerBucket::hourly("20240229", second).unwrap();
        let new_path = current.path_if_changed(directory, previous);
        assert_eq!(new_path.is_some(), second % 3600 == 0);
        if let Some(path) = new_path {
            assert_eq!(
                path,
                directory
                    .join("hourly/20240229")
                    .join((second / 3600).to_string())
            );
            changed += 1;
        }
        previous = Some(current);
    }
    assert_eq!(changed, 25);
    assert_eq!(
        LinerBucket::hourly("20240229", 90_000),
        Err(HourDecodeError::ExceedsExtendedDayWindow)
    );
}

#[test]
fn archives_ordered_and_late_observations_in_the_expected_files() {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("liner-{}-{nonce}", std::process::id()));
    let directory = root.join("validator_latency_ema");
    let mut selected = None;
    let mut file = None;
    for (date, seconds, record) in [
        ("20240229", 3599, "one"),
        ("20240229", 3600, "two"),
        ("20240229", 3601, "three"),
        ("20240301", 3600, "four"),
        ("20240229", 3598, "late"),
    ] {
        let bucket = LinerBucket::hourly(date, seconds).unwrap();
        if let Some(path) = bucket.path_if_changed(&directory, selected) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap(),
            );
            selected = Some(bucket);
        }
        writeln!(file.as_mut().unwrap(), "{record}").unwrap();
    }
    drop(file);
    assert_eq!(
        fs::read(directory.join("hourly/20240229/0")).unwrap(),
        b"one\nlate\n"
    );
    assert_eq!(
        fs::read(directory.join("hourly/20240229/1")).unwrap(),
        b"two\nthree\n"
    );
    assert_eq!(
        fs::read(directory.join("hourly/20240301/1")).unwrap(),
        b"four\n"
    );
    fs::remove_dir_all(root).unwrap();
}
