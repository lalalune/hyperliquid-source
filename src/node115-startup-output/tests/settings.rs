use node115_startup_output::{OutputSettings, StyleError};
use std::cell::RefCell;

const LOOKUPS: &str =
    include_str!("../../../research/work-items/RE-012-startup-output-settings-115/lookups.tsv");

#[test]
fn writer_and_service_flags_match_the_elf_lookup_table() {
    let flags: Vec<_> = LOOKUPS
        .lines()
        .skip(1)
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .filter(|row| row[0] == "presence")
        .collect();
    assert_eq!(flags.len(), 12);
    for mask in 0u16..4096 {
        let enabled = |name: &str| {
            let row = flags.iter().find(|row| row[1] == name).unwrap();
            let offset: u32 = row[2].parse().unwrap();
            mask & (1 << (offset - 24)) != 0
        };
        let settings = OutputSettings::read(enabled, |key| {
            (key == "replica-cmds-style").then_some(b"actions")
        })
        .unwrap();
        let expected: Vec<_> = flags
            .iter()
            .filter(|row| row[3] != "-" && enabled(row[1]))
            .map(|row| row[3])
            .collect();
        assert_eq!(
            settings.enabled_writer_names().collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            settings.disable_output_file_buffering,
            enabled("disable-output-file-buffering")
        );
        assert_eq!(settings.batch_by_block, enabled("batch-by-block"));
        assert_eq!(
            settings.stream_with_block_info,
            enabled("stream-with-block-info")
        );
        assert_eq!(settings.serve_evm_rpc, enabled("serve-evm-rpc"));
        assert_eq!(settings.serve_info, enabled("serve-info"));
        assert_eq!(
            settings.conflicting_stream_flags(),
            enabled("batch-by-block") && enabled("stream-with-block-info")
        );
    }
}

#[test]
fn queries_follow_constructor_order_and_copy_the_optional_value() {
    let queries = RefCell::new(Vec::new());
    let mut original = vec![0, 255, 42];
    let settings = OutputSettings::read(
        |key| {
            queries.borrow_mut().push(("presence", key.to_owned()));
            false
        },
        |key| {
            queries.borrow_mut().push(("value", key.to_owned()));
            if key == "replica-cmds-style" {
                Some(b"recent-actions")
            } else {
                Some(&original)
            }
        },
    )
    .unwrap();
    original.fill(7);
    let expected: Vec<_> = LOOKUPS
        .lines()
        .skip(1)
        .map(|line| {
            let mut fields = line.split('\t');
            (fields.next().unwrap(), fields.next().unwrap().to_owned())
        })
        .collect();
    assert_eq!(queries.into_inner(), expected);
    assert_eq!(settings.user_clearinghouse_states, Some(vec![0, 255, 42]));
}

#[test]
fn styles_and_empty_values_keep_their_distinct_results() {
    let read = |style: Option<&[u8]>, optional: Option<&[u8]>| {
        OutputSettings::read(
            |_| false,
            |key| {
                if key == "replica-cmds-style" {
                    style
                } else {
                    optional
                }
            },
        )
    };
    for (style, tag) in [
        (b"actions".as_slice(), 0),
        (b"actions-and-responses", 1),
        (b"recent-actions", 2),
    ] {
        assert_eq!(read(Some(style), None).unwrap().replica_style as u8, tag);
    }
    assert_eq!(
        read(Some(b"actions"), Some(b""))
            .unwrap()
            .user_clearinghouse_states,
        Some(vec![])
    );
    assert_eq!(
        read(Some(b"actions"), None)
            .unwrap()
            .user_clearinghouse_states,
        None
    );
    assert_eq!(read(None, None), Err(StyleError::Missing));
    for bad in [b"".as_slice(), b"Actions", b"actions ", b"recent-action"] {
        assert_eq!(read(Some(bad), None), Err(StyleError::Unrecognized));
    }
}
