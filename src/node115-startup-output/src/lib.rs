//! Logical output settings read from the two selected node #115 run commands.

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplicaStyle {
    Actions = 0,
    ActionsAndResponses = 1,
    RecentActions = 2,
}

/// The reader has distinct boundaries for absent and unrecognized style values.
#[derive(Debug, PartialEq, Eq)]
pub enum StyleError {
    Missing,
    Unrecognized,
}

const WRITERS: [(&str, &str); 7] = [
    ("write-trades", "node_trades"),
    ("write-fills", "node_fills"),
    ("write-raw-book-diffs", "node_raw_book_diffs"),
    ("write-order-statuses", "node_order_statuses"),
    ("write-misc-events", "misc_events"),
    ("write-hip3-oracle-updates", "hip3_oracle_updates"),
    (
        "write-system-and-core-writer-actions",
        "system_and_core_writer_actions",
    ),
];

#[derive(Debug, PartialEq, Eq)]
pub struct OutputSettings {
    writer_flags: [bool; 7],
    pub user_clearinghouse_states: Option<Vec<u8>>,
    pub disable_output_file_buffering: bool,
    pub batch_by_block: bool,
    pub stream_with_block_info: bool,
    pub serve_evm_rpc: bool,
    pub serve_info: bool,
    pub replica_style: ReplicaStyle,
}

impl OutputSettings {
    /// Read previously parsed options in constructor order. Both presence and
    /// value lookup are supplied by the caller, as in the captured reader.
    pub fn read<'a>(
        mut present: impl FnMut(&str) -> bool,
        mut value: impl FnMut(&str) -> Option<&'a [u8]>,
    ) -> Result<Self, StyleError> {
        let mut writer_flags = [false; 7];
        for (flag, (option, _)) in writer_flags[..6].iter_mut().zip(&WRITERS[..6]) {
            *flag = present(option);
        }
        let user_clearinghouse_states =
            value("write-user-clearinghouse-states").map(<[u8]>::to_vec);
        writer_flags[6] = present(WRITERS[6].0);
        let disable_output_file_buffering = present("disable-output-file-buffering");
        let batch_by_block = present("batch-by-block");
        let stream_with_block_info = present("stream-with-block-info");
        let serve_evm_rpc = present("serve-evm-rpc");
        let serve_info = present("serve-info");
        let replica_style = match value("replica-cmds-style") {
            None => return Err(StyleError::Missing),
            Some(b"actions") => ReplicaStyle::Actions,
            Some(b"actions-and-responses") => ReplicaStyle::ActionsAndResponses,
            Some(b"recent-actions") => ReplicaStyle::RecentActions,
            Some(_) => return Err(StyleError::Unrecognized),
        };
        Ok(Self {
            writer_flags,
            user_clearinghouse_states,
            disable_output_file_buffering,
            batch_by_block,
            stream_with_block_info,
            serve_evm_rpc,
            serve_info,
            replica_style,
        })
    }

    /// Names enabled by the seven writer flags on the mapped setter path.
    pub fn enabled_writer_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        WRITERS
            .iter()
            .zip(&self.writer_flags)
            .filter_map(|(&(_, name), &enabled)| enabled.then_some(name))
    }

    /// These two reader flags cannot both be set on the selected setter path.
    pub fn conflicting_stream_flags(&self) -> bool {
        self.batch_by_block && self.stream_with_block_info
    }
}
