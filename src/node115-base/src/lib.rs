#![forbid(unsafe_code)]
//! Integrated node #115 `base` (`foundation`) crate.
//!
//! Links all 39 Cargo-packaged `foundation` micro-crates and exposes binary-grounded
//! `cid`, `api_url`, `build_mode`, `time`, `guards`, `short_string`, `bucket_guard`,
//! `l1_map`, `lock_id`, and `log_settings` modules.

pub mod api_url;
pub mod bucket_guard;
pub mod build_mode;
pub mod cid;
pub mod guards;
pub mod l1_map;
pub mod lock_id;
pub mod log_settings;
pub mod short_string;
pub mod time;

pub use node115_billion_remainder as billion_remainder;
pub use node115_bounded_offset as bounded_offset;
pub use node115_buffer_hash32 as buffer_hash32;
pub use node115_byte_prefix_step_projection as byte_prefix_step_projection;
pub use node115_command_construction as command_construction;
pub use node115_cpu_quota as cpu_quota;
pub use node115_date_time_display as date_time_display;
pub use node115_daycount_date as daycount_date;
pub use node115_elf_build_id as elf_build_id;
pub use node115_f64_powi_leaf as f64_powi_leaf;
pub use node115_file_write_lifecycle as file_write_lifecycle;
pub use node115_gated_byte_consume as gated_byte_consume;
pub use node115_host_ip_gates as host_ip_gates;
pub use node115_iso_week_date as iso_week_date;
pub use node115_json_error_position as json_error_position;
pub use node115_json_string_scanner as json_string_scanner;
pub use node115_latency_ema_projection as latency_ema_projection;
pub use node115_newline_requests as newline_requests;
pub use node115_nonce_ring as nonce_ring;
pub use node115_nonce_text as nonce_text;
pub use node115_numeric_selector as numeric_selector;
pub use node115_owned_cstring as owned_cstring;
pub use node115_ready_identity as ready_identity;
pub use node115_recursive_directory_create as recursive_directory_create;
pub use node115_reverse_path_components as reverse_path_components;
pub use node115_reverse_word256 as reverse_word256;
pub use node115_rng_buffer_selection as rng_buffer_selection;
pub use node115_rng_refill as rng_refill;
pub use node115_scalar_reduction as scalar_reduction;
pub use node115_shortstring_intern as shortstring_intern;
pub use node115_stable_record_insertion as stable_record_insertion;
pub use node115_tagged_count as tagged_count;
pub use node115_three_digit_decimal as three_digit_decimal;
pub use node115_time_producer as time_producer;
pub use node115_timespec_difference as timespec_difference;
pub use node115_two_span_projection as two_span_projection;
pub use node115_u128_binary64 as u128_binary64;
pub use node115_utf8_admission as utf8_admission;
pub use node115_wide_byte_select as wide_byte_select;
