use flexi_logger::{writers::LogWriter, Duplicate, FileSpec, LogSpecification, Logger};
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    collections::VecDeque,
    env::{current_exe, var},
    fs::create_dir_all,
    io::{Cursor, Error, ErrorKind},
    mem::forget,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[cfg(target_os = "android")]
use android_logger;

#[cfg(target_os = "ios")]
use oslog::OsLogger;

use log::LevelFilter;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::thread::spawn;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use flexi_logger::LoggerHandle;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::{AtomicUsize, Ordering};

// Signal handling
#[cfg(any(target_os = "macos", target_os = "linux"))]
use signal_hook::consts::signal;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use signal_hook::iterator::Signals;

const MAX_LOG_LINES: usize = 20000;

pub struct MemoryWriterData {
    logs: VecDeque<String>,
    lines: usize,
    to_take: usize,
}

impl MemoryWriterData {
    pub fn new() -> Self {
        Self {
            logs: VecDeque::new(),
            lines: 0,
            to_take: 0,
        }
    }
}

lazy_static! {
    pub static ref MEMORY_WRITER_DATA: Arc<Mutex<MemoryWriterData>> =
        Arc::new(Mutex::new(MemoryWriterData::new()));
}

fn sanitize_keywords(input: &str, keywords: &[&str]) -> String {
    let mut output = input.to_string();

    for &keyword in keywords {
        let re = Regex::new(&format!(
            r#"(?P<key>"?(\b{})"?\s*[:=]?\s*)("(?P<val1>[^"]+)"|(?P<val2>\b[^\s",}}]+))"#,
            regex::escape(keyword)
        ))
        .unwrap();

        output = re
            .replace_all(&output, |caps: &regex::Captures| {
                let key = &caps["key"];
                let val1 = caps.name("val1").map_or("", |m| m.as_str());
                let val2 = caps.name("val2").map_or("", |m| m.as_str());
                let val = if !val1.is_empty() { val1 } else { val2 };
                let quotes = if !val1.is_empty() { "\"" } else { "" };

                format!("{}{}{}{}", key, quotes, "*".repeat(val.len()), quotes)
            })
            .to_string();
    }

    output
}

// TODO: make a test for this
/*
fn main() {
    let log_lines = vec![
        "{\"pin\": 888AA88}",
        "{\"pin\": \"888AA88\"}",
        "{\"Device ID\": 888AA88}",
        "Device ID: 88AA888",
        "Device ID 8AA8888",
        "code =AAA88888",
        "code=88888AAA",
        "pin 88888",
        "success_pin 888888AAA"
    ];

    for log_line in log_lines {
        let sanitized_log = sanitize_keywords(&log_line, &["pin", "Device ID", "code"]);
        println!("{}", sanitized_log);
    }
}
*/

struct MemoryWriter {}

impl MemoryWriter {
    pub fn new() -> Self {
        Self {}
    }
}

impl LogWriter for MemoryWriter {
    fn write(
        &self,
        now: &mut flexi_logger::DeferredNow,
        record: &flexi_logger::Record,
    ) -> std::io::Result<()> {
        let mut locked_data = MEMORY_WRITER_DATA.lock().unwrap();

        // Create a Cursor to write the log line to
        let mut cursor = Cursor::new(Vec::new());
        // Get the formatted log line from the record and push it to the logs
        match flexi_logger::default_format(&mut cursor, now, record) {
            Ok(res) => {
                let log_line = record.args().to_string();
                let level = record.level().to_string();
                let module = record.module_path().unwrap_or("unknown");

                // Sanitize
                let keywords = vec![
                    "id",
                    "uuid",
                    "pin",
                    "device",
                    "password",
                    "key",
                    "Device ID",
                    "device_id",
                    "code",
                ];
                let log_line_sanitized = sanitize_keywords(&log_line, &keywords);

                // Format
                let log_line_formatted = format!(
                    "[{}] {} [{}] {}\n",
                    now.format("%Y-%m-%d %H:%M:%S%.6f %:z"),
                    level,
                    module,
                    log_line_sanitized
                );
                // If we have more than MAX_LOG_LINES, remove the oldest one
                if locked_data.logs.len() >= MAX_LOG_LINES {
                    locked_data.logs.pop_back();
                    locked_data.lines -= 1;
                }

                // Save to memory in a reverse order (latest at the beginning)
                locked_data.logs.push_front(log_line_formatted.clone());
                // Update lines
                if locked_data.lines < MAX_LOG_LINES {
                    locked_data.lines += 1;
                }
                // Update to_take
                if locked_data.to_take < MAX_LOG_LINES {
                    locked_data.to_take += 1;
                }

                // Send errors to Sentry, exclude libp2p* that is generating too much network related errors
                // Also exclude network errors
                if (level == "ERROR") && (!module.starts_with("libp2p")
                    || (!log_line_sanitized.contains("Socket is not connected"))) {
                    let log_line_formatted =
                        format!("{} [{}] {}\n", level, module, log_line_sanitized);
                    sentry::capture_message(&log_line_formatted, sentry::Level::Error);
                }

                Ok(res)
            }
            Err(e) => {
                // Use print to avoid recursion
                println!("Error writing log line to memory logger: {}", e);
                Err(Error::new(ErrorKind::Other, e))
            }
        }
    }

    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

// Function to get new logs since the last call
pub fn get_new_logs() -> String {
    let mut locked_data = MEMORY_WRITER_DATA.lock().unwrap();
    let mut new_logs: String = "".to_string();
    // Don't pop elements from the circular buffer, just collect locked_data.to_take of those
    new_logs = locked_data
        .logs
        .iter()
        .take(locked_data.to_take)
        .fold(new_logs, |acc, x| format!("{}\n{}", acc, x));
    locked_data.to_take = 0;
    new_logs
}

// Function to get all logs
pub fn get_all_logs() -> String {
    let mut locked_data = MEMORY_WRITER_DATA.lock().unwrap();
    let mut all_logs: String = "".to_string();
    // Don't pop elements from the circular buffer, just collect them
    all_logs = locked_data
        .logs
        .iter()
        .fold(all_logs, |acc, x| format!("{}\n{}", acc, x));
    locked_data.to_take = 0;
    all_logs
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn init_signals(flexi_logger: LoggerHandle, log_spec: &LogSpecification) {
    // Change log_level on the fly using signal
    // Only for flexi_logger
    let current_log_level = Arc::new(AtomicUsize::new(
        log_spec.module_filters()[0].level_filter as usize,
    ));
    let current_log_level_signal = current_log_level.clone();

    let mut signals = Signals::new([signal::SIGUSR1]).unwrap();

    // Spawn a thread to handle signals and toggle log level (info / trace)
    spawn(move || {
        for _ in signals.forever() {
            let current_log_level = current_log_level_signal.load(Ordering::Relaxed);

            let new_log_level = if current_log_level == LevelFilter::Info as usize {
                LevelFilter::Trace
            } else {
                LevelFilter::Info
            };
            current_log_level_signal.store(new_log_level as usize, Ordering::Relaxed);
            let new_spec = LogSpecification::env_or_parse(&new_log_level.to_string()).unwrap();
            flexi_logger.set_new_spec(new_spec);
        }
    });
}

pub fn init_sentry(url: &str, release: &str) {
    // Init sentry
    let release = release.to_string();
    let sentry = sentry::init((
        url,
        sentry::ClientOptions {
            release: if release.is_empty() {
                sentry::release_name!()
            } else {
                Some(release.into())
            },
            traces_sample_rate: 1.0,
            ..Default::default()
        },
    ));

    if sentry.is_enabled() {
        println!("Sentry initialized");
    } else {
        eprintln!("Sentry initialization failed");
    }
    // Forget the sentry object to prevent it from being dropped
    forget(sentry);
}

#[cfg(not(all(debug_assertions, any(target_os = "android", target_os = "ios"))))]
fn init_flexi_logger(is_helper: bool) {

    println!("Initializing Flexi logger");

    // Init logger here, enforce log level to info as default
    let default_log_spec = "info";
    // Override with env variable if set
    let mut env_log_spec = var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
    // Add exceptions to log level
    // Suppress warnings in lib p2p
    env_log_spec.push_str(",libp2p=info");
    let log_spec = LogSpecification::env_or_parse(env_log_spec).unwrap();

    // Flexi logger
    // Our writer
    let memory_writer = MemoryWriter::new();
    // The helper on Windows doesn't have access to the console, so we log to a file instead
    let flexi_logger = if cfg!(target_os = "windows") {
        let log_dir = if is_helper {
            // Log to the same directory as the binary
            let exe_path: PathBuf = match current_exe() {
                Ok(path) => path,
                Err(e) => {
                    // Use Sentry for error reporting
                    let error = format!("Failed to get current_exe: {}", e);
                    eprintln!("{}", error);
                    sentry::capture_message(&error, sentry::Level::Error);
                    return;
                }
            };
            match exe_path.parent() {
                Some(parent) => parent.to_path_buf(),
                None => {
                    // Use Sentry for error reporting
                    let error = "Failed to get parent of current_exe".to_string();
                    eprintln!("{}", error);
                    sentry::capture_message(&error, sentry::Level::Error);
                    return;
                }
            }
        } else {
            // Log in APPDATA/com.edamametech/EDAMAME\ Security/ (redirected to proper location in UWP apps)
            let appdata = match var("APPDATA") {
                Ok(appdata) => appdata,
                Err(e) => {
                    let error = format!("Failed to get APPDATA: {}", e);
                    eprintln!("{}", error);
                    sentry::capture_message(&error, sentry::Level::Error);
                    return;
                }
            };
            let appdata_path = format!("{}/com.edamametech/EDAMAME Security", appdata);
            // Create the directory if it doesn't exist
            match create_dir_all(&appdata_path) {
                Ok(_) => (),
                Err(e) => {
                    let error = format!("Failed to create directory {} : {}", appdata_path, e);
                    eprintln!("{}", error);
                    sentry::capture_message(&error, sentry::Level::Error);
                    return;
                }
            };
            PathBuf::from(appdata_path)
        };
        let basename = if is_helper {
            "edamame_helper"
        } else {
            "edamame"
        };
        Logger::with(log_spec.clone())
            .format(flexi_logger::colored_opt_format)
            // Write logs to a file in the binary's directory
            .log_to_file_and_writer(
                FileSpec::default()
                    .directory(log_dir)
                    .basename(basename)
                    .suffix("log"),
                Box::new(memory_writer),
            )
            .duplicate_to_stdout(Duplicate::All)
            .start()
            .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e))
    } else {
        Logger::with(log_spec.clone())
            .format(flexi_logger::colored_opt_format)
            .log_to_writer(Box::new(memory_writer))
            .duplicate_to_stdout(Duplicate::All)
            .start()
            .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e))
    };

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    init_signals(flexi_logger, &log_spec);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = flexi_logger;
}

#[cfg(target_os = "android")]
pub fn init_android_logger() {

    println!("Initializing Android logger");

    let _ = android_logger::init_once(
        android_logger::Config::default()
            .with_tag("Rust")
            .with_max_level(LevelFilter::Info),
    );

    // Use Sentry for panic reporting only
    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |arg| {
        let error = format!("Panic: {:?}", arg);
        eprintln!("{}", error);
        sentry::capture_message(&error, sentry::Level::Error);
        old_hook(arg);
    }));
}

#[cfg(target_os = "ios")]
pub fn init_ios_logger() {

    println!("Initializing iOS logger");

    let _ = OsLogger::new("com.edamametech.edamame")
        .level_filter(LevelFilter::Debug)
        .category_level_filter("Settings", LevelFilter::Trace)
        .init()
        .unwrap();

    // Use Sentry for panic reporting only
    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |arg| {
        let error = format!("Panic: {:?}", arg);
        eprintln!("{}", error);
        sentry::capture_message(&error, sentry::Level::Error);
        old_hook(arg);
    }));
}

pub fn init_logger(url: &str, release: &str, is_helper: bool) {
    // Init Sentry first
    init_sentry(url, release);

    // This is mutually exclusive with flexi_logger, use native loggers in debug mode only
    #[cfg(all(debug_assertion, target_os = "android"))]
    init_android_logger();
    #[cfg(all(debug_assertion, target_os = "ios"))]
    init_ios_logger();
    #[cfg(not(all(debug_assertions, any(target_os = "android", target_os = "ios"))))]
    init_flexi_logger(is_helper);
}
