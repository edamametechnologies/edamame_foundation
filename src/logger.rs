use lazy_static::lazy_static;
use std::io::Cursor;
use std::collections::VecDeque;
use std::{
    env,
    path::PathBuf,
    sync::{
        Arc, Mutex
    },
};
use regex::Regex;
use flexi_logger::{Duplicate, FileSpec, LogSpecification, Logger, writers::LogWriter};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use flexi_logger::LoggerHandle;


#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::{AtomicUsize, Ordering};

// Signal handling
#[cfg(any(target_os = "macos", target_os = "linux"))]
use signal_hook::consts::signal;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use signal_hook::iterator::Signals;

const MAX_LOG_LINES: usize = 1000;

pub struct MemoryWriterData {
    logs: VecDeque<String>,
    lines: usize,
    to_take: usize
}

impl MemoryWriterData {
    pub fn new() -> Self {
        Self {
            logs: VecDeque::new(),
            lines: 0,
            to_take: 0
        }
    }
}

lazy_static! {
    pub static ref MEMORY_WRITER_DATA: Arc<Mutex<MemoryWriterData>> = Arc::new(Mutex::new(MemoryWriterData::new()));
}

fn sanitize_keywords(input: &str, keywords: &[&str]) -> String {
    let mut output = input.to_string();

    for &keyword in keywords {
        let re = Regex::new(&format!(
            r#"(?P<key>"?(\b{})"?\s*[:=]?\s*)("(?P<val1>[^"]+)"|(?P<val2>\b[^\s",}}]+))"#,
            regex::escape(keyword)
        ))
            .unwrap();

        output = re.replace_all(&output, |caps: &regex::Captures| {
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

struct MemoryWriter {
}

impl MemoryWriter {
    pub fn new() -> Self {
        Self {
        }
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
                // Format
                let log_line_formatted = format!("[{}] {} [{}] {}\n", now.format("%Y-%m-%d %H:%M:%S%.6f %:z"), level, module, log_line);
                // If we have more than MAX_LOG_LINES, remove the oldest one
                if locked_data.logs.len() >= MAX_LOG_LINES {
                    locked_data.logs.pop_back();
                    locked_data.lines -= 1;
                }
                // Sanitize
                let keywords = vec!["id", "uuid", "pin", "device", "password", "key", "Device ID", "device_id", "code"];
                let log_line_sanitized = sanitize_keywords(&log_line_formatted, &keywords);
                // Save to memory in a reverse order (latest at the beginning)
                locked_data.logs.push_front(log_line_sanitized.clone());
                // Update lines
                if locked_data.lines < MAX_LOG_LINES {
                    locked_data.lines += 1;
                }
                // Update to_take
                if locked_data.to_take < MAX_LOG_LINES {
                    locked_data.to_take += 1;
                }
                // Print it to stdout
                print!("{}", log_line_sanitized);
                Ok(res)
            }
            Err(e) => {
                // Use print to avoid recursion
                println!("Error writing log line to memory logger: {}", e);
                Err(std::io::Error::new(std::io::ErrorKind::Other, e))
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
    new_logs = locked_data.logs.iter().take(locked_data.to_take).fold(new_logs, |acc, x| format!("{}\n{}", acc, x));
    locked_data.to_take = 0;
    new_logs
}

// Function to get all logs
pub fn get_all_logs() -> String {
    let mut locked_data = MEMORY_WRITER_DATA.lock().unwrap();
    let mut all_logs: String = "".to_string();
    // Don't pop elements from the circular buffer, just collect them
    all_logs = locked_data.logs.iter().fold(all_logs, |acc, x| format!("{}\n{}", acc, x));
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
    std::thread::spawn(move || {
        for _ in signals.forever() {
            let current_log_level = current_log_level_signal.load(Ordering::Relaxed);

            let new_log_level = if current_log_level == log::LevelFilter::Info as usize {
                log::LevelFilter::Trace
            } else {
                log::LevelFilter::Info
            };
            current_log_level_signal.store(new_log_level as usize, Ordering::Relaxed);
            let new_spec =
                LogSpecification::env_or_parse(&new_log_level.to_string()).unwrap();
            flexi_logger.set_new_spec(new_spec);
        }
    });
}

pub fn init_app_logger() {

    // Init logger here, enforce log level to info as default
    let default_log_spec = "info";
    // Override with env variable if set
    let env_log_spec = env::var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
    let log_spec = LogSpecification::env_or_parse(env_log_spec).unwrap();

    // When running as an app, we use our own logger to memory
    let memory_writer = MemoryWriter::new();
    let flexi_logger = Logger::with(log_spec.clone())
        .format(flexi_logger::colored_opt_format)
        .log_to_writer(Box::new(memory_writer))
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e));

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    init_signals(flexi_logger, &log_spec);
}

pub fn init_helper_logger() {

    // Init logger here, enforce log level to info as default
    let default_log_spec = "info";
    // Override with env variable if set
    let env_log_spec = env::var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
    let log_spec = LogSpecification::env_or_parse(env_log_spec).unwrap();

    // Flexi logger
    // The helper on Windows doesn't have access to the console, so we log to a file instead
    let flexi_logger = if cfg!(target_os = "windows") {
        let exe_path: PathBuf = env::current_exe().unwrap();
        let log_dir = exe_path.parent().unwrap().to_path_buf();
        Logger::with(log_spec.clone())
            .format(flexi_logger::colored_opt_format)
            // Write logs to a file in the binary's directory
            .log_to_file(
                FileSpec::default()
                    .directory(log_dir)
                    .basename("edamame_helper")
                    .suffix("log"),
            )
            .start()
            .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e))
    } else {
        // Stderr logging
        Logger::with(log_spec.clone())
            .format(flexi_logger::colored_opt_format)
            .duplicate_to_stderr(Duplicate::Warn)
            .start()
            .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e))
    };

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    init_signals(flexi_logger, &log_spec);
}