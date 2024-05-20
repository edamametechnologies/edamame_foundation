use flexi_logger::{writers::LogWriter, Duplicate, FileSpec, LogSpecification, Logger};
use log::{info, error};
use regex::Regex;
use std::{
    collections::VecDeque,
    env::{current_exe, var},
    fs::create_dir_all,
    io::{Cursor, Error, ErrorKind},
    mem::forget,
    path::PathBuf,
    // Std mutex
    sync::{Arc, Mutex},
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use tokio::time::Duration;

#[cfg(target_os = "android")]
use android_logger;

#[cfg(not(target_os = "windows"))]
use log::LevelFilter;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use flexi_logger::LoggerHandle;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::runtime::async_spawn;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::sync::atomic::{AtomicUsize, Ordering};

// Signal handling
#[cfg(any(target_os = "macos", target_os = "linux"))]
use tokio::signal::unix::{signal, SignalKind};

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

pub struct MemoryWriter {
    data: Arc<Mutex<MemoryWriterData>>,
}

impl MemoryWriter {
    pub fn new(data: Arc<Mutex<MemoryWriterData>>) -> Self {
        Self { data }
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

    fn format_log_line(
        &self,
        now: &mut flexi_logger::DeferredNow,
        record: &flexi_logger::Record,
        log_line_sanitized: &str,
    ) -> String {
        format!(
            "[{}] {} [{}] {}\n",
            now.format("%Y-%m-%d %H:%M:%S%.6f %:z"),
            record.level(),
            record.module_path().unwrap_or("unknown"),
            log_line_sanitized
        )
    }

    fn handle_log(
        &self,
        now: &mut flexi_logger::DeferredNow,
        record: &flexi_logger::Record,
    ) -> std::io::Result<()> {
        let mut locked_data = self.data.lock().unwrap();

        // Create a Cursor to write the log line to
        let mut cursor = Cursor::new(Vec::new());
        // Get the formatted log line from the record and push it to the logs
        match flexi_logger::default_format(&mut cursor, now, record) {
            Ok(_) => {
                let log_line = record.args().to_string();
                let keywords = vec![
                    "id", "uuid", "pin", "device", "password", "key", "Device ID", "device_id", "code",
                ];
                let log_line_sanitized = Self::sanitize_keywords(&log_line, &keywords);
                let log_line_formatted = self.format_log_line(now, record, &log_line_sanitized);

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
                if (record.level() == log::Level::Error)
                    && (!record.module_path().unwrap_or("").starts_with("libp2p")
                    || (!log_line_sanitized.contains("Socket is not connected")))
                {
                    let log_line_formatted =
                        format!("{} [{}] {}\n", record.level(), record.module_path().unwrap_or("unknown"), log_line_sanitized);
                    sentry::capture_message(&log_line_formatted, sentry::Level::Error);
                }

                Ok(())
            }
            Err(e) => {
                // Use print to avoid recursion
                println!("Error writing log line to memory logger: {}", e);
                Err(Error::new(ErrorKind::Other, e))
            }
        }
    }
}

impl LogWriter for MemoryWriter {
    fn write(
        &self,
        now: &mut flexi_logger::DeferredNow,
        record: &flexi_logger::Record,
    ) -> std::io::Result<()> {
        self.handle_log(now, record)
    }

    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct FoundationLogger {
    log_spec: LogSpecification,
    logger_handle: Option<LoggerHandle>,
    memory_writer_data: Arc<Mutex<MemoryWriterData>>,
}

impl FoundationLogger {
    pub fn new(is_helper: bool) -> Self {
        let memory_writer_data = Arc::new(Mutex::new(MemoryWriterData::new()));

        println!("Initializing Flexi logger");

        let default_log_spec = "info";
        let mut env_log_spec = var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
        env_log_spec.push_str(",libp2p=info");
        let log_spec = LogSpecification::env_or_parse(&env_log_spec).unwrap();

        let memory_writer = MemoryWriter::new(memory_writer_data.clone());
        let logger_handle = if cfg!(target_os = "windows") {
            let log_dir = if is_helper {
                let exe_path: PathBuf = current_exe().expect("Failed to get current exe");
                exe_path.parent().expect("Failed to get parent of current exe").to_path_buf()
            } else {
                let appdata = var("APPDATA").expect("Failed to get APPDATA");
                let appdata_path = format!("{}/com.edamametech/EDAMAME Security", appdata);
                create_dir_all(&appdata_path).expect("Failed to create directory");
                PathBuf::from(appdata_path)
            };
            let basename = if is_helper { "edamame_helper" } else { "edamame" };
            let file_spec = FileSpec::default().basename(basename).directory(log_dir);
            Some(
                Logger::with(log_spec.clone())
                    .format(flexi_logger::colored_opt_format)
                    .log_to_file_and_writer(file_spec, Box::new(memory_writer))
                    .duplicate_to_stdout(Duplicate::All)
                    .start()
                    .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e))
            )
        } else {
            println!("Initializing Flexi logger for non-Windows");
            Some(
                Logger::with(log_spec.clone())
                    .format(flexi_logger::colored_opt_format)
                    .log_to_writer(Box::new(memory_writer))
                    .duplicate_to_stdout(Duplicate::All)
                    .start()
                    .unwrap_or_else(|e| panic!("Logger initialization failed: {:?}", e))
            )
        };

        Self {
            log_spec,
            logger_handle,
            memory_writer_data,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn init_signals(&self) {
        if let Some(ref logger_handle) = self.logger_handle {
            let log_spec = self.log_spec.clone();
            let current_log_level = Arc::new(AtomicUsize::new(log_spec.module_filters()[0].level_filter as usize));
            let current_log_level_signal = current_log_level.clone();
            let flexi_logger_clone = logger_handle.clone();
            async_spawn(async move {
                let mut signals = signal(SignalKind::user_defined1()).expect("Failed to set up signal handling");

                loop {
                    if signals.recv().await.is_some() {
                        let current_log_level = current_log_level_signal.load(Ordering::Relaxed);

                        let new_log_level = if current_log_level == LevelFilter::Info as usize {
                            LevelFilter::Trace
                        } else {
                            LevelFilter::Info
                        };

                        current_log_level_signal.store(new_log_level as usize, Ordering::Relaxed);

                        let new_spec = LogSpecification::env_or_parse(&new_log_level.to_string())
                            .expect("Failed to parse new log specification");

                        flexi_logger_clone.set_new_spec(new_spec);
                    }

                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
    }

    pub fn get_new_logs(&self) -> String {
        let mut locked_data = self.memory_writer_data.lock().unwrap();
        let new_logs: String = locked_data
            .logs
            .iter()
            .take(locked_data.to_take)
            .fold(String::new(), |acc, x| format!("{}\n{}", acc, x));
        locked_data.to_take = 0;
        new_logs
    }

    pub fn get_all_logs(&self) -> String {
        let locked_data = self.memory_writer_data.lock().unwrap();
        locked_data
            .logs
            .iter()
            .fold(String::new(), |acc, x| format!("{}\n{}", acc, x))
    }
}

pub fn init_sentry(url: &str, release: &str) {
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
        info!("Sentry initialized");
    } else {
        error!("Sentry initialization failed");
    }
    forget(sentry);
}

#[cfg(all(debug_assertions, target_os = "android"))]
pub fn init_android_logger() {
    match android_logger::init_once(
        android_logger::Config::default()
            .with_tag("Rust")
            .with_max_level(LevelFilter::Info),
    ) {
        Ok(_) => println!("Android logger initialized"),
        Err(e) => {
            let error = format!("Failed to initialize Android logger: {:?}", e);
            eprintln!("{}", error);
            sentry::capture_message(&error, sentry::Level::Error);
        }
    }
}

pub fn init_logger(is_helper: bool) -> FoundationLogger {
    #[cfg(not(all(debug_assertions, target_os = "android")))]
        let logger = FoundationLogger::new(is_helper);
    #[cfg(all(debug_assertions, target_os = "android"))]
    init_android_logger();

    // Return the logger for further use
    #[cfg(not(all(debug_assertions, target_os = "android")))]
    logger
}

#[cfg(test)]
mod tests {
    use super::*;
    use flexi_logger::{DeferredNow, Record};
    use std::sync::{Arc, Mutex};

    // Can only be called once (tests will fail if called more than once)
    fn create_logger(is_helper: bool) -> FoundationLogger {
        FoundationLogger::new(is_helper)
    }

    #[test]
    fn test_logger_initialization() {
        let logger = create_logger(false);

        assert!(logger.logger_handle.is_some());
    }

    #[test]
    fn test_memory_writer_initialization() {
        let data = Arc::new(Mutex::new(MemoryWriterData::new()));
        let writer = MemoryWriter::new(data.clone());

        assert!(writer.data.lock().unwrap().logs.is_empty());
    }

    #[test]
    fn test_log_sanitization() {

        let test_log = r#"{"id": "12345", "password": "secret"}"#;
        let sanitized_log = MemoryWriter::sanitize_keywords(
            test_log,
            &["id", "password"]
        );

        assert_eq!(
            sanitized_log,
            r#"{"id": "*****", "password": "******"}"#
        );
    }

    #[test]
    fn test_format_log_line() {
        let data = Arc::new(Mutex::new(MemoryWriterData::new()));
        let writer = MemoryWriter::new(data.clone());

        let now = &mut DeferredNow::new();
        let record = Record::builder()
            .args(format_args!("This is a test log"))
            .level(log::Level::Info)
            .line(Some(42))
            .build();

        let log_line = writer.format_log_line(now, &record, "This is a sanitized log");

        assert!(log_line.contains("This is a sanitized log"));
        assert!(log_line.contains("INFO"));
    }

    #[test]
    fn test_log_storage_in_memory_writer() {
        let data = Arc::new(Mutex::new(MemoryWriterData::new()));
        let writer = MemoryWriter::new(data.clone());

        let now = &mut DeferredNow::new();
        let record = Record::builder()
            .args(format_args!("This is a test log"))
            .level(log::Level::Info)
            .target("test_module")
            .file(Some("test_file.rs"))
            .line(Some(42))
            .build();

        writer.write(now, &record).unwrap();

        let locked_data = data.lock().unwrap();
        assert_eq!(locked_data.logs.len(), 1);
        assert!(locked_data.logs[0].contains("This is a test log"));
    }
}
