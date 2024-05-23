use fmt::MakeWriter;
use lazy_static::lazy_static;
use regex::Regex;
use sentry_tracing::EventFilter;
use std::{
    collections::VecDeque,
    env::{current_exe, var},
    fs::create_dir_all,
    io::{self, Write},
    mem::forget,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

#[cfg(target_os = "android")]
use tracing_android;

#[cfg(any(target_os = "ios", target_os = "macos"))]
use tracing_oslog::OsLogger;

const MAX_LOG_LINES: usize = 20000;

lazy_static! {
    static ref LOGGER: Mutex<Option<Arc<Logger>>> = Mutex::new(None);
}

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

#[derive(Clone)]
pub struct MemoryWriter {
    data: Arc<Mutex<MemoryWriterData>>,
}

impl MemoryWriter {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(MemoryWriterData::new())),
        }
    }

    fn handle_log(
        &self,
        log_line: &str,
    ) -> io::Result<()> {
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
        // Remove all escape codes (x1b\[[0-9;]*m) from the log line before storing it in the log buffer x1b\[[0-9;]*m
        let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        let log_line_formatted = re.replace_all(&log_line_sanitized, "");
        let log_line_formatted = log_line_formatted.trim().to_string();
        
        let mut locked_data = self.data.lock().unwrap();

        if locked_data.logs.len() >= MAX_LOG_LINES {
            locked_data.logs.pop_back();
            locked_data.lines -= 1;
        }

        locked_data.logs.push_front(log_line_formatted.clone());
        if locked_data.lines < MAX_LOG_LINES {
            locked_data.lines += 1;
        }
        if locked_data.to_take < MAX_LOG_LINES {
            locked_data.to_take += 1;
        }

        drop(locked_data);
        
        // Catch the error logs and send them to Sentry by catching "ERROR" in the log line
        if log_line_formatted.contains("ERROR")
            && (!log_line_formatted.contains("libp2p")
                || (!log_line_formatted.contains("Socket is not connected")))
        {
            sentry::capture_message(&log_line_formatted, sentry::Level::Error);
        }

        Ok(())
    }
}

impl<'a> MakeWriter<'a> for MemoryWriter {
    type Writer = MemoryWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        MemoryWriterGuard { writer: self }
    }
}

pub struct MemoryWriterGuard<'a> {
    writer: &'a MemoryWriter,
}

impl<'a> Write for MemoryWriterGuard<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let log = String::from_utf8_lossy(buf).to_string();
        self.writer.handle_log(&log)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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

pub struct Logger {
    memory_writer: MemoryWriter,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            memory_writer: MemoryWriter::new(),
        }
    }

    pub fn get_new_logs(&self) -> String {
        let mut locked_data = self.memory_writer.data.lock().unwrap();
        let new_logs: String = locked_data
            .logs
            .iter()
            .take(locked_data.to_take)
            .fold(String::new(), |acc, x| format!("{}\n{}", acc, x));
        locked_data.to_take = 0;
        new_logs
    }

    pub fn get_all_logs(&self) -> String {
        let locked_data = self.memory_writer.data.lock().unwrap();
        locked_data
            .logs
            .iter()
            .fold(String::new(), |acc, x| format!("{}\n{}", acc, x))
    }

    pub fn flush_logs(&self) {
        let mut locked_data = self.memory_writer.data.lock().unwrap();
        locked_data.logs.clear();
        locked_data.lines = 0;
        locked_data.to_take = 0;
    }
}

fn init_sentry(url: &str, release: &str) {
    let release = release.to_string();
    let sentry_guard = sentry::init((
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

    if sentry_guard.is_enabled() {
        println!("Sentry initialized");
    } else {
        eprintln!("Sentry initialization failed");
    }

    forget(sentry_guard);
}

pub fn init_logger(executable_type: &str, url: &str, release: &str) {
    let mut logger_guard = LOGGER.lock().unwrap();
    if logger_guard.is_some() {
        eprintln!("Logger already initialized, flushing logs");
        logger_guard.as_ref().unwrap().flush_logs();
        return;
    }

    *logger_guard = Some(Arc::new(Logger::new()));
    let logger = logger_guard.as_ref().unwrap();

    if !url.is_empty() {
        init_sentry(url, release);
    }

    let default_log_spec = "info";
    let mut env_log_spec = var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
    env_log_spec.push_str(",libp2p=info");

    // Set filter
    let filter_layer = EnvFilter::try_new(env_log_spec).unwrap();

    // Duplicate to stdout or file depending on platform
    let (non_blocking, appender_guard) = if cfg!(target_os = "windows") && matches!(executable_type, "cli") {
        let log_dir = if matches!(executable_type, "helper") {
            let exe_path: PathBuf = current_exe().expect("Failed to get current exe");
            exe_path
                .parent()
                .expect("Failed to get parent of current exe")
                .to_path_buf()
        } else {
            let appdata = var("APPDATA").expect("Failed to get APPDATA");
            let appdata_path = format!("{}/com.edamametech/EDAMAME Security", appdata);
            create_dir_all(&appdata_path).expect("Failed to create directory");
            PathBuf::from(appdata_path)
        };
        let basename = if matches!(executable_type, "helper") {
            "edamame_helper"
        } else {
            "edamame"
        };
        let file_appender = RollingFileAppender::new(Rotation::NEVER, log_dir, basename);
        tracing_appender::non_blocking(file_appender)
    } else {
        tracing_appender::non_blocking(io::stdout())
    };
    
    // Register the proper layers based on sentry availability and platform
    if !url.is_empty() {
        let sentry_layer = sentry_tracing::layer().event_filter(|md| match md.level() {
            &Level::ERROR => EventFilter::Event,
            _ => EventFilter::Ignore,
        });
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                let os_logger = OsLogger::new("com.edamametech.edamame", "");

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(non_blocking))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(sentry_layer)
                    .with(os_logger)
                    .try_init() {
                        Ok(_) => println!("Logger initialized"),
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
            }
        } else if cfg!(target_os = "android") {
            #[cfg(target_os = "android")]
            {
                let android_layer = tracing_android::layer("edamametech.edamame").unwrap();

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(non_blocking))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(sentry_layer)
                    .with(android_layer)
                    .try_init() {
                        Ok(_) => println!("Logger initialized"),
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
            }
        } else {
            // Linux and Windows
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(non_blocking.clone()))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .with(sentry_layer)
                .try_init() {
                    Ok(_) => println!("Logger initialized"),
                    Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        }
    } else {
        // Without sentry
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                let os_logger = OsLogger::new("com.edamametech.edamame", "default");

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(non_blocking))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(os_logger)
                    .try_init() {
                        Ok(_) => println!("Logger initialized"),
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                }
            }
        } else if cfg!(target_os = "android") {
            #[cfg(target_os = "android")]
            {
                let android_layer = tracing_android::layer("edamametech.edamame").unwrap();
                
                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(non_blocking))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(android_layer)
                    .try_init() {
                        Ok(_) => println!("Logger initialized"),
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
            }
        } else {
            // Linux and Windows
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(non_blocking))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .try_init() {
                    Ok(_) => println!("Logger initialized"),
                    Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        }
    }
    
    forget(appender_guard);
}

pub fn get_new_logs() -> String {
    let logger_guard = LOGGER.lock().unwrap();
    if let Some(logger) = logger_guard.as_ref() {
        logger.get_new_logs()
    } else {
        String::new()
    }
}

pub fn get_all_logs() -> String {
    let logger_guard = LOGGER.lock().unwrap();
    if let Some(logger) = logger_guard.as_ref() {
        logger.get_all_logs()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tracing::{debug, error, info, trace, warn};

    fn initialize_and_flush_logger() {
        init_logger("cli", "", "");
    }

    #[test]
    #[serial]
    fn test_logger_initialization() {
        initialize_and_flush_logger();
        assert!(true);
    }

    #[test]
    #[serial]
    fn test_memory_writer_initialization() {
        let writer = MemoryWriter::new();
        assert!(writer.data.lock().unwrap().logs.is_empty());
    }

    #[test]
    #[serial]
    fn test_log_sanitization() {
        let test_log = r#"{"id": "12345", "password": "secret"}"#;
        let sanitized_log = sanitize_keywords(test_log, &["id", "password"]);
        assert_eq!(sanitized_log, r#"{"id": "*****", "password": "******"}"#);
    }

    #[test]
    #[serial]
    fn test_log_storage_in_memory_writer() {
        initialize_and_flush_logger();

        let logger_guard = LOGGER.lock().unwrap();
        let logger = logger_guard.as_ref().unwrap();

        let log_line = "This is a test log";
        logger
            .memory_writer
            .handle_log(log_line)
            .unwrap();

        let locked_data = logger.memory_writer.data.lock().unwrap();
        assert_eq!(locked_data.logs.len(), 1);
        assert!(locked_data.logs[0].contains("This is a test log"));
    }

    #[test]
    #[serial]
    fn test_get_new_logs() {
        initialize_and_flush_logger();

        let log_data = get_new_logs();
        assert!(log_data.is_empty());

        info!("New log entry");

        let log_data = get_new_logs();
        assert!(!log_data.is_empty());
        assert!(log_data.contains("New log entry"));
    }

    #[test]
    #[serial]
    fn test_get_all_logs() {
        initialize_and_flush_logger();

        let log_data = get_all_logs();
        assert!(log_data.is_empty());

        info!("First log entry");
        info!("Second log entry");

        let log_data = get_all_logs();
        assert!(log_data.contains("First log entry"));
        assert!(log_data.contains("Second log entry"));
    }

    #[test]
    #[serial]
    fn test_log_levels() {
        initialize_and_flush_logger();

        info!("This is an info log");
        error!("This is an error log");
        warn!("This is a warn log");
        debug!("This is a debug log");
        trace!("This is a trace log");

        let log_data = get_all_logs();
        assert!(log_data.contains("This is an info log"));
        assert!(log_data.contains("This is an error log"));
        assert!(log_data.contains("This is a warn log"));
    }
}
