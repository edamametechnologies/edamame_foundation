use fmt::MakeWriter;
use lazy_static::lazy_static;
use regex::Regex;
use sentry_tracing::EventFilter;
use std::env::set_var;
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
#[cfg(target_os = "android")]
use tracing_android;
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

#[cfg(any(target_os = "ios", target_os = "macos"))]
use tracing_oslog::OsLogger;

const MAX_LOG_LINES: usize = 20000;

lazy_static! {
    static ref LOGGER: Mutex<Option<Arc<Logger>>> = Mutex::new(None);
    // Pre-compile the sanitization regex once so it can be reused for every log line.
    // The pattern dynamically embeds all sensitive keywords and performs a single pass
    // over the input instead of iterating and recompiling per-keyword.
    static ref SANITIZE_REGEX: Regex = {
        // Keep this list in sync with the one used in `handle_log`.
        let keywords = [
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
        // Join the escaped keywords with `|` to build the alternation part of the regex.
        let joined = keywords
            .iter()
            .map(|k| regex::escape(k))
            .collect::<Vec<_>>()
            .join("|");
        let pattern = format!(
            r#"(?P<key>"?(?:\b(?:{})\b)"?\s*[:=]?\s*)("(?P<val1>[^"]+)"|(?P<val2>\b[^\s",}}]+))"#,
            joined
        );
        Regex::new(&pattern).expect("Failed to compile sanitization regex")
    };
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

    fn handle_log(&self, log_line: &str) -> io::Result<()> {
        // Sanitize the log line (not in debug mode). All sensitive keywords are handled
        // by the pre-compiled regex inside `sanitize_keywords`, so we don't need to allocate
        // a keywords vector on every call.
        let log_line_sanitized = if cfg!(debug_assertions) {
            log_line.to_string()
        } else {
            sanitize_keywords(log_line, &[])
        };
        // Remove all escape codes (x1b\[[0-9;]*m) from the log line before storing it in the log buffer x1b\[[0-9;]*m
        let re = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        let log_line_formatted = re.replace_all(&log_line_sanitized, "");
        let log_line_formatted = log_line_formatted.trim().to_string();

        let mut locked_data = match self.data.lock() {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error locking data: {}", e);
                return Ok(());
            }
        };

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

fn sanitize_keywords(input: &str, _keywords: &[&str]) -> String {
    SANITIZE_REGEX
        .replace_all(input, |caps: &regex::Captures| {
            let key = &caps["key"];
            let val1 = caps.name("val1").map_or("", |m| m.as_str());
            let val2 = caps.name("val2").map_or("", |m| m.as_str());
            let val = if !val1.is_empty() { val1 } else { val2 };
            let quotes = if !val1.is_empty() { "\"" } else { "" };

            format!("{}{}{}{}", key, quotes, "*".repeat(val.len()), quotes)
        })
        .to_string()
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

    if !sentry_guard.is_enabled() {
        eprintln!("Sentry initialization failed");
    }

    forget(sentry_guard);
}

pub fn init_logger(
    executable_type: &str,
    url: &str,
    release: &str,
    provided_env_log_spec: &str,
    sentry_error_filter: &[&str],
) {
    // Force backtrace
    set_var("RUST_BACKTRACE", "1");

    let mut logger_guard = match LOGGER.lock() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("Error locking LOGGER: {}", e);
            return;
        }
    };
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
    // Set the default log level from the environment variable if provided
    let mut env_log_spec = var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
    // Add the provided log level to the env variable log level
    env_log_spec.push_str(format!(",{}", provided_env_log_spec).as_str());

    // Set filter
    let filter_layer = EnvFilter::try_new(env_log_spec).unwrap();

    // Check if we are installed in /usr or /opt
    let exe_path = current_exe().unwrap_or_else(|_| PathBuf::from(""));
    let exe_path_str = exe_path.to_str().unwrap_or("");
    let is_installed = exe_path_str.starts_with("/usr") || exe_path_str.starts_with("/opt/");

    // Optional file writer
    // Duplicate to file on Windows for the app and helper,
    // Or for posture for all platforms, except if installed in /usr or /opt
    let file_writer = if (matches!(executable_type, "cli") && !is_installed)
        || (cfg!(target_os = "windows"))
    {
        let log_dir = if matches!(executable_type, "helper") || matches!(executable_type, "cli") {
            let exe_path: PathBuf = current_exe().expect("Failed to get current exe");
            exe_path
                .parent()
                .expect("Failed to get parent of current exe")
                .to_path_buf()
        } else {
            // Windows app
            let appdata = var("APPDATA").expect("Failed to get APPDATA");
            let appdata_path = format!("{}/com.edamametech/EDAMAME Security", appdata);
            create_dir_all(&appdata_path).expect("Failed to create directory");
            PathBuf::from(appdata_path)
        };
        let basename = if matches!(executable_type, "helper") {
            "edamame_helper"
        } else if matches!(executable_type, "cli") {
            "edamame_cli"
        } else {
            "edamame"
        };
        // Add the PID to the basename
        let pid = std::process::id();
        let basename = format!("{}_{}", basename, pid);
        let file_appender = RollingFileAppender::new(Rotation::DAILY, log_dir.clone(), basename);
        tracing_appender::non_blocking(file_appender)
    } else {
        NonBlocking::new(io::sink())
    };

    // Duplicate to stdout except for posture
    let stdout_writer = if matches!(executable_type, "cli") {
        NonBlocking::new(io::sink())
    } else {
        NonBlocking::new(io::stdout())
    };

    // Register the proper layers based on sentry availability and platform
    if !url.is_empty() {
        let filter_strings: Vec<String> =
            sentry_error_filter.iter().map(|&s| s.to_string()).collect();
        let sentry_layer = sentry_tracing::layer().event_filter(move |md| {
            if let &Level::ERROR = md.level() {
                if filter_strings
                    .iter()
                    .any(|s| md.target().contains(s) || md.name().contains(s))
                {
                    EventFilter::Ignore
                } else {
                    EventFilter::Event
                }
            } else {
                EventFilter::Ignore
            }
        });
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                if !matches!(executable_type, "helper") && !matches!(executable_type, "cli") {
                    // OsLogger if not an helper or a posture
                    let os_logger = OsLogger::new("com.edamametech.edamame", "");
                    #[cfg(feature = "tokio-console")]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_writer.0))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_writer.0))
                        .with(os_logger)
                        .with(console_subscriber::spawn())
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                    #[cfg(not(feature = "tokio-console"))]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_writer.0))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_writer.0))
                        .with(os_logger)
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                } else {
                    // Tokio Console
                    #[cfg(feature = "tokio-console")]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_writer.0))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_writer.0))
                        // Use console layer for edamame_helper
                        .with(console_subscriber::spawn())
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Logger initialization with tokio console failed: {}", e)
                        }
                    }
                    #[cfg(not(feature = "tokio-console"))]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_writer.0))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_writer.0))
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                }
            }
        } else if cfg!(target_os = "android") {
            #[cfg(target_os = "android")]
            {
                let android_layer = tracing_android::layer("edamametech.edamame").unwrap();

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(stdout_writer.0))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(sentry_layer)
                    .with(android_layer)
                    .try_init()
                {
                    Ok(_) => {}
                    Err(e) => eprintln!("Logger initialization failed: {}", e),
                }
            }
        } else if cfg!(target_os = "windows") {
            // Windows
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(file_writer.0))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .with(sentry_layer)
                // Must be here when using sentry
                .with(fmt::layer().with_writer(stdout_writer.0))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        } else {
            // Linux
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(file_writer.0))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .with(sentry_layer)
                // Must be here when using sentry
                .with(fmt::layer().with_writer(stdout_writer.0))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        }
    } else {
        // Without sentry
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                if !matches!(executable_type, "helper") && !matches!(executable_type, "cli") {
                    // OsLogger if not an helper or a posture
                    let os_logger = OsLogger::new("com.edamametech.edamame", "default");

                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(stdout_writer.0))
                        .with(fmt::layer().with_writer(file_writer.0))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(os_logger)
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                } else {
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(stdout_writer.0))
                        .with(fmt::layer().with_writer(file_writer.0))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                }
            }
        } else if cfg!(target_os = "android") {
            #[cfg(target_os = "android")]
            {
                let android_layer = tracing_android::layer("edamametech.edamame").unwrap();

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(stdout_writer.0))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(android_layer)
                    .try_init()
                {
                    Ok(_) => {}
                    Err(e) => eprintln!("Logger initialization failed: {}", e),
                }
            }
        } else if cfg!(target_os = "windows") {
            // Windows
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(stdout_writer.0))
                .with(fmt::layer().with_writer(file_writer.0))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        } else {
            // Linux
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(stdout_writer.0))
                .with(fmt::layer().with_writer(file_writer.0))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        }
    }

    forget(stdout_writer.1);
    forget(file_writer.1);
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
    use tracing::{debug, error, info, trace, warn};

    #[test]
    fn test_logger_functionality() {
        // Initialize logger
        init_logger("cli", "", "", "", &[]);

        // Test MemoryWriter initialization
        let writer = MemoryWriter::new();
        assert!(writer.data.lock().unwrap().logs.is_empty());

        // Test log storage in memory writer
        {
            let logger_guard = LOGGER.lock().unwrap();
            let logger = logger_guard.as_ref().unwrap();

            let log_line = "This is a test log";
            logger.memory_writer.handle_log(log_line).unwrap();

            let locked_data = logger.memory_writer.data.lock().unwrap();
            assert!(locked_data.logs[0].contains("This is a test log"));
        }

        // Test get_new_logs
        info!("New log entry");

        let log_data = get_new_logs();
        assert!(!log_data.is_empty());
        assert!(log_data.contains("New log entry"));

        // Step 6: Test get_all_logs
        info!("First log entry");
        info!("Second log entry");

        let log_data = get_all_logs();
        assert!(log_data.contains("First log entry"));
        assert!(log_data.contains("Second log entry"));

        // Step 7: Test log levels
        info!("This is an info log");
        error!("This is an error log");
        warn!("This is a warn log");
        debug!("This is a debug log");
        trace!("This is a trace log");

        let log_data = get_all_logs();
        assert!(log_data.contains("This is an info log"));
        assert!(log_data.contains("This is an error log"));
        assert!(log_data.contains("This is a warn log"));
        // Note: Depending on the log level set, debug and trace logs may not be captured
    }

    #[test]
    fn test_sanitize_keywords() {
        let test_log = r#"{"id": "12345", "password": "secret"}"#;
        let sanitized_log = sanitize_keywords(test_log, &["id", "password"]);
        assert_eq!(sanitized_log, r#"{"id": "*****", "password": "******"}"#);
    }
}
