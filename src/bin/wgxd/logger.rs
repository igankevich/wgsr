use std::io::stderr;
use std::sync::OnceLock;

use log::set_logger;
use log::set_max_level;
use log::Level;
use log::Log;
use log::Metadata;
use log::Record;
use log::SetLoggerError;

pub struct Logger {
    level: Level,
}

impl Logger {
    pub fn init(level: Level) -> Result<(), SetLoggerError> {
        set_logger(LOGGER.get_or_init(move || Logger { level }))
            .map(|()| set_max_level(level.to_level_filter()))
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut buffer = String::with_capacity(4096);
        {
            use std::fmt::Write;
            let _ = writeln!(&mut buffer, "{}", record.args());
        }
        {
            use std::io::Write;
            let _ = std::io::stderr().write_all(buffer.as_bytes());
        }
    }

    fn flush(&self) {
        use std::io::Write;
        let _ = stderr().flush();
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
