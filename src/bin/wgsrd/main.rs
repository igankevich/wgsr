use std::path::Path;
use std::process::ExitCode;

use self::config::*;
use self::config_parser::*;
use self::error::*;
use self::event_loop::*;
use self::network_interface::*;
use crate::Config;
use crate::Error;
use crate::DEFAULT_CONFIGURATION_FILE_PATH;

mod config;
mod config_parser;
mod error;
mod event_loop;
mod network_interface;

fn usage() -> &'static str {
    "usage:\n  wgsrd [config-file]\n  wgsrd --version\n  wgsrd --help"
}

fn main() -> ExitCode {
    let config_file = match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("{}", env!("VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help") => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Some(config_file) => Path::new(config_file).to_path_buf(),
        None => Path::new(DEFAULT_CONFIGURATION_FILE_PATH).to_path_buf(),
    };
    match do_main(config_file.as_ref()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}

fn do_main(config_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        libc::umask(0o077);
    }
    let config = Config::open(config_file)?;
    let event_loop = EventLoop::new(config, config_file.to_path_buf())?;
    let waker = event_loop.waker()?;
    ctrlc::set_handler(move || {
        let _ = waker.wake();
    })
    .map_err(Error::other)?;
    event_loop.run()?;
    Ok(())
}
