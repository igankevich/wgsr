use std::path::Path;
use std::process::ExitCode;

use self::config::*;
use self::config_parser::*;
use self::dispatcher::*;
use self::error::*;
use self::network_interface::*;
use self::unix::*;
use self::wg_relay::*;
use crate::Config;
use crate::Error;
use crate::DEFAULT_CONFIGURATION_FILE_PATH;

mod config;
mod config_parser;
mod dispatcher;
mod error;
mod network_interface;
mod unix;
mod wg_relay;

fn usage() -> &'static str {
    "usage:\n  wgxd [config-file]\n  wgxd --version\n  wgxd --help"
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
    let config = Config::load(config_file)?;
    let event_loop = Dispatcher::new(config)?;
    let waker = event_loop.waker()?;
    ctrlc::set_handler(move || {
        let _ = waker.wake();
    })
    .map_err(Error::other)?;
    event_loop.run()?;
    Ok(())
}
