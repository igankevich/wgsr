use std::path::Path;
use std::process::ExitCode;

mod base64;
mod config;
mod config_parser;
mod error;
mod event_loop;

use self::base64::*;
use self::config::*;
use self::config_parser::*;
use self::error::*;
use self::event_loop::*;

fn usage() -> &'static str {
    "usage:\n  wgproxy [config-file]\n  wgproxy --version\n  wgproxy --help"
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("{}", env!("VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help") => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(config_file) => match do_main(config_file.as_ref()) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{}", e);
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

fn do_main(config_file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::open(config_file)?;
    let event_loop = EventLoop::new(config)?;
    let waker = event_loop.waker()?;
    ctrlc::set_handler(move || {
        let _ = waker.wake();
    }).map_err(Error::other)?;
    event_loop.run()?;
    Ok(())
}
