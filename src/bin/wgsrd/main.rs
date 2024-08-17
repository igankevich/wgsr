use std::path::Path;
use std::process::ExitCode;

use wgsr::Error;

mod config;
mod config_parser;
mod event_loop;

use self::config::*;
use self::config_parser::*;
use self::event_loop::*;

fn usage() -> &'static str {
    "usage:\n  wgsr [config-file]\n  wgsr --version\n  wgsr --help"
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
    unsafe {
        libc::umask(0o077);
    }
    let config = Config::open(config_file)?;
    let event_loop = EventLoop::new(config)?;
    let waker = event_loop.waker()?;
    ctrlc::set_handler(move || {
        let _ = waker.wake();
    })
    .map_err(Error::other)?;
    event_loop.run()?;
    Ok(())
}
