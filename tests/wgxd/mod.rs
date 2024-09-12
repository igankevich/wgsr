#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::net::UdpSocket;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use tempfile::tempdir;
use tempfile::TempDir;
use test_bin::get_test_bin;

pub struct Wgxd {
    #[allow(dead_code)]
    workdir: TempDir,
    unix_socket_path: PathBuf,
    listen_port: u16,
    child: Child,
}

impl Wgxd {
    pub fn new() -> Self {
        Self::with_port(random_port())
    }

    fn with_port(listen_port: NonZeroU16) -> Self {
        use std::fmt::Write;
        let workdir = tempdir().unwrap();
        let config_file = workdir.path().join("wgxd.conf");
        let unix_socket_path = workdir.path().join(".wgxd-socket");
        let mut config = String::new();
        writeln!(
            &mut config,
            "[Relay]\nUnixSocketPath = {}\nListenPort = {}\nAllowedPublicKeys = all\n",
            unix_socket_path.display(),
            listen_port,
        )
        .unwrap();
        writeln!(&mut config, "LogLevel = TRACE").unwrap();
        std::fs::write(config_file.as_path(), config).unwrap();
        let child = get_test_bin("wgxd")
            .args([config_file.as_path()])
            .spawn()
            .unwrap();
        Self {
            workdir,
            unix_socket_path,
            listen_port: listen_port.into(),
            child,
        }
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn wait_until_started(&self) {
        const NUM_SECONDS: usize = 7;
        for i in 1..=NUM_SECONDS {
            let output = self.wgx(["relay", "running"]).output().unwrap();
            if output.status.success() {
                return;
            }
            if i >= 3 {
                eprintln!("waiting for wgxd to start... {}", i);
            }
            sleep(Duration::from_millis(777));
        }
        panic!("wgxd has not stared in {}s", NUM_SECONDS);
    }

    pub fn wgx<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let rest = args;
        let mut args: Vec<OsString> = Vec::new();
        args.extend([
            OsStr::new("-s").into(),
            self.unix_socket_path.as_os_str().into(),
        ]);
        for arg in rest {
            args.push(arg.as_ref().into());
        }
        let mut command = get_test_bin("wgx");
        command.args(args);
        command
    }
}

impl Drop for Wgxd {
    fn drop(&mut self) {
        self.child.kill().unwrap();
    }
}

fn random_port() -> NonZeroU16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .try_into()
        .unwrap()
}

#[macro_export]
macro_rules! assert_success {
    ($output:expr) => {
        let output = $output;
        let stdout = String::from_utf8_lossy(output.stdout.as_slice());
        let stderr = String::from_utf8_lossy(output.stderr.as_slice());
        assert!(
            output.status.success(),
            "Stderr\n----------\n{}----------\n\nStdout\n----------\n{}",
            stderr,
            stdout
        );
        assert!(stdout.is_empty(), "Stdout\n----------\n{}", stdout);
        assert!(stderr.is_empty(), "Stderr\n----------\n{}", stderr);
    };
}

#[macro_export]
macro_rules! assert_failure {
    ($output:expr) => {
        let output = $output;
        let stdout = String::from_utf8_lossy(output.stdout.as_slice());
        let stderr = String::from_utf8_lossy(output.stderr.as_slice());
        assert!(
            !output.status.success(),
            "Stderr\n----------\n{}----------\n\nStdout\n----------\n{}",
            stderr,
            stdout
        );
        assert!(stdout.is_empty(), "Stdout\n----------\n{}", stdout);
        assert!(!stderr.is_empty(), "Stderr\n----------\n{}", stderr);
    };
}

#[macro_export]
macro_rules! assert_output {
    ($output:expr) => {
        let output = $output;
        let stdout = String::from_utf8_lossy(output.stdout.as_slice());
        let stderr = String::from_utf8_lossy(output.stderr.as_slice());
        assert!(
            output.status.success(),
            "Stderr\n----------\n{}----------\n\nStdout\n----------\n{}",
            stderr,
            stdout
        );
        assert!(!stdout.is_empty(), "Stdout\n----------\n{}", stdout);
        assert!(stderr.is_empty(), "Stderr\n----------\n{}", stderr);
    };
}
