#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use tempfile::tempdir;
use tempfile::TempDir;
use test_bin::get_test_bin;

pub struct Wgsrd {
    #[allow(dead_code)]
    workdir: TempDir,
    unix_socket_path: PathBuf,
    child: Child,
}

impl Wgsrd {
    pub fn new() -> Self {
        use std::fmt::Write;
        let workdir = tempdir().unwrap();
        let config_file = workdir.path().join("wgsrd.conf");
        let unix_socket_path = workdir.path().join(".wgsrd-socket");
        let mut config = String::new();
        writeln!(
            &mut config,
            "[Unix]\nUnixSocketPath = {}",
            unix_socket_path.display()
        )
        .unwrap();
        std::fs::write(config_file.as_path(), config).unwrap();
        let child = get_test_bin("wgsrd")
            .args([config_file.as_path()])
            .spawn()
            .unwrap();
        Self {
            workdir,
            unix_socket_path,
            child,
        }
    }

    pub fn wait_until_started(&self) {
        const NUM_SECONDS: usize = 7;
        for i in 1..=NUM_SECONDS {
            let output = self.wgsr(["running"]).output().unwrap();
            if output.status.success() {
                return;
            }
            if i >= 3 {
                eprintln!("waiting for wgsrd to start... {}", i);
            }
            sleep(Duration::from_millis(777));
        }
        panic!("wgsrd has not stared in {}s", NUM_SECONDS);
    }

    pub fn wgsr<I, S>(&self, args: I) -> Command
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
        let mut command = get_test_bin("wgsr");
        command.args(args);
        command
    }
}

impl Drop for Wgsrd {
    fn drop(&mut self) {
        self.child.kill().unwrap();
    }
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
