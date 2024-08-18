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
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgsr::ToBase64;

#[test]
fn running() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
}

#[test]
fn status() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["status"]).output().unwrap();
    assert_success!(output);
}

#[test]
fn relay_add_remove_port() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["relay", "add", "20000"]).output().unwrap();
    assert_success!(output);
    let output = wgsrd.wgsr(["status"]).output().unwrap();
    assert_output!(output);
    let output = wgsrd.wgsr(["relay", "rm", "20000"]).output().unwrap();
    assert_success!(output);
    let output = wgsrd.wgsr(["relay", "rm", "20000"]).output().unwrap();
    assert_failure!(output);
    let output = wgsrd.wgsr(["status"]).output().unwrap();
    assert_success!(output);
}

#[test]
fn relay_add_remove_random_port() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["relay", "add"]).output().unwrap();
    let port = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
    let port = port.trim();
    assert_output!(output);
    let output = wgsrd.wgsr(["status"]).output().unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let output = wgsrd.wgsr(["relay", "rm", port]).output().unwrap();
    assert_success!(output);
    let output = wgsrd.wgsr(["relay", "rm", port]).output().unwrap();
    assert_failure!(output);
    let output = wgsrd.wgsr(["status"]).output().unwrap();
    assert_success!(output);
}

#[test]
fn hub_add_remove() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["hub", "add"]).output().unwrap();
    assert_failure!(output);
    let output = wgsrd.wgsr(["relay", "add"]).output().unwrap();
    let port = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
    let port = port.trim();
    assert_output!(output);
    let private_key = PrivateKey::random();
    let public_key: PublicKey = (&private_key).into();
    let public_key = public_key.to_base64();
    let public_key = public_key.as_str();
    let output = wgsrd
        .wgsr(["hub", "add", port, public_key])
        .output()
        .unwrap();
    assert_success!(output);
    let output = wgsrd
        .wgsr(["hub", "add", port, public_key])
        .output()
        .unwrap();
    assert_failure!(output);
    let output = wgsrd
        .wgsr(["hub", "rm", port, public_key])
        .output()
        .unwrap();
    assert_success!(output);
    let output = wgsrd
        .wgsr(["hub", "rm", port, public_key])
        .output()
        .unwrap();
    assert_failure!(output);
}

#[test]
fn spoke_add_remove() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["spoke", "add"]).output().unwrap();
    assert_failure!(output);
    let output = wgsrd.wgsr(["relay", "add"]).output().unwrap();
    let port = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
    let port = port.trim();
    assert_output!(output);
    let private_key = PrivateKey::random();
    let public_key: PublicKey = (&private_key).into();
    let public_key = public_key.to_base64();
    let public_key = public_key.as_str();
    let output = wgsrd
        .wgsr(["spoke", "add", port, public_key])
        .output()
        .unwrap();
    assert_success!(output);
    let output = wgsrd
        .wgsr(["spoke", "add", port, public_key])
        .output()
        .unwrap();
    assert_failure!(output);
    let output = wgsrd
        .wgsr(["spoke", "rm", port, public_key])
        .output()
        .unwrap();
    assert_success!(output);
    let output = wgsrd
        .wgsr(["spoke", "rm", port, public_key])
        .output()
        .unwrap();
    assert_failure!(output);
}

#[test]
fn export() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["export", "12345"]).output().unwrap();
    assert_failure!(output);
    let output = wgsrd.wgsr(["relay", "add"]).output().unwrap();
    let port = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
    let port = port.trim();
    assert_output!(output);
    let output = wgsrd.wgsr(["export", port]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.is_empty());
}

struct Wgsrd {
    #[allow(dead_code)]
    workdir: TempDir,
    unix_socket_path: PathBuf,
    child: Child,
}

impl Wgsrd {
    fn new() -> Self {
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

    fn wait_until_started(&self) {
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

    fn wgsr<I, S>(&self, args: I) -> Command
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
