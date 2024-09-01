#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
use crate::wgxd::Wgxd;

#[allow(dead_code)]
mod wgxd;

#[test]
fn running() {
    let wgxd = Wgxd::new();
    wgxd.wait_until_started();
}

#[test]
fn status() {
    let wgxd = Wgxd::new();
    wgxd.wait_until_started();
    let output = wgxd.wgx(["relay", "status"]).output().unwrap();
    assert_output!(output);
}

#[test]
fn export() {
    let wgxd = Wgxd::new();
    wgxd.wait_until_started();
    let output = wgxd.wgx(["relay", "export"]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.is_empty());
}
