#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
use crate::wgsrd::Wgsrd;

#[allow(dead_code)]
mod wgsrd;

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
    assert_output!(output);
}

#[test]
fn export() {
    let wgsrd = Wgsrd::new();
    wgsrd.wait_until_started();
    let output = wgsrd.wgsr(["export"]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.is_empty());
}
