#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]
use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgsr::ToBase64;

use crate::wgsrd::Wgsrd;

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
