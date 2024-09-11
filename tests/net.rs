#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use std::ffi::OsStr;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use rand_core::OsRng;
use rand_core::RngCore;
use tempfile::tempdir;
use test_bin::get_test_bin;
use testnet::testnet;
use testnet::Context;
use testnet::NetConfig;
use testnet::NodeConfig;

use crate::logger::Logger;
use crate::wgxd::Wgxd;

mod logger;
#[allow(dead_code)]
mod wgxd;

#[test]
fn run_testnet() {
    let _ = Logger::init(log::Level::Info);
    let workdir = tempdir().unwrap();
    let random_bytes: Vec<u8> = generate_random_bytes();
    std::fs::write(workdir.path().join("random-file"), random_bytes).unwrap();
    let config = NetConfig {
        callback: |context| match context.current_node_name() {
            "relay" => relay_main(context),
            "hub" => hub_main(context, workdir.path()),
            "spoke" => spoke_main(context, workdir.path()),
            name => Err(format!("invalid node name: {name}").into()),
        },
        nodes: vec![
            NodeConfig {
                name: "relay".into(),
                ..Default::default()
            },
            NodeConfig {
                name: "hub".into(),
                ..Default::default()
            },
            NodeConfig {
                name: "spoke".into(),
                ..Default::default()
            },
        ],
    };
    testnet(config).unwrap();
}

fn relay_main(mut context: Context) -> Result<(), Box<dyn std::error::Error>> {
    let i = context.current_node_index();
    let wgxd = Wgxd::new();
    wgxd.wait_until_started();
    let config = &context.nodes()[i];
    let relay_socket_addr = SocketAddr::new(config.ifaddr.addr(), wgxd.listen_port());
    context.step("start relay");
    context.send(relay_socket_addr.to_string().into())?;
    context.wait()?;
    context.wait()?;
    Ok(())
}

fn hub_main(mut context: Context, workdir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let relay_socket_addr = context.receive()?;
    let relay_socket_addr = String::from_utf8(relay_socket_addr)?;
    let relay_socket_addr: SocketAddr = relay_socket_addr.parse()?;
    context.step("start hub");
    let config_file = workdir.join("hub.conf");
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("init"),
            OsStr::new(relay_socket_addr.to_string().as_str())
        ])
        .status()
        .unwrap()
        .success());
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("start"),
        ])
        .status()
        .unwrap()
        .success());
    let output = get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("add-spoke"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    std::fs::write(workdir.join("spoke.conf"), output.stdout).unwrap();
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("reload"),
        ])
        .status()
        .unwrap()
        .success());
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("hub"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("sync"),
        ])
        .status()
        .unwrap()
        .success());
    //Command::new("ip").args(["address"]).status().unwrap();
    //Command::new("wg").args(["show", "wgx"]).status().unwrap();
    Command::new("python3")
        .args(["-m", "http.server"])
        .current_dir(workdir)
        .spawn()
        .unwrap();
    wait_until_started(
        "python http server",
        Command::new("curl").args([
            "--fail",
            "--silent",
            "--head",
            "http://127.0.0.1:8000/random-file",
        ]),
    )?;
    context.send("hub started".into())?;
    context.wait()?;
    Ok(())
}

fn spoke_main(mut context: Context, workdir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let relay_socket_addr = context.receive()?;
    let relay_socket_addr = String::from_utf8(relay_socket_addr)?;
    let relay_socket_addr: SocketAddr = relay_socket_addr.parse()?;
    context.wait()?;
    context.step("start spoke");
    let config_file = workdir.join("spoke.conf");
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("spoke"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("init"),
            OsStr::new(relay_socket_addr.to_string().as_str())
        ])
        .status()
        .unwrap()
        .success());
    assert!(get_test_bin("wgx")
        .args([
            OsStr::new("spoke"),
            OsStr::new("-c"),
            config_file.as_os_str(),
            OsStr::new("start"),
        ])
        .status()
        .unwrap()
        .success());
    let hub_inner_ipaddr = "10.120.0.1";
    assert!(Command::new("curl")
        .args([
            OsStr::new("--fail"),
            OsStr::new("--silent"),
            OsStr::new("--retry"),
            OsStr::new("3"),
            OsStr::new("--connect-timeout"),
            OsStr::new("7"),
            OsStr::new("--output"),
            workdir.join("downloaded-random-file").as_os_str(),
            OsStr::new(format!("http://{}:8000/random-file", hub_inner_ipaddr).as_str()),
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        std::fs::read(workdir.join("downloaded-random-file")).unwrap(),
        std::fs::read(workdir.join("random-file")).unwrap(),
    );
    context.send("spoke exited".into())?;
    Ok(())
}

fn generate_random_bytes() -> Vec<u8> {
    let mut bytes = vec![0_u8; 4096];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn wait_until_started(name: &str, command: &mut Command) -> Result<(), std::io::Error> {
    const NUM_SECONDS: usize = 7;
    for i in 1..=NUM_SECONDS {
        let output = command.output()?;
        if output.status.success() {
            return Ok(());
        }
        if i >= 3 {
            eprintln!("waiting for {name} to start... {i}");
        }
        sleep(Duration::from_millis(777));
    }
    Err(std::io::Error::other(format!(
        "{name} has not stared in {NUM_SECONDS}s"
    )))
}
