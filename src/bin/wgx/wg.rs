use std::process::Command;
use std::process::Stdio;

use crate::ChildHR;
use crate::CommandHR;
use crate::Error;
use crate::InterfaceConfig;
use crate::PeerConfig;

pub(crate) struct Wg {
    name: String,
}

impl Wg {
    pub(crate) fn new(name: String) -> Self {
        Self { name }
    }

    pub(crate) fn start(
        &self,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<(), Error> {
        self.ip_link_add()?;
        self.ip_link_set_up()?;
        self.ip_address_add(interface)?;
        self.ip_route_add(interface)?;
        self.wg_conf("setconf", interface, peers)?;
        Ok(())
    }

    pub(crate) fn reload(
        &self,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<(), Error> {
        self.ip_address_flush()?;
        self.ip_address_add(interface)?;
        self.ip_route_flush()?;
        self.ip_route_add(interface)?;
        self.wg_conf("syncconf", interface, peers)?;
        Ok(())
    }

    pub(crate) fn stop(&self) -> Result<(), Error> {
        self.ip_link_delete()?;
        Ok(())
    }

    fn ip_link_add(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["link", "add", self.name.as_str(), "type", "wireguard"])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_link_delete(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["link", "delete", self.name.as_str()])
            .status_silent_hr()?;
        Ok(())
    }

    fn ip_link_set_up(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["link", "set", self.name.as_str(), "up"])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_address_add(&self, interface: &InterfaceConfig) -> Result<(), Error> {
        Command::new("ip")
            .args([
                "address",
                "add",
                interface.address.to_string().as_str(),
                "dev",
                self.name.as_str(),
            ])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_address_flush(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["address", "flush", "dev", self.name.as_str()])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_route_add(&self, interface: &InterfaceConfig) -> Result<(), Error> {
        Command::new("ip")
            .args([
                "route",
                "add",
                interface.address.network().to_string().as_str(),
                "dev",
                self.name.as_str(),
            ])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn ip_route_flush(&self) -> Result<(), Error> {
        Command::new("ip")
            .args(["route", "flush", "dev", self.name.as_str()])
            .stdin(Stdio::null())
            .status_hr()?;
        Ok(())
    }

    fn wg_conf(
        &self,
        verb: &str,
        interface: &InterfaceConfig,
        peers: &[PeerConfig],
    ) -> Result<(), Error> {
        let mut command = Command::new("wg");
        command.args([verb, self.name.as_str(), "/dev/stdin"]);
        command.stdin(Stdio::piped());
        let mut child = command.spawn_hr()?;
        if let Some(mut stdin) = child.stdin.take() {
            interface.write_wireguard_config(&mut stdin)?;
            for peer in peers.iter() {
                peer.write_wireguard_config(&mut stdin)?;
            }
        }
        child.wait_hr(&command)?;
        Ok(())
    }
}
