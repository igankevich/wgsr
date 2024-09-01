use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::path::Path;

use ipnet::IpNet;
use wgproto::PrivateKey;
use wgx::parse_config;
use wgx::FromBase64;
use wgx::ToBase64;

use crate::format_error;
use crate::Error;

pub(crate) const DEFAULT_CONFIGURATION_FILE_PATH: &str = "/etc/wgx/hub.conf";
type FwMark = u32;

pub(crate) struct Config {
    pub(crate) interface: InterfaceConfig,
    pub(crate) interface_name: String,
}

impl Config {
    pub(crate) fn load<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        match Self::do_load(path) {
            Ok(config) => Ok(config),
            Err(e) => Err(format_error!("failed to read `{}`: {}", path.display(), e)),
        }
    }

    fn do_load(path: &Path) -> Result<Self, Error> {
        let mut config: Config = Default::default();
        let mut prev_section: Option<String> = None;
        let result = parse_config(path, |section, key, value, new_section| {
            if new_section && prev_section.as_deref() == section {
                return Err(format_error!("duplicate section `{}`", new_section));
            }
            prev_section = section.map(ToString::to_string);
            match section {
                Some(section @ "Hub") => match key {
                    "InterfaceName" => config.interface_name = value.to_string(),
                    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                },
                Some(section @ "Interface") => match key {
                    "ListenPort" => {
                        config.interface.listen_port = Some(value.parse().map_err(Error::map)?)
                    }
                    "FwMark" => config.interface.fwmark = value.parse().map_err(Error::map)?,
                    "PrivateKey" => {
                        config.interface.private_key =
                            FromBase64::from_base64(value).map_err(Error::map)?
                    }
                    "Address" => config.interface.address = value.parse().map_err(Error::map)?,
                    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                },
                //Some(section @ "Peer") => match key {
                //    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                //},
                Some(other) => return Err(format_error!("unknown section: {}", other)),
                None => return Err(format_error!("unknown section")),
            }
            Ok(())
        });
        match result {
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
            Err(e) => return Err(e.into()),
            _ => {}
        }
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let path = path.as_ref();
        self.do_save(path)
            .map_err(|e| format_error!("failed to write `{}`: {}", path.display(), e))
    }

    fn do_save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            create_dir_all(dir)?;
        }
        let mut file = File::create(path)?;
        write!(&mut file, "{}", self)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface_name: "wgx".into(),
            interface: InterfaceConfig {
                private_key: PrivateKey::random(),
                address: default_interface_address(),
                fwmark: 0,
                listen_port: None,
            },
        }
    }
}

#[allow(clippy::unwrap_used)]
fn default_interface_address() -> IpNet {
    IpNet::new(Ipv4Addr::new(10, 120, 0, 1).into(), 16).unwrap()
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "{}", self.interface)?;
        writeln!(f, "InterfaceName = {}", self.interface_name)?;
        Ok(())
    }
}

pub(crate) struct InterfaceConfig {
    pub(crate) private_key: PrivateKey,
    pub(crate) address: IpNet,
    pub(crate) fwmark: FwMark,
    pub(crate) listen_port: Option<NonZeroU16>,
}

impl InterfaceConfig {
    pub(crate) fn write_wireguard_config(&self, out: &mut impl Write) -> Result<(), Error> {
        writeln!(out, "[Interface]")?;
        writeln!(out, "PrivateKey = {}", self.private_key.to_base64())?;
        if let Some(listen_port) = self.listen_port {
            writeln!(out, "ListenPort = {}", listen_port)?;
        }
        if self.fwmark != 0 {
            writeln!(out, "FwMark = {}", self.fwmark)?;
        }
        Ok(())
    }
}

impl Display for InterfaceConfig {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "[Interface]")?;
        writeln!(f, "PrivateKey = {}", self.private_key.to_base64())?;
        if let Some(listen_port) = self.listen_port {
            writeln!(f, "ListenPort = {}", listen_port)?;
        }
        writeln!(f, "Address = {}", self.address)?;
        if self.fwmark != 0 {
            writeln!(f, "FwMark = {}", self.fwmark)?;
        }
        Ok(())
    }
}
