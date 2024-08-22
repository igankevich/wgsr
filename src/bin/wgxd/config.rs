use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::File;
use std::io::Write;
use std::num::NonZeroU16;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use wgproto::PrivateKey;
use wgproto::PublicKey;
use wgx::FromBase64;
use wgx::ToBase64;
use wgx::DEFAULT_UNIX_SOCKET_PATH;

use crate::format_error;
use crate::parse_config;
use crate::Error;

pub(crate) const DEFAULT_CONFIGURATION_FILE_PATH: &str = "/etc/wgxd.conf";
pub(crate) const DEFAULT_LISTEN_PORT: u16 = 8787;

pub(crate) struct Config {
    pub(crate) private_key: PrivateKey,
    pub(crate) listen_port: NonZeroU16,
    pub(crate) allowed_public_keys: AllowedPublicKeys,
    pub(crate) unix_socket_path: PathBuf,
}

impl Config {
    pub(crate) fn load(path: &Path) -> Result<Self, Error> {
        match Self::do_open(path) {
            Ok(config) => Ok(config),
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(Default::default())
            }
            Err(e) => Err(format_error!("failed to read `{}`: {}", path.display(), e)),
        }
    }

    fn do_open(path: &Path) -> Result<Self, Error> {
        let mut config: Config = Default::default();
        let mut prev_section: Option<String> = None;
        parse_config(path, |section, key, value, new_section| {
            if new_section && prev_section.as_deref() == section {
                return Err(format_error!("duplicate section `{}`", new_section));
            }
            prev_section = section.map(ToString::to_string);
            match section {
                Some(section @ "Relay") => match key {
                    "PrivateKey" => config.private_key = FromBase64::from_base64(value)?,
                    "ListenPort" => config.listen_port = value.parse().map_err(Error::other)?,
                    "AllowedPublicKeys" => {
                        config.allowed_public_keys = value.parse().map_err(Error::other)?;
                    }
                    "UnixSocketPath" => config.unix_socket_path = value.into(),
                    key => return Err(format_error!("unknown key under `{}`: `{}`", section, key)),
                },
                Some(other) => return Err(format_error!("unknown section: {}", other)),
                None => return Err(format_error!("unknown section")),
            }
            Ok(())
        })?;
        config.validate()?;
        Ok(config)
    }

    #[allow(dead_code)]
    pub(crate) fn save(&self, path: &Path) -> Result<(), Error> {
        self.do_save(path)
            .map_err(|e| format_error!("failed to write `{}`: {}", path.display(), e))
    }

    fn do_save(&self, path: &Path) -> Result<(), Error> {
        self.validate()?;
        let mut file = File::create(path)?;
        write!(&mut file, "{}", self)?;
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        match &self.allowed_public_keys {
            AllowedPublicKeys::Set(public_keys) => {
                let public_key: PublicKey = (&self.private_key).into();
                if public_keys.contains(&public_key) {
                    Err(format_error!(
                        "peer public key is the same as server public key: `{}`",
                        public_key.to_base64()
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            private_key: PrivateKey::random(),
            listen_port: unsafe { NonZeroU16::new_unchecked(DEFAULT_LISTEN_PORT) },
            allowed_public_keys: AllowedPublicKeys::Set(Default::default()),
            unix_socket_path: DEFAULT_UNIX_SOCKET_PATH.into(),
        }
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        writeln!(f, "[Relay]")?;
        writeln!(f, "ListenPort = {}", self.listen_port)?;
        writeln!(f, "PrivateKey = {}", self.private_key.to_base64())?;
        writeln!(f, "AllowedPublicKeys = {}", self.allowed_public_keys)?;
        writeln!(f, "UnixSocketPath = {}", self.unix_socket_path.display())?;
        Ok(())
    }
}

#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub(crate) enum AllowedPublicKeys {
    All,
    Set(HashSet<PublicKey>),
}

impl Default for AllowedPublicKeys {
    fn default() -> Self {
        Self::Set(Default::default())
    }
}

impl Display for AllowedPublicKeys {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Set(public_keys) => {
                let mut iter = public_keys.iter();
                if let Some(public_key) = iter.next() {
                    write!(f, "{}", public_key.to_base64())?;
                }
                for public_key in iter {
                    write!(f, ", {}", public_key.to_base64())?;
                }
                Ok(())
            }
        }
    }
}

impl FromStr for AllowedPublicKeys {
    type Err = Error;
    fn from_str(other: &str) -> Result<Self, Self::Err> {
        if other == "all" {
            return Ok(Self::All);
        }
        let mut public_keys: HashSet<PublicKey> = HashSet::new();
        for item in other.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            public_keys.insert(FromBase64::from_base64(item)?);
        }
        Ok(Self::Set(public_keys))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::fmt::Formatter;

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;
    use tempfile::NamedTempFile;

    use super::*;

    fn test_io<T: FromStr + ToString + PartialEq + Debug + for<'a> Arbitrary<'a>>()
    where
        <T as std::str::FromStr>::Err: Debug,
    {
        arbtest(|u| {
            let expected: T = u.arbitrary()?;
            let string = expected.to_string();
            let actual = string.parse().unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    #[test]
    fn allowed_public_keys_io() {
        test_io::<AllowedPublicKeys>();
    }

    #[test]
    fn save_load() {
        arbtest(|u| {
            let expected: Config = u.arbitrary()?;
            let file = NamedTempFile::new().unwrap();
            expected.save(file.path()).unwrap();
            let actual = Config::load(file.path()).unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    fn arbitrary_path(u: &mut Unstructured<'_>) -> Result<PathBuf, arbitrary::Error> {
        let path: PathBuf = u.arbitrary()?;
        let string = path.as_path().to_string_lossy().to_string();
        let string: String = string.chars().filter(|ch| !"#\n".contains(*ch)).collect();
        Ok(string.trim().into())
    }

    impl<'a> Arbitrary<'a> for Config {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self {
                private_key: u.arbitrary::<[u8; 32]>()?.into(),
                listen_port: u.arbitrary()?,
                allowed_public_keys: u.arbitrary()?,
                unix_socket_path: arbitrary_path(u)?,
            })
        }
    }

    impl Debug for Config {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            f.debug_struct("ServerConfig")
                .field("private_key", &self.private_key.to_base64())
                .field("listen_port", &self.listen_port)
                .field("allowed_public_keys", &self.allowed_public_keys)
                .field("unix_socket_path", &self.unix_socket_path)
                .finish()
        }
    }

    impl PartialEq for Config {
        fn eq(&self, other: &Self) -> bool {
            self.private_key.as_bytes() == other.private_key.as_bytes()
                && self.listen_port == other.listen_port
                && self.allowed_public_keys == other.allowed_public_keys
                && self.unix_socket_path == other.unix_socket_path
        }
    }

    impl Eq for Config {}

    impl<'a> Arbitrary<'a> for AllowedPublicKeys {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            let i: usize = u.int_in_range(0..=1)?;
            Ok(match i {
                0 => AllowedPublicKeys::All,
                _ => AllowedPublicKeys::Set(
                    u.arbitrary::<HashSet<[u8; 32]>>()?
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                ),
            })
        }
    }
}
