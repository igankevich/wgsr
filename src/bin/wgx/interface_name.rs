use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use libc::IFNAMSIZ;

#[derive(PartialEq, Eq, Debug, Hash, Clone)]
pub(crate) struct InterfaceName(pub(crate) String);

impl FromStr for InterfaceName {
    type Err = InterfaceNameError;
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        validate_name(name)?;
        Ok(Self(name.to_string()))
    }
}

impl Display for InterfaceName {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn validate_name(name: &str) -> Result<(), InterfaceNameError> {
    if !name.is_empty()
        && name.len() < IFNAMSIZ
        && !name.contains(['/', '\0'])
        && !name.contains(char::is_whitespace)
    {
        Ok(())
    } else {
        Err(InterfaceNameError)
    }
}

#[derive(Debug)]
pub struct InterfaceNameError;

impl Display for InterfaceNameError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "interface name i/o error")
    }
}

impl std::error::Error for InterfaceNameError {}

#[cfg(test)]
mod tests {

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use arbtest::arbtest;

    use super::*;

    #[test]
    fn interface_name_io() {
        arbtest(|u| {
            let expected: InterfaceName = u.arbitrary()?;
            let string = expected.to_string();
            let actual: InterfaceName = string.parse().unwrap();
            assert_eq!(expected, actual);
            Ok(())
        });
    }

    impl<'a> Arbitrary<'a> for InterfaceName {
        fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
            Ok(Self(arbitrary_interface_name(u)?))
        }
    }

    fn arbitrary_interface_name(u: &mut Unstructured<'_>) -> Result<String, arbitrary::Error> {
        let len = u.int_in_range(1..=(IFNAMSIZ - 1))?;
        let mut name = String::with_capacity(len);
        while name.len() < len {
            let ch: char = u.arbitrary()?;
            if ch != '/' && !char::is_whitespace(ch) && ch != '\0' {
                name.push(ch);
            }
        }
        while name.len() >= IFNAMSIZ {
            name.pop();
        }
        Ok(name)
    }
}
