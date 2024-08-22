use std::fmt::Display;
use std::fmt::Formatter;

pub(crate) struct FormatBytes {
    unit: &'static str,
    integer: u16, // max. value 1023
    fraction: u8, // max. value 9
}

impl Display for FormatBytes {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.integer)?;
        if self.fraction != 0 {
            write!(f, ".{}", self.fraction)?;
        }
        write!(f, " {}", self.unit)
    }
}

pub(crate) fn format_bytes(bytes: u64) -> FormatBytes {
    let mut i = 0;
    let mut scale = 1;
    let mut n = bytes;
    while n >= 1024 {
        scale *= 1024;
        n /= 1024;
        i += 1;
    }
    let a = n;
    let mut b = bytes % scale;
    if b != 0 {
        // compute the first digit of the fractional part
        b = b * 10_u64 / scale;
    }
    FormatBytes {
        unit: UNITS[i],
        integer: a as u16,
        fraction: b as u8,
    }
}

const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "PiB", "EiB", "ZiB"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!("0 B", format_bytes(0).to_string());
        assert_eq!("1 B", format_bytes(1).to_string());
        assert_eq!("512 B", format_bytes(512).to_string());
        assert_eq!("1 KiB", format_bytes(1024).to_string());
        assert_eq!("512 KiB", format_bytes(512 * 1024).to_string());
        assert_eq!("1023 B", format_bytes(1023).to_string());
        assert_eq!("1023 KiB", format_bytes(1023 * 1024).to_string());
        assert_eq!("1 MiB", format_bytes(1024 * 1024).to_string());
        assert_eq!("1 GiB", format_bytes(1024 * 1024 * 1024).to_string());
        assert_eq!("1023 MiB", format_bytes(1024 * 1024 * 1023).to_string());
        assert_eq!(
            "3.5 GiB",
            format_bytes(1024_u64 * 1024 * 1024 * 3 + 1024_u64 * 1024 * 1024 / 2).to_string()
        );
        assert_eq!("3.9 GiB", format_bytes(u32::MAX as u64).to_string());
        assert_eq!("15.9 ZiB", format_bytes(u64::MAX).to_string());
    }
}
