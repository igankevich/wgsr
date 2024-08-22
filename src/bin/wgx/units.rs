use std::fmt::Display;
use std::fmt::Formatter;
use std::time::Duration;

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
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "PiB", "EiB", "ZiB"];
    let mut i = 0;
    let mut scale = 1;
    let mut n = bytes;
    while n >= 1024 {
        scale *= 1024;
        n /= 1024;
        i += 1;
    }
    let mut b = bytes % scale;
    if b != 0 {
        // compute the first digit of the fractional part
        b = b * 10_u64 / scale;
    }
    FormatBytes {
        unit: UNITS[i],
        integer: n as u16,
        fraction: b as u8,
    }
}

pub(crate) struct FormatDuration {
    unit: &'static str,
    integer: u64,
    fraction: u8, // max. value 9
}

impl Display for FormatDuration {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.integer)?;
        if self.fraction != 0 {
            write!(f, ".{}", self.fraction)?;
        }
        write!(f, " {}", self.unit)
    }
}

pub(crate) fn format_duration(duration: Duration) -> FormatDuration {
    let seconds = duration.as_secs();
    let nanoseconds = duration.subsec_nanos();
    if seconds == 0 && nanoseconds == 0 {
        FormatDuration {
            unit: "s",
            integer: 0,
            fraction: 0,
        }
    } else if seconds == 0 {
        const UNITS: [&str; 4] = ["ns", "μs", "ms", "s"];
        let mut i = 0;
        let mut scale = 1;
        let mut n = nanoseconds;
        while n >= 1000 {
            scale *= 1000;
            n /= 1000;
            i += 1;
        }
        let mut b = nanoseconds % scale;
        if b != 0 {
            // compute the first digit of the fractional part
            b = b * 10_u32 / scale;
        }
        FormatDuration {
            unit: UNITS[i],
            integer: n as u64,
            fraction: b as u8,
        }
    } else {
        const UNITS: [(u64, &str); 4] = [(1, "s"), (60, "m"), (60, "h"), (24, "d")];
        let mut i = 0;
        let mut scale = UNITS[0].0;
        let mut n = seconds;
        while i + 1 != UNITS.len() && n >= UNITS[i + 1].0 {
            scale *= UNITS[i + 1].0;
            n /= UNITS[i + 1].0;
            i += 1;
        }
        let mut b = seconds % scale;
        if b != 0 {
            // compute the first digit of the fractional part
            b = b * 10_u64 / scale;
        }
        FormatDuration {
            unit: UNITS[i].1,
            integer: n,
            fraction: b as u8,
        }
    }
}

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

    #[test]
    fn test_format_duration() {
        assert_eq!("0 s", format_duration(Duration::from_secs(0)).to_string());
        assert_eq!("1 ns", format_duration(Duration::from_nanos(1)).to_string());
        assert_eq!(
            "1 μs",
            format_duration(Duration::from_nanos(1000)).to_string()
        );
        assert_eq!(
            "1 ms",
            format_duration(Duration::from_nanos(1000 * 1000)).to_string()
        );
        assert_eq!(
            "1.5 ms",
            format_duration(Duration::from_nanos(1000 * 1000 + 1000 * 1000 / 2)).to_string()
        );
        assert_eq!(
            "500 μs",
            format_duration(Duration::from_nanos(1000 * 1000 / 2)).to_string()
        );
        assert_eq!(
            "999 ms",
            format_duration(Duration::from_nanos(1000 * 1000 * 999)).to_string()
        );
        assert_eq!("1 s", format_duration(Duration::from_secs(1)).to_string());
        assert_eq!("1 m", format_duration(Duration::from_secs(60)).to_string());
        assert_eq!(
            "1 h",
            format_duration(Duration::from_secs(60 * 60)).to_string()
        );
        assert_eq!(
            "1 d",
            format_duration(Duration::from_secs(60 * 60 * 24)).to_string()
        );
        assert_eq!(
            "12 h",
            format_duration(Duration::from_secs(60 * 60 * 12)).to_string()
        );
        assert_eq!(
            "12.5 h",
            format_duration(Duration::from_secs(60 * 60 * 12 + 60 * 60 / 2)).to_string()
        );
        assert_eq!(
            "12.5 h",
            format_duration(Duration::new(
                60 * 60 * 12 + 60 * 60 / 2,
                1000 * 1000 * 1000 - 1
            ))
            .to_string()
        );
    }
}
