#[macro_export]
macro_rules! log_format {
    ($($args:expr),*) => {
        { let _ = ::std::io::Write::write_all(&mut ::std::io::stderr(), format!($($args),*).as_bytes()); }
    };
}

#[macro_export]
macro_rules! format_error {
    ($($args:expr),*) => {
        ::std::io::Error::new(::std::io::ErrorKind::Other, format!($($args),*))
    };
}
