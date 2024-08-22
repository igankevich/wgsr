use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use crate::format_error;
use crate::Error;

pub(crate) fn parse_config<F: FnMut(Option<&str>, &str, &str, bool) -> Result<(), Error>>(
    path: &Path,
    mut on_key_value: F,
) -> Result<(), Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut current_section: Option<String> = None;
    let mut new_section = false;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let line = match line.find('#') {
            Some(i) => &line[..i],
            None => &line[..],
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..(line.len() - 1)];
            current_section = Some(section.to_string());
            new_section = true;
        } else {
            let j = match line.find('=') {
                Some(j) => j,
                None => {
                    return Err(format_error!(
                        "{}:{}: invalid line: `{}`",
                        path.display(),
                        i + 1,
                        line
                    ))
                }
            };
            let key = line[..j].trim();
            let value = line[(j + 1)..].trim();
            if key.is_empty() {
                return Err(format_error!(
                    "{}:{}: empty key: `{}`",
                    path.display(),
                    i + 1,
                    line
                ));
            }
            on_key_value(current_section.as_deref(), key, value, new_section)
                .map_err(|e| format_error!("{}:{}: {}", path.display(), i + 1, e))?;
            new_section = false;
        }
    }
    Ok(())
}
