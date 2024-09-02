use std::io::Error;
use std::io::ErrorKind;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;
use std::process::Stdio;

/// A trait that makes `Command` product human-readable errors.
pub(crate) trait CommandHR {
    fn status_hr(&mut self) -> Result<ExitStatus, Error>;
    fn status_silent_hr(&mut self) -> Result<ExitStatus, Error>;
    fn output_hr(&mut self) -> Result<Output, Error>;
}

impl CommandHR for Command {
    fn status_hr(&mut self) -> Result<ExitStatus, Error> {
        let status = self.status().map_err(|e| failed_to_execute(self, e))?;
        check_status(self, status)?;
        Ok(status)
    }

    fn status_silent_hr(&mut self) -> Result<ExitStatus, Error> {
        self.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = self.status().map_err(|e| failed_to_execute(self, e))?;
        Ok(status)
    }

    fn output_hr(&mut self) -> Result<Output, Error> {
        let output = self.output().map_err(|e| failed_to_execute(self, e))?;
        check_output(self, &output)?;
        Ok(output)
    }
}

fn failed_to_execute(command: &Command, e: Error) -> Error {
    let executable = command.get_program().to_string_lossy();
    Error::new(
        ErrorKind::Other,
        format!("failed to execute `{}`: {}", executable, e),
    )
}

fn check_output(command: &Command, output: &Output) -> Result<(), Error> {
    if !output.status.success() {
        let executable = command.get_program().to_string_lossy();
        Err(Error::new(
            ErrorKind::Other,
            format!(
                "`{}` failed: {}: {}",
                executable,
                status_to_string(output.status),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ))
    } else {
        Ok(())
    }
}

fn check_status(command: &Command, status: ExitStatus) -> Result<(), Error> {
    if !status.success() {
        let executable = command.get_program().to_string_lossy();
        Err(Error::new(
            ErrorKind::Other,
            format!("`{}` failed: {}", executable, status_to_string(status)),
        ))
    } else {
        Ok(())
    }
}

fn status_to_string(status: ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exited with status code {}", code),
        None => "terminated by signal".to_string(),
    }
}
