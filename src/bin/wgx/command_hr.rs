use std::io::Error;
use std::io::ErrorKind;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;

/// A trait that makes `Command` product human-readable errors.
pub(crate) trait CommandHR {
    fn status_hr(&mut self) -> Result<ExitStatus, Error>;
    fn status_silent_hr(&mut self) -> Result<ExitStatus, Error>;
    fn spawn_hr(&mut self) -> Result<Child, Error>;
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

    fn spawn_hr(&mut self) -> Result<Child, Error> {
        let child = self.spawn().map_err(|e| failed_to_execute(self, e))?;
        Ok(child)
    }
}

pub(crate) trait ChildHR {
    fn wait_hr(&mut self, command: &Command) -> Result<ExitStatus, Error>;
}

impl ChildHR for Child {
    fn wait_hr(&mut self, command: &Command) -> Result<ExitStatus, Error> {
        let status = self.wait().map_err(|e| failed_to_execute(command, e))?;
        check_status(command, status)?;
        Ok(status)
    }
}

fn failed_to_execute(command: &Command, e: Error) -> Error {
    let args = command_args_to_string(command);
    Error::new(
        ErrorKind::Other,
        format!("failed to execute `{}`: {}", args, e),
    )
}

fn check_status(command: &Command, status: ExitStatus) -> Result<(), Error> {
    if !status.success() {
        let args = command_args_to_string(command);
        Err(Error::new(
            ErrorKind::Other,
            format!("`{}` failed: {}", args, status_to_string(status)),
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

fn command_args_to_string(command: &Command) -> String {
    let mut args = String::with_capacity(4096);
    args.push_str(command.get_program().to_string_lossy().to_string().as_str());
    for arg in command.get_args() {
        args.push(' ');
        args.push_str(arg.to_string_lossy().to_string().as_str());
    }
    args
}
