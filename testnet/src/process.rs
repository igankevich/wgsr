use std::ffi::c_int;
use std::ffi::c_void;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::RawFd;

use mio_pidfd::PidFd;
use nix::errno::Errno;
use nix::poll::poll;
use nix::poll::PollFd;
use nix::poll::PollFlags;
use nix::poll::PollTimeout;
use nix::sched::CloneFlags;
use nix::sys::signal::killpg;
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitStatus;
use nix::unistd::setpgid;
use nix::unistd::Pid;

use crate::log_format;

pub(crate) struct Process {
    id: Pid,
    #[allow(dead_code)]
    stack: Vec<u8>,
}

impl Process {
    #[allow(clippy::uninit_vec)]
    pub(crate) fn spawn<F: FnOnce() -> c_int>(
        child_main: F,
        stack_size: usize,
        flags: CloneFlags,
        inherited_fds: Vec<RawFd>,
    ) -> Result<Self, Errno> {
        let stack_size = stack_size | 16;
        let mut stack = Vec::with_capacity(stack_size);
        // The stack can be large. We don't want to initialize it with zeros to aid kernel
        // in conserving memory (first-touch policy).
        unsafe {
            stack.set_len(stack_size);
        }
        let id = unsafe {
            clone(
                || {
                    close_unused_fds(inherited_fds);
                    child_main()
                },
                &mut stack,
                flags,
                Some(Signal::SIGCHLD as c_int),
            )?
        };
        Ok(Self { id, stack })
    }

    pub(crate) fn kill(&self, signal: Signal) -> Result<(), Errno> {
        killpg(self.id, signal)
    }

    pub(crate) fn wait(&self) -> Result<WaitStatus, Errno> {
        waitpid(self.id, None)
    }

    pub(crate) fn id(&self) -> Pid {
        self.id
    }

    pub(crate) fn fd(&self) -> Result<PidFd, std::io::Error> {
        PidFd::open(self.id.as_raw(), 0)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        match self.kill(Signal::SIGTERM) {
            Ok(_) => {}
            Err(Errno::ESRCH) => return,
            Err(e) => {
                log_format!("failed to kill process group {}: {}", self.id, e);
                return;
            }
        }
        match self.wait() {
            Ok(_) => {}
            Err(Errno::ECHILD) => {}
            Err(e) => log_format!("failed to wait for process {}: {}", self.id, e),
        }
    }
}

// A  clone(2) wrapper that accepts FnOnce instead of FnMut.
unsafe fn clone<F: FnOnce() -> c_int>(
    mut cb: F,
    stack: &mut [u8],
    flags: CloneFlags,
    signal: Option<c_int>,
) -> Result<Pid, Errno> {
    extern "C" fn callback<F: FnOnce() -> c_int>(data: *mut c_void) -> c_int {
        // make all child processes belong to the same process group
        let this = Pid::this();
        if let Err(e) = setpgid(this, this) {
            log_format!("failed to set process group to {}: {}", this, e);
            return 1;
        }
        unsafe {
            let cb: *mut F = std::mem::transmute(data);
            std::ptr::read(cb)()
        }
    }
    let combined = flags.bits() | signal.unwrap_or(0);
    let res = unsafe {
        let ptr = stack.as_mut_ptr().add(stack.len());
        let ptr_aligned = ptr.sub(ptr as usize % 16);
        nix::libc::clone(
            callback::<F>,
            ptr_aligned as *mut c_void,
            combined,
            &mut cb as *mut _ as *mut c_void,
        )
    };
    Errno::result(res).map(Pid::from_raw)
}

fn close_unused_fds(inherited_fds: Vec<RawFd>) {
    let fd_min: RawFd = 3;
    let fd_max: RawFd = 4096;
    let batch_size: RawFd = 1024;
    for fd in (fd_min..fd_max).step_by(batch_size as usize) {
        let fd0 = fd;
        let fd1 = (fd + batch_size).min(fd_max);
        let mut fds: Vec<PollFd> = (fd0..fd1)
            .filter_map(|fd| {
                if !inherited_fds.contains(&fd) {
                    Some(PollFd::new(
                        unsafe { BorrowedFd::borrow_raw(fd) },
                        PollFlags::empty(),
                    ))
                } else {
                    None
                }
            })
            .collect();
        if let Err(e) = poll(&mut fds, PollTimeout::ZERO) {
            log_format!("poll failed: {e}");
            continue;
        }
        for fd in fds.iter() {
            if let Some(revents) = fd.revents() {
                if !revents.contains(PollFlags::POLLNVAL) {
                    if let Err(e) = nix::unistd::close(fd.as_fd().as_raw_fd()) {
                        log_format!("close failed: {e}");
                    }
                }
            }
        }
    }
}
