use std::ffi::c_int;
use std::ffi::c_void;

use nix::errno::Errno;
use nix::sched::CloneFlags;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

pub struct Process {
    id: Pid,
    #[allow(dead_code)]
    stack: Vec<u8>,
}

impl Process {
    #[allow(clippy::uninit_vec)]
    pub fn spawn<F: FnOnce() -> c_int>(
        child_main: F,
        stack_size: usize,
        flags: CloneFlags,
    ) -> Result<Self, Errno> {
        let mut stack = Vec::with_capacity(stack_size);
        // The stack can be large. We don't want to initialize it with zeros to aid kernel
        // in conserving memory (first-touch policy).
        unsafe {
            stack.set_len(stack_size);
        }
        let id = unsafe {
            clone(
                child_main,
                &mut stack,
                flags,
                Some(Signal::SIGCHLD as c_int),
            )?
        };
        Ok(Self { id, stack })
    }

    pub fn kill(&self, signal: Signal) -> Result<(), Errno> {
        kill(self.id, signal)
    }

    pub fn wait(&self) -> Result<WaitStatus, Errno> {
        waitpid(self.id, None)
    }

    pub fn id(&self) -> Pid {
        self.id
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Err(e) = self.kill(Signal::SIGTERM) {
            log::error!("failed to kill {}: {}", self.id, e);
            return;
        }
        if let Err(e) = self.wait() {
            log::error!("failed to wait for {}: {}", self.id, e);
        }
    }
}

// A version of the clone that accepts FnOnce instead of FnMut.
unsafe fn clone<F: FnOnce() -> c_int>(
    mut cb: F,
    stack: &mut [u8],
    flags: CloneFlags,
    signal: Option<c_int>,
) -> Result<Pid, Errno> {
    extern "C" fn callback<F: FnOnce() -> c_int>(data: *mut c_void) -> c_int {
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
