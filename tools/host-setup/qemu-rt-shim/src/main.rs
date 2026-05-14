//! qemu-rt-shim — self-elevate to SCHED_FIFO via this binary's own
//! CAP_SYS_NICE file capability, then execvp the wrapped command.
//!
//! Motivated by Telix #135 host vCPU descheduling: running QEMU under
//! SCHED_FIFO suppresses the multi-second tick gaps that the kernel-side
//! Fix A (RESCUE-MIGRATE) can only mitigate after-the-fact.
//!
//! Build + install:
//!   cargo build --release
//!   sudo setcap 'cap_sys_nice=ep' target/release/qemu-rt-shim
//!
//! Usage (from `tools/run-qemu-x86.sh`):
//!   TELIX_RTPRIO=50 \
//!   TELIX_RT_SHIM=$ROOT/tools/host-setup/qemu-rt-shim/target/release/qemu-rt-shim \
//!     tools/boot-h14.sh
//!
//! When TELIX_RTPRIO is unset, the shim is a no-op exec wrapper (still
//! works, just doesn't bump priority).  Designed so the same wrapper
//! pipeline works whether or not the cap is installed.

use std::env;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::process;

const SCHED_FIFO: libc::c_int = 1;

fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.is_empty() {
        eprintln!("qemu-rt-shim: usage: qemu-rt-shim <program> [args...]");
        eprintln!("  env TELIX_RTPRIO=N (1..99) sets SCHED_FIFO priority before exec");
        process::exit(64);
    }

    // Try to elevate.  Failure is logged but non-fatal — the wrapped
    // command still runs at default scheduling.
    if let Ok(prio_str) = env::var("TELIX_RTPRIO") {
        match prio_str.parse::<libc::c_int>() {
            Ok(prio) if (1..=99).contains(&prio) => {
                let param = libc::sched_param { sched_priority: prio };
                // SAFETY: passing a stack-local sched_param by ref to a
                // kernel syscall that copies it synchronously.  pid=0
                // targets the calling thread.
                let rc = unsafe {
                    libc::sched_setscheduler(0, SCHED_FIFO, &param)
                };
                if rc != 0 {
                    let errno = std::io::Error::last_os_error();
                    eprintln!(
                        "qemu-rt-shim: sched_setscheduler(SCHED_FIFO, {}) failed: {}",
                        prio, errno,
                    );
                    eprintln!(
                        "  Check setcap: getcap {}",
                        env::current_exe()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|_| "<self>".into())
                    );
                    eprintln!("  Install with: sudo setcap 'cap_sys_nice=ep' <this-binary>");
                    eprintln!("  Continuing at default scheduling.");
                } else {
                    eprintln!("qemu-rt-shim: SCHED_FIFO prio={}", prio);
                }
            }
            _ => {
                eprintln!(
                    "qemu-rt-shim: TELIX_RTPRIO={:?} invalid (need 1..99); skipping",
                    prio_str,
                );
            }
        }
    }

    // execvp the wrapped command.  Build a NUL-terminated argv array.
    let prog = CString::new(args[0].as_bytes()).expect("argv[0] contains NUL");
    let cargs: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_bytes()).expect("argv contains NUL"))
        .collect();
    let mut argv: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: argv is NUL-terminated; the CStrings backing it live for
    // the rest of this function (which will not return on success).
    unsafe { libc::execvp(prog.as_ptr(), argv.as_ptr()) };
    // execvp only returns on error.
    let errno = std::io::Error::last_os_error();
    eprintln!(
        "qemu-rt-shim: execvp({:?}) failed: {}",
        args[0], errno,
    );
    process::exit(127);
}
