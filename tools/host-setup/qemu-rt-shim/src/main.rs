//! qemu-rt-shim — self-elevate to SCHED_FIFO and (optionally) join a
//! cgroup v2 isolated cpuset, then execvp the wrapped command.
//!
//! Motivated by Telix #135 host vCPU descheduling: running QEMU under
//! SCHED_FIFO suppresses the multi-second tick gaps that the kernel-side
//! Fix A (RESCUE-MIGRATE) can only mitigate after-the-fact.  Pair with
//! a cgroup v2 isolated cpuset partition (see
//! `tools/host-setup/setup-qemu-rt-cgroup.sh`) so SCHED_OTHER tasks
//! don't get starved behind FIFO on the pinned CPUs.
//!
//! File capabilities (apply ONE of):
//!   sudo setcap 'cap_sys_nice=ep' qemu-rt-shim                # FIFO only
//!   sudo setcap 'cap_sys_nice,cap_sys_admin=ep' qemu-rt-shim  # FIFO + cgroup
//!
//! CAP_SYS_ADMIN is needed because cgroup v2's "common ancestor" rule
//! refuses migrations between sibling subtrees (e.g. /user.slice/...
//! → /qemu-rt) when the caller lacks write on the common ancestor
//! (the root cgroup, which is root-owned).  CAP_SYS_ADMIN bypasses
//! that check.  Without it, the cgroup join logs a warning and the
//! shim continues without isolation.
//!
//! Env knobs (read by main(), all optional):
//!   TELIX_RTPRIO=N      — SCHED_FIFO priority (1..99).  Uses CAP_SYS_NICE.
//!   TELIX_RT_CGROUP=DIR — cgroup v2 path; writes own pid to
//!                          $DIR/cgroup.procs.  Uses CAP_SYS_ADMIN.
//!
//! Failure of either step is logged but non-fatal — qemu still runs.

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
        eprintln!("  env TELIX_RT_CGROUP=DIR writes our pid to DIR/cgroup.procs");
        process::exit(64);
    }

    // Diagnostic: dump our own runtime capabilities so failures are
    // explicable.  If CapEff is 0 here despite getcap showing file
    // caps, the kernel didn't apply the file caps (mount nosuid?
    // user namespace?  AppArmor/SELinux stripping?).
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("Cap") {
                eprintln!("qemu-rt-shim: {}", line);
            }
        }
    }

    // Step 1: optionally join an isolated cpuset cgroup.  Done FIRST
    // because moving the process restricts its CPU affinity, and we
    // want the subsequent FIFO scheduling decision to be made within
    // that affinity (the kernel scheduler picks an initial CPU when
    // FIFO is enabled).  CAP_SYS_ADMIN required to bypass the cgroup
    // common-ancestor migration check.
    if let Ok(cgroup_dir) = env::var("TELIX_RT_CGROUP") {
        let procs_path = format!("{}/cgroup.procs", cgroup_dir);
        let pid_str = std::process::id().to_string();
        match std::fs::OpenOptions::new()
            .write(true)
            .open(&procs_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, pid_str.as_bytes()))
        {
            Ok(()) => {
                eprintln!("qemu-rt-shim: joined cgroup {}", cgroup_dir);
            }
            Err(e) => {
                eprintln!(
                    "qemu-rt-shim: cgroup join {} failed: {}",
                    procs_path, e,
                );
                eprintln!(
                    "  setcap cap_sys_admin=ep needed (or cap_sys_nice,cap_sys_admin=ep)"
                );
                eprintln!("  Continuing without cgroup isolation.");
            }
        }
    }

    // Step 2: optionally elevate to SCHED_FIFO.  CAP_SYS_NICE required.
    // Failure is logged but non-fatal — the wrapped command still runs
    // at default scheduling.
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
