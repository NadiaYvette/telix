# Host scheduling setup for QEMU boots

The Telix kernel exposes the chronic `#135` boot variability as host vCPU
descheduling (see kernel commits `4c6469f` … `ee18c5f`).  When the host
Linux scheduler deschedules a QEMU vCPU thread for hundreds of ms or
seconds — e.g. because Discord, the IDE, browsers, and one or two
Claude Code sessions are all competing for CPU — the guest sees that
vCPU stop taking interrupts entirely.  Threads in that vCPU's run-queue
get orphaned in the (Ready ∧ on_cpu=PENDING) transient until the kernel
rescue can migrate them, and that 16-second timeout dominates boot
wallclock.

`tools/run-qemu-x86.sh` now supports two env knobs that ask the host
scheduler to be kinder to QEMU:

| Var               | Default | Effect                                                       |
|-------------------|---------|--------------------------------------------------------------|
| `TELIX_PIN_CPUS`  | `0-3`   | `taskset -c $TELIX_PIN_CPUS qemu …`.  Free, no caps needed.  |
| `TELIX_RTPRIO`    | unset   | Self-elevate to SCHED_FIFO prio N.  Path depends on caps:    |
|                   |         | • `TELIX_RT_SHIM=<path>` set → use shim (preferred).         |
|                   |         | • else: `chrt -f $TELIX_RTPRIO qemu …` (needs caller rtprio).|
| `TELIX_RT_SHIM`   | unset   | Path to a setcap'd `qemu-rt-shim` binary; bypasses caller's  |
|                   |         | rtprio rlimit by self-elevating via its own CAP_SYS_NICE.    |
| `TELIX_RT_CGROUP` | unset   | Path to an isolated cgroup v2 cpuset (created by             |
|                   |         | `setup-qemu-rt-cgroup.sh`).  Wrapper writes its own pid to   |
|                   |         | `$TELIX_RT_CGROUP/cgroup.procs` before exec; qemu inherits.  |
|                   |         | Keeps SCHED_OTHER tasks off the pinned CPUs.                 |
| `TELIX_MLOCK`     | unset   | Adds `-overcommit mem-lock=on` to qemu args.  Uses qemu's    |
|                   |         | own CAP_SYS_NICE file cap to mlockall its memory image —     |
|                   |         | reduces paging-out under host pressure.  Complementary to    |
|                   |         | (not a replacement for) SCHED_FIFO.                          |
| `TELIX_NICE_OFF`  | unset   | Skip pinning + RT wrappers entirely (legacy behaviour).      |

Pinning alone usually helps and costs nothing.  For the dramatic wins
(suppressing the 10–80 second tick gaps observed under heavy host
load) `TELIX_RTPRIO=50` is the lever, and getting `chrt -f` to work
without `sudo qemu` is what this doc covers.

## Option 1 — rtprio limit (simplest, recommended)

PAM consults `/etc/security/limits.conf` at login and applies the
`rtprio` line as a per-user soft cap on `RLIMIT_RTPRIO`.  Once that's
raised above zero, `chrt -f` works for that user with no caps fiddling
or polkit auth needed.

```ini
# /etc/security/limits.conf
nyc       -       rtprio       99
```

Apply it once with sudo, then **log out and log back in** for PAM to
re-read limits.  Verify with `ulimit -r` (should print `99` or whatever
you set).  After that:

```bash
TELIX_RTPRIO=50 tools/boot-h14.sh
```

Drawbacks: any process the user runs can request SCHED_FIFO; a runaway
RT loop will pin a core (Ctrl+Alt+F2 + reboot territory).  Acceptable
on a developer workstation.

## Option 2 — polkit rule for `systemd-run --scope`

If you don't want a blanket rtprio cap, polkit can authorise the user
to create transient scope units with FIFO scheduling.  Then
`systemd-run --scope -p CPUSchedulingPolicy=fifo qemu …` works without
a password prompt for that user.

Drop this file in place (needs sudo):

```javascript
// /etc/polkit-1/rules.d/50-telix-qemu-rt.rules
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units"
        && subject.user == "nyc"
        && action.lookup("verb") == "start"
        && action.lookup("unit").indexOf("run-r") == 0) {
        return polkit.Result.YES;
    }
});
```

The `run-r*` prefix matches systemd-run's auto-generated transient
unit names so this rule applies only to those, not to user-installed
service units.

Reload polkit with `systemctl reload polkit` and then:

```bash
systemd-run --scope --uid="$USER" \
    -p CPUSchedulingPolicy=fifo -p CPUSchedulingPriority=50 \
    -p AllowedCPUs=0-3 \
    tools/boot-h14.sh
```

Drawbacks: heavier per-launch overhead than `chrt`; `boot-h14.sh`
doesn't natively wrap with systemd-run, so this is a manual prefix
for now.  If we use this often we can add a `TELIX_RT_SYSTEMD=1` knob
to `run-qemu-x86.sh`.

## Option 3 — file capability on `qemu-system-x86_64` (per-binary)

```bash
sudo setcap 'cap_sys_nice=ep' /usr/bin/qemu-system-x86_64
```

Note: this cap belongs to qemu *after* it execs — it does NOT let an
outer `chrt -f $PRIO qemu` call work (chrt itself needs the cap to set
FIFO before exec'ing qemu, and chrt has no cap of its own).  The qemu
binary cap is still useful: with `TELIX_MLOCK=1`, qemu uses it to
mlockall its memory image and resist host swap-out pressure.

Caveat: `dnf upgrade qemu-system-x86_64` replaces the binary inode and
drops the cap.  Re-`setcap` after upgrades, or install a one-line
`/etc/tmpfiles.d/telix-qemu-cap.conf`:
```
e /usr/bin/qemu-system-x86_64 - - - - cap_sys_nice=ep
```
…to have systemd-tmpfiles re-apply on boot.

## Option 4 — setcap'd `qemu-rt-shim` (recommended for screen / nested shells)

`tools/host-setup/qemu-rt-shim/` is a small Rust binary that
self-elevates to SCHED_FIFO using its own CAP_SYS_NICE file capability,
then `execvp`s the wrapped command.  Unlike Options 1-2, it doesn't
depend on the calling shell having any rtprio rlimit or polkit grant.
Particularly useful when your boots are launched from inside a long-
running `screen` session that pre-dates `/etc/security/limits.conf`
changes (the screen daemon already inherited the old zero-rtprio
limit, and reloading PAM doesn't reach existing processes).

```bash
cd tools/host-setup/qemu-rt-shim
./build-and-install.sh            # builds + sudo setcap
export TELIX_RT_SHIM="$(pwd)/target/x86_64-unknown-linux-gnu/release/qemu-rt-shim"
TELIX_RTPRIO=50 tools/boot-h14.sh
```

The shim is ~70 lines and lives in the repo, so `dnf` won't ever
unsetcap it.  Caveat: rebuild + re-setcap when you change toolchains
or the binary content, since the cap is on the inode.

## Option 5 — isolated cgroup v2 cpuset partition (pairs with FIFO)

SCHED_FIFO on its own has a known caveat: ordinary SCHED_OTHER tasks
scheduled onto the same CPUs as the FIFO qemu vCPUs get starved
indefinitely (FIFO runs to block).  The fix is to tell the kernel's
load balancer **not to** schedule other tasks onto those CPUs at all.

cgroup v2 `cpuset.cpus.partition=isolated` does exactly that: CPUs
in an isolated partition are excluded from load balancing, and only
tasks explicitly placed there (via `cgroup.procs`) or affined to
those CPUs (via `sched_setaffinity` / `taskset`) will run there.

Setup (one sudo per boot, since the cgroup vanishes at reboot):

```bash
sudo tools/host-setup/setup-qemu-rt-cgroup.sh             # CPUs 0-3
# or with a custom CPU list:
# sudo tools/host-setup/setup-qemu-rt-cgroup.sh 0-3,6-7
```

The script enables the cpuset controller, creates `/sys/fs/cgroup/qemu-rt`,
sets its `cpuset.cpus` and `cpuset.cpus.partition=isolated`, then
`chown`s `cgroup.procs` to you so the wrapper can write to it without
sudo.

Then in your shell:

```bash
export TELIX_RT_CGROUP=/sys/fs/cgroup/qemu-rt
TELIX_RTPRIO=50 TELIX_MLOCK=1 tools/boot-h14.sh
```

The full pipeline composes nicely:
* `taskset -c 0-3` pins qemu to the isolated CPUs.
* `cpuset.cpus.partition=isolated` keeps other tasks away from 0-3.
* `qemu-rt-shim` (via TELIX_RT_SHIM) elevates qemu to SCHED_FIFO.
* `-overcommit mem-lock=on` (via TELIX_MLOCK) locks qemu memory
  against host swap pressure.

Verify after launching with `cat /sys/fs/cgroup/qemu-rt/cgroup.procs`
— the qemu pid should appear.  `htop` or `top -1` then shows CPUs 0-3
dedicated to qemu's vCPU threads, with system tasks crowded onto the
remaining CPUs.

## Verifying it worked

After launching a boot, check `/tmp/h14/<id>.log` for the launch
prefix line:

```
  [run-qemu] launch prefix: taskset -c 0-3 chrt -f 50
```

…and grep for `TICK-GAP` events.  A healthy boot should have at most
a handful of sub-second gaps; many multi-second gaps mean the host is
still descheduling QEMU and you need to close competing apps or raise
the rtprio further (the host RT class still yields to itself when
contended).
