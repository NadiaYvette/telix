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

| Var               | Default | Effect                                                      |
|-------------------|---------|-------------------------------------------------------------|
| `TELIX_PIN_CPUS`  | `0-3`   | `taskset -c $TELIX_PIN_CPUS qemu …`.  Free, no caps needed. |
| `TELIX_RTPRIO`    | unset   | `chrt -f $TELIX_RTPRIO qemu …` (SCHED_FIFO).  Needs caps.   |
| `TELIX_NICE_OFF`  | unset   | Skip both wrappers entirely (legacy behaviour).             |

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

Lets just this binary call `sched_setscheduler` to SCHED_FIFO without
any other setup.  Survives reboots but **not dnf upgrades** — the
capability is on the inode and `dnf upgrade qemu-system-x86_64` swaps
in a fresh binary with no caps.  Workable if you re-apply via a
systemd-tmpfiles rule or a post-upgrade hook.

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
