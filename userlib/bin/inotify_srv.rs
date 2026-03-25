#![no_std]
#![no_main]

//! Inotify server — filesystem change notifications.
//!
//! Protocol tags (0x7100-0x71FF):
//!   IN_CREATE(0x7100)    — create inotify instance, d2=reply<<32
//!   IN_ADD_WATCH(0x7110) — add watch, d0=handle, d1=path_w0, d2=mask(low16)|reply(high32), d3=path_w1
//!   IN_RM_WATCH(0x7120)  — remove watch, d0=handle, d1=wd, d2=reply<<32
//!   IN_READ(0x7130)      — read event, d0=handle, d2=reply<<32
//!   IN_CLOSE(0x7140)     — close instance, d0=handle, d2=reply<<32
//!   IN_POLL(0x7150)      — poll readiness, d0=handle, d2=reply<<32
//!   IN_NOTIFY(0x7160)    — notification from VFS (internal), d0=event_mask, d1=path_w0, d2=path_w1

extern crate userlib;

use userlib::syscall;

const IN_CREATE_TAG: u64 = 0x7100;
const IN_ADD_WATCH: u64 = 0x7110;
const IN_RM_WATCH: u64 = 0x7120;
const IN_READ: u64 = 0x7130;
const IN_CLOSE: u64 = 0x7140;
const IN_POLL: u64 = 0x7150;
const IN_NOTIFY: u64 = 0x7160;

const IN_OK: u64 = 0x7180;
const IN_ERROR: u64 = 0x71F0;

// Event mask bits.
const IN_EVT_CREATE: u32 = 0x100;
const IN_EVT_DELETE: u32 = 0x200;
const IN_EVT_MODIFY: u32 = 0x002;
const IN_EVT_OPEN: u32 = 0x020;
const IN_EVT_CLOSE_WRITE: u32 = 0x008;
const IN_EVT_ALL: u32 = IN_EVT_CREATE | IN_EVT_DELETE | IN_EVT_MODIFY | IN_EVT_OPEN | IN_EVT_CLOSE_WRITE;

const MAX_INSTANCES: usize = 8;
const MAX_WATCHES_PER: usize = 8;
const EVENT_QUEUE_SIZE: usize = 16;

#[derive(Clone, Copy)]
struct InotifyEvent {
    wd: u32,
    mask: u32,
    name_w0: u64,
    name_w1: u64,
}

impl InotifyEvent {
    const fn empty() -> Self {
        Self { wd: 0, mask: 0, name_w0: 0, name_w1: 0 }
    }
}

#[derive(Clone, Copy)]
struct Watch {
    active: bool,
    path_w0: u64,
    path_w1: u64,
    mask: u32,
}

impl Watch {
    const fn empty() -> Self {
        Self { active: false, path_w0: 0, path_w1: 0, mask: 0 }
    }
}

struct InotifyInstance {
    active: bool,
    watches: [Watch; MAX_WATCHES_PER],
    next_wd: u32,
    events: [InotifyEvent; EVENT_QUEUE_SIZE],
    event_head: usize,
    event_tail: usize,
    blocked_reader: u64,
}

impl InotifyInstance {
    const fn empty() -> Self {
        Self {
            active: false,
            watches: [Watch::empty(); MAX_WATCHES_PER],
            next_wd: 1,
            events: [InotifyEvent::empty(); EVENT_QUEUE_SIZE],
            event_head: 0,
            event_tail: 0,
            blocked_reader: u64::MAX,
        }
    }

    fn event_count(&self) -> usize {
        if self.event_head >= self.event_tail {
            self.event_head - self.event_tail
        } else {
            EVENT_QUEUE_SIZE - self.event_tail + self.event_head
        }
    }

    fn push_event(&mut self, evt: InotifyEvent) {
        if self.event_count() >= EVENT_QUEUE_SIZE - 1 {
            return; // drop if full
        }
        self.events[self.event_head] = evt;
        self.event_head = (self.event_head + 1) % EVENT_QUEUE_SIZE;
    }

    fn pop_event(&mut self) -> Option<InotifyEvent> {
        if self.event_head == self.event_tail {
            return None;
        }
        let evt = self.events[self.event_tail];
        self.event_tail = (self.event_tail + 1) % EVENT_QUEUE_SIZE;
        Some(evt)
    }
}

static mut INSTANCES: [InotifyInstance; MAX_INSTANCES] = {
    const EMPTY: InotifyInstance = InotifyInstance::empty();
    [EMPTY; MAX_INSTANCES]
};

fn alloc_instance() -> Option<u32> {
    unsafe {
        for i in 0..MAX_INSTANCES {
            if !INSTANCES[i].active {
                INSTANCES[i].active = true;
                INSTANCES[i].next_wd = 1;
                INSTANCES[i].event_head = 0;
                INSTANCES[i].event_tail = 0;
                INSTANCES[i].blocked_reader = 0xFFFFFFFF;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Check if a path (packed as two u64 words) matches a watch path.
/// Simple prefix match: watch path "/" matches everything.
fn path_matches(watch: &Watch, path_w0: u64, _path_w1: u64) -> bool {
    // "/" matches everything (root watch).
    if watch.path_w0 == (b'/' as u64) && watch.path_w1 == 0 {
        return true;
    }
    watch.path_w0 == path_w0 && watch.path_w1 == _path_w1
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) -> ! {
    let port = syscall::port_create();
    syscall::ns_register(b"inotify", port);

    loop {
        let msg = match syscall::recv_nb_msg(port) {
            Some(m) => m,
            None => {
                syscall::yield_now();
                continue;
            }
        };

        match msg.tag {
            IN_CREATE_TAG => {
                let reply = msg.data[2] >> 32;
                match alloc_instance() {
                    Some(handle) => {
                        syscall::send(reply, IN_OK, port as u64, handle as u64, 0, 0);
                    }
                    None => {
                        syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            IN_ADD_WATCH => {
                let handle = msg.data[0] as u32;
                let path_w0 = msg.data[1];
                let mask = (msg.data[2] & 0xFFFF) as u32;
                let reply = msg.data[2] >> 32;
                let path_w1 = msg.data[3];

                if handle as usize >= MAX_INSTANCES {
                    syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let inst = &mut INSTANCES[handle as usize];
                    if !inst.active {
                        syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    // Find free watch slot.
                    let mut found = false;
                    for w in inst.watches.iter_mut() {
                        if !w.active {
                            w.active = true;
                            w.path_w0 = path_w0;
                            w.path_w1 = path_w1;
                            w.mask = if mask == 0 { IN_EVT_ALL } else { mask };
                            let wd = inst.next_wd;
                            inst.next_wd += 1;
                            syscall::send(reply, IN_OK, wd as u64, 0, 0, 0);
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            IN_RM_WATCH => {
                let handle = msg.data[0] as u32;
                let wd = msg.data[1] as u32;
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_INSTANCES {
                    syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let inst = &mut INSTANCES[handle as usize];
                    // Remove watch with matching wd (index = wd - 1).
                    if wd > 0 && (wd as usize - 1) < MAX_WATCHES_PER {
                        inst.watches[wd as usize - 1].active = false;
                    }
                }
                syscall::send(reply, IN_OK, 0, 0, 0, 0);
            }

            IN_READ => {
                let handle = msg.data[0] as u32;
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_INSTANCES {
                    syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let inst = &mut INSTANCES[handle as usize];
                    if !inst.active {
                        syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    match inst.pop_event() {
                        Some(evt) => {
                            // Reply: d0 = wd, d1 = mask, d2 = name_w0, d3 = name_w1
                            syscall::send(reply, IN_OK, evt.wd as u64, evt.mask as u64, evt.name_w0, evt.name_w1);
                        }
                        None => {
                            // Block reader.
                            inst.blocked_reader = reply;
                        }
                    }
                }
            }

            IN_CLOSE => {
                let handle = msg.data[0] as u32;
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_INSTANCES {
                    syscall::send(reply, IN_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let inst = &mut INSTANCES[handle as usize];
                    inst.active = false;
                    for w in inst.watches.iter_mut() {
                        w.active = false;
                    }
                    inst.blocked_reader = 0xFFFFFFFF;
                }
                syscall::send(reply, IN_OK, 0, 0, 0, 0);
            }

            IN_POLL => {
                let handle = msg.data[0] as u32;
                let reply = msg.data[2] >> 32;

                let ready = if handle as usize >= MAX_INSTANCES {
                    0u64
                } else {
                    unsafe {
                        let inst = &INSTANCES[handle as usize];
                        if inst.active && inst.event_count() > 0 { 1 } else { 0 }
                    }
                };
                syscall::send(reply, IN_OK, ready, 0, 0, 0);
            }

            IN_NOTIFY => {
                // VFS sends this when a file operation happens.
                // d0 = event_mask, d1 = path_w0, d2 = path_w1
                let event_mask = msg.data[0] as u32;
                let path_w0 = msg.data[1];
                let path_w1 = msg.data[2];

                // Dispatch to all matching watches across all instances.
                unsafe {
                    for i in 0..MAX_INSTANCES {
                        if !INSTANCES[i].active { continue; }

                        // Collect matching watch indices first to avoid borrow conflict.
                        let mut matched = [false; MAX_WATCHES_PER];
                        for idx in 0..MAX_WATCHES_PER {
                            let w = &INSTANCES[i].watches[idx];
                            if w.active && (w.mask & event_mask) != 0 && path_matches(w, path_w0, path_w1) {
                                matched[idx] = true;
                            }
                        }

                        for idx in 0..MAX_WATCHES_PER {
                            if !matched[idx] { continue; }
                            let evt = InotifyEvent {
                                wd: (idx + 1) as u32,
                                mask: event_mask,
                                name_w0: path_w0,
                                name_w1: path_w1,
                            };
                            INSTANCES[i].push_event(evt);

                            // Wake blocked reader.
                            if INSTANCES[i].blocked_reader != u64::MAX {
                                let reader = INSTANCES[i].blocked_reader;
                                INSTANCES[i].blocked_reader = 0xFFFFFFFF;
                                if let Some(e) = INSTANCES[i].pop_event() {
                                    syscall::send(reader, IN_OK, e.wd as u64, e.mask as u64, e.name_w0, e.name_w1);
                                }
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }
}
