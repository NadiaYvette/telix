#![no_std]
#![no_main]

//! Event server — manages eventfd, signalfd, and timerfd instances.
//!
//! Protocol tags (0x7000-0x70FF):
//!   EVENT_CREATE(0x7000)  — create event fd, d0=type(0=eventfd,1=signalfd,2=timerfd), d1=initval, d2=flags|reply<<32
//!   EVENT_READ(0x7010)    — read from event fd, d0=handle, d2=reply<<32
//!   EVENT_WRITE(0x7020)   — write to event fd, d0=handle, d1=value, d2=reply<<32
//!   EVENT_CLOSE(0x7030)   — close event fd, d0=handle, d2=reply<<32
//!   EVENT_TIMER_SET(0x7040) — set timer, d0=handle, d1=interval_ns, d2=reply<<32
//!   EVENT_POLL(0x7050)    — poll readiness, d0=handle, d2=reply<<32

extern crate userlib;

use userlib::syscall;

// Protocol tags.
const EVENT_CREATE: u64 = 0x7000;
const EVENT_READ: u64 = 0x7010;
const EVENT_WRITE: u64 = 0x7020;
const EVENT_CLOSE: u64 = 0x7030;
const EVENT_TIMER_SET: u64 = 0x7040;
const EVENT_POLL: u64 = 0x7050;

const EVENT_OK: u64 = 0x7100;
const EVENT_ERROR: u64 = 0x7F00;

// Event types.
const EVT_EVENTFD: u64 = 0;
const EVT_SIGNALFD: u64 = 1;
const EVT_TIMERFD: u64 = 2;

// Flags.
const EFD_SEMAPHORE: u64 = 1;
#[allow(dead_code)]
const EFD_NONBLOCK: u64 = 2;

// Limits.
const MAX_EVENTS: usize = 32;

#[derive(Clone, Copy, PartialEq)]
enum EventType {
    None,
    EventFd,
    SignalFd,
    TimerFd,
}

struct EventSlot {
    active: bool,
    etype: EventType,
    // eventfd: counter value
    counter: u64,
    flags: u64,
    // timerfd: interval in nanoseconds, next expiry timestamp (ns)
    timer_interval_ns: u64,
    timer_next_ns: u64,
    timer_expirations: u64,
    // Blocked reader reply port (u64::MAX = none).
    blocked_reader: u64,
}

impl EventSlot {
    const fn empty() -> Self {
        Self {
            active: false,
            etype: EventType::None,
            counter: 0,
            flags: 0,
            timer_interval_ns: 0,
            timer_next_ns: 0,
            timer_expirations: 0,
            blocked_reader: u64::MAX,
        }
    }
}

static mut EVENTS: [EventSlot; MAX_EVENTS] = {
    const EMPTY: EventSlot = EventSlot::empty();
    [EMPTY; MAX_EVENTS]
};

fn alloc_slot() -> Option<u32> {
    unsafe {
        for i in 0..MAX_EVENTS {
            if !EVENTS[i].active {
                EVENTS[i].active = true;
                return Some(i as u32);
            }
        }
    }
    None
}

fn get_time_ns() -> u64 {
    syscall::clock_gettime()
}

fn check_timers() {
    let now = get_time_ns();
    unsafe {
        for i in 0..MAX_EVENTS {
            let slot = &mut EVENTS[i];
            if !slot.active || slot.etype != EventType::TimerFd {
                continue;
            }
            if slot.timer_next_ns == 0 || now < slot.timer_next_ns {
                continue;
            }
            // Timer expired.
            slot.timer_expirations += 1;
            if slot.timer_interval_ns > 0 {
                // Repeating timer: advance to next expiry.
                slot.timer_next_ns += slot.timer_interval_ns;
                // If we fell behind, catch up.
                if slot.timer_next_ns <= now {
                    slot.timer_next_ns = now + slot.timer_interval_ns;
                }
            } else {
                // One-shot: disable.
                slot.timer_next_ns = 0;
            }

            // Wake blocked reader if any.
            if slot.blocked_reader != u64::MAX {
                let reply = slot.blocked_reader;
                slot.blocked_reader = u64::MAX;
                let exp = slot.timer_expirations;
                slot.timer_expirations = 0;
                syscall::send(reply, EVENT_OK, exp, 0, 0, 0);
            }
        }
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) -> ! {
    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"event", port);

    loop {
        // Check timers before blocking on recv.
        check_timers();

        // Non-blocking recv so we can keep checking timers.
        let msg = syscall::recv_nb_msg(port);
        if msg.is_none() {
            syscall::yield_now();
            continue;
        }
        let msg = msg.unwrap();

        match msg.tag {
            EVENT_CREATE => {
                let etype_raw = msg.data[0];
                let initval = msg.data[1];
                let flags = msg.data[2] & 0xFFFFFFFF;
                let reply = msg.data[2] >> 32;

                let etype = match etype_raw {
                    EVT_EVENTFD => EventType::EventFd,
                    EVT_SIGNALFD => EventType::SignalFd,
                    EVT_TIMERFD => EventType::TimerFd,
                    _ => {
                        syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                        continue;
                    }
                };

                match alloc_slot() {
                    Some(handle) => {
                        unsafe {
                            let slot = &mut EVENTS[handle as usize];
                            slot.etype = etype;
                            slot.counter = initval;
                            slot.flags = flags;
                            slot.timer_interval_ns = 0;
                            slot.timer_next_ns = 0;
                            slot.timer_expirations = 0;
                            slot.blocked_reader = u64::MAX;
                        }
                        // Reply: d0 = server_port, d1 = handle
                        syscall::send(reply, EVENT_OK, port as u64, handle as u64, 0, 0);
                    }
                    None => {
                        syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            EVENT_READ => {
                let handle = msg.data[0] as u32;
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_EVENTS {
                    syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let slot = &mut EVENTS[handle as usize];
                    if !slot.active {
                        syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    match slot.etype {
                        EventType::EventFd => {
                            if slot.counter > 0 {
                                let val = if slot.flags & EFD_SEMAPHORE != 0 {
                                    slot.counter -= 1;
                                    1
                                } else {
                                    let v = slot.counter;
                                    slot.counter = 0;
                                    v
                                };
                                syscall::send(reply, EVENT_OK, val, 0, 0, 0);
                            } else {
                                slot.blocked_reader = reply;
                            }
                        }
                        EventType::TimerFd => {
                            if slot.timer_expirations > 0 {
                                let exp = slot.timer_expirations;
                                slot.timer_expirations = 0;
                                syscall::send(reply, EVENT_OK, exp, 0, 0, 0);
                            } else {
                                slot.blocked_reader = reply;
                            }
                        }
                        EventType::SignalFd => {
                            slot.blocked_reader = reply;
                        }
                        EventType::None => {
                            syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                        }
                    }
                }
            }

            EVENT_WRITE => {
                let handle = msg.data[0] as u32;
                let value = msg.data[1];
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_EVENTS {
                    syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let slot = &mut EVENTS[handle as usize];
                    if !slot.active || slot.etype != EventType::EventFd {
                        syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    slot.counter = slot.counter.saturating_add(value);

                    // Wake blocked reader.
                    if slot.blocked_reader != u64::MAX && slot.counter > 0 {
                        let reader = slot.blocked_reader;
                        slot.blocked_reader = u64::MAX;
                        let val = if slot.flags & EFD_SEMAPHORE != 0 {
                            slot.counter -= 1;
                            1
                        } else {
                            let v = slot.counter;
                            slot.counter = 0;
                            v
                        };
                        syscall::send(reader, EVENT_OK, val, 0, 0, 0);
                    }

                    syscall::send(reply, EVENT_OK, 8, 0, 0, 0); // wrote 8 bytes
                }
            }

            EVENT_TIMER_SET => {
                let handle = msg.data[0] as u32;
                let interval_ns = msg.data[1];
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_EVENTS {
                    syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let slot = &mut EVENTS[handle as usize];
                    if !slot.active || slot.etype != EventType::TimerFd {
                        syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    slot.timer_interval_ns = interval_ns;
                    slot.timer_next_ns = get_time_ns() + interval_ns;
                    slot.timer_expirations = 0;
                }

                syscall::send(reply, EVENT_OK, 0, 0, 0, 0);
            }

            EVENT_CLOSE => {
                let handle = msg.data[0] as u32;
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_EVENTS {
                    syscall::send(reply, EVENT_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let slot = &mut EVENTS[handle as usize];
                    slot.active = false;
                    slot.etype = EventType::None;
                    slot.counter = 0;
                    slot.blocked_reader = u64::MAX;
                }

                syscall::send(reply, EVENT_OK, 0, 0, 0, 0);
            }

            EVENT_POLL => {
                let handle = msg.data[0] as u32;
                let reply = msg.data[2] >> 32;

                if handle as usize >= MAX_EVENTS {
                    syscall::send(reply, EVENT_OK, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    let slot = &EVENTS[handle as usize];
                    let ready: u64 = if !slot.active {
                        0
                    } else {
                        match slot.etype {
                            EventType::EventFd => {
                                if slot.counter > 0 { 1 } else { 0 }
                            }
                            EventType::TimerFd => {
                                if slot.timer_expirations > 0 { 1 } else { 0 }
                            }
                            _ => 0,
                        }
                    };
                    syscall::send(reply, EVENT_OK, ready, 0, 0, 0);
                }
            }

            _ => {
                // Unknown tag — ignore.
            }
        }
    }
}
