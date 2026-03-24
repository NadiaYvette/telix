#![no_std]
#![no_main]

//! SysV IPC server — semaphore sets for PostgreSQL inter-process sync.
//!
//! Protocol tags (0xA000-0xAFFF):
//!   SEM_GET(0xA000)  — d0=key, d1=nsems, d2=flags|reply<<32
//!   SEM_OP(0xA010)   — d0=semid, d1=sem_num|op<<16, d2=reply<<32
//!   SEM_CTL(0xA020)  — d0=semid, d1=sem_num, d2=cmd|reply<<32, d3=value
//!   SEM_OK(0xA100)   — success, d0=result
//!   SEM_VALUE(0xA110) — value reply
//!   SEM_ERROR(0xAF00) — error

extern crate userlib;

use userlib::syscall;

const SEM_GET: u64 = 0xA000;
const SEM_OP: u64 = 0xA010;
const SEM_CTL: u64 = 0xA020;

const SEM_OK: u64 = 0xA100;
const SEM_VALUE: u64 = 0xA110;
const SEM_ERROR: u64 = 0xAF00;

// semctl commands.
const IPC_RMID: u32 = 0;
const GETVAL: u32 = 12;
const SETVAL: u32 = 16;

const MAX_SEM_SETS: usize = 16;
const MAX_SEMS_PER: usize = 8;
const MAX_WAITERS: usize = 16;

#[derive(Clone, Copy)]
struct SemSet {
    active: bool,
    key: i32,
    nsems: usize,
    vals: [i32; MAX_SEMS_PER],
}

impl SemSet {
    const fn empty() -> Self {
        Self { active: false, key: 0, nsems: 0, vals: [0; MAX_SEMS_PER] }
    }
}

#[derive(Clone, Copy)]
struct Waiter {
    active: bool,
    semid: u32,
    sem_num: u16,
    op: i16,
    reply: u32,
}

impl Waiter {
    const fn empty() -> Self {
        Self { active: false, semid: 0, sem_num: 0, op: 0, reply: 0 }
    }
}

static mut SEM_SETS: [SemSet; MAX_SEM_SETS] = [SemSet::empty(); MAX_SEM_SETS];
static mut WAITERS: [Waiter; MAX_WAITERS] = [Waiter::empty(); MAX_WAITERS];
static mut NEXT_KEY: i32 = 1;

fn try_wake_waiters() {
    unsafe {
        for i in 0..MAX_WAITERS {
            if !WAITERS[i].active { continue; }
            let sid = WAITERS[i].semid as usize;
            let sn = WAITERS[i].sem_num as usize;
            let op = WAITERS[i].op;

            if sid >= MAX_SEM_SETS || !SEM_SETS[sid].active { continue; }
            if sn >= SEM_SETS[sid].nsems { continue; }

            if op < 0 {
                let needed = (-op) as i32;
                if SEM_SETS[sid].vals[sn] >= needed {
                    SEM_SETS[sid].vals[sn] -= needed;
                    let reply = WAITERS[i].reply;
                    WAITERS[i].active = false;
                    syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                }
            } else if op == 0 {
                if SEM_SETS[sid].vals[sn] == 0 {
                    let reply = WAITERS[i].reply;
                    WAITERS[i].active = false;
                    syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) -> ! {
    let port = syscall::port_create() as u32;
    syscall::ns_register(b"sysv", port);

    loop {
        let msg = match syscall::recv_nb_msg(port) {
            Some(m) => m,
            None => {
                syscall::yield_now();
                continue;
            }
        };

        match msg.tag {
            SEM_GET => {
                let key = msg.data[0] as i32;
                let nsems = msg.data[1] as usize;
                let _flags = (msg.data[2] & 0xFFFFFFFF) as u32;
                let reply = (msg.data[2] >> 32) as u32;

                // IPC_PRIVATE (key=0): always create new.
                // Otherwise, look for existing key.
                let mut found: Option<usize> = None;
                if key != 0 {
                    unsafe {
                        for i in 0..MAX_SEM_SETS {
                            if SEM_SETS[i].active && SEM_SETS[i].key == key {
                                found = Some(i);
                                break;
                            }
                        }
                    }
                }

                if let Some(idx) = found {
                    syscall::send(reply, SEM_OK, idx as u64, 0, 0, 0);
                } else {
                    // Allocate new set.
                    let mut allocated = false;
                    unsafe {
                        for i in 0..MAX_SEM_SETS {
                            if !SEM_SETS[i].active {
                                SEM_SETS[i].active = true;
                                SEM_SETS[i].key = if key == 0 { NEXT_KEY } else { key };
                                if key == 0 { NEXT_KEY += 1; }
                                SEM_SETS[i].nsems = if nsems > MAX_SEMS_PER { MAX_SEMS_PER } else { nsems };
                                SEM_SETS[i].vals = [0; MAX_SEMS_PER];
                                syscall::send(reply, SEM_OK, i as u64, 0, 0, 0);
                                allocated = true;
                                break;
                            }
                        }
                    }
                    if !allocated {
                        syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            SEM_OP => {
                let semid = msg.data[0] as u32;
                let sem_num = (msg.data[1] & 0xFFFF) as u16;
                let op_raw = ((msg.data[1] >> 16) & 0xFFFF) as u16;
                let op = op_raw as i16;
                let reply = (msg.data[2] >> 32) as u32;

                if semid as usize >= MAX_SEM_SETS {
                    syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    if !SEM_SETS[semid as usize].active || (sem_num as usize) >= SEM_SETS[semid as usize].nsems {
                        syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    if op > 0 {
                        // Increment.
                        SEM_SETS[semid as usize].vals[sem_num as usize] += op as i32;
                        syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                        try_wake_waiters();
                    } else if op < 0 {
                        let needed = (-op) as i32;
                        if SEM_SETS[semid as usize].vals[sem_num as usize] >= needed {
                            SEM_SETS[semid as usize].vals[sem_num as usize] -= needed;
                            syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                        } else {
                            // Block: save waiter.
                            let mut queued = false;
                            for w in 0..MAX_WAITERS {
                                if !WAITERS[w].active {
                                    WAITERS[w] = Waiter {
                                        active: true,
                                        semid,
                                        sem_num,
                                        op,
                                        reply,
                                    };
                                    queued = true;
                                    break;
                                }
                            }
                            if !queued {
                                syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                            }
                        }
                    } else {
                        // op == 0: wait for zero.
                        if SEM_SETS[semid as usize].vals[sem_num as usize] == 0 {
                            syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                        } else {
                            let mut queued = false;
                            for w in 0..MAX_WAITERS {
                                if !WAITERS[w].active {
                                    WAITERS[w] = Waiter {
                                        active: true,
                                        semid,
                                        sem_num,
                                        op,
                                        reply,
                                    };
                                    queued = true;
                                    break;
                                }
                            }
                            if !queued {
                                syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                            }
                        }
                    }
                }
            }

            SEM_CTL => {
                let semid = msg.data[0] as u32;
                let sem_num = msg.data[1] as u32;
                let cmd = (msg.data[2] & 0xFFFFFFFF) as u32;
                let reply = (msg.data[2] >> 32) as u32;
                let value = msg.data[3] as i32;

                if semid as usize >= MAX_SEM_SETS {
                    syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                    continue;
                }

                unsafe {
                    if !SEM_SETS[semid as usize].active {
                        syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                        continue;
                    }

                    match cmd {
                        cmd if cmd == IPC_RMID => {
                            SEM_SETS[semid as usize].active = false;
                            // Wake any blocked waiters with error.
                            for w in 0..MAX_WAITERS {
                                if WAITERS[w].active && WAITERS[w].semid == semid {
                                    syscall::send(WAITERS[w].reply, SEM_ERROR, 0, 0, 0, 0);
                                    WAITERS[w].active = false;
                                }
                            }
                            syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                        }
                        cmd if cmd == GETVAL => {
                            if (sem_num as usize) < SEM_SETS[semid as usize].nsems {
                                let v = SEM_SETS[semid as usize].vals[sem_num as usize];
                                syscall::send(reply, SEM_VALUE, v as u64, 0, 0, 0);
                            } else {
                                syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                            }
                        }
                        cmd if cmd == SETVAL => {
                            if (sem_num as usize) < SEM_SETS[semid as usize].nsems {
                                SEM_SETS[semid as usize].vals[sem_num as usize] = value;
                                syscall::send(reply, SEM_OK, 0, 0, 0, 0);
                                try_wake_waiters();
                            } else {
                                syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                            }
                        }
                        _ => {
                            syscall::send(reply, SEM_ERROR, 0, 0, 0, 0);
                        }
                    }
                }
            }

            _ => {}
        }
    }
}
