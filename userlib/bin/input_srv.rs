#![no_std]
#![no_main]

//! Userspace input event server: PS/2 keyboard + mouse via i8042 controller.
//!
//! Reads scancodes from the PS/2 keyboard (IRQ 1, port 0x60) and mouse
//! (IRQ 12, port 0x60), translates to key events, and delivers to
//! subscribers via IPC.

extern crate userlib;

use userlib::syscall;

// --- Input IPC protocol ---
const INPUT_SUBSCRIBE: u64 = 0x9000;
const INPUT_SUBSCRIBE_OK: u64 = 0x9001;
const INPUT_EVENT: u64 = 0x9002;
const INPUT_UNSUBSCRIBE: u64 = 0x9003;

// Event types (packed in data[0] low byte).
const EVENT_KEY_DOWN: u8 = 1;
const EVENT_KEY_UP: u8 = 2;
const EVENT_MOUSE_MOVE: u8 = 3;
const EVENT_MOUSE_BUTTON: u8 = 4;

// Maximum subscribers.
const MAX_SUBSCRIBERS: usize = 8;

// PS/2 i8042 ports.
const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_COMMAND: u16 = 0x64;

// PS/2 status register bits.
const PS2_STATUS_OUTPUT_FULL: u8 = 0x01;
const PS2_STATUS_MOUSE_DATA: u8 = 0x20;

// --- Scancode Set 1 to ASCII/keycode translation ---

/// Unshifted scancode set 1 to ASCII translation.
#[rustfmt::skip]
static KEY_MAP: [u8; 128] = [
    0, 27, // 0x00=none, 0x01=Esc
    b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', // 0x02-0x0B
    b'-', b'=', 8,   // 0x0C=-, 0x0D==, 0x0E=Backspace
    b'\t',            // 0x0F=Tab
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', // 0x10-0x19
    b'[', b']', b'\n', // 0x1A=[, 0x1B=], 0x1C=Enter
    0,                // 0x1D=LCtrl
    b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', // 0x1E-0x26
    b';', b'\'', b'`', // 0x27=;, 0x28=', 0x29=`
    0,                // 0x2A=LShift
    b'\\',            // 0x2B=backslash
    b'z', b'x', b'c', b'v', b'b', b'n', b'm', // 0x2C-0x32
    b',', b'.', b'/', // 0x33=,, 0x34=., 0x35=/
    0,                // 0x36=RShift
    b'*',             // 0x37=KP*
    0,                // 0x38=LAlt
    b' ',             // 0x39=Space
    0,                // 0x3A=CapsLock
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x3B-0x44=F1-F10
    0, 0,             // 0x45=NumLock, 0x46=ScrollLock
    b'7', b'8', b'9', b'-', // 0x47-0x4A=KP7,8,9,-
    b'4', b'5', b'6', b'+', // 0x4B-0x4E=KP4,5,6,+
    b'1', b'2', b'3',       // 0x4F-0x51=KP1,2,3
    b'0', b'.',             // 0x52=KP0, 0x53=KP.
    0, 0, 0,                // 0x54-0x56
    0, 0,                   // 0x57=F11, 0x58=F12
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x59-0x68
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x69-0x78
    0, 0, 0, 0, 0, 0, 0,    // 0x79-0x7F
];

/// Shifted scancode set 1 to ASCII translation.
#[rustfmt::skip]
static SHIFT_MAP: [u8; 128] = [
    0, 27, // 0x00=none, 0x01=Esc
    b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', // 0x02-0x0B
    b'_', b'+', 8,   // 0x0C, 0x0D, 0x0E=Backspace
    b'\t',            // 0x0F=Tab
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I', b'O', b'P', // 0x10-0x19
    b'{', b'}', b'\n', // 0x1A, 0x1B, 0x1C=Enter
    0,                // 0x1D=LCtrl
    b'A', b'S', b'D', b'F', b'G', b'H', b'J', b'K', b'L', // 0x1E-0x26
    b':', b'"', b'~', // 0x27, 0x28, 0x29
    0,                // 0x2A=LShift
    b'|',             // 0x2B
    b'Z', b'X', b'C', b'V', b'B', b'N', b'M', // 0x2C-0x32
    b'<', b'>', b'?', // 0x33, 0x34, 0x35
    0,                // 0x36=RShift
    b'*',             // 0x37=KP*
    0,                // 0x38=LAlt
    b' ',             // 0x39=Space
    0,                // 0x3A=CapsLock
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x3B-0x44=F1-F10
    0, 0,             // 0x45=NumLock, 0x46=ScrollLock
    b'7', b'8', b'9', b'-', // 0x47-0x4A=KP7,8,9,-
    b'4', b'5', b'6', b'+', // 0x4B-0x4E=KP4,5,6,+
    b'1', b'2', b'3',       // 0x4F-0x51=KP1,2,3
    b'0', b'.',             // 0x52=KP0, 0x53=KP.
    0, 0, 0,                // 0x54-0x56
    0, 0,                   // 0x57=F11, 0x58=F12
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x59-0x68
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x69-0x78
    0, 0, 0, 0, 0, 0, 0,    // 0x79-0x7F
];

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

struct InputServer {
    subscribers: [u64; MAX_SUBSCRIBERS],
    num_subscribers: usize,
    // Mouse state for 3-byte PS/2 mouse packets.
    mouse_byte: u8,
    mouse_packet: [u8; 3],
    prev_buttons: u8,
    // Modifier key state.
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps: bool,
}

impl InputServer {
    fn new() -> Self {
        Self {
            subscribers: [0; MAX_SUBSCRIBERS],
            num_subscribers: 0,
            mouse_byte: 0,
            mouse_packet: [0; 3],
            prev_buttons: 0,
            shift: false,
            ctrl: false,
            alt: false,
            caps: false,
        }
    }

    fn add_subscriber(&mut self, port: u64) -> bool {
        if self.num_subscribers >= MAX_SUBSCRIBERS {
            return false;
        }
        // Check for duplicate.
        for i in 0..self.num_subscribers {
            if self.subscribers[i] == port {
                return true;
            }
        }
        self.subscribers[self.num_subscribers] = port;
        self.num_subscribers += 1;
        true
    }

    fn remove_subscriber(&mut self, port: u64) {
        for i in 0..self.num_subscribers {
            if self.subscribers[i] == port {
                self.subscribers[i] = self.subscribers[self.num_subscribers - 1];
                self.num_subscribers -= 1;
                return;
            }
        }
    }

    /// Broadcast an input event to all subscribers.
    /// d0 encoding: [0:8]=event_type [8:16]=keycode [16:24]=ascii [24]=shift [25]=ctrl [26]=alt [27]=caps
    fn broadcast(&self, event_type: u8, keycode: u8, ascii: u8, extra: u64) {
        let mods = (self.shift as u64) << 24
            | (self.ctrl as u64) << 25
            | (self.alt as u64) << 26
            | (self.caps as u64) << 27;
        let d0 = (event_type as u64)
            | ((keycode as u64) << 8)
            | ((ascii as u64) << 16)
            | mods;
        for i in 0..self.num_subscribers {
            syscall::send(self.subscribers[i], INPUT_EVENT, d0, extra, 0, 0);
        }
    }

    /// Process a keyboard scancode.
    fn handle_keyboard(&mut self, scancode: u8) {
        let is_release = scancode & 0x80 != 0;
        let make = scancode & 0x7F;

        // Update modifier state.
        match make {
            0x2A | 0x36 => { self.shift = !is_release; }  // LShift / RShift
            0x1D => { self.ctrl = !is_release; }           // LCtrl
            0x38 => { self.alt = !is_release; }            // LAlt
            0x3A => { if !is_release { self.caps = !self.caps; } } // CapsLock toggle
            _ => {}
        }

        // Look up ASCII from appropriate map.
        let raw_ascii = if (make as usize) < 128 {
            let use_shift = self.shift ^ self.caps;
            if use_shift { SHIFT_MAP[make as usize] } else { KEY_MAP[make as usize] }
        } else {
            0
        };

        // Apply Ctrl: letter → control code (0x01-0x1A).
        let ascii = if self.ctrl && raw_ascii >= b'a' && raw_ascii <= b'z' {
            raw_ascii - b'a' + 1
        } else if self.ctrl && raw_ascii >= b'A' && raw_ascii <= b'Z' {
            raw_ascii - b'A' + 1
        } else {
            raw_ascii
        };

        let event_type = if is_release { EVENT_KEY_UP } else { EVENT_KEY_DOWN };
        self.broadcast(event_type, make, ascii, 0);
    }

    /// Process a mouse data byte (PS/2 3-byte protocol).
    fn handle_mouse(&mut self, byte: u8) {
        self.mouse_packet[self.mouse_byte as usize] = byte;
        self.mouse_byte += 1;

        if self.mouse_byte < 3 {
            return;
        }
        self.mouse_byte = 0;

        // Parse 3-byte PS/2 mouse packet.
        let flags = self.mouse_packet[0];
        let dx = self.mouse_packet[1] as i16
            - if flags & 0x10 != 0 { 256 } else { 0 };
        let dy = self.mouse_packet[2] as i16
            - if flags & 0x20 != 0 { 256 } else { 0 };
        let buttons = flags & 0x07;

        // Mouse move event.
        if dx != 0 || dy != 0 {
            let extra = (dx as u16 as u64) | ((dy as u16 as u64) << 16);
            self.broadcast(EVENT_MOUSE_MOVE, 0, 0, extra);
        }
        // Mouse button event on state change — send current button state in extra.
        if buttons != self.prev_buttons {
            self.broadcast(EVENT_MOUSE_BUTTON, 0, 0, buttons as u64);
            self.prev_buttons = buttons;
        }
    }
}

/// Enable PS/2 mouse (auxiliary device on i8042).
fn enable_ps2_mouse() {
    // Enable auxiliary device.
    syscall::ioport_outb(PS2_COMMAND, 0xA8);
    // Get compaq status byte.
    syscall::ioport_outb(PS2_COMMAND, 0x20);
    // Wait for output buffer.
    for _ in 0..1000 {
        if syscall::ioport_inb(PS2_STATUS) & PS2_STATUS_OUTPUT_FULL != 0 {
            break;
        }
    }
    let status = syscall::ioport_inb(PS2_DATA);
    // Set bit 1 (enable IRQ12) and clear bit 5 (disable mouse clock).
    let new_status = (status | 0x02) & !0x20;
    syscall::ioport_outb(PS2_COMMAND, 0x60);
    syscall::ioport_outb(PS2_DATA, new_status);
    // Enable data reporting on the mouse.
    syscall::ioport_outb(PS2_COMMAND, 0xD4); // Send to auxiliary device.
    syscall::ioport_outb(PS2_DATA, 0xF4);    // Enable data reporting.
    // Flush any ACK byte.
    for _ in 0..100 {
        if syscall::ioport_inb(PS2_STATUS) & PS2_STATUS_OUTPUT_FULL != 0 {
            let _ = syscall::ioport_inb(PS2_DATA);
        } else {
            break;
        }
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [input_srv] starting\n");

    let mut server = InputServer::new();

    // Enable PS/2 mouse.
    enable_ps2_mouse();

    // Register for keyboard IRQ (IRQ 1).
    // mmio_base=1 is a dummy non-zero value to trigger registration.
    syscall::irq_wait(1, 1);

    // Register for mouse IRQ (IRQ 12).
    syscall::irq_wait(12, 1);

    // Create IPC port and register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"input", port);

    syscall::debug_puts(b"  [input_srv] ready (kbd IRQ 1, mouse IRQ 12), port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    // Use a port set to listen for both IPC messages and IRQ wakeups.
    // For simplicity, we poll: check for IRQs, then check for IPC.
    loop {
        // Check for keyboard data (non-blocking).
        let status = syscall::ioport_inb(PS2_STATUS);
        if status & PS2_STATUS_OUTPUT_FULL != 0 {
            let data = syscall::ioport_inb(PS2_DATA);
            if status & PS2_STATUS_MOUSE_DATA != 0 {
                server.handle_mouse(data);
            } else {
                server.handle_keyboard(data);
            }
            continue; // Process all pending data before checking IPC.
        }

        // Check for IPC messages (non-blocking).
        if let Some(msg) = syscall::recv_nb_msg(port) {
            match msg.tag {
                INPUT_SUBSCRIBE => {
                    let reply_port = msg.data[2] >> 32;
                    let sub_port = msg.data[0];
                    if sub_port != 0 && server.add_subscriber(sub_port) {
                        syscall::send(reply_port, INPUT_SUBSCRIBE_OK, 0, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, INPUT_SUBSCRIBE_OK, u64::MAX, 0, 0, 0);
                    }
                }
                INPUT_UNSUBSCRIBE => {
                    let sub_port = msg.data[0];
                    server.remove_subscriber(sub_port);
                }
                _ => {}
            }
            continue;
        }

        // Nothing pending — yield to avoid busy-spin.
        // We can't block on irq_wait(1,0) because that would prevent
        // processing IPC messages until the next keyboard IRQ fires.
        syscall::yield_now();
    }
}
