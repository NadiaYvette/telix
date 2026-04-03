#![no_std]
#![no_main]

//! Window compositor server: manages windows, composites onto framebuffer,
//! routes input events to focused window.
//!
//! Bridges fb_srv (display output) and input_srv (keyboard/mouse input).
//! Clients create windows with shared pixel buffers (XRGB8888), draw into
//! them directly, and send COMMIT to trigger recomposition.

extern crate userlib;

use core::ptr;
use userlib::syscall;

// --- Compositor IPC protocol (0xA0xx) ---
const COMP_CREATE_WINDOW: u64 = 0xA000;
const COMP_CREATE_WINDOW_OK: u64 = 0xA001;
const COMP_DESTROY_WINDOW: u64 = 0xA002;
const COMP_DESTROY_WINDOW_OK: u64 = 0xA003;
const COMP_COMMIT: u64 = 0xA004;
const COMP_COMMIT_OK: u64 = 0xA005;
const COMP_MOVE_WINDOW: u64 = 0xA006;
const COMP_MOVE_WINDOW_OK: u64 = 0xA007;
const COMP_GET_INFO: u64 = 0xA008;
const COMP_GET_INFO_OK: u64 = 0xA009;
const COMP_INPUT_EVENT: u64 = 0xA00A;
const COMP_FOCUS_EVENT: u64 = 0xA00C;
const COMP_CLOSE_EVENT: u64 = 0xA00E;

// fb_srv protocol.
const FB_GET_INFO: u64 = 0x8000;
const FB_GET_INFO_OK: u64 = 0x8001;
const FB_MAP: u64 = 0x8002;
const FB_MAP_OK: u64 = 0x8003;
const FB_FLIP: u64 = 0x8004;
const FB_FLIP_OK: u64 = 0x8005;

// input_srv protocol.
const INPUT_SUBSCRIBE: u64 = 0x9000;
const INPUT_SUBSCRIBE_OK: u64 = 0x9001;
const INPUT_EVENT: u64 = 0x9002;

// Input event types.
const EVENT_KEY_DOWN: u8 = 1;
const EVENT_KEY_UP: u8 = 2;
const EVENT_MOUSE_MOVE: u8 = 3;
const EVENT_MOUSE_BUTTON: u8 = 4;

// Visual constants.
const MAX_WINDOWS: usize = 8;
const BORDER_WIDTH: i32 = 2;
const BG_COLOR: u32 = 0x00303030;
const BORDER_COLOR: u32 = 0x00808080;
const BORDER_FOCUSED_COLOR: u32 = 0x004488FF;
const TITLEBAR_H: i32 = 20;
const TITLEBAR_BG: u32 = 0x00404060;
const TITLEBAR_FOCUSED_BG: u32 = 0x003355AA;
const TITLEBAR_TEXT_COLOR: u32 = 0x00FFFFFF;
const CLOSE_BTN_SIZE: i32 = 14;
const CLOSE_BTN_COLOR: u32 = 0x00CC4444;
const CLOSE_BTN_X_COLOR: u32 = 0x00FFFFFF;
const TASKBAR_H: i32 = 24;
const TASKBAR_BG: u32 = 0x00202020;
const TASKBAR_BTN_BG: u32 = 0x00404040;
const TASKBAR_BTN_FOCUSED: u32 = 0x003355AA;
const TASKBAR_BTN_H: i32 = 18;
const TASKBAR_BTN_GAP: i32 = 4;

// Page size for mmap_anon (allocation pages).
const PAGE_SIZE: usize = 4096;

// --- Mouse cursor bitmap (12x19 arrow) ---
// Each entry: bit 11 = leftmost pixel. CURSOR_MASK = opaque, CURSOR_FILL = white.
const CURSOR_W: usize = 12;
const CURSOR_H: usize = 19;
#[rustfmt::skip]
const CURSOR_MASK: [u16; 19] = [
    0b1000_0000_0000, // X...........
    0b1100_0000_0000, // XX..........
    0b1110_0000_0000, // XXX.........
    0b1111_0000_0000, // XXXX........
    0b1111_1000_0000, // XXXXX.......
    0b1111_1100_0000, // XXXXXX......
    0b1111_1110_0000, // XXXXXXX.....
    0b1111_1111_0000, // XXXXXXXX....
    0b1111_1111_1000, // XXXXXXXXX...
    0b1111_1111_1100, // XXXXXXXXXX..
    0b1111_1111_1110, // XXXXXXXXXXX.
    0b1111_1110_0000, // XXXXXXX.....
    0b1110_1111_0000, // XXX.XXXX....
    0b1100_1111_0000, // XX..XXXX....
    0b1000_0111_1000, // X....XXXX...
    0b0000_0111_1000, // .....XXXX...
    0b0000_0011_1100, // ......XXXX..
    0b0000_0011_1100, // ......XXXX..
    0b0000_0001_1000, // .......XX...
];
#[rustfmt::skip]
const CURSOR_FILL: [u16; 19] = [
    0b0000_0000_0000, // ............
    0b0000_0000_0000, // ............
    0b0100_0000_0000, // .#..........
    0b0110_0000_0000, // .##.........
    0b0111_0000_0000, // .###........
    0b0111_1000_0000, // .####.......
    0b0111_1100_0000, // .#####......
    0b0111_1110_0000, // .######.....
    0b0111_1111_0000, // .#######....
    0b0111_1111_1000, // .########...
    0b0111_1100_0000, // .#####......
    0b0110_1100_0000, // .##.##......
    0b0100_0110_0000, // .#...##.....
    0b0000_0110_0000, // .....##.....
    0b0000_0011_0000, // ......##....
    0b0000_0011_0000, // ......##....
    0b0000_0001_1000, // .......##...
    0b0000_0001_1000, // .......##...
    0b0000_0000_0000, // ............
];

// --- 8x8 bitmap font (ASCII 32..126) for title bar text ---
#[rustfmt::skip]
const FONT_8X8: [[u8; 8]; 95] = [
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00], // 32 ' '
    [0x18,0x3C,0x3C,0x18,0x18,0x00,0x18,0x00], // 33 '!'
    [0x36,0x36,0x14,0x00,0x00,0x00,0x00,0x00], // 34 '"'
    [0x36,0x36,0x7F,0x36,0x7F,0x36,0x36,0x00], // 35 '#'
    [0x0C,0x3E,0x03,0x1E,0x30,0x1F,0x0C,0x00], // 36 '$'
    [0x00,0x63,0x33,0x18,0x0C,0x66,0x63,0x00], // 37 '%'
    [0x1C,0x36,0x1C,0x6E,0x3B,0x33,0x6E,0x00], // 38 '&'
    [0x06,0x06,0x03,0x00,0x00,0x00,0x00,0x00], // 39 '\''
    [0x18,0x0C,0x06,0x06,0x06,0x0C,0x18,0x00], // 40 '('
    [0x06,0x0C,0x18,0x18,0x18,0x0C,0x06,0x00], // 41 ')'
    [0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00], // 42 '*'
    [0x00,0x0C,0x0C,0x3F,0x0C,0x0C,0x00,0x00], // 43 '+'
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x06], // 44 ','
    [0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00], // 45 '-'
    [0x00,0x00,0x00,0x00,0x00,0x0C,0x0C,0x00], // 46 '.'
    [0x60,0x30,0x18,0x0C,0x06,0x03,0x01,0x00], // 47 '/'
    [0x3E,0x63,0x73,0x7B,0x6F,0x67,0x3E,0x00], // 48 '0'
    [0x0C,0x0E,0x0C,0x0C,0x0C,0x0C,0x3F,0x00], // 49 '1'
    [0x1E,0x33,0x30,0x1C,0x06,0x33,0x3F,0x00], // 50 '2'
    [0x1E,0x33,0x30,0x1C,0x30,0x33,0x1E,0x00], // 51 '3'
    [0x38,0x3C,0x36,0x33,0x7F,0x30,0x78,0x00], // 52 '4'
    [0x3F,0x03,0x1F,0x30,0x30,0x33,0x1E,0x00], // 53 '5'
    [0x1C,0x06,0x03,0x1F,0x33,0x33,0x1E,0x00], // 54 '6'
    [0x3F,0x33,0x30,0x18,0x0C,0x0C,0x0C,0x00], // 55 '7'
    [0x1E,0x33,0x33,0x1E,0x33,0x33,0x1E,0x00], // 56 '8'
    [0x1E,0x33,0x33,0x3E,0x30,0x18,0x0E,0x00], // 57 '9'
    [0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x00], // 58 ':'
    [0x00,0x0C,0x0C,0x00,0x00,0x0C,0x0C,0x06], // 59 ';'
    [0x18,0x0C,0x06,0x03,0x06,0x0C,0x18,0x00], // 60 '<'
    [0x00,0x00,0x3F,0x00,0x00,0x3F,0x00,0x00], // 61 '='
    [0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00], // 62 '>'
    [0x1E,0x33,0x30,0x18,0x0C,0x00,0x0C,0x00], // 63 '?'
    [0x3E,0x63,0x7B,0x7B,0x7B,0x03,0x1E,0x00], // 64 '@'
    [0x0C,0x1E,0x33,0x33,0x3F,0x33,0x33,0x00], // 65 'A'
    [0x3F,0x66,0x66,0x3E,0x66,0x66,0x3F,0x00], // 66 'B'
    [0x3C,0x66,0x03,0x03,0x03,0x66,0x3C,0x00], // 67 'C'
    [0x1F,0x36,0x66,0x66,0x66,0x36,0x1F,0x00], // 68 'D'
    [0x7F,0x46,0x16,0x1E,0x16,0x46,0x7F,0x00], // 69 'E'
    [0x7F,0x46,0x16,0x1E,0x16,0x06,0x0F,0x00], // 70 'F'
    [0x3C,0x66,0x03,0x03,0x73,0x66,0x7C,0x00], // 71 'G'
    [0x33,0x33,0x33,0x3F,0x33,0x33,0x33,0x00], // 72 'H'
    [0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 73 'I'
    [0x78,0x30,0x30,0x30,0x33,0x33,0x1E,0x00], // 74 'J'
    [0x67,0x66,0x36,0x1E,0x36,0x66,0x67,0x00], // 75 'K'
    [0x0F,0x06,0x06,0x06,0x46,0x66,0x7F,0x00], // 76 'L'
    [0x63,0x77,0x7F,0x7F,0x6B,0x63,0x63,0x00], // 77 'M'
    [0x63,0x67,0x6F,0x7B,0x73,0x63,0x63,0x00], // 78 'N'
    [0x1C,0x36,0x63,0x63,0x63,0x36,0x1C,0x00], // 79 'O'
    [0x3F,0x66,0x66,0x3E,0x06,0x06,0x0F,0x00], // 80 'P'
    [0x1E,0x33,0x33,0x33,0x3B,0x1E,0x38,0x00], // 81 'Q'
    [0x3F,0x66,0x66,0x3E,0x36,0x66,0x67,0x00], // 82 'R'
    [0x1E,0x33,0x07,0x0E,0x38,0x33,0x1E,0x00], // 83 'S'
    [0x3F,0x2D,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 84 'T'
    [0x33,0x33,0x33,0x33,0x33,0x33,0x3F,0x00], // 85 'U'
    [0x33,0x33,0x33,0x33,0x33,0x1E,0x0C,0x00], // 86 'V'
    [0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00], // 87 'W'
    [0x63,0x63,0x36,0x1C,0x1C,0x36,0x63,0x00], // 88 'X'
    [0x33,0x33,0x33,0x1E,0x0C,0x0C,0x1E,0x00], // 89 'Y'
    [0x7F,0x63,0x31,0x18,0x4C,0x66,0x7F,0x00], // 90 'Z'
    [0x1E,0x06,0x06,0x06,0x06,0x06,0x1E,0x00], // 91 '['
    [0x03,0x06,0x0C,0x18,0x30,0x60,0x40,0x00], // 92 '\\'
    [0x1E,0x18,0x18,0x18,0x18,0x18,0x1E,0x00], // 93 ']'
    [0x08,0x1C,0x36,0x63,0x00,0x00,0x00,0x00], // 94 '^'
    [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF], // 95 '_'
    [0x0C,0x0C,0x18,0x00,0x00,0x00,0x00,0x00], // 96 '`'
    [0x00,0x00,0x1E,0x30,0x3E,0x33,0x6E,0x00], // 97 'a'
    [0x07,0x06,0x06,0x3E,0x66,0x66,0x3B,0x00], // 98 'b'
    [0x00,0x00,0x1E,0x33,0x03,0x33,0x1E,0x00], // 99 'c'
    [0x38,0x30,0x30,0x3E,0x33,0x33,0x6E,0x00], // 100 'd'
    [0x00,0x00,0x1E,0x33,0x3F,0x03,0x1E,0x00], // 101 'e'
    [0x1C,0x36,0x06,0x0F,0x06,0x06,0x0F,0x00], // 102 'f'
    [0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x1F], // 103 'g'
    [0x07,0x06,0x36,0x6E,0x66,0x66,0x67,0x00], // 104 'h'
    [0x0C,0x00,0x0E,0x0C,0x0C,0x0C,0x1E,0x00], // 105 'i'
    [0x30,0x00,0x30,0x30,0x30,0x33,0x33,0x1E], // 106 'j'
    [0x07,0x06,0x66,0x36,0x1E,0x36,0x67,0x00], // 107 'k'
    [0x0E,0x0C,0x0C,0x0C,0x0C,0x0C,0x1E,0x00], // 108 'l'
    [0x00,0x00,0x33,0x7F,0x7F,0x6B,0x63,0x00], // 109 'm'
    [0x00,0x00,0x1F,0x33,0x33,0x33,0x33,0x00], // 110 'n'
    [0x00,0x00,0x1E,0x33,0x33,0x33,0x1E,0x00], // 111 'o'
    [0x00,0x00,0x3B,0x66,0x66,0x3E,0x06,0x0F], // 112 'p'
    [0x00,0x00,0x6E,0x33,0x33,0x3E,0x30,0x78], // 113 'q'
    [0x00,0x00,0x3B,0x6E,0x66,0x06,0x0F,0x00], // 114 'r'
    [0x00,0x00,0x3E,0x03,0x1E,0x30,0x1F,0x00], // 115 's'
    [0x08,0x0C,0x3E,0x0C,0x0C,0x2C,0x18,0x00], // 116 't'
    [0x00,0x00,0x33,0x33,0x33,0x33,0x6E,0x00], // 117 'u'
    [0x00,0x00,0x33,0x33,0x33,0x1E,0x0C,0x00], // 118 'v'
    [0x00,0x00,0x63,0x6B,0x7F,0x7F,0x36,0x00], // 119 'w'
    [0x00,0x00,0x63,0x36,0x1C,0x36,0x63,0x00], // 120 'x'
    [0x00,0x00,0x33,0x33,0x33,0x3E,0x30,0x1F], // 121 'y'
    [0x00,0x00,0x3F,0x19,0x0C,0x26,0x3F,0x00], // 122 'z'
    [0x38,0x0C,0x0C,0x07,0x0C,0x0C,0x38,0x00], // 123 '{'
    [0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00], // 124 '|'
    [0x07,0x0C,0x0C,0x38,0x0C,0x0C,0x07,0x00], // 125 '}'
    [0x6E,0x3B,0x00,0x00,0x00,0x00,0x00,0x00], // 126 '~'
];

struct Window {
    active: bool,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    buf_va: usize,    // compositor's VA for window pixel buffer
    buf_pages: usize,
    owner_task: u64,  // client's task port (for revoke)
    event_port: u64,  // port to send input/focus events to client
    granted_va: usize, // VA in client's address space
    z_order: u16,
    title: [u8; 16],
    title_len: u8,
}

impl Window {
    const fn empty() -> Self {
        Self {
            active: false,
            x: 0, y: 0, w: 0, h: 0,
            buf_va: 0, buf_pages: 0,
            owner_task: 0, event_port: 0,
            granted_va: 0, z_order: 0,
            title: [0; 16], title_len: 0,
        }
    }
}

struct Compositor {
    fb_va: usize,
    fb_w: u32,
    fb_h: u32,
    fb_pitch: u32,
    fb_port: u64,
    input_event_port: u64,
    windows: [Window; MAX_WINDOWS],
    focus: i8,       // -1 = no focus
    next_z: u16,
    mouse_x: i32,
    mouse_y: i32,
    flip_reply: u64,
    dirty: bool,
    dragging: i8,    // -1 = not dragging, else window index
    drag_off_x: i32, // offset from window origin to grab point
    drag_off_y: i32,
}

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

/// Poll for a reply on `port` with tag `expected_tag`. Returns first matching message.
fn poll_reply(port: u64, expected_tag: u64) -> Option<syscall::Message> {
    for _ in 0..500 {
        if let Some(msg) = syscall::recv_nb_msg(port) {
            if msg.tag == expected_tag {
                return Some(msg);
            }
            // Unexpected tag, discard.
            return None;
        }
        syscall::yield_now();
    }
    None
}

/// Connect to fb_srv: get info and map the framebuffer.
fn init_framebuffer() -> Option<(u64, usize, u32, u32, u32)> {
    // Retry ns_lookup for fb.
    let mut fb_port = None;
    for _ in 0..500 {
        fb_port = syscall::ns_lookup(b"fb");
        if fb_port.is_some() { break; }
        syscall::yield_now();
    }
    let fb_port = fb_port?;

    let reply = syscall::port_create();

    // FB_GET_INFO: get dimensions and physical address.
    syscall::send(fb_port, FB_GET_INFO, 0, 0, reply << 32, 0);
    let info = poll_reply(reply, FB_GET_INFO_OK)?;
    let fb_w = info.data[0] as u32;
    let fb_h = (info.data[0] >> 32) as u32;
    let fb_pitch = info.data[1] as u32;
    let _bpp = (info.data[1] >> 32) as u32;
    let fb_phys = info.data[2];

    // Map framebuffer directly via mmap_device (same as fb_srv does internally).
    let fb_bytes = fb_pitch as usize * fb_h as usize;
    let fb_pages_4k = (fb_bytes + 4095) / 4096;
    let fb_va = if fb_phys != 0 {
        match syscall::mmap_device(fb_phys as usize, fb_pages_4k) {
            Some(va) => va,
            None => return None,
        }
    } else {
        return None;
    };

    syscall::port_destroy(reply);

    if fb_va == 0 || fb_w == 0 || fb_h == 0 {
        return None;
    }

    Some((fb_port, fb_va, fb_w, fb_h, fb_pitch))
}

/// Subscribe to input_srv for keyboard/mouse events.
fn subscribe_input() -> u64 {
    let event_port = syscall::port_create();

    let mut input_port = None;
    for _ in 0..200 {
        input_port = syscall::ns_lookup(b"input");
        if input_port.is_some() { break; }
        syscall::yield_now();
    }

    if let Some(input_port) = input_port {
        let reply = syscall::port_create();
        syscall::send(input_port, INPUT_SUBSCRIBE, event_port, 0, reply << 32, 0);
        let _ = poll_reply(reply, INPUT_SUBSCRIBE_OK);
        syscall::port_destroy(reply);
    }

    event_port
}

impl Compositor {
    fn new(fb_port: u64, fb_va: usize, fb_w: u32, fb_h: u32, fb_pitch: u32, input_event_port: u64) -> Self {
        Self {
            fb_va,
            fb_w,
            fb_h,
            fb_pitch,
            fb_port,
            input_event_port,
            windows: [
                Window::empty(), Window::empty(), Window::empty(), Window::empty(),
                Window::empty(), Window::empty(), Window::empty(), Window::empty(),
            ],
            focus: -1,
            next_z: 1,
            mouse_x: (fb_w / 2) as i32,
            mouse_y: (fb_h / 2) as i32,
            flip_reply: syscall::port_create(),
            dirty: false,
            dragging: -1,
            drag_off_x: 0,
            drag_off_y: 0,
        }
    }

    fn alloc_window_slot(&self) -> Option<usize> {
        for i in 0..MAX_WINDOWS {
            if !self.windows[i].active {
                return Some(i);
            }
        }
        None
    }

    fn handle_create_window(&mut self, msg: &syscall::Message) {
        let x = msg.data[0] as i32;
        let y = (msg.data[0] >> 32) as i32;
        let w = msg.data[1] as u32;
        let h = (msg.data[1] >> 32) as u32;
        let event_port = msg.data[2] as u32 as u64;
        let reply_port = msg.data[2] >> 32;
        let desired_va = msg.data[3] as usize;
        let owner_task = msg.sender();

        // Validate.
        if w == 0 || h == 0 || w > self.fb_w || h > self.fb_h {
            syscall::send(reply_port, COMP_CREATE_WINDOW_OK, u64::MAX, 0, 0, 0);
            return;
        }

        let slot = match self.alloc_window_slot() {
            Some(s) => s,
            None => {
                syscall::send(reply_port, COMP_CREATE_WINDOW_OK, u64::MAX, 0, 0, 0);
                return;
            }
        };

        // Allocate buffer: w*h*4 bytes.
        let buf_bytes = (w as usize) * (h as usize) * 4;
        let buf_pages = (buf_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let buf_va = match syscall::mmap_anon(0, buf_pages, 1) {
            Some(va) => va,
            None => {
                syscall::send(reply_port, COMP_CREATE_WINDOW_OK, u64::MAX, 0, 0, 0);
                return;
            }
        };

        // Touch all pages to ensure physical backing.
        for p in 0..buf_pages {
            unsafe {
                ptr::write_volatile((buf_va + p * PAGE_SIZE) as *mut u8, 0);
            }
        }

        // Choose destination VA for client.
        let dst_va = if desired_va != 0 {
            desired_va
        } else {
            0x6_0000_0000 + slot * 0x100_0000 // 16MB apart per window
        };

        // Grant pages to client.
        let ok = syscall::grant_pages(owner_task, buf_va, dst_va, buf_pages, false);
        if !ok {
            syscall::munmap(buf_va);
            syscall::send(reply_port, COMP_CREATE_WINDOW_OK, u64::MAX, 0, 0, 0);
            return;
        }

        // Generate default title "Window N".
        let mut title = [0u8; 16];
        let prefix = b"Window ";
        let mut ti = 0;
        while ti < prefix.len() {
            title[ti] = prefix[ti];
            ti += 1;
        }
        title[ti] = b'0' + (slot as u8);
        let title_len = (ti + 1) as u8;

        self.windows[slot] = Window {
            active: true,
            x, y,
            w, h,
            buf_va,
            buf_pages,
            owner_task,
            event_port,
            granted_va: dst_va,
            z_order: self.next_z,
            title,
            title_len,
        };
        self.next_z += 1;
        self.focus = slot as i8;
        self.dirty = true;

        syscall::send(
            reply_port,
            COMP_CREATE_WINDOW_OK,
            slot as u64,
            dst_va as u64,
            buf_bytes as u64,
            0,
        );
    }

    fn handle_destroy_window(&mut self, msg: &syscall::Message) {
        let win_id = msg.data[0] as usize;
        let reply_port = msg.data[2] >> 32;

        if win_id >= MAX_WINDOWS || !self.windows[win_id].active {
            syscall::send(reply_port, COMP_DESTROY_WINDOW_OK, u64::MAX, 0, 0, 0);
            return;
        }

        let win = &self.windows[win_id];
        let _ = syscall::revoke(win.owner_task, win.granted_va);
        syscall::munmap(win.buf_va);

        self.windows[win_id] = Window::empty();

        if self.focus == win_id as i8 {
            self.focus = -1;
            // Find next topmost window.
            let mut best_z = 0u16;
            for i in 0..MAX_WINDOWS {
                if self.windows[i].active && self.windows[i].z_order >= best_z {
                    best_z = self.windows[i].z_order;
                    self.focus = i as i8;
                }
            }
        }
        self.dirty = true;

        syscall::send(reply_port, COMP_DESTROY_WINDOW_OK, 0, 0, 0, 0);
    }

    fn handle_commit(&mut self, msg: &syscall::Message) {
        let win_id = msg.data[0] as usize;
        let reply_port = msg.data[2] >> 32;

        if win_id >= MAX_WINDOWS || !self.windows[win_id].active {
            syscall::send(reply_port, COMP_COMMIT_OK, u64::MAX, 0, 0, 0);
            return;
        }

        self.composite();
        self.flip();

        syscall::send(reply_port, COMP_COMMIT_OK, 0, 0, 0, 0);
    }

    fn handle_move_window(&mut self, msg: &syscall::Message) {
        let win_id = msg.data[0] as usize;
        let new_x = msg.data[1] as i32;
        let new_y = (msg.data[1] >> 32) as i32;
        let reply_port = msg.data[2] >> 32;

        if win_id >= MAX_WINDOWS || !self.windows[win_id].active {
            syscall::send(reply_port, COMP_MOVE_WINDOW_OK, u64::MAX, 0, 0, 0);
            return;
        }

        self.windows[win_id].x = new_x;
        self.windows[win_id].y = new_y;
        self.dirty = true;

        syscall::send(reply_port, COMP_MOVE_WINDOW_OK, 0, 0, 0, 0);
    }

    fn handle_get_info(&self, msg: &syscall::Message) {
        let reply_port = msg.data[2] >> 32;
        let wh = (self.fb_w as u64) | ((self.fb_h as u64) << 32);
        let mw_bpp = (MAX_WINDOWS as u64) | (32u64 << 32);
        syscall::send(reply_port, COMP_GET_INFO_OK, wh, mw_bpp, 0, 0);
    }

    /// Fill the entire framebuffer with the background color.
    fn fill_background(&self) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4; // pixels per row
        for y in 0..self.fb_h as usize {
            for x in 0..self.fb_w as usize {
                unsafe {
                    ptr::write_volatile(fb.add(y * stride + x), BG_COLOR);
                }
            }
        }
    }

    /// Draw a border around a window (including title bar area).
    fn draw_border(&self, win: &Window, color: u32) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;
        let bw = BORDER_WIDTH;

        // Border extends around content + title bar.
        let bx0 = win.x - bw;
        let by0 = win.y - TITLEBAR_H - bw;
        let bx1 = win.x + win.w as i32 + bw;
        let by1 = win.y + win.h as i32 + bw;

        for sy in by0..by1 {
            if sy < 0 || sy >= self.fb_h as i32 { continue; }
            for sx in bx0..bx1 {
                if sx < 0 || sx >= self.fb_w as i32 { continue; }
                // Only draw if in the border region (not content or titlebar).
                let in_content = sx >= win.x && sx < win.x + win.w as i32
                    && sy >= win.y && sy < win.y + win.h as i32;
                let in_titlebar = sx >= win.x && sx < win.x + win.w as i32
                    && sy >= win.y - TITLEBAR_H && sy < win.y;
                if !in_content && !in_titlebar {
                    unsafe {
                        ptr::write_volatile(
                            fb.add(sy as usize * stride + sx as usize),
                            color,
                        );
                    }
                }
            }
        }
    }

    /// Draw title bar above a window.
    fn draw_titlebar(&self, win: &Window, focused: bool) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;
        let bg = if focused { TITLEBAR_FOCUSED_BG } else { TITLEBAR_BG };

        // Title bar region: win.x .. win.x+win.w, win.y-TITLEBAR_H .. win.y
        for sy in (win.y - TITLEBAR_H)..win.y {
            if sy < 0 || sy >= self.fb_h as i32 { continue; }
            for sx in win.x..(win.x + win.w as i32) {
                if sx < 0 || sx >= self.fb_w as i32 { continue; }
                unsafe {
                    ptr::write_volatile(fb.add(sy as usize * stride + sx as usize), bg);
                }
            }
        }

        // Draw title text centered vertically in title bar.
        let text_y = win.y - TITLEBAR_H + (TITLEBAR_H - 8) / 2;
        let text_x = win.x + 4; // small left padding
        self.draw_text(text_x, text_y, &win.title[..win.title_len as usize], TITLEBAR_TEXT_COLOR);

        // Draw close button (14x14 red square with white X) in top-right.
        let btn_x = win.x + win.w as i32 - CLOSE_BTN_SIZE - 3;
        let btn_y = win.y - TITLEBAR_H + 3;
        for cy in 0..CLOSE_BTN_SIZE {
            let sy = btn_y + cy;
            if sy < 0 || sy >= self.fb_h as i32 { continue; }
            for cx in 0..CLOSE_BTN_SIZE {
                let sx = btn_x + cx;
                if sx < 0 || sx >= self.fb_w as i32 { continue; }
                // Draw X: two diagonals in the inner 8x8 region (offset 3..11).
                let ix = cx - 3;
                let iy = cy - 3;
                let on_x = ix >= 0 && ix < 8 && iy >= 0 && iy < 8
                    && ((ix - iy).abs() <= 1 || (ix - (7 - iy)).abs() <= 1);
                let color = if on_x { CLOSE_BTN_X_COLOR } else { CLOSE_BTN_COLOR };
                unsafe {
                    ptr::write_volatile(fb.add(sy as usize * stride + sx as usize), color);
                }
            }
        }
    }

    /// Draw text using the embedded 8x8 font.
    fn draw_text(&self, x: i32, y: i32, text: &[u8], color: u32) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;

        for (i, &ch) in text.iter().enumerate() {
            let gx = x + (i as i32) * 8;
            let glyph_idx = if ch >= 32 && ch <= 126 { (ch - 32) as usize } else { 0 };
            let glyph = &FONT_8X8[glyph_idx];

            for row in 0..8 {
                let sy = y + row as i32;
                if sy < 0 || sy >= self.fb_h as i32 { continue; }
                let bits = glyph[row];
                for col in 0..8 {
                    let sx = gx + col as i32;
                    if sx < 0 || sx >= self.fb_w as i32 { continue; }
                    if bits & (0x80 >> col) != 0 {
                        unsafe {
                            ptr::write_volatile(fb.add(sy as usize * stride + sx as usize), color);
                        }
                    }
                }
            }
        }
    }

    /// Draw the software mouse cursor on the framebuffer.
    /// Draw the taskbar at the bottom of the screen.
    fn draw_taskbar(&self) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;
        let bar_y = self.fb_h as i32 - TASKBAR_H;

        // Fill taskbar background.
        for sy in bar_y..(self.fb_h as i32) {
            if sy < 0 { continue; }
            for sx in 0..self.fb_w as i32 {
                unsafe {
                    ptr::write_volatile(fb.add(sy as usize * stride + sx as usize), TASKBAR_BG);
                }
            }
        }

        // Collect active windows.
        let mut active = [0u8; MAX_WINDOWS];
        let mut count = 0usize;
        for i in 0..MAX_WINDOWS {
            if self.windows[i].active {
                active[count] = i as u8;
                count += 1;
            }
        }
        if count == 0 { return; }

        let max_btn_w: i32 = 150;
        let total_gap = TASKBAR_BTN_GAP * (count as i32 + 1);
        let avail = self.fb_w as i32 - total_gap;
        let btn_w = (avail / count as i32).min(max_btn_w);
        let btn_y = bar_y + 3;

        for i in 0..count {
            let idx = active[i] as usize;
            let btn_x = TASKBAR_BTN_GAP + i as i32 * (btn_w + TASKBAR_BTN_GAP);
            let focused = self.focus == idx as i8;
            let bg = if focused { TASKBAR_BTN_FOCUSED } else { TASKBAR_BTN_BG };

            // Draw button rectangle.
            for sy in btn_y..(btn_y + TASKBAR_BTN_H) {
                if sy < 0 || sy >= self.fb_h as i32 { continue; }
                for sx in btn_x..(btn_x + btn_w) {
                    if sx >= 0 && sx < self.fb_w as i32 {
                        unsafe {
                            ptr::write_volatile(fb.add(sy as usize * stride + sx as usize), bg);
                        }
                    }
                }
            }

            // Draw title text (truncated to fit button).
            let win = &self.windows[idx];
            let max_chars = if btn_w > 8 { ((btn_w - 8) / 8) as usize } else { 0 };
            let text_len = (win.title_len as usize).min(max_chars);
            if text_len > 0 {
                let text_y = btn_y + (TASKBAR_BTN_H - 8) / 2;
                self.draw_text(btn_x + 4, text_y, &win.title[..text_len], TITLEBAR_TEXT_COLOR);
            }
        }
    }

    fn draw_cursor(&self) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;

        for cy in 0..CURSOR_H {
            let sy = self.mouse_y + cy as i32;
            if sy < 0 || sy >= self.fb_h as i32 { continue; }
            let mask_bits = CURSOR_MASK[cy];
            let fill_bits = CURSOR_FILL[cy];
            for cx in 0..CURSOR_W {
                let sx = self.mouse_x + cx as i32;
                if sx < 0 || sx >= self.fb_w as i32 { continue; }
                let bit = 1u16 << (CURSOR_W - 1 - cx);
                if mask_bits & bit != 0 {
                    let color = if fill_bits & bit != 0 { 0x00FFFFFFu32 } else { 0x00000000u32 };
                    unsafe {
                        ptr::write_volatile(fb.add(sy as usize * stride + sx as usize), color);
                    }
                }
            }
        }
    }

    /// Blit a window's pixel buffer onto the framebuffer.
    fn blit_window(&self, win: &Window) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;
        let src = win.buf_va as *const u32;
        let sw = win.w as usize;

        for row in 0..win.h as usize {
            let sy = win.y + row as i32;
            if sy < 0 || sy >= self.fb_h as i32 { continue; }
            for col in 0..win.w as usize {
                let sx = win.x + col as i32;
                if sx < 0 || sx >= self.fb_w as i32 { continue; }
                let pixel = unsafe { ptr::read_volatile(src.add(row * sw + col)) };
                unsafe {
                    ptr::write_volatile(
                        fb.add(sy as usize * stride + sx as usize),
                        pixel,
                    );
                }
            }
        }
    }

    /// Full-screen composite: background + all windows in z-order.
    fn composite(&self) {
        self.fill_background();

        // Sort windows by z_order (ascending = back to front).
        // With max 8 windows, simple selection sort.
        let mut order = [0u8; MAX_WINDOWS];
        let mut count = 0;
        for i in 0..MAX_WINDOWS {
            if self.windows[i].active {
                order[count] = i as u8;
                count += 1;
            }
        }
        // Insertion sort by z_order.
        for i in 1..count {
            let mut j = i;
            while j > 0 && self.windows[order[j] as usize].z_order
                < self.windows[order[j - 1] as usize].z_order
            {
                order.swap(j, j - 1);
                j -= 1;
            }
        }

        // Draw back to front.
        for i in 0..count {
            let idx = order[i] as usize;
            let win = &self.windows[idx];
            let focused = self.focus == idx as i8;
            let border_color = if focused {
                BORDER_FOCUSED_COLOR
            } else {
                BORDER_COLOR
            };
            self.draw_border(win, border_color);
            self.draw_titlebar(win, focused);
            self.blit_window(win);
        }

        // Draw taskbar at bottom of screen.
        self.draw_taskbar();

        // Draw mouse cursor on top of everything.
        self.draw_cursor();
    }

    /// Send FB_FLIP to fb_srv.
    fn flip(&self) {
        let wh = (self.fb_w as u64) | ((self.fb_h as u64) << 32);
        syscall::send(self.fb_port, FB_FLIP, 0, wh, self.flip_reply << 32, 0);
        // Drain reply (non-blocking).
        for _ in 0..50 {
            if syscall::recv_nb_msg(self.flip_reply).is_some() {
                break;
            }
            syscall::yield_now();
        }
    }

    /// Handle an input event from input_srv.
    fn handle_input_event(&mut self, msg: &syscall::Message) {
        let d0 = msg.data[0];
        let event_type = (d0 & 0xFF) as u8;
        let extra = msg.data[1];

        match event_type {
            EVENT_KEY_DOWN => {
                let keycode = ((d0 >> 8) & 0xFF) as u8;
                let alt = (d0 >> 26) & 1 != 0;

                if alt {
                    match keycode {
                        0x0F => { // Alt+Tab: cycle focus
                            self.cycle_focus();
                            self.dirty = true;
                            return;
                        }
                        0x1C => { // Alt+Enter: spawn new terminal
                            self.spawn_terminal();
                            return;
                        }
                        0x3E => { // Alt+F4: close focused window
                            if self.focus >= 0 {
                                let idx = self.focus as usize;
                                self.close_window(idx);
                            }
                            return;
                        }
                        _ => {}
                    }
                }
            }
            EVENT_MOUSE_MOVE => {
                let dx = extra as u16 as i16;
                let dy = (extra >> 16) as u16 as i16;
                self.mouse_x = (self.mouse_x + dx as i32)
                    .max(0)
                    .min(self.fb_w as i32 - 1);
                self.mouse_y = (self.mouse_y + dy as i32)
                    .max(0)
                    .min(self.fb_h as i32 - 1);
                self.dirty = true;

                // Update drag position if dragging.
                if self.dragging >= 0 {
                    let idx = self.dragging as usize;
                    if idx < MAX_WINDOWS && self.windows[idx].active {
                        self.windows[idx].x = self.mouse_x - self.drag_off_x;
                        self.windows[idx].y = self.mouse_y - self.drag_off_y;
                    }
                }
            }
            EVENT_MOUSE_BUTTON => {
                let left_pressed = extra & 1 != 0;
                if left_pressed {
                    // Check if click is in a title bar → start drag.
                    let mut drag_target: i8 = -1;
                    let mut best_z: u16 = 0;
                    for i in 0..MAX_WINDOWS {
                        let win = &self.windows[i];
                        if !win.active { continue; }
                        if self.mouse_x >= win.x && self.mouse_x < win.x + win.w as i32
                            && self.mouse_y >= win.y - TITLEBAR_H && self.mouse_y < win.y
                        {
                            if drag_target == -1 || win.z_order > best_z {
                                drag_target = i as i8;
                                best_z = win.z_order;
                            }
                        }
                    }
                    if drag_target >= 0 {
                        // Check if click is on the close button.
                        let win = &self.windows[drag_target as usize];
                        let btn_x = win.x + win.w as i32 - CLOSE_BTN_SIZE - 3;
                        let btn_y = win.y - TITLEBAR_H + 3;
                        if self.mouse_x >= btn_x && self.mouse_x < btn_x + CLOSE_BTN_SIZE
                            && self.mouse_y >= btn_y && self.mouse_y < btn_y + CLOSE_BTN_SIZE
                        {
                            self.close_window(drag_target as usize);
                        } else {
                            self.dragging = drag_target;
                            self.drag_off_x = self.mouse_x - win.x;
                            self.drag_off_y = self.mouse_y - win.y;
                        }
                    }

                    // Click-to-focus (title bar or content).
                    self.handle_click();
                } else {
                    // Button release → end drag.
                    self.dragging = -1;
                }
            }
            _ => {}
        }

        // Forward to focused window.
        if self.focus >= 0 && self.focus < MAX_WINDOWS as i8 {
            let win = &self.windows[self.focus as usize];
            if win.active && win.event_port != 0 {
                let abs = (self.mouse_x as u32 as u64) | ((self.mouse_y as u32 as u64) << 32);
                syscall::send_nb_4(win.event_port, COMP_INPUT_EVENT, d0, extra, abs, 0);
            }
        }
    }

    /// Cycle focus to next active window (Alt+Tab).
    fn cycle_focus(&mut self) {
        let start = if self.focus >= 0 { self.focus as usize } else { 0 };
        for offset in 1..=MAX_WINDOWS {
            let idx = (start + offset) % MAX_WINDOWS;
            if self.windows[idx].active {
                let old_focus = self.focus;
                self.focus = idx as i8;
                // Raise to top.
                self.windows[idx].z_order = self.next_z;
                self.next_z += 1;
                // Send focus events.
                if old_focus >= 0 && old_focus != idx as i8 {
                    let old = &self.windows[old_focus as usize];
                    if old.active && old.event_port != 0 {
                        syscall::send_nb_4(old.event_port, COMP_FOCUS_EVENT, 0, 0, 0, 0);
                    }
                }
                let new_win = &self.windows[idx];
                if new_win.event_port != 0 {
                    syscall::send_nb_4(new_win.event_port, COMP_FOCUS_EVENT, 1, 0, 0, 0);
                }
                return;
            }
        }
    }

    /// Spawn a new terminal emulator window (Alt+Enter).
    fn spawn_terminal(&self) {
        let tid = syscall::spawn(b"term_srv", 50);
        if tid == u64::MAX {
            syscall::debug_puts(b"  [compositor] spawn term_srv failed\n");
        }
    }

    /// Close a window: notify client, then destroy.
    fn close_window(&mut self, idx: usize) {
        if idx >= MAX_WINDOWS || !self.windows[idx].active {
            return;
        }
        // Notify client of impending close.
        let win = &self.windows[idx];
        if win.event_port != 0 {
            syscall::send_nb_4(win.event_port, COMP_CLOSE_EVENT, 0, 0, 0, 0);
        }
        // Destroy: revoke, munmap, clear slot.
        let _ = syscall::revoke(win.owner_task, win.granted_va);
        syscall::munmap(win.buf_va);
        self.windows[idx] = Window::empty();

        if self.focus == idx as i8 {
            self.focus = -1;
            let mut best_z = 0u16;
            for i in 0..MAX_WINDOWS {
                if self.windows[i].active && self.windows[i].z_order >= best_z {
                    best_z = self.windows[i].z_order;
                    self.focus = i as i8;
                }
            }
        }
        // End any drag on this window.
        if self.dragging == idx as i8 {
            self.dragging = -1;
        }
        self.dirty = true;
    }

    /// Click-to-focus: find topmost window under mouse cursor (content or title bar).
    fn handle_click(&mut self) {
        let mx = self.mouse_x;
        let my = self.mouse_y;

        // Check for taskbar click.
        if my >= self.fb_h as i32 - TASKBAR_H {
            // Determine which button was clicked using the same layout as draw_taskbar.
            let mut active = [0u8; MAX_WINDOWS];
            let mut count = 0usize;
            for i in 0..MAX_WINDOWS {
                if self.windows[i].active {
                    active[count] = i as u8;
                    count += 1;
                }
            }
            if count > 0 {
                let max_btn_w: i32 = 150;
                let total_gap = TASKBAR_BTN_GAP * (count as i32 + 1);
                let avail = self.fb_w as i32 - total_gap;
                let btn_w = (avail / count as i32).min(max_btn_w);

                for i in 0..count {
                    let btn_x = TASKBAR_BTN_GAP + i as i32 * (btn_w + TASKBAR_BTN_GAP);
                    if mx >= btn_x && mx < btn_x + btn_w {
                        let idx = active[i] as usize;
                        let old_focus = self.focus;
                        self.focus = idx as i8;
                        self.windows[idx].z_order = self.next_z;
                        self.next_z += 1;
                        if old_focus >= 0 && old_focus != idx as i8 {
                            let old = &self.windows[old_focus as usize];
                            if old.active && old.event_port != 0 {
                                syscall::send_nb_4(old.event_port, COMP_FOCUS_EVENT, 0, 0, 0, 0);
                            }
                        }
                        let new_win = &self.windows[idx];
                        if new_win.event_port != 0 {
                            syscall::send_nb_4(new_win.event_port, COMP_FOCUS_EVENT, 1, 0, 0, 0);
                        }
                        self.dirty = true;
                        return;
                    }
                }
            }
            return;
        }

        // Find window with highest z_order that contains (mx, my) in content or title bar.
        let mut best: i8 = -1;
        let mut best_z: u16 = 0;
        for i in 0..MAX_WINDOWS {
            let win = &self.windows[i];
            if !win.active { continue; }
            if mx >= win.x && mx < win.x + win.w as i32
                && my >= win.y - TITLEBAR_H && my < win.y + win.h as i32
            {
                if best == -1 || win.z_order > best_z {
                    best = i as i8;
                    best_z = win.z_order;
                }
            }
        }

        if best >= 0 && best != self.focus {
            let old_focus = self.focus;
            self.focus = best;
            // Raise to top.
            self.windows[best as usize].z_order = self.next_z;
            self.next_z += 1;

            // Notify old focused window.
            if old_focus >= 0 {
                let old = &self.windows[old_focus as usize];
                if old.active && old.event_port != 0 {
                    syscall::send_nb_4(old.event_port, COMP_FOCUS_EVENT, 0, 0, 0, 0);
                }
            }
            // Notify new focused window.
            let new_win = &self.windows[best as usize];
            if new_win.event_port != 0 {
                syscall::send_nb_4(new_win.event_port, COMP_FOCUS_EVENT, 1, 0, 0, 0);
            }

            self.dirty = true;
        }
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [compositor_srv] starting\n");

    // Connect to fb_srv.
    let (fb_port, fb_va, fb_w, fb_h, fb_pitch) = match init_framebuffer() {
        Some(info) => info,
        None => {
            syscall::debug_puts(b"  [compositor_srv] ERROR: failed to connect to fb_srv\n");
            loop { syscall::yield_now(); }
        }
    };

    // Subscribe to input_srv.
    let input_event_port = subscribe_input();

    // Create service port and register.
    let port = syscall::port_create();
    syscall::ns_register(b"compositor", port);

    let mut comp = Compositor::new(fb_port, fb_va, fb_w, fb_h, fb_pitch, input_event_port);

    // Skip initial fill — will composite on first COMMIT.

    syscall::debug_puts(b"  [compositor_srv] ready (");
    print_num(fb_w as u64);
    syscall::debug_puts(b"x");
    print_num(fb_h as u64);
    syscall::debug_puts(b"), port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    // Main loop.
    loop {
        // Check for input events.
        if let Some(msg) = syscall::recv_nb_msg(input_event_port) {
            if msg.tag == INPUT_EVENT {
                comp.handle_input_event(&msg);
            }
            continue;
        }

        // Check for client IPC.
        if let Some(msg) = syscall::recv_nb_msg(port) {
            match msg.tag {
                COMP_CREATE_WINDOW => comp.handle_create_window(&msg),
                COMP_DESTROY_WINDOW => comp.handle_destroy_window(&msg),
                COMP_COMMIT => comp.handle_commit(&msg),
                COMP_MOVE_WINDOW => comp.handle_move_window(&msg),
                COMP_GET_INFO => comp.handle_get_info(&msg),
                _ => {}
            }
            continue;
        }

        // If dirty from focus change or move, recomposite.
        if comp.dirty {
            comp.dirty = false;
            comp.composite();
            comp.flip();
        }

        syscall::sleep_ms(1);
    }
}
