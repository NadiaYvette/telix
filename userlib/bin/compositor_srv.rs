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

// Page size for mmap_anon (allocation pages).
const PAGE_SIZE: usize = 4096;

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
}

impl Window {
    const fn empty() -> Self {
        Self {
            active: false,
            x: 0, y: 0, w: 0, h: 0,
            buf_va: 0, buf_pages: 0,
            owner_task: 0, event_port: 0,
            granted_va: 0, z_order: 0,
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

    /// Draw a border around a window.
    fn draw_border(&self, win: &Window, color: u32) {
        let fb = self.fb_va as *mut u32;
        let stride = self.fb_pitch as usize / 4;
        let bw = BORDER_WIDTH;

        // Border extends outside the window content area.
        let bx0 = win.x - bw;
        let by0 = win.y - bw;
        let bx1 = win.x + win.w as i32 + bw;
        let by1 = win.y + win.h as i32 + bw;

        for sy in by0..by1 {
            if sy < 0 || sy >= self.fb_h as i32 { continue; }
            for sx in bx0..bx1 {
                if sx < 0 || sx >= self.fb_w as i32 { continue; }
                // Only draw if in the border region (not the content area).
                let in_content = sx >= win.x && sx < win.x + win.w as i32
                    && sy >= win.y && sy < win.y + win.h as i32;
                if !in_content {
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
            let border_color = if self.focus == idx as i8 {
                BORDER_FOCUSED_COLOR
            } else {
                BORDER_COLOR
            };
            self.draw_border(win, border_color);
            self.blit_window(win);
        }
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
            EVENT_MOUSE_MOVE => {
                let dx = extra as u16 as i16;
                let dy = (extra >> 16) as u16 as i16;
                self.mouse_x = (self.mouse_x + dx as i32)
                    .max(0)
                    .min(self.fb_w as i32 - 1);
                self.mouse_y = (self.mouse_y + dy as i32)
                    .max(0)
                    .min(self.fb_h as i32 - 1);
            }
            EVENT_MOUSE_BUTTON => {
                // Click-to-focus: find topmost window under cursor.
                self.handle_click();
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

    /// Click-to-focus: find topmost window under mouse cursor.
    fn handle_click(&mut self) {
        let mx = self.mouse_x;
        let my = self.mouse_y;

        // Find window with highest z_order that contains (mx, my).
        let mut best: i8 = -1;
        let mut best_z: u16 = 0;
        for i in 0..MAX_WINDOWS {
            let win = &self.windows[i];
            if !win.active { continue; }
            if mx >= win.x && mx < win.x + win.w as i32
                && my >= win.y && my < win.y + win.h as i32
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
