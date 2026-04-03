#![no_std]
#![no_main]

//! Graphical terminal emulator: renders text in a compositor window,
//! bridges keyboard input to a PTY-connected shell.
//!
//! Creates a compositor window (640x200, 80x25 chars with 8x8 font),
//! opens a PTY pair via pty_srv, spawns tsh on the slave side, and
//! runs a poll loop shuttling keyboard→PTY and PTY output→pixels.

extern crate userlib;

use core::ptr;
use userlib::syscall;

// --- Compositor IPC (0xA0xx) ---
const COMP_CREATE_WINDOW: u64 = 0xA000;
const COMP_CREATE_WINDOW_OK: u64 = 0xA001;
const COMP_COMMIT: u64 = 0xA004;
const COMP_COMMIT_OK: u64 = 0xA005;
const COMP_GET_INFO: u64 = 0xA008;
#[allow(dead_code)]
const COMP_GET_INFO_OK: u64 = 0xA009;
const COMP_INPUT_EVENT: u64 = 0xA00A;
const COMP_CLOSE_EVENT: u64 = 0xA00E;

// --- PTY IPC (0x90xx) ---
const PTY_OPEN: u64 = 0x9000;
const PTY_OPEN_OK: u64 = 0x9001;
const PTY_WRITE: u64 = 0x9010;
const PTY_WRITE_OK: u64 = 0x9011;
const PTY_READ: u64 = 0x9020;
const PTY_READ_OK: u64 = 0x9021;
const PTY_POLL: u64 = 0x9050;
const PTY_POLL_OK: u64 = 0x9051;

// Input event types.
const EVENT_KEY_DOWN: u8 = 1;

// Terminal dimensions.
const TERM_COLS: usize = 80;
const TERM_ROWS: usize = 25;
const WIN_W: usize = TERM_COLS * 8;  // 640
const WIN_H: usize = TERM_ROWS * 8;  // 200

const FG_COLOR: u32 = 0x00C0C0C0; // light gray
const BG_COLOR: u32 = 0x00000000; // black
const CURSOR_COLOR: u32 = 0x00808080; // gray cursor block

// Standard ANSI 16-color palette (8 normal + 8 bright).
#[rustfmt::skip]
const ANSI_COLORS: [u32; 16] = [
    0x00000000, 0x00AA0000, 0x0000AA00, 0x00AA5500, // black, red, green, yellow
    0x000000AA, 0x00AA00AA, 0x0000AAAA, 0x00AAAAAA, // blue, magenta, cyan, white
    0x00555555, 0x00FF5555, 0x0055FF55, 0x00FFFF55, // bright: black, red, green, yellow
    0x005555FF, 0x00FF55FF, 0x0055FFFF, 0x00FFFFFF, // bright: blue, magenta, cyan, white
];

#[derive(Copy, Clone)]
struct Cell {
    ch: u8,
    fg: u32,
    bg: u32,
}

const DEFAULT_CELL: Cell = Cell { ch: b' ', fg: FG_COLOR, bg: BG_COLOR };

// Desired VA for compositor window buffer grant.
const TERM_BUF_VA: usize = 0x7_0000_0000;

// --- 8x8 bitmap font (ASCII 32..126, 95 glyphs) ---
// Each glyph: 8 bytes, 1 per row, bit 7 = leftmost pixel.
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

struct Terminal {
    comp_port: u64,
    event_port: u64,
    reply_port: u64,
    win_id: u64,
    buf_va: usize,

    pty_port: u64,
    pty_reply: u64,
    master_h: u32,

    cells: [[Cell; TERM_COLS]; TERM_ROWS],
    cursor_col: usize,
    cursor_row: usize,
    dirty: bool,

    // Current text attributes (applied to new characters).
    cur_fg: u32,
    cur_bg: u32,
    bold: bool,

    // ANSI escape sequence parser state.
    esc_state: u8,          // 0=Normal, 1=ESC seen, 2=CSI collecting
    esc_params: [u16; 8],
    esc_param_count: u8,
    esc_intermediate: u8,   // '?' for DEC private sequences

    // Saved cursor position.
    saved_col: usize,
    saved_row: usize,
}

impl Terminal {
    fn put_char(&mut self, ch: u8) {
        match self.esc_state {
            1 => {
                // ESC seen — waiting for '[' or other.
                if ch == b'[' {
                    self.esc_state = 2;
                    self.esc_params = [0; 8];
                    self.esc_param_count = 0;
                    self.esc_intermediate = 0;
                } else {
                    self.esc_state = 0; // unrecognized, reset
                }
                return;
            }
            2 => {
                // CSI: collecting parameters.
                if ch >= b'0' && ch <= b'9' {
                    let idx = self.esc_param_count as usize;
                    if idx < 8 {
                        self.esc_params[idx] = self.esc_params[idx]
                            .wrapping_mul(10)
                            .wrapping_add((ch - b'0') as u16);
                    }
                } else if ch == b';' {
                    if self.esc_param_count < 7 {
                        self.esc_param_count += 1;
                    }
                } else if ch == b'?' {
                    self.esc_intermediate = b'?';
                } else if ch >= 0x40 && ch <= 0x7E {
                    // Final byte — dispatch command.
                    let count = self.esc_param_count as usize + 1;
                    self.dispatch_csi(ch, count);
                    self.esc_state = 0;
                } else {
                    self.esc_state = 0; // unexpected, reset
                }
                self.dirty = true;
                return;
            }
            _ => {}
        }

        // Normal mode.
        if ch == 0x1B {
            self.esc_state = 1;
            return;
        }

        match ch {
            b'\n' => {
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= TERM_ROWS {
                    self.scroll_up();
                    self.cursor_row = TERM_ROWS - 1;
                }
            }
            b'\r' => {
                self.cursor_col = 0;
            }
            0x08 => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                }
            }
            0x7F => {
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    self.cells[self.cursor_row][self.cursor_col] = DEFAULT_CELL;
                }
            }
            0x09 => {
                let next = (self.cursor_col + 8) & !7;
                self.cursor_col = if next < TERM_COLS { next } else { TERM_COLS - 1 };
            }
            ch if ch >= 32 && ch < 127 => {
                self.cells[self.cursor_row][self.cursor_col] = Cell {
                    ch,
                    fg: self.cur_fg,
                    bg: self.cur_bg,
                };
                self.cursor_col += 1;
                if self.cursor_col >= TERM_COLS {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= TERM_ROWS {
                        self.scroll_up();
                        self.cursor_row = TERM_ROWS - 1;
                    }
                }
            }
            _ => {}
        }
        self.dirty = true;
    }

    fn dispatch_csi(&mut self, cmd: u8, count: usize) {
        let p0 = self.esc_params[0] as usize;
        let p1 = if count > 1 { self.esc_params[1] as usize } else { 0 };

        match cmd {
            b'A' => { // CUU — cursor up
                let n = if p0 == 0 { 1 } else { p0 };
                self.cursor_row = self.cursor_row.saturating_sub(n);
            }
            b'B' => { // CUD — cursor down
                let n = if p0 == 0 { 1 } else { p0 };
                self.cursor_row = (self.cursor_row + n).min(TERM_ROWS - 1);
            }
            b'C' => { // CUF — cursor forward
                let n = if p0 == 0 { 1 } else { p0 };
                self.cursor_col = (self.cursor_col + n).min(TERM_COLS - 1);
            }
            b'D' => { // CUB — cursor back
                let n = if p0 == 0 { 1 } else { p0 };
                self.cursor_col = self.cursor_col.saturating_sub(n);
            }
            b'H' | b'f' => { // CUP — cursor position (1-based)
                let row = if p0 == 0 { 1 } else { p0 };
                let col = if p1 == 0 { 1 } else { p1 };
                self.cursor_row = (row - 1).min(TERM_ROWS - 1);
                self.cursor_col = (col - 1).min(TERM_COLS - 1);
            }
            b'J' => { // ED — erase display
                self.erase_display(p0);
            }
            b'K' => { // EL — erase line
                self.erase_line(p0);
            }
            b'm' => { // SGR — set graphic rendition
                self.handle_sgr(count);
            }
            b's' => { // SCP — save cursor position
                self.saved_col = self.cursor_col;
                self.saved_row = self.cursor_row;
            }
            b'u' => { // RCP — restore cursor position
                self.cursor_col = self.saved_col.min(TERM_COLS - 1);
                self.cursor_row = self.saved_row.min(TERM_ROWS - 1);
            }
            b'h' | b'l' => {
                // DEC private modes (CSI ? n h/l) — ignore silently.
            }
            _ => {} // unrecognized
        }
    }

    fn handle_sgr(&mut self, count: usize) {
        if count == 1 && self.esc_params[0] == 0 {
            // CSI m with no params → reset.
            self.cur_fg = FG_COLOR;
            self.cur_bg = BG_COLOR;
            self.bold = false;
            return;
        }
        let mut i = 0;
        while i < count {
            let p = self.esc_params[i] as usize;
            match p {
                0 => {
                    self.cur_fg = FG_COLOR;
                    self.cur_bg = BG_COLOR;
                    self.bold = false;
                }
                1 => {
                    self.bold = true;
                    // If current fg is a basic ANSI color, upgrade to bright.
                    for c in 0..8 {
                        if self.cur_fg == ANSI_COLORS[c] {
                            self.cur_fg = ANSI_COLORS[c + 8];
                            break;
                        }
                    }
                }
                22 => {
                    self.bold = false;
                }
                30..=37 => {
                    let idx = p - 30;
                    self.cur_fg = if self.bold { ANSI_COLORS[idx + 8] } else { ANSI_COLORS[idx] };
                }
                39 => {
                    self.cur_fg = FG_COLOR;
                }
                40..=47 => {
                    self.cur_bg = ANSI_COLORS[p - 40];
                }
                49 => {
                    self.cur_bg = BG_COLOR;
                }
                90..=97 => {
                    self.cur_fg = ANSI_COLORS[p - 90 + 8];
                }
                100..=107 => {
                    self.cur_bg = ANSI_COLORS[p - 100 + 8];
                }
                _ => {} // unrecognized SGR param
            }
            i += 1;
        }
    }

    fn erase_display(&mut self, mode: usize) {
        let blank = Cell { ch: b' ', fg: self.cur_fg, bg: self.cur_bg };
        match mode {
            0 => {
                // Erase from cursor to end.
                for col in self.cursor_col..TERM_COLS {
                    self.cells[self.cursor_row][col] = blank;
                }
                for row in (self.cursor_row + 1)..TERM_ROWS {
                    for col in 0..TERM_COLS {
                        self.cells[row][col] = blank;
                    }
                }
            }
            1 => {
                // Erase from start to cursor.
                for row in 0..self.cursor_row {
                    for col in 0..TERM_COLS {
                        self.cells[row][col] = blank;
                    }
                }
                for col in 0..=self.cursor_col.min(TERM_COLS - 1) {
                    self.cells[self.cursor_row][col] = blank;
                }
            }
            2 | 3 => {
                // Erase entire display.
                for row in 0..TERM_ROWS {
                    for col in 0..TERM_COLS {
                        self.cells[row][col] = blank;
                    }
                }
            }
            _ => {}
        }
    }

    fn erase_line(&mut self, mode: usize) {
        let blank = Cell { ch: b' ', fg: self.cur_fg, bg: self.cur_bg };
        match mode {
            0 => {
                for col in self.cursor_col..TERM_COLS {
                    self.cells[self.cursor_row][col] = blank;
                }
            }
            1 => {
                for col in 0..=self.cursor_col.min(TERM_COLS - 1) {
                    self.cells[self.cursor_row][col] = blank;
                }
            }
            2 => {
                for col in 0..TERM_COLS {
                    self.cells[self.cursor_row][col] = blank;
                }
            }
            _ => {}
        }
    }

    fn scroll_up(&mut self) {
        for row in 1..TERM_ROWS {
            self.cells[row - 1] = self.cells[row];
        }
        self.cells[TERM_ROWS - 1] = [DEFAULT_CELL; TERM_COLS];
    }

    fn render(&self) {
        let fb = self.buf_va as *mut u32;
        for row in 0..TERM_ROWS {
            for col in 0..TERM_COLS {
                let cell = &self.cells[row][col];
                let glyph_idx = if cell.ch >= 32 && cell.ch <= 126 {
                    (cell.ch - 32) as usize
                } else {
                    0
                };
                let glyph = &FONT_8X8[glyph_idx];
                let base_x = col * 8;
                let base_y = row * 8;

                let is_cursor = row == self.cursor_row && col == self.cursor_col;

                for gy in 0..8 {
                    let bits = glyph[gy];
                    for gx in 0..8 {
                        let on = (bits >> (7 - gx)) & 1 != 0;
                        let color = if is_cursor {
                            if on { cell.bg } else { CURSOR_COLOR }
                        } else {
                            if on { cell.fg } else { cell.bg }
                        };
                        let px = base_x + gx;
                        let py = base_y + gy;
                        unsafe {
                            ptr::write_volatile(fb.add(py * WIN_W + px), color);
                        }
                    }
                }
            }
        }
    }

    fn commit(&self) {
        let d2 = self.reply_port << 32;
        syscall::send(self.comp_port, COMP_COMMIT, self.win_id, 0, d2, 0);
        // Wait for reply.
        for _ in 0..100 {
            if let Some(r) = syscall::recv_nb_msg(self.reply_port) {
                if r.tag == COMP_COMMIT_OK {
                    return;
                }
            }
            syscall::yield_now();
        }
    }

    fn pty_write_master(&self, data: &[u8]) {
        let len = if data.len() > 16 { 16 } else { data.len() };
        let mut b0 = [0u8; 8];
        let mut b1 = [0u8; 8];
        let mut i = 0;
        while i < len && i < 8 {
            b0[i] = data[i];
            i += 1;
        }
        while i < len {
            b1[i - 8] = data[i];
            i += 1;
        }
        let d1 = u64::from_le_bytes(b0);
        let d3 = u64::from_le_bytes(b1);
        let d2 = (len as u64) | (self.pty_reply << 32);
        syscall::send(self.pty_port, PTY_WRITE, self.master_h as u64, d1, d2, d3);
        // Wait for write ack.
        for _ in 0..100 {
            if let Some(r) = syscall::recv_nb_msg(self.pty_reply) {
                if r.tag == PTY_WRITE_OK {
                    return;
                }
            }
            syscall::yield_now();
        }
    }

    fn pty_poll_master(&self) -> bool {
        let d2 = (1u64) | (self.pty_reply << 32); // events=POLLIN
        syscall::send(self.pty_port, PTY_POLL, self.master_h as u64, 0, d2, 0);
        for _ in 0..50 {
            if let Some(r) = syscall::recv_nb_msg(self.pty_reply) {
                if r.tag == PTY_POLL_OK {
                    return r.data[0] & 1 != 0; // POLLIN
                }
                return false;
            }
            syscall::yield_now();
        }
        false
    }

    fn pty_read_master(&self, buf: &mut [u8; 16]) -> usize {
        let d2 = self.pty_reply << 32;
        syscall::send(self.pty_port, PTY_READ, self.master_h as u64, 0, d2, 0);
        for _ in 0..200 {
            if let Some(r) = syscall::recv_nb_msg(self.pty_reply) {
                if r.tag == PTY_READ_OK {
                    let n = (r.data[2] & 0xFFFF) as usize;
                    let b0 = r.data[0].to_le_bytes();
                    let b1 = r.data[1].to_le_bytes();
                    let mut i = 0;
                    while i < n && i < 8 {
                        buf[i] = b0[i];
                        i += 1;
                    }
                    while i < n && i < 16 {
                        buf[i] = b1[i - 8];
                        i += 1;
                    }
                    return n;
                }
                return 0;
            }
            syscall::yield_now();
        }
        0
    }
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

#[unsafe(no_mangle)]
pub extern "C" fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let _ = arg0;
    syscall::debug_puts(b"  [term_srv] starting\n");

    // 1. Wait for compositor.
    let comp_port = loop {
        if let Some(p) = syscall::ns_lookup(b"compositor") {
            break p;
        }
        syscall::sleep_ms(10);
    };

    // 2. Wait for pty_srv.
    let pty_port = loop {
        if let Some(p) = syscall::ns_lookup(b"pty") {
            break p;
        }
        syscall::sleep_ms(10);
    };

    let event_port = syscall::port_create();
    let reply_port = syscall::port_create();
    let pty_reply = syscall::port_create();

    // 3. Query compositor for screen info (optional, for centering).
    let (scr_w, scr_h) = {
        let d2 = reply_port << 32;
        syscall::send(comp_port, COMP_GET_INFO, 0, 0, d2, 0);
        let mut w = 1024u32;
        let mut h = 768u32;
        for _ in 0..100 {
            if let Some(r) = syscall::recv_nb_msg(reply_port) {
                w = r.data[0] as u32;
                h = (r.data[0] >> 32) as u32;
                break;
            }
            syscall::yield_now();
        }
        (w, h)
    };

    // 4. Create compositor window (centered).
    let center_x = ((scr_w as i32) - (WIN_W as i32)) / 2;
    let center_y = ((scr_h as i32) - (WIN_H as i32)) / 2;
    let x = if center_x > 0 { center_x } else { 0 };
    let y = if center_y > 0 { center_y } else { 0 };

    let d0 = (x as u32 as u64) | ((y as u32 as u64) << 32);
    let d1 = (WIN_W as u64) | ((WIN_H as u64) << 32);
    let d2 = (event_port as u64) | (reply_port << 32);
    let d3 = TERM_BUF_VA as u64;
    syscall::send(comp_port, COMP_CREATE_WINDOW, d0, d1, d2, d3);

    let (win_id, buf_va) = loop {
        if let Some(r) = syscall::recv_nb_msg(reply_port) {
            if r.tag == COMP_CREATE_WINDOW_OK && r.data[0] != u64::MAX {
                break (r.data[0], r.data[1] as usize);
            } else {
                syscall::debug_puts(b"  [term_srv] FAILED: create window\n");
                loop { syscall::yield_now(); }
            }
        }
        syscall::yield_now();
    };

    // 5. Open PTY pair.
    let d2_pty = pty_reply << 32;
    syscall::send(pty_port, PTY_OPEN, 0, 0, d2_pty, 0);
    let (master_h, slave_h) = loop {
        if let Some(r) = syscall::recv_nb_msg(pty_reply) {
            if r.tag == PTY_OPEN_OK {
                let mh = (r.data[0] & 0xFFFFFFFF) as u32;
                let sh = (r.data[0] >> 32) as u32;
                break (mh, sh);
            } else {
                syscall::debug_puts(b"  [term_srv] FAILED: pty open\n");
                loop { syscall::yield_now(); }
            }
        }
        syscall::yield_now();
    };

    // 6. Spawn shell with PTY info: arg0 = (pty_port << 32) | slave_handle.
    let shell_arg = (pty_port << 32) | (slave_h as u64);
    let shell_tid = syscall::spawn_with_arg(b"shell", 50, shell_arg);
    if shell_tid == u64::MAX {
        syscall::debug_puts(b"  [term_srv] WARNING: tsh spawn failed\n");
    }

    syscall::debug_puts(b"  [term_srv] ready (");
    print_num(WIN_W as u64);
    syscall::debug_puts(b"x");
    print_num(WIN_H as u64);
    syscall::debug_puts(b", pty=");
    print_num(master_h as u64);
    syscall::debug_puts(b")\n");

    let mut term = Terminal {
        comp_port,
        event_port,
        reply_port,
        win_id,
        buf_va,
        pty_port,
        pty_reply,
        master_h,
        cells: [[DEFAULT_CELL; TERM_COLS]; TERM_ROWS],
        cursor_col: 0,
        cursor_row: 0,
        dirty: true,
        cur_fg: FG_COLOR,
        cur_bg: BG_COLOR,
        bold: false,
        esc_state: 0,
        esc_params: [0; 8],
        esc_param_count: 0,
        esc_intermediate: 0,
        saved_col: 0,
        saved_row: 0,
    };

    // Initial render (blank screen with cursor).
    term.render();
    term.commit();
    term.dirty = false;

    // 7. Main loop.
    let mut running = true;
    while running {
        // Drain keyboard events from compositor.
        loop {
            match syscall::recv_nb_msg(event_port) {
                Some(msg) => {
                    if msg.tag == COMP_CLOSE_EVENT {
                        running = false;
                        break;
                    }
                    if msg.tag == COMP_INPUT_EVENT {
                        let d0 = msg.data[0];
                        let event_type = (d0 & 0xFF) as u8;
                        let ascii = ((d0 >> 16) & 0xFF) as u8;
                        if event_type == EVENT_KEY_DOWN && ascii != 0 {
                            term.pty_write_master(&[ascii]);
                        }
                    }
                }
                None => break,
            }
        }
        if !running { break; }

        // Poll PTY master for shell output (drain all available).
        let mut read_any = false;
        loop {
            if !term.pty_poll_master() {
                break;
            }
            let mut buf = [0u8; 16];
            let n = term.pty_read_master(&mut buf);
            if n == 0 {
                break;
            }
            for i in 0..n {
                term.put_char(buf[i]);
            }
            read_any = true;
        }
        let _ = read_any;

        // Render and commit if dirty.
        if term.dirty {
            term.render();
            term.commit();
            term.dirty = false;
        }

        syscall::sleep_ms(1);
    }
}
