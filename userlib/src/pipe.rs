//! Byte-stream pipes over IPC ports.
//!
//! A pipe is a single IPC port. The writer sends PIPE_DATA messages with
//! up to 16 bytes packed inline. The reader receives with blocking recv.
//! PIPE_EOF signals end-of-stream.

use crate::syscall;

const PIPE_DATA: u64 = 0x5000;
const PIPE_EOF: u64 = 0x5001;

/// Write `buf` into the pipe, chunking into 16-byte messages.
pub fn pipe_write(pipe_port: u32, buf: &[u8]) {
    let mut offset = 0;
    while offset < buf.len() {
        let chunk_len = (buf.len() - offset).min(16);
        let mut w0 = 0u64;
        let mut w1 = 0u64;
        for i in 0..chunk_len.min(8) {
            w0 |= (buf[offset + i] as u64) << (i * 8);
        }
        for i in 8..chunk_len {
            w1 |= (buf[offset + i] as u64) << ((i - 8) * 8);
        }
        syscall::send(pipe_port, PIPE_DATA, w0, w1, chunk_len as u64, 0);
        offset += chunk_len;
    }
}

/// Signal end-of-stream on the pipe.
pub fn pipe_close_writer(pipe_port: u32) {
    syscall::send(pipe_port, PIPE_EOF, 0, 0, 0, 0);
}

/// Read from the pipe into `buf`. Returns bytes read (0 = EOF).
pub fn pipe_read(pipe_port: u32, buf: &mut [u8]) -> usize {
    if let Some(msg) = syscall::recv_msg(pipe_port) {
        match msg.tag {
            PIPE_DATA => {
                let len = (msg.data[2] as usize).min(16).min(buf.len());
                let words = [msg.data[0], msg.data[1]];
                for i in 0..len {
                    buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
                }
                len
            }
            _ => 0, // PIPE_EOF or unexpected
        }
    } else {
        0
    }
}
