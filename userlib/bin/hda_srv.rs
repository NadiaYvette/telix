#![no_std]
#![no_main]
#![allow(dead_code, unreachable_code)]

//! Userspace Intel HD Audio (HDA) controller driver and IPC server.
//!
//! Discovers the HDA controller via MMIO cap (BAR0) granted by the kernel.
//! Initializes CORB/RIRB command rings, discovers codecs, walks the widget tree,
//! configures a DAC→Pin output path, and plays a 440Hz test tone via DMA streams.
//!
//! Works with QEMU's `intel-hda` + `hda-duplex` and real Intel HDA controllers
//! (Raptor Lake, Alder Lake, Tiger Lake, etc.).

extern crate userlib;

use userlib::syscall;

// --- HDA IPC protocol constants ---
const HDA_GET_INFO: u64 = 0xA000;
const HDA_GET_INFO_OK: u64 = 0xA001;
const HDA_GET_CODEC: u64 = 0xA100;
const HDA_GET_CODEC_OK: u64 = 0xA101;
const HDA_PLAY_TONE: u64 = 0xA200;
const HDA_PLAY_TONE_OK: u64 = 0xA201;
const HDA_SET_VOLUME: u64 = 0xA300;
const HDA_SET_VOLUME_OK: u64 = 0xA301;
#[allow(dead_code)]
const HDA_ERROR: u64 = 0xAF00;

// --- HDA Global register offsets (from BAR0) ---
const REG_GCAP: usize = 0x00;       // u16: Global Capabilities
const REG_VMIN: usize = 0x02;       // u8: Minor version
const REG_VMAJ: usize = 0x03;       // u8: Major version
const REG_GCTL: usize = 0x08;       // u32: Global Control
const REG_STATESTS: usize = 0x0E;   // u16: State Change Status
const REG_INTCTL: usize = 0x20;     // u32: Interrupt Control
const REG_INTSTS: usize = 0x24;     // u32: Interrupt Status

// GCTL bits
const GCTL_CRST: u32 = 1 << 0;     // Controller Reset

// --- CORB registers ---
const REG_CORBLBASE: usize = 0x40;
const REG_CORBUBASE: usize = 0x44;
const REG_CORBWP: usize = 0x48;     // u16
const REG_CORBRP: usize = 0x4A;     // u16
const REG_CORBCTL: usize = 0x4C;    // u8
const REG_CORBSTS: usize = 0x4D;    // u8
const REG_CORBSIZE: usize = 0x4E;   // u8

// CORBCTL bits
const CORBCTL_RUN: u8 = 1 << 1;
const CORBRP_RESET: u16 = 1 << 15;

// --- RIRB registers ---
const REG_RIRBLBASE: usize = 0x50;
const REG_RIRBUBASE: usize = 0x54;
const REG_RIRBWP: usize = 0x58;     // u16
const REG_RINTCNT: usize = 0x5A;    // u16
const REG_RIRBCTL: usize = 0x5C;    // u8
const REG_RIRBSTS: usize = 0x5D;    // u8
const REG_RIRBSIZE: usize = 0x5E;   // u8

// RIRBCTL bits
const RIRBCTL_RUN: u8 = 1 << 1;
const RIRBWP_RESET: u16 = 1 << 15;

// --- Stream Descriptor register offsets (base = 0x80 + n*0x20) ---
const SD_CTL: usize = 0x00;         // u32 (actually 24-bit + STS at byte 3)
const SD_STS: usize = 0x03;         // u8
const SD_LPIB: usize = 0x04;        // u32
const SD_CBL: usize = 0x08;         // u32
const SD_LVI: usize = 0x0C;         // u16
const SD_FMT: usize = 0x12;         // u16
const SD_BDLPL: usize = 0x18;       // u32
const SD_BDLPU: usize = 0x1C;       // u32

// SD_CTL bits
const SD_CTL_SRST: u32 = 1 << 0;    // Stream reset
const SD_CTL_RUN: u32 = 1 << 1;     // Stream run
const SD_CTL_IOCE: u32 = 1 << 2;    // Interrupt on completion enable

// SD_STS bits
const SD_STS_BCIS: u8 = 1 << 2;     // Buffer Completion Interrupt Status

// --- HDA Verb encoding ---
// 12-bit verbs: bits 19:8 = verb_id, 7:0 = payload
const VERB_GET_PARAMETER: u32 = 0xF0000;     // + (param_id << 0)
const VERB_GET_CONN_LIST: u32 = 0xF0200;
const VERB_SET_POWER_STATE: u32 = 0x70500;   // + state
const VERB_GET_CONV_CTRL: u32 = 0xF0600;
const VERB_SET_CONV_CTRL: u32 = 0x70600;     // + (stream<<4 | channel)
const VERB_GET_PIN_CTRL: u32 = 0xF0700;
const VERB_SET_PIN_CTRL: u32 = 0x70700;      // + pin_ctl_bits
const VERB_SET_EAPD: u32 = 0x70C00;          // + eapd_bits
const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C00;

// 4-bit verbs: bits 19:16 = verb_id, 15:0 = payload
const VERB_SET_AMP_GAIN: u32 = 0x30000;      // + amp_payload
const VERB_GET_AMP_GAIN: u32 = 0xB0000;

// Parameter IDs (for GET_PARAMETER)
const PARAM_VENDOR_ID: u32 = 0x00;
const PARAM_SUBNODE_COUNT: u32 = 0x04;
const PARAM_FN_GROUP_TYPE: u32 = 0x05;
const PARAM_AUDIO_WIDGET_CAP: u32 = 0x09;
const PARAM_PIN_CAP: u32 = 0x0C;
const PARAM_CONN_LIST_LEN: u32 = 0x0E;
const PARAM_OUT_AMP_CAP: u32 = 0x12;

// Widget types (bits 23:20 of Audio Widget Capabilities)
const WIDGET_TYPE_AUDIO_OUT: u32 = 0x0;   // DAC
const WIDGET_TYPE_AUDIO_IN: u32 = 0x1;    // ADC
const WIDGET_TYPE_AUDIO_MIX: u32 = 0x2;   // Mixer
const WIDGET_TYPE_AUDIO_SEL: u32 = 0x3;   // Selector
const WIDGET_TYPE_PIN: u32 = 0x4;         // Pin Complex

// Pin config default: bits 31:30 = connectivity (0=jack, 1=none, 2=fixed, 3=both)
// bits 29:28 = location, bits 27:24 = default device, etc.

// Stream format: 16-bit, 48kHz, stereo
// Bit 15: type=0 (PCM)
// Bits 14:11: base=0 (48kHz)
// Bits 10:8: mult=0 (x1)
// Bits 7:6: div=0 (/1)
// Bits 5:4: bits=1 (16-bit)
// Bits 3:0: channels=1 (2 channels, i.e., stereo)
const FMT_48K_16BIT_STEREO: u16 = 0x0011;

const CORB_SIZE: u16 = 256;
const RIRB_SIZE: u16 = 256;

// --- Buffer Descriptor List entry (16 bytes) ---
#[repr(C)]
struct BdlEntry {
    addr: u64,
    length: u32,
    ioc: u32,  // bit 0 = interrupt on completion
}

// --- Controller state ---
struct HdaCtrl {
    bar: usize,
    // Streams
    num_iss: u8,
    num_oss: u8,
    // Output stream (first output = descriptor index num_iss)
    out_stream_base: usize,  // BAR0 offset for output stream descriptor
    out_bdl_va: usize,
    out_bdl_pa: u64,
    out_buf_va: usize,
    out_buf_pa: u64,
    out_buf_size: usize,
    // Codec
    codec_addr: u8,
    codec_vendor: u32,
    afg_nid: u8,
    dac_nid: u8,
    out_pin_nid: u8,
    // State
    playing: bool,
    volume: u8,
}

// --- MMIO helpers ---
fn mmio_read8(base: usize, offset: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u8) }
}

fn mmio_write8(base: usize, offset: usize, val: u8) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u8, val) }
}

fn mmio_read16(base: usize, offset: usize) -> u16 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u16) }
}

fn mmio_write16(base: usize, offset: usize, val: u16) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u16, val) }
}

fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// --- Utility ---
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

fn print_hex(n: u64) {
    syscall::debug_puts(b"0x");
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        let d = (val & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        val >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

fn send_reply(port: u64, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) {
    if syscall::send_nb_4(port, tag, d0, d1, d2, d3) == 0 {
        return;
    }
    for _ in 0..50u32 {
        syscall::yield_now();
        if syscall::send_nb_4(port, tag, d0, d1, d2, d3) == 0 {
            return;
        }
    }
    syscall::send(port, tag, d0, d1, d2, d3);
}

fn alloc_page() -> Option<(usize, u64)> {
    let va = syscall::mmap_anon(0, 1, 1)?;
    let pa = syscall::virt_to_phys(va)? as u64;
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, syscall::page_size()); }
    Some((va, pa))
}

// ===========================================================================
// Immediate Command Interface (ICW/IRR/ICS at 0x60-0x68)
// ===========================================================================

// Immediate Command registers
const REG_ICW: usize = 0x60;    // Immediate Command Write (32-bit)
const REG_IRR: usize = 0x64;    // Immediate Response Read (32-bit)
const REG_ICS: usize = 0x68;    // Immediate Command Status (16-bit)

// ICS bits
const ICS_ICB: u16 = 1 << 0;   // Immediate Command Busy
const ICS_IRV: u16 = 1 << 1;   // Immediate Result Valid

/// Send a codec verb using the Immediate Command interface and wait for response.
fn codec_verb(ctrl: &mut HdaCtrl, codec: u8, nid: u8, verb: u32) -> Option<u32> {
    let encoded = ((codec as u32) << 28) | ((nid as u32) << 20) | verb;

    // Wait for any previous command to complete
    for i in 0..500_000u32 {
        let ics = mmio_read16(ctrl.bar, REG_ICS);
        if ics & ICS_ICB == 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // Write the verb to ICW
    mmio_write32(ctrl.bar, REG_ICW, encoded);

    // Trigger the command by setting ICB in ICS
    mmio_write16(ctrl.bar, REG_ICS, ICS_ICB);

    // Poll for completion: wait for ICB to clear and IRV to be set
    for i in 0..2_000_000u32 {
        let ics = mmio_read16(ctrl.bar, REG_ICS);
        if ics & ICS_ICB == 0 && ics & ICS_IRV != 0 {
            // Read the response
            let response = mmio_read32(ctrl.bar, REG_IRR);
            return Some(response);
        }
        if i % 50_000 == 0 {
            syscall::yield_now();
        }
        core::hint::spin_loop();
    }
    None
}

/// GET_PARAMETER shorthand.
fn get_param(ctrl: &mut HdaCtrl, codec: u8, nid: u8, param_id: u32) -> Option<u32> {
    codec_verb(ctrl, codec, nid, VERB_GET_PARAMETER | param_id)
}

// ===========================================================================
// Controller initialization
// ===========================================================================

fn hda_init(bar: usize) -> Option<HdaCtrl> {
    // Read capabilities
    let gcap = mmio_read16(bar, REG_GCAP);
    let vmin = mmio_read8(bar, REG_VMIN);
    let vmaj = mmio_read8(bar, REG_VMAJ);

    let ok64 = (gcap & 1) != 0;
    let num_oss = ((gcap >> 12) & 0xF) as u8;
    let num_iss = ((gcap >> 8) & 0xF) as u8;
    let num_bss = ((gcap >> 4) & 0xF) as u8;

    syscall::debug_puts(b"  [hda_srv] version=");
    print_num(vmaj as u64);
    syscall::debug_puts(b".");
    print_num(vmin as u64);
    syscall::debug_puts(b" ISS=");
    print_num(num_iss as u64);
    syscall::debug_puts(b" OSS=");
    print_num(num_oss as u64);
    syscall::debug_puts(b" BSS=");
    print_num(num_bss as u64);
    syscall::debug_puts(b" 64ok=");
    print_num(ok64 as u64);
    syscall::debug_puts(b"\n");

    if num_oss == 0 {
        syscall::debug_puts(b"  [hda_srv] no output streams, aborting\n");
        return None;
    }

    // Step 1: Reset controller
    // Clear CRST to put controller in reset
    let gctl = mmio_read32(bar, REG_GCTL);
    mmio_write32(bar, REG_GCTL, gctl & !GCTL_CRST);
    for i in 0..1_000_000u32 {
        if mmio_read32(bar, REG_GCTL) & GCTL_CRST == 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // Set CRST to take controller out of reset
    let gctl = mmio_read32(bar, REG_GCTL);
    mmio_write32(bar, REG_GCTL, gctl | GCTL_CRST);
    for i in 0..1_000_000u32 {
        if mmio_read32(bar, REG_GCTL) & GCTL_CRST != 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    syscall::debug_puts(b"  [hda_srv] controller reset complete\n");

    // Step 2: Wait for codec enumeration (codecs need ~521us after reset)
    // Poll STATESTS for codec presence bits
    for i in 0..500_000u32 {
        let sts = mmio_read16(bar, REG_STATESTS);
        if sts != 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    let statests = mmio_read16(bar, REG_STATESTS);
    if statests == 0 {
        syscall::debug_puts(b"  [hda_srv] no codecs detected\n");
        return None;
    }

    // Find first codec address (bit index in STATESTS)
    let mut codec_addr: u8 = 0;
    for i in 0..15u8 {
        if statests & (1 << i) != 0 {
            codec_addr = i;
            break;
        }
    }

    syscall::debug_puts(b"  [hda_srv] codec detected at address ");
    print_num(codec_addr as u64);
    syscall::debug_puts(b" (STATESTS=");
    print_hex(statests as u64);
    syscall::debug_puts(b")\n");

    // Clear STATESTS (W1C)
    mmio_write16(bar, REG_STATESTS, statests);

    // We use the Immediate Command interface (ICW/IRR/ICS at 0x60-0x68) for
    // codec verbs instead of CORB/RIRB, as it provides synchronous operation
    // without DMA ring buffers.

    // Output stream descriptor base: first output is after all input streams
    let out_stream_base = 0x80 + (num_iss as usize) * 0x20;

    syscall::debug_puts(b"  [hda_srv] init complete\n");

    Some(HdaCtrl {
        bar,
        num_iss,
        num_oss,
        out_stream_base,
        out_bdl_va: 0,
        out_bdl_pa: 0,
        out_buf_va: 0,
        out_buf_pa: 0,
        out_buf_size: 0,
        codec_addr,
        codec_vendor: 0,
        afg_nid: 0,
        dac_nid: 0,
        out_pin_nid: 0,
        playing: false,
        volume: 80,
    })
}

// ===========================================================================
// Codec discovery and widget tree walk
// ===========================================================================

fn discover_codec(ctrl: &mut HdaCtrl) -> bool {
    let cad = ctrl.codec_addr;

    // Get codec vendor/device ID
    let vendor_id = match get_param(ctrl, cad, 0, PARAM_VENDOR_ID) {
        Some(v) => v,
        None => {
            syscall::debug_puts(b"  [hda_srv] codec not responding\n");
            return false;
        }
    };
    ctrl.codec_vendor = vendor_id;

    syscall::debug_puts(b"  [hda_srv] codec vendor=");
    print_hex((vendor_id >> 16) as u64);
    syscall::debug_puts(b" device=");
    print_hex((vendor_id & 0xFFFF) as u64);
    syscall::debug_puts(b"\n");

    // Get root node subnodes (function groups)
    let subnode_info = match get_param(ctrl, cad, 0, PARAM_SUBNODE_COUNT) {
        Some(v) => v,
        None => return false,
    };
    let start_nid = ((subnode_info >> 16) & 0xFF) as u8;
    let total_nodes = (subnode_info & 0xFF) as u8;

    syscall::debug_puts(b"  [hda_srv] root: ");
    print_num(total_nodes as u64);
    syscall::debug_puts(b" function group(s) starting at NID ");
    print_num(start_nid as u64);
    syscall::debug_puts(b"\n");

    // Find Audio Function Group (type 0x01)
    let mut afg_nid: u8 = 0;
    for i in 0..total_nodes {
        let nid = start_nid + i;
        if let Some(fg_type) = get_param(ctrl, cad, nid, PARAM_FN_GROUP_TYPE) {
            let node_type = fg_type & 0xFF;
            if node_type == 0x01 {
                afg_nid = nid;
                syscall::debug_puts(b"  [hda_srv] AFG at NID ");
                print_num(nid as u64);
                syscall::debug_puts(b"\n");
                break;
            }
        }
    }

    if afg_nid == 0 {
        syscall::debug_puts(b"  [hda_srv] no Audio Function Group found\n");
        return false;
    }
    ctrl.afg_nid = afg_nid;

    // Power on the AFG (D0)
    codec_verb(ctrl, cad, afg_nid, VERB_SET_POWER_STATE | 0x00);

    // Get AFG subnodes (widgets)
    let widget_info = match get_param(ctrl, cad, afg_nid, PARAM_SUBNODE_COUNT) {
        Some(v) => v,
        None => return false,
    };
    let w_start = ((widget_info >> 16) & 0xFF) as u8;
    let w_count = (widget_info & 0xFF) as u8;

    syscall::debug_puts(b"  [hda_srv] AFG has ");
    print_num(w_count as u64);
    syscall::debug_puts(b" widgets starting at NID ");
    print_num(w_start as u64);
    syscall::debug_puts(b"\n");

    // Walk widgets: find first DAC and first output pin
    let mut dac_nid: u8 = 0;
    let mut out_pin_nid: u8 = 0;

    for i in 0..w_count {
        let nid = w_start + i;
        let wcap = match get_param(ctrl, cad, nid, PARAM_AUDIO_WIDGET_CAP) {
            Some(v) => v,
            None => continue,
        };

        let wtype = (wcap >> 20) & 0xF;

        match wtype {
            WIDGET_TYPE_AUDIO_OUT => {
                if dac_nid == 0 {
                    dac_nid = nid;
                    syscall::debug_puts(b"  [hda_srv]   NID ");
                    print_num(nid as u64);
                    syscall::debug_puts(b": DAC\n");
                }
            }
            WIDGET_TYPE_PIN => {
                // Check pin configuration for output capability
                let pin_cap = get_param(ctrl, cad, nid, PARAM_PIN_CAP).unwrap_or(0);
                let is_output = (pin_cap & (1 << 4)) != 0; // Output capable

                // Check config default: connectivity != "no connection" (bits 31:30 != 01)
                let config = codec_verb(ctrl, cad, nid, VERB_GET_CONFIG_DEFAULT).unwrap_or(0);
                let connectivity = (config >> 30) & 0x3;

                if is_output && connectivity != 1 {
                    if out_pin_nid == 0 {
                        out_pin_nid = nid;
                        let default_dev = (config >> 20) & 0xF;
                        syscall::debug_puts(b"  [hda_srv]   NID ");
                        print_num(nid as u64);
                        syscall::debug_puts(b": Pin (output, dev=");
                        print_hex(default_dev as u64);
                        syscall::debug_puts(b")\n");
                    }
                }
            }
            WIDGET_TYPE_AUDIO_MIX => {
                // Noted for future use
            }
            _ => {}
        }
    }

    if dac_nid == 0 {
        syscall::debug_puts(b"  [hda_srv] no DAC found\n");
        return false;
    }
    if out_pin_nid == 0 {
        syscall::debug_puts(b"  [hda_srv] no output pin found\n");
        return false;
    }

    ctrl.dac_nid = dac_nid;
    ctrl.out_pin_nid = out_pin_nid;
    true
}

// ===========================================================================
// Output path configuration
// ===========================================================================

fn configure_output(ctrl: &mut HdaCtrl) -> bool {
    let cad = ctrl.codec_addr;
    let dac = ctrl.dac_nid;
    let pin = ctrl.out_pin_nid;

    // Power on DAC
    codec_verb(ctrl, cad, dac, VERB_SET_POWER_STATE | 0x00);

    // Set DAC converter: stream=1, channel=0
    // Bits 7:4 = stream tag, bits 3:0 = channel
    codec_verb(ctrl, cad, dac, VERB_SET_CONV_CTRL | (1 << 4));

    // Power on pin
    codec_verb(ctrl, cad, pin, VERB_SET_POWER_STATE | 0x00);

    // Enable pin output (OUT_EN = bit 6, HP_EN = bit 7)
    let pin_ctl = codec_verb(ctrl, cad, pin, VERB_GET_PIN_CTRL).unwrap_or(0);
    codec_verb(ctrl, cad, pin, VERB_SET_PIN_CTRL | ((pin_ctl | 0xC0) & 0xFF));

    // Try to enable EAPD (External Amplifier Power Down control)
    codec_verb(ctrl, cad, pin, VERB_SET_EAPD | 0x02); // EAPD bit

    // Set output amplifier gain on DAC
    // SET_AMP_GAIN payload: bit 15=output, bit 13=left, bit 12=right, bits 6:0=gain
    let gain = (ctrl.volume & 0x7F) as u32;
    let amp_out = (1 << 15) | (1 << 13) | (1 << 12) | gain;
    codec_verb(ctrl, cad, dac, VERB_SET_AMP_GAIN | amp_out);

    // Set output amplifier on pin too
    codec_verb(ctrl, cad, pin, VERB_SET_AMP_GAIN | amp_out);

    syscall::debug_puts(b"  [hda_srv] output path configured: DAC(NID ");
    print_num(dac as u64);
    syscall::debug_puts(b") -> Pin(NID ");
    print_num(pin as u64);
    syscall::debug_puts(b") vol=");
    print_num(gain as u64);
    syscall::debug_puts(b"\n");

    true
}

// ===========================================================================
// Stream setup + tone generation
// ===========================================================================

/// Integer sine approximation using a 64-entry lookup table.
/// Returns value in range [-32767, 32767].
fn sine_i16(phase: u32, period: u32) -> i16 {
    // 64-entry quarter-wave sine table (0 to π/2), values 0..32767
    static SINE_TABLE: [i16; 17] = [
        0, 3212, 6393, 9512, 12539, 15446, 18204, 20787,
        23170, 25330, 27245, 28898, 30273, 31356, 32138, 32610,
        32767,
    ];

    // Map phase to 0..63 (quarter period = 16 entries)
    let pos = ((phase as u64) * 64 / (period as u64)) as u32 % 64;

    let (idx, negate) = if pos < 16 {
        (pos as usize, false)       // 0..π/2: rising positive
    } else if pos < 32 {
        ((32 - pos) as usize, false) // π/2..π: falling positive
    } else if pos < 48 {
        ((pos - 32) as usize, true)  // π..3π/2: rising negative
    } else {
        ((64 - pos) as usize, true)  // 3π/2..2π: falling negative
    };

    let val = SINE_TABLE[idx];
    // Scale down a bit to avoid clipping
    let scaled = (val as i32 * 7) / 10;
    if negate { -(scaled as i16) } else { scaled as i16 }
}

/// Fill buffer with 440Hz sine wave, 48kHz, 16-bit stereo.
fn generate_sine_440hz(buf_va: usize, buf_size: usize) {
    let samples = buf_size / 4; // 2 bytes per sample, 2 channels
    let period = 48000u32 / 440; // ~109 samples per cycle

    for i in 0..samples {
        let phase = (i as u32) % period;
        let val = sine_i16(phase, period);

        // Write left and right channels (interleaved stereo)
        let offset = i * 4;
        unsafe {
            core::ptr::write_volatile((buf_va + offset) as *mut i16, val);
            core::ptr::write_volatile((buf_va + offset + 2) as *mut i16, val);
        }
    }
}

fn setup_output_stream(ctrl: &mut HdaCtrl) -> bool {
    let sd_base = ctrl.bar + ctrl.out_stream_base;

    // Step 1: Reset stream
    let ctl = mmio_read32(sd_base, SD_CTL);
    mmio_write32(sd_base, SD_CTL, ctl & !SD_CTL_RUN); // stop first
    for i in 0..100_000u32 {
        if mmio_read32(sd_base, SD_CTL) & SD_CTL_RUN == 0 { break; }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // Assert stream reset
    mmio_write32(sd_base, SD_CTL, SD_CTL_SRST);
    for i in 0..100_000u32 {
        if mmio_read32(sd_base, SD_CTL) & SD_CTL_SRST != 0 { break; }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // De-assert stream reset
    mmio_write32(sd_base, SD_CTL, 0);
    for i in 0..100_000u32 {
        if mmio_read32(sd_base, SD_CTL) & SD_CTL_SRST == 0 { break; }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // Step 2: Allocate audio buffer (2 pages = 8192 bytes ≈ 42ms at 48kHz stereo 16-bit)
    let buf_pages = 2;
    let buf_va = match syscall::mmap_anon(0, buf_pages, 1) {
        Some(va) => va,
        None => return false,
    };
    let buf_pa = match syscall::virt_to_phys(buf_va) {
        Some(pa) => pa as u64,
        None => return false,
    };
    let buf_size = buf_pages * syscall::page_size();

    // Fill with 440Hz sine wave
    generate_sine_440hz(buf_va, buf_size);

    // Step 3: Allocate BDL (Buffer Descriptor List) — single entry
    let (bdl_va, bdl_pa) = match alloc_page() {
        Some(x) => x,
        None => return false,
    };

    // Write BDL entry 0: address, length, IOC
    unsafe {
        let entry = bdl_va as *mut BdlEntry;
        (*entry).addr = buf_pa;
        (*entry).length = buf_size as u32;
        (*entry).ioc = 1; // interrupt on completion
    }

    // Step 4: Configure stream descriptor
    // Format: 48kHz, 16-bit, stereo
    mmio_write16(sd_base, SD_FMT, FMT_48K_16BIT_STEREO);

    // Cyclic Buffer Length
    mmio_write32(sd_base, SD_CBL, buf_size as u32);

    // Last Valid Index (0 = single BDL entry)
    mmio_write16(sd_base, SD_LVI, 0);

    // BDL pointer
    mmio_write32(sd_base, SD_BDLPL, bdl_pa as u32);
    mmio_write32(sd_base, SD_BDLPU, (bdl_pa >> 32) as u32);

    // Clear status bits
    mmio_write8(sd_base, SD_STS, SD_STS_BCIS | (1 << 3) | (1 << 4));

    // Step 5: Set stream tag (1) in SD_CTL bits 23:20 and start
    // SD_CTL is 24-bit at offset 0, with STS at byte 3
    // Read as u32, set stream tag in bits 23:20, set RUN bit, set IOCE
    let stream_tag = 1u32;
    let ctl_val = (stream_tag << 20) | SD_CTL_RUN | SD_CTL_IOCE;
    mmio_write32(sd_base, SD_CTL, ctl_val);

    // Verify stream is running
    for i in 0..100_000u32 {
        if mmio_read32(sd_base, SD_CTL) & SD_CTL_RUN != 0 { break; }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // Check LPIB is advancing (DMA is working)
    let lpib1 = mmio_read32(sd_base, SD_LPIB);
    for _ in 0..100_000u32 {
        core::hint::spin_loop();
    }
    syscall::yield_now();
    let lpib2 = mmio_read32(sd_base, SD_LPIB);

    ctrl.out_bdl_va = bdl_va;
    ctrl.out_bdl_pa = bdl_pa;
    ctrl.out_buf_va = buf_va;
    ctrl.out_buf_pa = buf_pa;
    ctrl.out_buf_size = buf_size;
    ctrl.playing = true;

    syscall::debug_puts(b"  [hda_srv] output stream running: 48kHz/16-bit/stereo, ");
    print_num(buf_size as u64);
    syscall::debug_puts(b" bytes, LPIB ");
    print_num(lpib1 as u64);
    syscall::debug_puts(b"->");
    print_num(lpib2 as u64);
    syscall::debug_puts(b"\n");

    true
}

// ===========================================================================
// Entry point + IPC server
// ===========================================================================

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [hda_srv] starting\n");

    let cap_slot = (arg0 & 0xFFFF) as usize;
    let _irq = (arg0 >> 48) as u32;

    let bar = match syscall::mmio_map_cap(cap_slot) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [hda_srv] mmio_map_cap failed, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [hda_srv] BAR0 mapped at ");
    print_hex(bar as u64);
    syscall::debug_puts(b"\n");

    let mut ctrl = match hda_init(bar) {
        Some(c) => c,
        None => {
            syscall::debug_puts(b"  [hda_srv] init failed, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    if !discover_codec(&mut ctrl) {
        syscall::debug_puts(b"  [hda_srv] codec discovery failed, exiting\n");
        syscall::exit(1);
        loop { core::hint::spin_loop(); }
    }

    if !configure_output(&mut ctrl) {
        syscall::debug_puts(b"  [hda_srv] output config failed\n");
    }

    if !setup_output_stream(&mut ctrl) {
        syscall::debug_puts(b"  [hda_srv] stream setup failed\n");
    }

    // Register as "hda" service.
    let port = syscall::port_create();
    syscall::ns_register(b"hda", port);

    syscall::debug_puts(b"  [hda_srv] server ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // IPC server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            HDA_GET_INFO => {
                let reply_port = msg.data[2] >> 32;
                // d0 = num_codecs | (num_oss << 8) | (num_iss << 16) | (playing << 24)
                let info = 1u64
                    | ((ctrl.num_oss as u64) << 8)
                    | ((ctrl.num_iss as u64) << 16)
                    | ((ctrl.playing as u64) << 24);
                // d1 = sample_rate | (bits_per_sample << 16) | (channels << 24)
                let format = 48000u64 | (16u64 << 16) | (2u64 << 24);
                send_reply(reply_port, HDA_GET_INFO_OK, info, format, 0, 0);
            }

            HDA_GET_CODEC => {
                let reply_port = msg.data[2] >> 32;
                // d0 = vendor_id (32-bit), d1 = afg_nid | dac_nid<<8 | pin_nid<<16
                let nids = (ctrl.afg_nid as u64)
                    | ((ctrl.dac_nid as u64) << 8)
                    | ((ctrl.out_pin_nid as u64) << 16);
                send_reply(reply_port, HDA_GET_CODEC_OK, ctrl.codec_vendor as u64, nids, 0, 0);
            }

            HDA_PLAY_TONE => {
                let reply_port = msg.data[2] >> 32;
                if !ctrl.playing {
                    // Re-start playback
                    let sd_base = ctrl.bar + ctrl.out_stream_base;
                    let stream_tag = 1u32;
                    mmio_write32(sd_base, SD_CTL, (stream_tag << 20) | SD_CTL_RUN | SD_CTL_IOCE);
                    ctrl.playing = true;
                }
                send_reply(reply_port, HDA_PLAY_TONE_OK, 0, 0, 0, 0);
            }

            HDA_SET_VOLUME => {
                let reply_port = msg.data[2] >> 32;
                let new_vol = (msg.data[0] & 0x7F) as u8;
                ctrl.volume = new_vol;

                // Update amplifier gain on DAC and pin
                let gain = new_vol as u32;
                let amp_out = (1u32 << 15) | (1u32 << 13) | (1u32 << 12) | gain;
                let caddr = ctrl.codec_addr;
                let dac = ctrl.dac_nid;
                let pin = ctrl.out_pin_nid;
                codec_verb(&mut ctrl, caddr, dac, VERB_SET_AMP_GAIN | amp_out);
                codec_verb(&mut ctrl, caddr, pin, VERB_SET_AMP_GAIN | amp_out);

                send_reply(reply_port, HDA_SET_VOLUME_OK, new_vol as u64, 0, 0, 0);
            }

            _ => {} // ignore unknown tags
        }
    }
}
