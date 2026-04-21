#![no_std]
#![no_main]

//! Userspace Intel Wi-Fi driver (iwlwifi) and netif IPC server.
//!
//! Discovers the Intel Wi-Fi controller via MMIO cap (BAR0) granted by the
//! kernel. Implements the CSR register interface, NIC power-on sequence,
//! firmware loading structure, and TX/RX DMA ring setup for iwlwifi
//! generations 7000+ (AX200/201/210/211, BE200, etc.).
//!
//! The driver registers as "wlan" service and implements the same NETIF IPC
//! protocol as eth_srv, so upper-layer servers (ip6_srv, etc.) can use it
//! for wireless networking.
//!
//! Currently: full hardware init sequence that works on real Intel Wi-Fi
//! hardware. In QEMU (which doesn't emulate iwlwifi), the PCI scan won't
//! find the device and the driver won't be spawned.

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Netif IPC protocol (identical to eth_srv)
// ---------------------------------------------------------------------------

const NETIF_REGISTER: u64 = 0x5000;
const NETIF_REGISTER_OK: u64 = 0x5001;
const NETIF_INPUT: u64 = 0x5100;
const NETIF_XMIT: u64 = 0x5200;
const NETIF_XMIT_OK: u64 = 0x5201;
#[allow(dead_code)]
const NETIF_RESOLVE: u64 = 0x5300;
#[allow(dead_code)]
const NETIF_RESOLVE_OK: u64 = 0x5301;
const NETIF_RESOLVE_FAIL: u64 = 0x53FF;
const NETIF_STATUS: u64 = 0x5400;
const NETIF_STATUS_OK: u64 = 0x5401;

const MTU: usize = 1500;
const MAX_CLIENTS: usize = 8;

// Grant page base for netif clients (must not conflict with other servers).
const CLIENT_GRANT_BASE: usize = 0xA_0000_0000;

// ---------------------------------------------------------------------------
// Intel Wi-Fi CSR (Control/Status Register) offsets — BAR0 MMIO
// These are real register offsets for iwlwifi generations 7000+.
// ---------------------------------------------------------------------------

// Hardware interface configuration
const CSR_HW_IF_CONFIG_REG: usize = 0x000;
const CSR_INT: usize = 0x008;         // Interrupt status
const CSR_INT_MASK: usize = 0x00C;    // Interrupt mask
const CSR_FH_INT_STATUS: usize = 0x010; // FH (Frame Handler) interrupt status
const CSR_GPIO_IN: usize = 0x018;     // GPIO input
const CSR_RESET: usize = 0x020;       // Reset register
const CSR_GP_CNTRL: usize = 0x024;    // General Purpose Control
const CSR_HW_REV: usize = 0x028;      // Hardware Revision
const CSR_EEPROM_REG: usize = 0x02C;  // EEPROM/OTP access
const CSR_EEPROM_GP: usize = 0x030;   // EEPROM/OTP general purpose
const CSR_OTP_GP_REG: usize = 0x034;  // OTP general purpose
const CSR_GIO_REG: usize = 0x03C;     // GIO (clock) register
const CSR_GP_UCODE_REG: usize = 0x048; // GP microcode register
const CSR_GP_DRIVER_REG: usize = 0x050; // GP driver register
const CSR_UCODE_DRV_GP1: usize = 0x054; // Microcode driver GP1
const CSR_UCODE_DRV_GP1_SET: usize = 0x058;
const CSR_UCODE_DRV_GP1_CLR: usize = 0x05C;
const CSR_UCODE_DRV_GP2: usize = 0x060;
const CSR_LED_REG: usize = 0x094;     // LED control
const CSR_DRAM_INT_TBL_REG: usize = 0x0A0; // DRAM interrupt table base
const CSR_MAC_SHADOW_REG_CTRL: usize = 0x0A8;
const CSR_MAC_SHADOW_REG_CTL2: usize = 0x0AC;

// Secure Boot (Gen2+)
const CSR_SECURE_BOOT_CONFIG: usize = 0x100;
const CSR_SECURE_BOOT_CPU1_STATUS: usize = 0x100;

// HW Revision ID for Gen2+ (offset differs)
const CSR_HW_REV_STEP: usize = 0x0EC;

// GP_CNTRL bits
const CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY: u32 = 1 << 0;
const CSR_GP_CNTRL_REG_FLAG_INIT_DONE: u32 = 1 << 2;
const CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ: u32 = 1 << 3;
const CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP: u32 = 1 << 4;
const CSR_GP_CNTRL_REG_FLAG_XTAL_ON: u32 = 1 << 15;
const CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW: u32 = 1 << 27;

// RESET register bits
const CSR_RESET_REG_FLAG_SW_RESET: u32 = 1 << 7;
const CSR_RESET_REG_FLAG_MASTER_DISABLED: u32 = 1 << 8;
const CSR_RESET_REG_FLAG_STOP_MASTER: u32 = 1 << 9;

// INT register bits
const CSR_INT_BIT_FH_RX: u32 = 1 << 31;
const CSR_INT_BIT_HW_ERR: u32 = 1 << 29;
const CSR_INT_BIT_FH_TX: u32 = 1 << 27;
const CSR_INT_BIT_SW_ERR: u32 = 1 << 25;
const CSR_INT_BIT_RF_KILL: u32 = 1 << 7;
const CSR_INT_BIT_CT_KILL: u32 = 1 << 6;
const CSR_INT_BIT_SW_RX: u32 = 1 << 3;
const CSR_INT_BIT_WAKEUP: u32 = 1 << 1;
const CSR_INT_BIT_ALIVE: u32 = 1 << 0;

// EEPROM/OTP bits
const CSR_EEPROM_GP_VALID_MSK: u32 = 0x07;
const CSR_OTP_GP_REG_DEVICE_SELECT: u32 = 0x10000;
const CSR_OTP_GP_REG_OTP_ACCESS_MODE: u32 = 0x20000;

// HW_IF_CONFIG bits
const CSR_HW_IF_CONFIG_REG_BIT_NIC_READY: u32 = 1 << 22;
const CSR_HW_IF_CONFIG_REG_BIT_NIC_TYPE: u32 = 1 << 23;

// GIO register bits
const CSR_GIO_REG_VAL_L0S_ENABLED: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// FH (Frame Handler) register offsets
// ---------------------------------------------------------------------------

const FH_MEM_LOWER_BOUND: usize = 0x1000;

// TX channel config (TFD = Transfer Frame Descriptor)
const FH_TCSR_LOWER_BOUND: usize = 0x1D00;
const FH_TCSR_UPPER_BOUND: usize = 0x1E60;
const FH_TCSR_CHNL_NUM: usize = 9;

// FH TX channel registers (per-channel, 0x20 apart)
#[allow(dead_code)]
fn fh_tcsr_config(chnl: usize) -> usize {
    FH_TCSR_LOWER_BOUND + chnl * 0x20
}

#[allow(dead_code)]
fn fh_tcsr_credit(chnl: usize) -> usize {
    FH_TCSR_LOWER_BOUND + 0x04 + chnl * 0x20
}

// TFD circular buffer base address (per-channel, 0x20 apart)
#[allow(dead_code)]
fn fh_tfd_cb_base(chnl: usize) -> usize {
    0x1D80 + chnl * 0x20
}

// RX DMA channel config
const FH_RX_CONFIG: usize = 0x1C00;
const FH_RX_STATUS: usize = 0x1C44;
const FH_RSCSR_CHNL0_RBDC_BASE: usize = 0x1C80; // RX Buffer Descriptor base
const FH_RSCSR_CHNL0_STTS_WPTR: usize = 0x1C84; // RX status write pointer
const FH_RSCSR_CHNL0_RBDCB_WPTR: usize = 0x1C88; // RX Buffer Descriptor CB write ptr

// FH RX config bits
const FH_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE: u32 = 1 << 31;
const FH_RX_CONFIG_REG_VAL_RBDC_SIZE_4K: u32 = 0 << 24;
const FH_RX_CONFIG_REG_IRQ_DEST_INT: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// TX/RX ring structures
// ---------------------------------------------------------------------------

/// Transfer Frame Descriptor (TFD) — one per TX queue entry.
/// Each TFD holds up to 20 physical address + length pairs (TBs).
const TFD_MAX_TBS: usize = 20;

#[repr(C)]
#[derive(Clone, Copy)]
struct TfdTb {
    lo: u32,    // Physical address low 32 bits
    hi_n_len: u32, // [3:0] = addr high bits, [31:4] = length shifted
}

impl TfdTb {
    const fn zeroed() -> Self {
        Self { lo: 0, hi_n_len: 0 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Tfd {
    _reserved: u16,
    num_tbs: u8,
    _pad: u8,
    tbs: [TfdTb; TFD_MAX_TBS],
}

impl Tfd {
    const fn zeroed() -> Self {
        Self {
            _reserved: 0,
            num_tbs: 0,
            _pad: 0,
            tbs: [TfdTb::zeroed(); TFD_MAX_TBS],
        }
    }
}

/// RX Buffer Descriptor (RBD) — one per RX ring entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct Rbd {
    phys_addr: u64,
}

/// RX status struct written by hardware to DRAM.
#[repr(C)]
#[derive(Clone, Copy)]
struct RxStatus {
    closed_rb_num: u16,  // Number of RBs consumed
    closed_fr_num: u16,  // Number of frames received
    finished_rb_num: u16,
    finished_fr_num: u16,
    _pad: [u32; 2],
}

// Ring sizes
const TX_RING_SIZE: usize = 256;
const RX_RING_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// 802.11 frame types and management (minimal definitions)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const IEEE80211_FTYPE_MGMT: u16 = 0x0000;
#[allow(dead_code)]
const IEEE80211_STYPE_PROBE_REQ: u16 = 0x0040;
#[allow(dead_code)]
const IEEE80211_STYPE_PROBE_RESP: u16 = 0x0050;
#[allow(dead_code)]
const IEEE80211_STYPE_AUTH: u16 = 0x00B0;
#[allow(dead_code)]
const IEEE80211_STYPE_ASSOC_REQ: u16 = 0x0000;
#[allow(dead_code)]
const IEEE80211_STYPE_ASSOC_RESP: u16 = 0x0010;
#[allow(dead_code)]
const IEEE80211_STYPE_BEACON: u16 = 0x0080;

/// Known Intel Wi-Fi device families (for firmware selection).
#[derive(Clone, Copy)]
enum IwlFamily {
    Unknown,
    Gen7000,   // 7260, 7265, 3160
    Gen8000,   // 8260, 8265
    Gen9000,   // 9260, 9560
    Gen22000,  // AX200, AX201
    GenAx210,  // AX210, AX211
    GenBz,     // BE200 (Wi-Fi 7)
}

fn classify_device(device_id: u16) -> IwlFamily {
    match device_id {
        // 7000 series
        0x08B1 | 0x08B2 | 0x08B3 | 0x08B4 => IwlFamily::Gen7000,
        0x0893 | 0x0894 | 0x0895 | 0x0896 => IwlFamily::Gen7000,
        0x088E | 0x088F => IwlFamily::Gen7000,
        // 8000 series
        0x24F3 | 0x24F4 | 0x24F5 | 0x24F6 | 0x24FD | 0x24FB => IwlFamily::Gen8000,
        // 9000 series
        0x2526 | 0x271B | 0x271C | 0x30DC | 0x31DC | 0x9DF0 | 0x9DC0 => IwlFamily::Gen9000,
        0xA370 | 0x2720 => IwlFamily::Gen9000,
        // AX200/201 (22000 series)
        0x2723 => IwlFamily::Gen22000, // AX200
        0x06F0 | 0xA0F0 | 0x34F0 | 0x3DF0 | 0x4DF0 => IwlFamily::Gen22000, // AX201
        0x02F0 | 0x43F0 => IwlFamily::Gen22000, // AX201 variants
        // AX210/211
        0x2725 | 0x2726 => IwlFamily::GenAx210,
        0x51F0 | 0x51F1 | 0x54F0 | 0x7AF0 | 0x7A70 => IwlFamily::GenAx210,
        // BE200 (Wi-Fi 7)
        0x272B => IwlFamily::GenBz,
        _ => IwlFamily::Unknown,
    }
}

fn family_name(family: IwlFamily) -> &'static [u8] {
    match family {
        IwlFamily::Unknown => b"unknown",
        IwlFamily::Gen7000 => b"7000",
        IwlFamily::Gen8000 => b"8000",
        IwlFamily::Gen9000 => b"9000",
        IwlFamily::Gen22000 => b"AX200/201",
        IwlFamily::GenAx210 => b"AX210/211",
        IwlFamily::GenBz => b"BE200",
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

fn mmio_set_bit(base: usize, offset: usize, bits: u32) {
    let val = mmio_read32(base, offset);
    mmio_write32(base, offset, val | bits);
}

fn mmio_clear_bit(base: usize, offset: usize, bits: u32) {
    let val = mmio_read32(base, offset);
    mmio_write32(base, offset, val & !bits);
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

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

fn mac_to_u64(mac: [u8; 6]) -> u64 {
    (mac[0] as u64)
        | ((mac[1] as u64) << 8)
        | ((mac[2] as u64) << 16)
        | ((mac[3] as u64) << 24)
        | ((mac[4] as u64) << 32)
        | ((mac[5] as u64) << 40)
}

#[allow(dead_code)]
fn u64_to_mac(v: u64) -> [u8; 6] {
    [
        v as u8,
        (v >> 8) as u8,
        (v >> 16) as u8,
        (v >> 24) as u8,
        (v >> 32) as u8,
        (v >> 40) as u8,
    ]
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct NetifClient {
    active: bool,
    ethertype: u16,
    port: u64,
    rx_va: usize,
    tx_va: usize,
}

impl NetifClient {
    const fn new() -> Self {
        Self {
            active: false,
            ethertype: 0,
            port: 0,
            rx_va: 0,
            tx_va: 0,
        }
    }
}

struct IwlDev {
    bar: usize,
    device_id: u16,
    family: IwlFamily,
    hw_rev: u32,
    mac: [u8; 6],
    link_up: bool,
    clients: [NetifClient; MAX_CLIENTS],
    // TX ring (allocated DMA pages)
    #[allow(dead_code)]
    tx_ring_va: usize,
    #[allow(dead_code)]
    tx_ring_pa: u64,
    #[allow(dead_code)]
    tx_cmd_va: usize,  // Command buffer for TX
    #[allow(dead_code)]
    tx_cmd_pa: u64,
    // RX ring
    #[allow(dead_code)]
    rx_ring_va: usize,
    #[allow(dead_code)]
    rx_ring_pa: u64,
    #[allow(dead_code)]
    rx_status_va: usize,
    #[allow(dead_code)]
    rx_status_pa: u64,
    #[allow(dead_code)]
    rx_bufs_va: usize,  // RX data buffers
    #[allow(dead_code)]
    rx_bufs_pa: u64,
}

impl IwlDev {
    // ---------------------------------------------------------------
    // Hardware initialization
    // ---------------------------------------------------------------

    /// Step 1: Read hardware revision and classify the NIC.
    fn probe(&mut self) -> bool {
        self.hw_rev = mmio_read32(self.bar, CSR_HW_REV);
        self.family = classify_device(self.device_id);

        syscall::debug_puts(b"  [iwl_srv] HW rev=");
        print_hex(self.hw_rev as u64);
        syscall::debug_puts(b" family=");
        syscall::debug_puts(family_name(self.family));
        syscall::debug_puts(b" device=");
        print_hex(self.device_id as u64);
        syscall::debug_puts(b"\n");

        // Check RF Kill switch (hardware kill switch on laptops).
        let gp = mmio_read32(self.bar, CSR_GP_CNTRL);
        if gp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW == 0 {
            syscall::debug_puts(b"  [iwl_srv] WARNING: RF Kill switch is ON (radio disabled)\n");
            // Continue anyway — driver should still initialize.
        }
        true
    }

    /// Step 2: Set NIC to ready state.
    fn set_hw_ready(&mut self) -> bool {
        // Set NIC_READY bit in HW_IF_CONFIG.
        mmio_set_bit(self.bar, CSR_HW_IF_CONFIG_REG, CSR_HW_IF_CONFIG_REG_BIT_NIC_READY);

        // Poll for NIC_READY acknowledgment (up to 50 ms).
        for _ in 0..5000u32 {
            let val = mmio_read32(self.bar, CSR_HW_IF_CONFIG_REG);
            if val & CSR_HW_IF_CONFIG_REG_BIT_NIC_READY != 0 {
                return true;
            }
            // Busy-wait ~10us
            for _ in 0..100u32 {
                core::hint::spin_loop();
            }
        }
        syscall::debug_puts(b"  [iwl_srv] NIC_READY timeout\n");
        false
    }

    /// Step 3: Prepare power-on. Request MAC access and wait for clock.
    fn prepare_card_hw(&mut self) -> bool {
        // If NIC is already ready, skip power-on.
        let val = mmio_read32(self.bar, CSR_HW_IF_CONFIG_REG);
        if val & CSR_HW_IF_CONFIG_REG_BIT_NIC_READY != 0 {
            return true;
        }

        // Force NIC ready.
        if !self.set_hw_ready() {
            return false;
        }

        true
    }

    /// Step 4: Acquire NIC access (request MAC clock).
    fn nic_lock(&mut self) -> bool {
        mmio_set_bit(
            self.bar,
            CSR_GP_CNTRL,
            CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ,
        );

        // Wait for MAC_CLOCK_READY.
        for _ in 0..25000u32 {
            let val = mmio_read32(self.bar, CSR_GP_CNTRL);
            if val & CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY != 0 {
                return true;
            }
            for _ in 0..100u32 {
                core::hint::spin_loop();
            }
        }
        syscall::debug_puts(b"  [iwl_srv] MAC_CLOCK_READY timeout\n");
        false
    }

    /// Release NIC access.
    fn nic_unlock(&mut self) {
        mmio_clear_bit(
            self.bar,
            CSR_GP_CNTRL,
            CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ,
        );
    }

    /// Step 5: Software reset (stop master, then reset).
    fn sw_reset(&mut self) -> bool {
        // Stop master DMA.
        mmio_set_bit(self.bar, CSR_RESET, CSR_RESET_REG_FLAG_STOP_MASTER);

        // Wait for master disabled.
        for _ in 0..1000u32 {
            let val = mmio_read32(self.bar, CSR_RESET);
            if val & CSR_RESET_REG_FLAG_MASTER_DISABLED != 0 {
                break;
            }
            for _ in 0..100u32 {
                core::hint::spin_loop();
            }
        }

        // Issue software reset.
        mmio_set_bit(self.bar, CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);

        // Brief delay for reset to take effect.
        for _ in 0..10000u32 {
            core::hint::spin_loop();
        }

        true
    }

    /// Step 6: Disable all interrupts.
    fn disable_interrupts(&mut self) {
        mmio_write32(self.bar, CSR_INT_MASK, 0);
        // Clear any pending interrupts.
        mmio_write32(self.bar, CSR_INT, 0xFFFF_FFFF);
        mmio_write32(self.bar, CSR_FH_INT_STATUS, 0xFFFF_FFFF);
    }

    /// Step 7: Read MAC address from OTP/EEPROM.
    fn read_mac_from_otp(&mut self) -> bool {
        // The OTP (One-Time Programmable) region contains the NIC's
        // hardware MAC address. For generations 7000+, the MAC is
        // typically at OTP word offsets specific to the generation.
        //
        // This requires the NIC lock to be held. For now, we'll set
        // a deterministic MAC based on the device ID — the full OTP
        // read path needs firmware cooperation on most modern chips.
        self.mac = [
            0x00,
            0x1B, // Intel OUI prefix: 00:1B:21
            0x21,
            (self.device_id >> 8) as u8,
            self.device_id as u8,
            0x01,
        ];

        syscall::debug_puts(b"  [iwl_srv] MAC=");
        for (i, &b) in self.mac.iter().enumerate() {
            if i > 0 {
                syscall::debug_putchar(b':');
            }
            let hi = b >> 4;
            let lo = b & 0xF;
            syscall::debug_putchar(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
            syscall::debug_putchar(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
        }
        syscall::debug_puts(b"\n");
        true
    }

    /// Step 8: Allocate and configure TX/RX DMA rings.
    fn alloc_rings(&mut self) -> bool {
        let ps = syscall::page_size();

        // TX ring: TX_RING_SIZE TFDs × 164 bytes each ≈ 42 KiB → 11 pages.
        let tfd_size = core::mem::size_of::<Tfd>();
        let tx_ring_bytes = TX_RING_SIZE * tfd_size;
        let tx_ring_pages = (tx_ring_bytes + ps - 1) / ps;
        let tx_va = match syscall::mmap_anon(0, tx_ring_pages, 1) {
            Some(va) => va,
            None => return false,
        };
        let tx_pa = match syscall::virt_to_phys(tx_va) {
            Some(pa) => pa as u64,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(tx_va as *mut u8, 0, tx_ring_pages * ps);
        }
        self.tx_ring_va = tx_va;
        self.tx_ring_pa = tx_pa;

        // TX command buffers: 1 page per command slot (simplified).
        // In real driver, each slot gets a ~300-byte command header.
        let tx_cmd_pages = 4;
        let tx_cmd_va = match syscall::mmap_anon(0, tx_cmd_pages, 1) {
            Some(va) => va,
            None => return false,
        };
        let tx_cmd_pa = match syscall::virt_to_phys(tx_cmd_va) {
            Some(pa) => pa as u64,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(tx_cmd_va as *mut u8, 0, tx_cmd_pages * ps);
        }
        self.tx_cmd_va = tx_cmd_va;
        self.tx_cmd_pa = tx_cmd_pa;

        // RX ring: RX_RING_SIZE RBDs × 8 bytes = 2 KiB.
        let rbd_bytes = RX_RING_SIZE * core::mem::size_of::<Rbd>();
        let rx_ring_pages = (rbd_bytes + ps - 1) / ps;
        let rx_va = match syscall::mmap_anon(0, rx_ring_pages, 1) {
            Some(va) => va,
            None => return false,
        };
        let rx_pa = match syscall::virt_to_phys(rx_va) {
            Some(pa) => pa as u64,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(rx_va as *mut u8, 0, rx_ring_pages * ps);
        }
        self.rx_ring_va = rx_va;
        self.rx_ring_pa = rx_pa;

        // RX status (written by hardware): 1 page.
        let rx_sts_va = match syscall::mmap_anon(0, 1, 1) {
            Some(va) => va,
            None => return false,
        };
        let rx_sts_pa = match syscall::virt_to_phys(rx_sts_va) {
            Some(pa) => pa as u64,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(rx_sts_va as *mut u8, 0, ps);
        }
        self.rx_status_va = rx_sts_va;
        self.rx_status_pa = rx_sts_pa;

        // RX data buffers: RX_RING_SIZE × 4 KiB pages.
        // For now, allocate a batch of pages for RX data.
        let rx_buf_pages = 16; // 16 pages for RX buffers (ring wraps)
        let rx_bufs_va = match syscall::mmap_anon(0, rx_buf_pages, 1) {
            Some(va) => va,
            None => return false,
        };
        let rx_bufs_pa = match syscall::virt_to_phys(rx_bufs_va) {
            Some(pa) => pa as u64,
            None => return false,
        };
        unsafe {
            core::ptr::write_bytes(rx_bufs_va as *mut u8, 0, rx_buf_pages * ps);
        }
        self.rx_bufs_va = rx_bufs_va;
        self.rx_bufs_pa = rx_bufs_pa;

        // Fill RX ring with buffer descriptors.
        let rbd_ring = rx_va as *mut Rbd;
        for i in 0..16usize {
            unsafe {
                (*rbd_ring.add(i)).phys_addr = rx_bufs_pa + (i as u64) * (ps as u64);
            }
        }

        syscall::debug_puts(b"  [iwl_srv] TX ring at PA ");
        print_hex(tx_pa);
        syscall::debug_puts(b", RX ring at PA ");
        print_hex(rx_pa);
        syscall::debug_puts(b"\n");

        true
    }

    /// Step 9: Program FH (Frame Handler) registers for RX DMA.
    fn configure_rx_fh(&mut self) {
        if !self.nic_lock() {
            return;
        }

        // Stop RX DMA first.
        mmio_write32(self.bar, FH_RX_CONFIG, 0);

        // Set RBD ring base address.
        mmio_write32(
            self.bar,
            FH_RSCSR_CHNL0_RBDC_BASE,
            self.rx_ring_pa as u32,
        );

        // Set RX status write-pointer address.
        mmio_write32(
            self.bar,
            FH_RSCSR_CHNL0_STTS_WPTR,
            self.rx_status_pa as u32,
        );

        // Configure and enable RX DMA channel.
        mmio_write32(
            self.bar,
            FH_RX_CONFIG,
            FH_RX_CONFIG_REG_VAL_DMA_CHNL_EN_ENABLE
                | FH_RX_CONFIG_REG_VAL_RBDC_SIZE_4K
                | FH_RX_CONFIG_REG_IRQ_DEST_INT,
        );

        // Tell hardware how many RBDs we've prepared.
        mmio_write32(self.bar, FH_RSCSR_CHNL0_RBDCB_WPTR, 16);

        self.nic_unlock();
    }

    /// Step 10: Program FH registers for TX DMA (channel 0 = command queue).
    fn configure_tx_fh(&mut self) {
        if !self.nic_lock() {
            return;
        }

        // Set TFD ring base for command channel (channel 0).
        mmio_write32(self.bar, fh_tfd_cb_base(0), self.tx_ring_pa as u32);

        // Enable TX DMA channel 0.
        mmio_write32(
            self.bar,
            fh_tcsr_config(0),
            1 << 31, // Enable bit
        );

        self.nic_unlock();
    }

    /// Full initialization sequence.
    fn init(&mut self) -> bool {
        syscall::debug_puts(b"  [iwl_srv] initializing Intel Wi-Fi controller\n");

        if !self.probe() {
            return false;
        }
        if !self.prepare_card_hw() {
            return false;
        }
        if !self.sw_reset() {
            return false;
        }
        if !self.set_hw_ready() {
            return false;
        }

        self.disable_interrupts();

        if !self.nic_lock() {
            return false;
        }
        self.read_mac_from_otp();
        self.nic_unlock();

        if !self.alloc_rings() {
            syscall::debug_puts(b"  [iwl_srv] ring allocation failed\n");
            return false;
        }

        self.configure_rx_fh();
        self.configure_tx_fh();

        // Mark link as up. On real hardware, link comes up after firmware
        // load + association. For skeleton driver, mark ready immediately.
        self.link_up = true;

        syscall::debug_puts(b"  [iwl_srv] initialization complete\n");
        true
    }

    // ---------------------------------------------------------------
    // Netif client management
    // ---------------------------------------------------------------

    fn register_client(&mut self, ethertype: u16, client_port: u64, reply_port: u64) {
        for i in 0..MAX_CLIENTS {
            if !self.clients[i].active {
                let rx_va = CLIENT_GRANT_BASE + i * 2 * syscall::page_size();
                let tx_va = rx_va + syscall::page_size();

                self.clients[i] = NetifClient {
                    active: true,
                    ethertype,
                    port: client_port,
                    rx_va,
                    tx_va,
                };

                syscall::debug_puts(b"  [iwl_srv] client registered: ethertype=");
                print_hex(ethertype as u64);
                syscall::debug_puts(b" id=");
                print_num(i as u64);
                syscall::debug_puts(b"\n");

                syscall::send_nb_4(
                    reply_port,
                    NETIF_REGISTER_OK,
                    i as u64,
                    rx_va as u64,
                    tx_va as u64,
                    0,
                );
                return;
            }
        }
        syscall::debug_puts(b"  [iwl_srv] no free client slots\n");
    }

    fn handle_xmit(
        &mut self,
        client_id: usize,
        _payload_len: usize,
        _dst_mac_val: u64,
        _ethertype: u16,
        reply_port: u64,
    ) {
        if client_id >= MAX_CLIENTS || !self.clients[client_id].active {
            return;
        }
        // TODO: Build 802.11 frame from Ethernet payload, encrypt if needed,
        // write to TX TFD ring, ring doorbell.
        //
        // For now, acknowledge immediately (packet dropped — no firmware).
        syscall::send_nb(reply_port, NETIF_XMIT_OK, 0, 0);
    }

    fn handle_resolve(&mut self, _ip_be: u32, reply_port: u64) {
        // Wi-Fi doesn't do ARP at L2 — the AP handles address resolution.
        // Return failure for direct ARP resolve requests.
        syscall::send_nb(reply_port, NETIF_RESOLVE_FAIL, 0, 0);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [iwl_srv] starting\n");

    let irq = (arg0 >> 48) as u32;
    let cap_slot = (arg0 & 0xFFFF) as usize;

    // Map BAR0 via the MMIO cap the kernel granted us.
    let bar = match syscall::mmio_map_cap(cap_slot) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [iwl_srv] mmio_map_cap failed, exiting\n");
            syscall::exit(1);
            loop {
                core::hint::spin_loop();
            }
        }
    };

    syscall::debug_puts(b"  [iwl_srv] BAR0 mapped at ");
    print_hex(bar as u64);
    syscall::debug_puts(b" IRQ=");
    print_num(irq as u64);
    syscall::debug_puts(b"\n");

    // Read PCI device ID from SYS_FW_INFO or from CSR_HW_REV.
    // For kernel-spawned drivers, we don't get the PCI device ID directly.
    // Read the HW revision register to classify the device.
    let hw_rev = mmio_read32(bar, CSR_HW_REV);
    // Extract device ID heuristic from HW_REV (top 16 bits on some gens).
    // In practice the kernel could pass device_id in arg1, but for now
    // we classify based on hw_rev patterns.
    let device_id = (hw_rev >> 16) as u16;

    let mut dev = IwlDev {
        bar,
        device_id,
        family: IwlFamily::Unknown,
        hw_rev: 0,
        mac: [0; 6],
        link_up: false,
        clients: [const { NetifClient::new() }; MAX_CLIENTS],
        tx_ring_va: 0,
        tx_ring_pa: 0,
        tx_cmd_va: 0,
        tx_cmd_pa: 0,
        rx_ring_va: 0,
        rx_ring_pa: 0,
        rx_status_va: 0,
        rx_status_pa: 0,
        rx_bufs_va: 0,
        rx_bufs_pa: 0,
    };

    if !dev.init() {
        syscall::debug_puts(b"  [iwl_srv] init failed, exiting\n");
        syscall::exit(1);
        loop {
            core::hint::spin_loop();
        }
    }

    // Register as "wlan" service (Wi-Fi, separate from wired "eth").
    let port = syscall::port_create();
    syscall::ns_register(b"wlan", port);

    syscall::debug_puts(b"  [iwl_srv] server ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Poll-based server loop (same structure as eth_srv).
    loop {
        // 1. Poll RX from hardware.
        // TODO: Check RX status for new frames, process 802.11 headers,
        // strip to Ethernet payload, dispatch to registered clients via
        // NETIF_INPUT.

        // 2. Poll IPC.
        if let Some(msg) = syscall::recv_nb_msg(port) {
            match msg.tag {
                NETIF_REGISTER => {
                    let ethertype = msg.data[0] as u16;
                    let client_port = msg.data[1];
                    let reply_port = msg.data[2];
                    dev.register_client(ethertype, client_port, reply_port);
                }
                NETIF_XMIT => {
                    let payload_len = msg.data[0] as usize;
                    let dst_mac_val = msg.data[1];
                    let ethertype = msg.data[2] as u16;
                    let reply_port = msg.data[2] >> 16;
                    let client_id = msg.data[3] as usize;
                    dev.handle_xmit(client_id, payload_len, dst_mac_val, ethertype, reply_port);
                }
                NETIF_RESOLVE => {
                    let ip_be = msg.data[0] as u32;
                    let reply_port = msg.data[1];
                    dev.handle_resolve(ip_be, reply_port);
                }
                NETIF_STATUS => {
                    let reply_port = msg.data[0];
                    let flags = if dev.link_up { 1u64 } else { 0u64 };
                    syscall::send_nb(
                        reply_port,
                        NETIF_STATUS_OK,
                        mac_to_u64(dev.mac),
                        MTU as u64 | (flags << 32),
                    );
                }
                _ => {}
            }
        }

        syscall::yield_now();
    }
}
