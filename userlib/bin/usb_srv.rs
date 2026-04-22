#![no_std]
#![no_main]

//! Userspace USB xHCI host controller driver and IPC server.
//!
//! Discovers the xHCI controller via MMIO cap (BAR0) granted by the kernel.
//! Initializes the controller, enumerates ports, addresses devices, and serves
//! USB_LIST_DEVICES / USB_GET_DESCRIPTOR / USB_CONTROL_XFER requests.
//!
//! Currently x86_64-only (PCI xHCI). The driver is polled (no IRQ) for
//! simplicity — QEMU xHCI completions are fast enough.

extern crate userlib;

use userlib::syscall;

// --- USB IPC protocol constants ---
const USB_LIST_DEVICES: u64 = 0x9000;
const USB_LIST_DEVICES_OK: u64 = 0x9001;
const USB_GET_DESCRIPTOR: u64 = 0x9100;
const USB_GET_DESCRIPTOR_OK: u64 = 0x9101;
const USB_CONTROL_XFER: u64 = 0x9200;
const USB_CONTROL_XFER_OK: u64 = 0x9201;
const USB_PORT_STATUS: u64 = 0x9400;
const USB_PORT_STATUS_OK: u64 = 0x9401;
const USB_ERROR: u64 = 0x9F00;

// --- xHCI Capability Register offsets (from BAR0) ---
const CAP_CAPLENGTH: usize = 0x00;  // u8: offset to operational regs
const CAP_HCSPARAMS1: usize = 0x04; // u32: max_slots[31:24], max_intrs[18:8], max_ports[7:0]
const CAP_HCSPARAMS2: usize = 0x08; // u32: scratchpad bufs
const CAP_HCCPARAMS1: usize = 0x10; // u32: AC64[0], CSZ[2]
const CAP_DBOFF: usize = 0x14;      // u32: doorbell array offset
const CAP_RTSOFF: usize = 0x18;     // u32: runtime register space offset

// --- xHCI Operational Register offsets (from op_base = bar + caplength) ---
const OP_USBCMD: usize = 0x00;
const OP_USBSTS: usize = 0x04;
const OP_PAGESIZE: usize = 0x08;
const OP_CRCR: usize = 0x18;    // 64-bit: Command Ring Control Register
const OP_DCBAAP: usize = 0x30;  // 64-bit: Device Context Base Address Array Pointer
const OP_CONFIG: usize = 0x38;

// USBCMD bits
const USBCMD_RS: u32 = 1 << 0;    // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
const USBCMD_INTE: u32 = 1 << 2;  // Interrupter Enable

// USBSTS bits
const USBSTS_HCH: u32 = 1 << 0;   // HC Halted
const USBSTS_CNR: u32 = 1 << 11;   // Controller Not Ready

// Port register offsets (from op_base + 0x400 + 16*port_index)
const PORT_BASE: usize = 0x400;
const PORTSC_OFFSET: usize = 0x00;

// PORTSC bits
const PORTSC_CCS: u32 = 1 << 0;    // Current Connect Status
const PORTSC_PED: u32 = 1 << 1;    // Port Enabled/Disabled
const PORTSC_PR: u32 = 1 << 4;     // Port Reset
const PORTSC_PP: u32 = 1 << 9;     // Port Power
const PORTSC_SPEED_MASK: u32 = 0xF << 10; // Port Speed
const PORTSC_CSC: u32 = 1 << 17;   // Connect Status Change (W1C)
const PORTSC_PRC: u32 = 1 << 21;   // Port Reset Change (W1C)
// Write-1-to-clear status bits — preserve when doing RMW on PORTSC
const PORTSC_W1C_MASK: u32 = PORTSC_CSC | PORTSC_PRC | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 22) | (1 << 23);

// Interrupter register offsets (from rt_base + 0x20 + 32*interrupter)
const INTR_BASE: usize = 0x20;
const INTR_IMAN: usize = 0x00;
const INTR_IMOD: usize = 0x04;
const INTR_ERSTSZ: usize = 0x08;
const INTR_ERSTBA: usize = 0x10;  // 64-bit
const INTR_ERDP: usize = 0x18;    // 64-bit

// --- TRB type codes (bits 15:10 of control field) ---
const TRB_NORMAL: u32 = 1;
const TRB_SETUP_STAGE: u32 = 2;
const TRB_DATA_STAGE: u32 = 3;
const TRB_STATUS_STAGE: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_NOOP_CMD: u32 = 23;
const TRB_TRANSFER_EVENT: u32 = 32;
const TRB_CMD_COMPLETION: u32 = 33;
const TRB_PORT_STATUS_CHANGE: u32 = 34;

// TRB completion codes
const TRB_CC_SUCCESS: u32 = 1;
const TRB_CC_SHORT_PACKET: u32 = 13;

// Ring sizes
const CMD_RING_SIZE: usize = 64;   // 63 usable + 1 link TRB
const EVT_RING_SIZE: usize = 256;  // 1 page = 256 TRBs
const TRANSFER_RING_SIZE: usize = 64;

const MAX_SLOTS: usize = 128;
const MAX_PORTS: usize = 16;

// --- TRB structure (16 bytes) ---
#[repr(C)]
#[derive(Clone, Copy)]
struct Trb {
    param: u64,    // Parameter (address, or inline data)
    status: u32,   // Status / transfer length / completion code
    control: u32,  // Cycle[0], type[15:10], direction[16], + type-specific
}

impl Trb {
    const fn zeroed() -> Self {
        Trb { param: 0, status: 0, control: 0 }
    }

    fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    fn completion_code(&self) -> u32 {
        (self.status >> 24) & 0xFF
    }

    fn slot_id(&self) -> u8 {
        (self.control >> 24) as u8
    }
}

// --- Event Ring Segment Table Entry (16 bytes) ---
#[repr(C)]
struct ErstEntry {
    ring_base: u64,
    ring_size: u32,
    _rsvd: u32,
}

// --- Slot/Endpoint Contexts ---
// Using raw u32 arrays — context size is 32 bytes (8 dwords) or 64 bytes if CSZ=1.
#[repr(C)]
#[derive(Clone, Copy)]
struct SlotContext {
    dw: [u32; 8],
}

impl SlotContext {
    const fn zeroed() -> Self {
        SlotContext { dw: [0; 8] }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EndpointContext {
    dw: [u32; 8],
}

impl EndpointContext {
    const fn zeroed() -> Self {
        EndpointContext { dw: [0; 8] }
    }
}

// --- Per-slot tracking ---
#[derive(Clone, Copy)]
struct SlotState {
    active: bool,
    port: u8,
    speed: u8,          // 1=FS, 2=LS, 3=HS, 4=SS
    vendor_id: u16,
    product_id: u16,
    device_class: u8,
    device_ctx_va: usize,
    device_ctx_pa: u64,
    input_ctx_va: usize,
    input_ctx_pa: u64,
    transfer_ring_va: usize,
    transfer_ring_pa: u64,
    tr_enq: usize,
    tr_cycle: bool,
}

impl SlotState {
    const fn empty() -> Self {
        SlotState {
            active: false,
            port: 0,
            speed: 0,
            vendor_id: 0,
            product_id: 0,
            device_class: 0,
            device_ctx_va: 0,
            device_ctx_pa: 0,
            input_ctx_va: 0,
            input_ctx_pa: 0,
            transfer_ring_va: 0,
            transfer_ring_pa: 0,
            tr_enq: 0,
            tr_cycle: true,
        }
    }
}

// --- xHCI Controller State ---
struct XhciCtrl {
    bar: usize,
    cap_len: u8,
    op_base: usize,
    db_base: usize,
    rt_base: usize,
    max_slots: u8,
    max_ports: u8,
    context_size: usize,  // 32 or 64
    // DCBAA
    dcbaa_va: usize,
    dcbaa_pa: u64,
    // Command ring
    cmd_ring_va: usize,
    cmd_ring_pa: u64,
    cmd_ring_enq: usize,
    cmd_ring_cycle: bool,
    // Event ring (interrupter 0)
    evt_ring_va: usize,
    evt_ring_pa: u64,
    erst_va: usize,
    erst_pa: u64,
    evt_ring_deq: usize,
    evt_ring_cycle: bool,
    // Data buffer for control transfers
    data_va: usize,
    data_pa: u64,
    // Per-slot state
    slots: [SlotState; MAX_SLOTS],
    num_devices: u8,
}

// --- MMIO read/write helpers ---
fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

fn mmio_read64(base: usize, offset: usize) -> u64 {
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    lo | (hi << 32)
}

fn mmio_write64(base: usize, offset: usize, val: u64) {
    mmio_write32(base, offset, val as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
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

/// Non-blocking send with retry.
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

// --- Allocate a zeroed page and return (VA, PA) ---
fn alloc_page() -> Option<(usize, u64)> {
    let va = syscall::mmap_anon(0, 1, 1)?;
    let pa = syscall::virt_to_phys(va)? as u64;
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, syscall::page_size()); }
    Some((va, pa))
}

fn alloc_pages(n: usize) -> Option<(usize, u64)> {
    let va = syscall::mmap_anon(0, n, 1)?;
    let pa = syscall::virt_to_phys(va)? as u64;
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, n * syscall::page_size()); }
    Some((va, pa))
}

// ===========================================================================
// Ring management
// ===========================================================================

/// Enqueue a TRB on the command ring. Sets/clears cycle bit to match producer state.
fn cmd_ring_enqueue(ctrl: &mut XhciCtrl, mut trb: Trb) {
    // Set cycle bit
    if ctrl.cmd_ring_cycle {
        trb.control |= 1;
    } else {
        trb.control &= !1;
    }

    let offset = ctrl.cmd_ring_enq * 16;
    unsafe {
        core::ptr::write_volatile((ctrl.cmd_ring_va + offset) as *mut Trb, trb);
    }

    ctrl.cmd_ring_enq += 1;

    // If we hit the link TRB slot, write a link TRB and wrap
    if ctrl.cmd_ring_enq >= CMD_RING_SIZE - 1 {
        let mut link = Trb::zeroed();
        link.param = ctrl.cmd_ring_pa;
        link.control = (TRB_LINK << 10) | (1 << 1); // Toggle Cycle bit
        if ctrl.cmd_ring_cycle {
            link.control |= 1;
        }
        let link_offset = ctrl.cmd_ring_enq * 16;
        unsafe {
            core::ptr::write_volatile((ctrl.cmd_ring_va + link_offset) as *mut Trb, link);
        }
        ctrl.cmd_ring_enq = 0;
        ctrl.cmd_ring_cycle = !ctrl.cmd_ring_cycle;
    }
}

/// Ring the host controller doorbell (DB[0] = 0 for command ring).
fn cmd_ring_doorbell(ctrl: &XhciCtrl) {
    mmio_write32(ctrl.db_base, 0, 0);
}

/// Poll the event ring for a completion. Returns None on timeout.
fn poll_event(ctrl: &mut XhciCtrl, timeout: u32) -> Option<Trb> {
    for i in 0..timeout {
        let offset = ctrl.evt_ring_deq * 16;
        let trb = unsafe {
            core::ptr::read_volatile((ctrl.evt_ring_va + offset) as *const Trb)
        };

        let cycle = (trb.control & 1) != 0;
        if cycle != ctrl.evt_ring_cycle {
            if i % 50_000 == 0 { syscall::yield_now(); }
            core::hint::spin_loop();
            continue;
        }

        // Got an event — advance dequeue pointer
        ctrl.evt_ring_deq += 1;
        if ctrl.evt_ring_deq >= EVT_RING_SIZE {
            ctrl.evt_ring_deq = 0;
            ctrl.evt_ring_cycle = !ctrl.evt_ring_cycle;
        }

        // Update ERDP (write physical address of current dequeue position)
        let erdp_pa = ctrl.evt_ring_pa + (ctrl.evt_ring_deq as u64) * 16;
        let intr0 = ctrl.rt_base + INTR_BASE;
        // Set EHB (bit 3) to clear Event Handler Busy
        mmio_write64(intr0, INTR_ERDP, erdp_pa | (1 << 3));

        return Some(trb);
    }
    None
}

/// Poll for a command completion event.
fn poll_command_completion(ctrl: &mut XhciCtrl) -> Option<Trb> {
    let timeout = 5_000_000u32;
    loop {
        let trb = poll_event(ctrl, timeout)?;
        match trb.trb_type() {
            TRB_CMD_COMPLETION => return Some(trb),
            TRB_PORT_STATUS_CHANGE => {
                // Consume port status change events silently during init
                continue;
            }
            _ => continue,
        }
    }
}

/// Enqueue a TRB on a slot's EP0 transfer ring.
fn transfer_ring_enqueue(slot: &mut SlotState, mut trb: Trb) {
    if slot.tr_cycle {
        trb.control |= 1;
    } else {
        trb.control &= !1;
    }

    let offset = slot.tr_enq * 16;
    unsafe {
        core::ptr::write_volatile((slot.transfer_ring_va + offset) as *mut Trb, trb);
    }

    slot.tr_enq += 1;

    if slot.tr_enq >= TRANSFER_RING_SIZE - 1 {
        let mut link = Trb::zeroed();
        link.param = slot.transfer_ring_pa;
        link.control = (TRB_LINK << 10) | (1 << 1); // Toggle Cycle
        if slot.tr_cycle {
            link.control |= 1;
        }
        let link_offset = slot.tr_enq * 16;
        unsafe {
            core::ptr::write_volatile((slot.transfer_ring_va + link_offset) as *mut Trb, link);
        }
        slot.tr_enq = 0;
        slot.tr_cycle = !slot.tr_cycle;
    }
}

/// Ring the doorbell for a device slot's endpoint.
/// target: 1 = EP0 (control), 2 = EP1 OUT, 3 = EP1 IN, etc.
fn slot_doorbell(ctrl: &XhciCtrl, slot_id: u8, target: u8) {
    let db_offset = (slot_id as usize) * 4;
    mmio_write32(ctrl.db_base, db_offset, target as u32);
}

// ===========================================================================
// Controller initialization
// ===========================================================================

fn xhci_init(bar: usize) -> Option<XhciCtrl> {
    // Read capability registers
    let cap_len = mmio_read32(bar, CAP_CAPLENGTH) as u8;
    let hcsparams1 = mmio_read32(bar, CAP_HCSPARAMS1);
    let hcsparams2 = mmio_read32(bar, CAP_HCSPARAMS2);
    let hccparams1 = mmio_read32(bar, CAP_HCCPARAMS1);
    let dboff = mmio_read32(bar, CAP_DBOFF) & !0x3; // aligned
    let rtsoff = mmio_read32(bar, CAP_RTSOFF) & !0x1F; // 32-byte aligned

    let max_slots = ((hcsparams1 >> 24) & 0xFF) as u8;
    let max_ports = (hcsparams1 & 0xFF) as u8;
    let ac64 = (hccparams1 & 1) != 0;
    let csz = (hccparams1 >> 2) & 1; // Context Size: 0=32B, 1=64B
    let context_size: usize = if csz != 0 { 64 } else { 32 };

    // Scratchpad buffer count: bits 31:27 (hi) | bits 25:21 (lo) of HCSPARAMS2
    let spad_hi = ((hcsparams2 >> 27) & 0x1F) as usize;
    let spad_lo = ((hcsparams2 >> 21) & 0x1F) as usize;
    let scratchpad_count = (spad_hi << 5) | spad_lo;

    let op_base = bar + cap_len as usize;
    let db_base = bar + dboff as usize;
    let rt_base = bar + rtsoff as usize;

    syscall::debug_puts(b"  [usb_srv] cap_len=");
    print_num(cap_len as u64);
    syscall::debug_puts(b" max_slots=");
    print_num(max_slots as u64);
    syscall::debug_puts(b" max_ports=");
    print_num(max_ports as u64);
    syscall::debug_puts(b" ctx_size=");
    print_num(context_size as u64);
    syscall::debug_puts(b" scratchpad=");
    print_num(scratchpad_count as u64);
    syscall::debug_puts(b" AC64=");
    print_num(ac64 as u64);
    syscall::debug_puts(b"\n");

    if !ac64 {
        syscall::debug_puts(b"  [usb_srv] 64-bit addressing not supported, aborting\n");
        return None;
    }

    // Step 1: Halt controller — clear Run/Stop, wait for HCH
    let cmd = mmio_read32(op_base, OP_USBCMD);
    if cmd & USBCMD_RS != 0 {
        mmio_write32(op_base, OP_USBCMD, cmd & !USBCMD_RS);
    }
    for i in 0..1_000_000u32 {
        let sts = mmio_read32(op_base, OP_USBSTS);
        if sts & USBSTS_HCH != 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    // Step 2: Reset controller
    mmio_write32(op_base, OP_USBCMD, USBCMD_HCRST);
    for i in 0..2_000_000u32 {
        let cmd_val = mmio_read32(op_base, OP_USBCMD);
        let sts = mmio_read32(op_base, OP_USBSTS);
        if (cmd_val & USBCMD_HCRST) == 0 && (sts & USBSTS_CNR) == 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }
    // Verify reset complete
    let sts = mmio_read32(op_base, OP_USBSTS);
    if sts & USBSTS_CNR != 0 {
        syscall::debug_puts(b"  [usb_srv] controller not ready after reset\n");
        return None;
    }
    syscall::debug_puts(b"  [usb_srv] controller reset complete\n");

    // Step 3: Configure max device slots
    let slots_enabled = if max_slots > MAX_SLOTS as u8 { MAX_SLOTS as u8 } else { max_slots };
    mmio_write32(op_base, OP_CONFIG, slots_enabled as u32);

    // Step 4: Allocate DCBAA (Device Context Base Address Array)
    // Need (max_slots + 1) * 8 bytes. Slot 0 = scratchpad buf array pointer.
    let (dcbaa_va, dcbaa_pa) = alloc_page()?;

    // Step 5: Allocate scratchpad buffers if needed
    if scratchpad_count > 0 {
        // Scratchpad buffer array: array of 64-bit physical addresses
        let (spad_arr_va, spad_arr_pa) = alloc_page()?;

        for i in 0..scratchpad_count {
            let (_, buf_pa) = alloc_page()?;
            unsafe {
                let ptr = (spad_arr_va + i * 8) as *mut u64;
                core::ptr::write_volatile(ptr, buf_pa);
            }
        }

        // DCBAA[0] = scratchpad buffer array physical address
        unsafe {
            core::ptr::write_volatile(dcbaa_va as *mut u64, spad_arr_pa);
        }
    }

    // Write DCBAAP
    mmio_write64(op_base, OP_DCBAAP, dcbaa_pa);

    // Step 6: Allocate command ring (1 page)
    let (cmd_ring_va, cmd_ring_pa) = alloc_page()?;

    // Write link TRB at the last slot pointing back to start
    let link_trb = Trb {
        param: cmd_ring_pa,
        status: 0,
        control: (TRB_LINK << 10) | (1 << 1) | 1, // Toggle + initial cycle=1
    };
    unsafe {
        let ptr = (cmd_ring_va + (CMD_RING_SIZE - 1) * 16) as *mut Trb;
        core::ptr::write_volatile(ptr, link_trb);
    }

    // Write CRCR: ring base | RCS=1 (Ring Cycle State)
    mmio_write64(op_base, OP_CRCR, cmd_ring_pa | 1);

    // Step 7: Allocate event ring (1 page = 256 TRBs)
    let (evt_ring_va, evt_ring_pa) = alloc_page()?;

    // Allocate ERST (Event Ring Segment Table) — 1 entry
    let (erst_va, erst_pa) = alloc_page()?;
    unsafe {
        let entry = erst_va as *mut ErstEntry;
        (*entry).ring_base = evt_ring_pa;
        (*entry).ring_size = EVT_RING_SIZE as u32;
        (*entry)._rsvd = 0;
    }

    // Configure interrupter 0
    let intr0 = rt_base + INTR_BASE;
    mmio_write32(intr0, INTR_ERSTSZ, 1); // 1 segment
    // Write ERDP first (before ERSTBA per spec)
    mmio_write64(intr0, INTR_ERDP, evt_ring_pa);
    mmio_write64(intr0, INTR_ERSTBA, erst_pa);
    // Enable interrupt (even though we poll, some controllers need this)
    mmio_write32(intr0, INTR_IMOD, 0);
    mmio_write32(intr0, INTR_IMAN, 0x3); // IE + IP clear

    // Step 8: Allocate a data buffer page for control transfers
    let (data_va, data_pa) = alloc_page()?;

    // Step 9: Start controller
    mmio_write32(op_base, OP_USBCMD, USBCMD_RS | USBCMD_INTE);

    // Wait for not halted
    for i in 0..1_000_000u32 {
        let sts_val = mmio_read32(op_base, OP_USBSTS);
        if sts_val & USBSTS_HCH == 0 {
            break;
        }
        if i % 10_000 == 0 { syscall::yield_now(); }
        core::hint::spin_loop();
    }

    let sts_final = mmio_read32(op_base, OP_USBSTS);
    if sts_final & USBSTS_HCH != 0 {
        syscall::debug_puts(b"  [usb_srv] controller failed to start\n");
        return None;
    }

    syscall::debug_puts(b"  [usb_srv] controller running\n");

    Some(XhciCtrl {
        bar,
        cap_len,
        op_base,
        db_base,
        rt_base,
        max_slots: slots_enabled,
        max_ports: if max_ports > MAX_PORTS as u8 { MAX_PORTS as u8 } else { max_ports },
        context_size,
        dcbaa_va,
        dcbaa_pa,
        cmd_ring_va,
        cmd_ring_pa,
        cmd_ring_enq: 0,
        cmd_ring_cycle: true,
        evt_ring_va,
        evt_ring_pa,
        erst_va,
        erst_pa,
        evt_ring_deq: 0,
        evt_ring_cycle: true,
        data_va,
        data_pa,
        slots: [SlotState::empty(); MAX_SLOTS],
        num_devices: 0,
    })
}

// ===========================================================================
// Port enumeration
// ===========================================================================

fn port_reg_base(ctrl: &XhciCtrl, port: u8) -> usize {
    ctrl.op_base + PORT_BASE + (port as usize) * 16
}

/// Read PORTSC for a given port (0-indexed).
fn read_portsc(ctrl: &XhciCtrl, port: u8) -> u32 {
    mmio_read32(port_reg_base(ctrl, port), PORTSC_OFFSET)
}

/// Get port speed from PORTSC (bits 13:10): 1=FS, 2=LS, 3=HS, 4=SS.
fn port_speed(portsc: u32) -> u8 {
    ((portsc & PORTSC_SPEED_MASK) >> 10) as u8
}

fn speed_name(speed: u8) -> &'static [u8] {
    match speed {
        1 => b"Full",
        2 => b"Low",
        3 => b"High",
        4 => b"Super",
        _ => b"?",
    }
}

/// Reset a port and wait for it to become enabled.
fn port_reset(ctrl: &mut XhciCtrl, port: u8) -> bool {
    let base = port_reg_base(ctrl, port);
    let portsc = mmio_read32(base, PORTSC_OFFSET);

    // Write PR=1 to initiate reset. Preserve PP, clear W1C bits.
    let val = (portsc & !(PORTSC_PED | PORTSC_W1C_MASK)) | PORTSC_PR;
    mmio_write32(base, PORTSC_OFFSET, val);

    // Wait for PRC (Port Reset Change) or PED (Port Enabled).
    // Yield periodically to avoid starving other threads during startup.
    for i in 0..2_000_000u32 {
        let ps = mmio_read32(base, PORTSC_OFFSET);
        if ps & PORTSC_PRC != 0 {
            // Clear PRC by writing 1
            let clear = (ps & !PORTSC_W1C_MASK) | PORTSC_PRC;
            mmio_write32(base, PORTSC_OFFSET, clear);

            // Drain any port status change events
            for _ in 0..10u32 {
                if let Some(evt) = poll_event(ctrl, 10_000) {
                    if evt.trb_type() == TRB_PORT_STATUS_CHANGE {
                        continue;
                    }
                }
                break;
            }
            return true;
        }
        if i % 10_000 == 0 {
            syscall::yield_now();
        }
        core::hint::spin_loop();
    }
    false
}

/// Enumerate all ports and reset connected ones.
/// Returns list of (port_index, speed) for connected+enabled ports.
fn enumerate_ports(ctrl: &mut XhciCtrl) -> [(u8, u8); MAX_PORTS] {
    let mut connected = [(0u8, 0u8); MAX_PORTS];
    let mut count = 0usize;

    for port in 0..ctrl.max_ports {
        let portsc = read_portsc(ctrl, port);

        if portsc & PORTSC_CCS == 0 {
            continue; // nothing connected
        }

        syscall::debug_puts(b"  [usb_srv] port ");
        print_num(port as u64);
        syscall::debug_puts(b": connected, resetting...\n");

        if port_reset(ctrl, port) {
            let portsc_after = read_portsc(ctrl, port);
            let spd = port_speed(portsc_after);

            if portsc_after & PORTSC_PED != 0 {
                syscall::debug_puts(b"  [usb_srv]   enabled, speed=");
                syscall::debug_puts(speed_name(spd));
                syscall::debug_puts(b"\n");

                if count < MAX_PORTS {
                    connected[count] = (port, spd);
                    count += 1;
                }
            } else {
                syscall::debug_puts(b"  [usb_srv]   reset done but not enabled\n");
            }
        } else {
            syscall::debug_puts(b"  [usb_srv]   reset timeout\n");
        }
    }

    // Mark end of list with port=0xFF
    if count < MAX_PORTS {
        connected[count] = (0xFF, 0);
    }
    connected
}

// ===========================================================================
// USB device enumeration
// ===========================================================================

/// Send Enable Slot command, returns slot_id (1-based) on success.
fn enable_slot(ctrl: &mut XhciCtrl) -> Option<u8> {
    let trb = Trb {
        param: 0,
        status: 0,
        control: TRB_ENABLE_SLOT << 10,
    };
    cmd_ring_enqueue(ctrl, trb);
    cmd_ring_doorbell(ctrl);

    let evt = poll_command_completion(ctrl)?;
    let cc = evt.completion_code();
    if cc != TRB_CC_SUCCESS {
        syscall::debug_puts(b"  [usb_srv] enable_slot failed, cc=");
        print_num(cc as u64);
        syscall::debug_puts(b"\n");
        return None;
    }

    let slot_id = evt.slot_id();
    if slot_id == 0 || slot_id as usize > MAX_SLOTS {
        return None;
    }
    Some(slot_id)
}

/// Address a device: allocate contexts, fill input context, send Address Device command.
fn address_device(ctrl: &mut XhciCtrl, slot_id: u8, port: u8, speed: u8) -> bool {
    let ctx_sz = ctrl.context_size;

    // Allocate device context: slot context + 31 endpoint contexts
    // Total = 32 * context_size bytes. For 32-byte contexts: 1024 bytes (1 page).
    // For 64-byte contexts: 2048 bytes (1 page).
    let (dev_ctx_va, dev_ctx_pa) = match alloc_page() {
        Some(x) => x,
        None => return false,
    };

    // Allocate input context: input control ctx + slot ctx + 31 EP contexts
    // Total = 33 * context_size bytes.
    let (input_ctx_va, input_ctx_pa) = match alloc_page() {
        Some(x) => x,
        None => return false,
    };

    // Allocate EP0 transfer ring
    let (tr_va, tr_pa) = match alloc_page() {
        Some(x) => x,
        None => return false,
    };

    // Write link TRB at end of transfer ring
    let link = Trb {
        param: tr_pa,
        status: 0,
        control: (TRB_LINK << 10) | (1 << 1) | 1, // Toggle + cycle=1
    };
    unsafe {
        let ptr = (tr_va + (TRANSFER_RING_SIZE - 1) * 16) as *mut Trb;
        core::ptr::write_volatile(ptr, link);
    }

    // Fill Input Control Context (first context_size bytes of input context)
    // dw1 (offset 4): Add Context Flags — bit 0 = slot, bit 1 = EP0
    unsafe {
        let icc = input_ctx_va as *mut u32;
        // dw0 = drop flags = 0
        core::ptr::write_volatile(icc.add(0), 0);
        // dw1 = add flags: slot(bit 0) + EP0(bit 1) = 0x3
        core::ptr::write_volatile(icc.add(1), 0x3);
    }

    // Fill Slot Context (starts at input_ctx + context_size)
    let slot_ctx_offset = input_ctx_va + ctx_sz;
    unsafe {
        let sc = slot_ctx_offset as *mut u32;
        // dw0: Route String[19:0]=0, Speed[23:20], Context Entries[31:27]=1
        let dw0 = ((speed as u32) << 20) | (1u32 << 27);
        core::ptr::write_volatile(sc.add(0), dw0);
        // dw1: Max Exit Latency = 0, Root Hub Port Number[23:16], Num Ports = 0
        let dw1 = ((port as u32 + 1) << 16); // port is 0-indexed, xHCI wants 1-indexed
        core::ptr::write_volatile(sc.add(1), dw1);
    }

    // Fill EP0 Context (starts at input_ctx + 2*context_size)
    let ep0_ctx_offset = input_ctx_va + 2 * ctx_sz;
    // Max packet size: 8 for LS, 64 for FS/HS, 512 for SS
    let max_packet = match speed {
        2 => 8u16,       // Low Speed
        1 => 64,         // Full Speed (start with 64, may need 8 initially)
        3 => 64,         // High Speed
        4 => 512,        // Super Speed
        _ => 64,
    };
    unsafe {
        let ep = ep0_ctx_offset as *mut u32;
        // dw0: EP State = 0 (disabled, xHC will set it)
        core::ptr::write_volatile(ep.add(0), 0);
        // dw1: CErr[2:1]=3, EP Type[5:3]=4 (Control Bidir), Max Burst=0, Max Packet Size[31:16]
        let dw1 = (3u32 << 1) | (4u32 << 3) | ((max_packet as u32) << 16);
        core::ptr::write_volatile(ep.add(1), dw1);
        // dw2: TR Dequeue Pointer low (with DCS=1)
        core::ptr::write_volatile(ep.add(2), (tr_pa as u32) | 1); // DCS = 1
        // dw3: TR Dequeue Pointer high
        core::ptr::write_volatile(ep.add(3), (tr_pa >> 32) as u32);
        // dw4: Average TRB Length = 8 (typical for control), Max ESIT Payload = 0
        core::ptr::write_volatile(ep.add(4), 8);
    }

    // Set DCBAA[slot_id] = device context physical address
    unsafe {
        let dcbaa_entry = (ctrl.dcbaa_va + (slot_id as usize) * 8) as *mut u64;
        core::ptr::write_volatile(dcbaa_entry, dev_ctx_pa);
    }

    // Send Address Device command
    let cmd_trb = Trb {
        param: input_ctx_pa,
        status: 0,
        control: (TRB_ADDRESS_DEVICE << 10) | ((slot_id as u32) << 24),
    };
    cmd_ring_enqueue(ctrl, cmd_trb);
    cmd_ring_doorbell(ctrl);

    let evt = match poll_command_completion(ctrl) {
        Some(e) => e,
        None => {
            syscall::debug_puts(b"  [usb_srv] address_device timeout\n");
            return false;
        }
    };

    let cc = evt.completion_code();
    if cc != TRB_CC_SUCCESS {
        syscall::debug_puts(b"  [usb_srv] address_device failed, cc=");
        print_num(cc as u64);
        syscall::debug_puts(b"\n");
        return false;
    }

    // Save slot state
    let slot = &mut ctrl.slots[slot_id as usize];
    slot.active = true;
    slot.port = port;
    slot.speed = speed;
    slot.device_ctx_va = dev_ctx_va;
    slot.device_ctx_pa = dev_ctx_pa;
    slot.input_ctx_va = input_ctx_va;
    slot.input_ctx_pa = input_ctx_pa;
    slot.transfer_ring_va = tr_va;
    slot.transfer_ring_pa = tr_pa;
    slot.tr_enq = 0;
    slot.tr_cycle = true;

    syscall::debug_puts(b"  [usb_srv] slot ");
    print_num(slot_id as u64);
    syscall::debug_puts(b" addressed\n");
    true
}

/// Execute a control transfer on EP0 and read data into ctrl.data_va.
/// Returns number of bytes transferred, or None on failure.
fn control_transfer_in(
    ctrl: &mut XhciCtrl,
    slot_id: u8,
    bm_request_type: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
) -> Option<usize> {
    let slot = &mut ctrl.slots[slot_id as usize];
    if !slot.active {
        return None;
    }

    // Setup Stage TRB
    // param = bmRequestType | bRequest<<8 | wValue<<16 | wIndex<<32 | wLength<<48
    let setup_param = (bm_request_type as u64)
        | ((b_request as u64) << 8)
        | ((w_value as u64) << 16)
        | ((w_index as u64) << 32)
        | ((w_length as u64) << 48);

    let setup_trb = Trb {
        param: setup_param,
        status: 8, // TRB Transfer Length = 8 (setup packet size)
        // TRT (Transfer Type) = 3 (IN data stage) in bits 17:16
        // IDT (Immediate Data) = 1 in bit 6
        control: (TRB_SETUP_STAGE << 10) | (3 << 16) | (1 << 6),
    };
    transfer_ring_enqueue(slot, setup_trb);

    // Data Stage TRB (if wLength > 0)
    if w_length > 0 {
        let data_trb = Trb {
            param: ctrl.data_pa,
            status: w_length as u32,
            // Direction = 1 (IN) in bit 16
            control: (TRB_DATA_STAGE << 10) | (1 << 16),
        };
        transfer_ring_enqueue(slot, data_trb);
    }

    // Status Stage TRB
    // Direction: 0 if data was IN (status is OUT), 1 if no data/data was OUT
    let status_dir = if w_length > 0 { 0u32 } else { 1u32 };
    let status_trb = Trb {
        param: 0,
        status: 0,
        // IOC (Interrupt on Completion) = bit 5
        control: (TRB_STATUS_STAGE << 10) | (status_dir << 16) | (1 << 5),
    };
    transfer_ring_enqueue(slot, status_trb);

    // Ring doorbell for EP0 (target = 1 = DCI for EP0)
    slot_doorbell(ctrl, slot_id, 1);

    // Poll for transfer completion event
    let timeout = 5_000_000u32;
    let mut bytes_transferred = w_length as usize;
    let mut got_completion = false;

    for _ in 0..3u32 {
        // May get multiple events (one per TRB with IOC, or short packet)
        match poll_event(ctrl, timeout) {
            Some(evt) => {
                if evt.trb_type() == TRB_TRANSFER_EVENT {
                    let cc = evt.completion_code();
                    if cc == TRB_CC_SUCCESS || cc == TRB_CC_SHORT_PACKET {
                        // Residual bytes = status & 0xFFFFFF (lower 24 bits)
                        let residual = (evt.status & 0x00FF_FFFF) as usize;
                        if cc == TRB_CC_SHORT_PACKET {
                            bytes_transferred = (w_length as usize).saturating_sub(residual);
                        }
                        got_completion = true;
                    } else {
                        syscall::debug_puts(b"  [usb_srv] xfer cc=");
                        print_num(cc as u64);
                        syscall::debug_puts(b"\n");
                        return None;
                    }
                } else if evt.trb_type() == TRB_CMD_COMPLETION {
                    continue;
                } else if evt.trb_type() == TRB_PORT_STATUS_CHANGE {
                    continue;
                }
                if got_completion {
                    break;
                }
            }
            None => break,
        }
    }

    if got_completion {
        Some(bytes_transferred)
    } else {
        None
    }
}

/// Get the 18-byte device descriptor for a slot.
fn get_device_descriptor(ctrl: &mut XhciCtrl, slot_id: u8) -> Option<[u8; 18]> {
    // GET_DESCRIPTOR: bmRequestType=0x80 (device-to-host, standard, device)
    // bRequest=6 (GET_DESCRIPTOR), wValue=0x0100 (DEVICE descriptor, index 0)
    let n = control_transfer_in(ctrl, slot_id, 0x80, 6, 0x0100, 0, 18)?;

    let mut desc = [0u8; 18];
    let copy_len = n.min(18);
    unsafe {
        core::ptr::copy_nonoverlapping(ctrl.data_va as *const u8, desc.as_mut_ptr(), copy_len);
    }

    // Validate: bLength >= 18, bDescriptorType == 1 (DEVICE)
    if desc[0] < 18 || desc[1] != 1 {
        syscall::debug_puts(b"  [usb_srv] bad device descriptor\n");
        return None;
    }

    Some(desc)
}

/// Parse and print device descriptor, updating slot with vendor/product/class.
fn parse_device_descriptor(ctrl: &mut XhciCtrl, slot_id: u8, desc: &[u8; 18]) {
    let bcd_usb = (desc[3] as u16) << 8 | desc[2] as u16;
    let device_class = desc[4];
    let vendor_id = (desc[9] as u16) << 8 | desc[8] as u16;
    let product_id = (desc[11] as u16) << 8 | desc[10] as u16;
    let num_configs = desc[17];

    let slot = &mut ctrl.slots[slot_id as usize];
    slot.vendor_id = vendor_id;
    slot.product_id = product_id;
    slot.device_class = device_class;

    syscall::debug_puts(b"  [usb_srv]   USB");
    print_num((bcd_usb >> 8) as u64);
    syscall::debug_puts(b".");
    print_num(((bcd_usb >> 4) & 0xF) as u64);
    print_num((bcd_usb & 0xF) as u64);
    syscall::debug_puts(b" vendor=");
    print_hex(vendor_id as u64);
    syscall::debug_puts(b" product=");
    print_hex(product_id as u64);
    syscall::debug_puts(b" class=");
    print_hex(device_class as u64);
    syscall::debug_puts(b" configs=");
    print_num(num_configs as u64);
    syscall::debug_puts(b"\n");
}

// ===========================================================================
// Entry point + IPC server
// ===========================================================================

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [usb_srv] starting\n");

    // Decode arg0: low 16 bits = MMIO cap slot, bits 48-63 = IRQ line.
    let cap_slot = (arg0 & 0xFFFF) as usize;
    let _irq = (arg0 >> 48) as u32;

    // Map BAR0 via the MMIO cap the kernel granted us.
    let bar = match syscall::mmio_map_cap(cap_slot) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [usb_srv] mmio_map_cap failed, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [usb_srv] BAR0 mapped at ");
    print_hex(bar as u64);
    syscall::debug_puts(b"\n");

    // Initialize the xHCI controller.
    let mut ctrl = match xhci_init(bar) {
        Some(c) => c,
        None => {
            syscall::debug_puts(b"  [usb_srv] init failed, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    // Enumerate ports — find connected devices and reset them.
    let connected = enumerate_ports(&mut ctrl);

    // For each connected port: enable slot, address device, get descriptor.
    let mut device_count: u8 = 0;
    for &(port, speed) in connected.iter() {
        if port == 0xFF {
            break;
        }

        syscall::debug_puts(b"  [usb_srv] enumerating port ");
        print_num(port as u64);
        syscall::debug_puts(b"...\n");

        let slot_id = match enable_slot(&mut ctrl) {
            Some(id) => id,
            None => {
                syscall::debug_puts(b"  [usb_srv]   enable_slot failed\n");
                continue;
            }
        };

        if !address_device(&mut ctrl, slot_id, port, speed) {
            syscall::debug_puts(b"  [usb_srv]   address_device failed\n");
            continue;
        }

        match get_device_descriptor(&mut ctrl, slot_id) {
            Some(desc) => {
                parse_device_descriptor(&mut ctrl, slot_id, &desc);
            }
            None => {
                syscall::debug_puts(b"  [usb_srv]   get_device_descriptor failed\n");
            }
        }

        device_count += 1;
    }

    ctrl.num_devices = device_count;

    syscall::debug_puts(b"  [usb_srv] ");
    print_num(device_count as u64);
    syscall::debug_puts(b" device(s) enumerated\n");

    // Register as "usb" service.
    let port = syscall::port_create();
    syscall::ns_register(b"usb", port);

    syscall::debug_puts(b"  [usb_srv] server ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // IPC server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            USB_LIST_DEVICES => {
                // Reply: d0 = device count, d1 = packed slot info for first 4 devices
                // Each device packed as: slot_id:8 | port:8 | speed:8 | class:8
                let reply_port = msg.data[2] >> 32;
                let mut packed: u64 = 0;
                let mut idx = 0u32;
                for slot_id in 1..=ctrl.max_slots {
                    let s = &ctrl.slots[slot_id as usize];
                    if !s.active {
                        continue;
                    }
                    if idx < 4 {
                        let entry = (slot_id as u64)
                            | ((s.port as u64) << 8)
                            | ((s.speed as u64) << 16)
                            | ((s.device_class as u64) << 24);
                        packed |= entry << (idx * 32);
                    }
                    idx += 1;
                    if idx >= 2 {
                        break; // pack up to 2 in one u64
                    }
                }

                // d1 = packed vendor:product for first device
                let mut vendor_product: u64 = 0;
                for slot_id in 1..=ctrl.max_slots {
                    let s = &ctrl.slots[slot_id as usize];
                    if s.active {
                        vendor_product = (s.vendor_id as u64) | ((s.product_id as u64) << 16);
                        break;
                    }
                }

                send_reply(
                    reply_port,
                    USB_LIST_DEVICES_OK,
                    ctrl.num_devices as u64,
                    packed,
                    vendor_product,
                    0,
                );
            }

            USB_GET_DESCRIPTOR => {
                // d0 = slot_id, d1 = descriptor type<<8 | index, d2 low = reply port
                let reply_port = msg.data[2] >> 32;
                let slot_id = msg.data[0] as u8;
                let w_value = msg.data[1] as u16;
                let w_length = (msg.data[1] >> 16) as u16;
                let w_length = if w_length == 0 { 18 } else { w_length.min(256) };

                match control_transfer_in(
                    &mut ctrl, slot_id, 0x80, 6, w_value, 0, w_length,
                ) {
                    Some(n) => {
                        // Pack first 24 bytes into d0..d2
                        let bytes_to_pack = n.min(24);
                        let mut words = [0u64; 3];
                        for i in 0..bytes_to_pack {
                            let b = unsafe {
                                core::ptr::read_volatile((ctrl.data_va + i) as *const u8)
                            };
                            words[i / 8] |= (b as u64) << ((i % 8) * 8);
                        }
                        send_reply(
                            reply_port,
                            USB_GET_DESCRIPTOR_OK,
                            n as u64 | (words[0] << 16),
                            words[1],
                            words[2],
                            0,
                        );
                    }
                    None => {
                        send_reply(reply_port, USB_ERROR, 1, 0, 0, 0);
                    }
                }
            }

            USB_CONTROL_XFER => {
                // d0 = slot_id | bmRequestType<<8 | bRequest<<16 | wValue<<32
                // d1 = wIndex | wLength<<16
                // d2 high = reply port
                let reply_port = msg.data[2] >> 32;
                let slot_id = (msg.data[0] & 0xFF) as u8;
                let bm_request_type = ((msg.data[0] >> 8) & 0xFF) as u8;
                let b_request = ((msg.data[0] >> 16) & 0xFF) as u8;
                let w_value = (msg.data[0] >> 32) as u16;
                let w_index = (msg.data[1] & 0xFFFF) as u16;
                let w_length = ((msg.data[1] >> 16) & 0xFFFF) as u16;

                match control_transfer_in(
                    &mut ctrl, slot_id, bm_request_type, b_request,
                    w_value, w_index, w_length.min(256),
                ) {
                    Some(n) => {
                        send_reply(reply_port, USB_CONTROL_XFER_OK, n as u64, 0, 0, 0);
                    }
                    None => {
                        send_reply(reply_port, USB_ERROR, 2, 0, 0, 0);
                    }
                }
            }

            USB_PORT_STATUS => {
                let reply_port = msg.data[2] >> 32;
                let port_idx = msg.data[0] as u8;
                if port_idx < ctrl.max_ports {
                    let portsc = read_portsc(&ctrl, port_idx);
                    send_reply(reply_port, USB_PORT_STATUS_OK, portsc as u64, 0, 0, 0);
                } else {
                    send_reply(reply_port, USB_ERROR, 3, 0, 0, 0);
                }
            }

            _ => {} // ignore unknown tags
        }
    }
}
