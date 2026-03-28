//! Zero-allocation Flattened Device Tree (FDT/DTB) parser.
//!
//! Operates in-place on a `&[u8]` slice of the raw DTB in physical memory.
//! All FDT values are big-endian; this parser handles byte-swapping.

// FDT structure block tokens.
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
const FDT_END: u32 = 0x0000_0009;

const FDT_MAGIC: u32 = 0xd00d_feed;

// ---------------------------------------------------------------------------
// Helper: big-endian reads
// ---------------------------------------------------------------------------

#[inline]
fn be32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn be64(data: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        data[off], data[off + 1], data[off + 2], data[off + 3],
        data[off + 4], data[off + 5], data[off + 6], data[off + 7],
    ])
}

/// Read an N-cell value (1 cell = 4 bytes = u32, 2 cells = 8 bytes = u64).
#[inline]
fn read_cells(data: &[u8], off: usize, cells: u32) -> u64 {
    match cells {
        1 => be32(data, off) as u64,
        2 => be64(data, off),
        _ => 0,
    }
}

/// Round up to next 4-byte boundary.
#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FdtError {
    TooShort,
    BadMagic,
}

// ---------------------------------------------------------------------------
// Fdt — validated handle over raw DTB data
// ---------------------------------------------------------------------------

/// A validated FDT handle. Borrows the raw DTB data.
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    data: &'a [u8],
    struct_off: usize,
    struct_size: usize,
    strings_off: usize,
}

impl<'a> Fdt<'a> {
    /// Validate header and construct an Fdt handle.
    pub fn new(data: &'a [u8]) -> Result<Self, FdtError> {
        if data.len() < 40 {
            return Err(FdtError::TooShort);
        }
        if be32(data, 0) != FDT_MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total_size = be32(data, 4) as usize;
        if data.len() < total_size {
            return Err(FdtError::TooShort);
        }
        let struct_off = be32(data, 8) as usize;
        let strings_off = be32(data, 0x0C) as usize;
        let struct_size = be32(data, 0x24) as usize;
        Ok(Self { data, struct_off, struct_size, strings_off })
    }

    /// Get the string at the given offset in the strings block.
    fn string_at(&self, nameoff: u32) -> &'a [u8] {
        let start = self.strings_off + nameoff as usize;
        let rest = &self.data[start..];
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        &rest[..len]
    }

    /// Read a token at the given byte offset within the structure block.
    fn token_at(&self, pos: usize) -> u32 {
        let abs = self.struct_off + pos;
        if abs + 4 > self.data.len() { return FDT_END; }
        be32(self.data, abs)
    }

    /// Read raw bytes at an absolute offset.
    fn bytes_at(&self, abs: usize, len: usize) -> &'a [u8] {
        &self.data[abs..abs + len]
    }

    /// Skip the node name (null-terminated, padded to 4 bytes) starting at `pos`.
    /// Returns the position after the padded name.
    fn skip_name(&self, pos: usize) -> usize {
        let abs = self.struct_off + pos;
        let rest = &self.data[abs..];
        let nul = rest.iter().position(|&b| b == 0).unwrap_or(0);
        pos + align4(nul + 1)
    }

    /// Read the node name at `pos` (after BEGIN_NODE token).
    fn read_name(&self, pos: usize) -> &'a [u8] {
        let abs = self.struct_off + pos;
        let rest = &self.data[abs..];
        let nul = rest.iter().position(|&b| b == 0).unwrap_or(0);
        &rest[..nul]
    }

    /// Iterate all nodes depth-first starting from the structure block root.
    pub fn all_nodes(&self) -> NodeIter<'a> {
        // Skip the root BEGIN_NODE + name to position at its contents.
        // But NodeIter will handle depth tracking from position 0.
        NodeIter {
            fdt: *self,
            pos: 0,
            base_depth: 0,
            current_depth: 0,
            done: false,
        }
    }

    /// Find a node by path. Supports 1- and 2-level paths like "/cpus" or "/soc/plic@c000000".
    /// For 2-level paths, the second component uses prefix matching (before '@').
    pub fn find_node(&self, path: &[u8]) -> Option<FdtNode<'a>> {
        if path.is_empty() || path[0] != b'/' { return None; }
        let path = &path[1..]; // strip leading '/'

        // Split into components.
        let (first, rest) = match path.iter().position(|&b| b == b'/') {
            Some(i) => (&path[..i], Some(&path[i + 1..])),
            None => (path, None),
        };

        // Search root children for `first`.
        for node in self.root_children() {
            if node_name_matches(node.name, first) {
                match rest {
                    None => return Some(node),
                    Some(sub) => {
                        // Search this node's children for `sub`.
                        for child in node.children() {
                            if node_name_matches(child.name, sub) {
                                return Some(child);
                            }
                        }
                        return None;
                    }
                }
            }
        }
        None
    }

    /// Iterate direct children of the root node.
    pub fn root_children(&self) -> NodeIter<'a> {
        // Position past root's BEGIN_NODE + name.
        let mut pos: usize = 0;
        // Expect BEGIN_NODE at pos 0.
        if self.token_at(pos) != FDT_BEGIN_NODE { return NodeIter::empty(*self); }
        pos += 4;
        pos = self.skip_name(pos);

        NodeIter {
            fdt: *self,
            pos,
            base_depth: 1,
            current_depth: 0, // We're inside root (depth 0); children are at depth 1.
            done: false,
        }
    }
}

/// Check if a DTB node name matches a query. The query can be a full name
/// ("memory@40000000") or a prefix before '@' ("memory").
fn node_name_matches(node_name: &[u8], query: &[u8]) -> bool {
    if node_name == query { return true; }
    // Check prefix match: query matches the part before '@' in node_name.
    if let Some(at_pos) = node_name.iter().position(|&b| b == b'@') {
        &node_name[..at_pos] == query
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// FdtNode
// ---------------------------------------------------------------------------

/// A node in the FDT. Borrows the Fdt.
#[derive(Clone, Copy)]
pub struct FdtNode<'a> {
    fdt: Fdt<'a>,
    /// Node name (e.g., "memory@40000000").
    pub name: &'a [u8],
    /// Byte offset within structure block, positioned right after the name.
    content_pos: usize,
    /// Depth of this node (root = 0, root children = 1, ...).
    depth: u32,
}

impl<'a> FdtNode<'a> {
    /// Find a property by name within this node.
    pub fn property(&self, name: &[u8]) -> Option<FdtProp<'a>> {
        for prop in self.properties() {
            if prop.name == name {
                return Some(prop);
            }
        }
        None
    }

    /// Iterate properties of this node (stops at the first child node or END_NODE).
    pub fn properties(&self) -> PropIter<'a> {
        PropIter { fdt: self.fdt, pos: self.content_pos }
    }

    /// Iterate direct children of this node.
    pub fn children(&self) -> NodeIter<'a> {
        // Skip past all properties to reach child nodes.
        let mut pos = self.content_pos;
        loop {
            let tok = self.fdt.token_at(pos);
            match tok {
                FDT_PROP => {
                    // Skip property: token(4) + len(4) + nameoff(4) + data(align4(len))
                    let len = be32(self.fdt.data, self.fdt.struct_off + pos + 4) as usize;
                    pos += 4 + 4 + 4 + align4(len);
                }
                FDT_NOP => { pos += 4; }
                _ => break, // BEGIN_NODE (child) or END_NODE (no children)
            }
        }
        NodeIter {
            fdt: self.fdt,
            pos,
            base_depth: self.depth + 1,
            current_depth: self.depth, // We're inside this node; children are one deeper.
            done: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FdtProp
// ---------------------------------------------------------------------------

/// A property within an FDT node.
pub struct FdtProp<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> FdtProp<'a> {
    /// Read as a single big-endian u32.
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 { Some(be32(self.data, 0)) } else { None }
    }

    /// Read as a single big-endian u64 (or two concatenated u32s).
    #[allow(dead_code)]
    pub fn as_u64(&self) -> Option<u64> {
        if self.data.len() >= 8 { Some(be64(self.data, 0)) } else { None }
    }

    /// Iterate (address, size) pairs from a `reg` property.
    pub fn reg_iter(&self, addr_cells: u32, size_cells: u32) -> RegIter<'a> {
        RegIter {
            data: self.data,
            pos: 0,
            addr_cells,
            size_cells,
        }
    }

    /// Check if this property's data contains the given null-terminated string.
    /// DTB string lists are concatenated null-terminated strings.
    pub fn contains_string(&self, s: &[u8]) -> bool {
        let mut start = 0;
        while start < self.data.len() {
            let end = self.data[start..].iter().position(|&b| b == 0)
                .map(|i| start + i)
                .unwrap_or(self.data.len());
            if &self.data[start..end] == s {
                return true;
            }
            start = end + 1;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Iterators
// ---------------------------------------------------------------------------

/// Iterates nodes at a specific depth level.
pub struct NodeIter<'a> {
    fdt: Fdt<'a>,
    pos: usize,
    base_depth: u32,
    current_depth: u32,
    done: bool,
}

impl<'a> NodeIter<'a> {
    fn empty(fdt: Fdt<'a>) -> Self {
        Self { fdt, pos: 0, base_depth: 0, current_depth: 0, done: true }
    }
}

impl<'a> Iterator for NodeIter<'a> {
    type Item = FdtNode<'a>;

    fn next(&mut self) -> Option<FdtNode<'a>> {
        if self.done { return None; }

        loop {
            if self.pos + 4 > self.fdt.struct_size { self.done = true; return None; }
            let tok = self.fdt.token_at(self.pos);

            match tok {
                FDT_BEGIN_NODE => {
                    self.current_depth += 1;
                    let name_pos = self.pos + 4;
                    let name = self.fdt.read_name(name_pos);
                    let content_pos = self.fdt.skip_name(name_pos);

                    if self.current_depth == self.base_depth {
                        // This is a node at our target depth — yield it.
                        // Advance past this node's contents to find the next sibling.
                        // We need to skip the entire subtree.
                        let node = FdtNode {
                            fdt: self.fdt,
                            name,
                            content_pos,
                            depth: self.current_depth - 1, // depth is 0-based from root
                        };
                        // Skip the subtree to position at the next token after END_NODE.
                        self.pos = content_pos;
                        self.skip_subtree();
                        return Some(node);
                    } else {
                        // Descending into a deeper node — skip over its name.
                        self.pos = content_pos;
                    }
                }
                FDT_END_NODE => {
                    self.current_depth -= 1;
                    self.pos += 4;
                    if self.current_depth < self.base_depth {
                        // We've exited the parent — done iterating.
                        self.done = true;
                        return None;
                    }
                }
                FDT_PROP => {
                    let len = be32(self.fdt.data, self.fdt.struct_off + self.pos + 4) as usize;
                    self.pos += 4 + 4 + 4 + align4(len);
                }
                FDT_NOP => {
                    self.pos += 4;
                }
                FDT_END | _ => {
                    self.done = true;
                    return None;
                }
            }
        }
    }
}

impl<'a> NodeIter<'a> {
    /// Skip the current subtree (we're positioned at the first token inside a node).
    fn skip_subtree(&mut self) {
        let mut depth: u32 = 1;
        loop {
            if self.pos + 4 > self.fdt.struct_size { self.done = true; return; }
            let tok = self.fdt.token_at(self.pos);
            match tok {
                FDT_BEGIN_NODE => {
                    depth += 1;
                    self.pos += 4;
                    self.pos = self.fdt.skip_name(self.pos);
                }
                FDT_END_NODE => {
                    depth -= 1;
                    self.pos += 4;
                    if depth == 0 {
                        self.current_depth -= 1;
                        return;
                    }
                }
                FDT_PROP => {
                    let len = be32(self.fdt.data, self.fdt.struct_off + self.pos + 4) as usize;
                    self.pos += 4 + 4 + 4 + align4(len);
                }
                FDT_NOP => { self.pos += 4; }
                _ => { self.done = true; return; }
            }
        }
    }
}

/// Iterates properties within a node.
pub struct PropIter<'a> {
    fdt: Fdt<'a>,
    pos: usize,
}

impl<'a> Iterator for PropIter<'a> {
    type Item = FdtProp<'a>;

    fn next(&mut self) -> Option<FdtProp<'a>> {
        loop {
            let tok = self.fdt.token_at(self.pos);
            match tok {
                FDT_PROP => {
                    let abs = self.fdt.struct_off + self.pos;
                    let len = be32(self.fdt.data, abs + 4) as usize;
                    let nameoff = be32(self.fdt.data, abs + 8);
                    let data = self.fdt.bytes_at(abs + 12, len);
                    let name = self.fdt.string_at(nameoff);
                    self.pos += 4 + 4 + 4 + align4(len);
                    return Some(FdtProp { name, data });
                }
                FDT_NOP => { self.pos += 4; }
                _ => return None, // BEGIN_NODE or END_NODE = end of properties
            }
        }
    }
}

/// Iterates (address, size) pairs from a `reg` property.
pub struct RegIter<'a> {
    data: &'a [u8],
    pos: usize,
    addr_cells: u32,
    size_cells: u32,
}

impl<'a> Iterator for RegIter<'a> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        let entry_size = (self.addr_cells + self.size_cells) as usize * 4;
        if self.pos + entry_size > self.data.len() { return None; }
        let addr = read_cells(self.data, self.pos, self.addr_cells);
        let size = read_cells(self.data, self.pos + self.addr_cells as usize * 4, self.size_cells);
        self.pos += entry_size;
        Some((addr, size))
    }
}

// ---------------------------------------------------------------------------
// Arch-specific extraction: AArch64
// ---------------------------------------------------------------------------

/// Parse the DTB for AArch64 QEMU virt machine.
/// Extracts memory regions, CPUs, GIC info, and virtio-mmio devices.
#[cfg(target_arch = "aarch64")]
pub fn parse_aarch64(dtb_addr: usize) {
    if dtb_addr == 0 { return; }
    let data = unsafe { dtb_slice(dtb_addr) };
    let fdt = match Fdt::new(data) {
        Ok(f) => f,
        Err(_) => return,
    };

    // 1. Memory: find nodes with device_type = "memory".
    for node in fdt.root_children() {
        if !node_name_starts_with(node.name, b"memory") { continue; }
        if let Some(reg) = node.property(b"reg") {
            for (base, size) in reg.reg_iter(2, 2) {
                super::push_mem_region(super::MemRegion { base, size });
            }
        }
    }

    // 2. CPUs: find /cpus, iterate cpu@N children.
    if let Some(cpus_node) = fdt.find_node(b"/cpus") {
        for child in cpus_node.children() {
            if !node_name_starts_with(child.name, b"cpu@") { continue; }
            if let Some(reg) = child.property(b"reg") {
                let id = reg.as_u32().unwrap_or(0);
                super::push_cpu(super::CpuDesc { id, flags: 1 });
            }
        }
    }

    // 3. GIC: find interrupt controller with "arm,gic-v3".
    for node in fdt.root_children() {
        if let Some(compat) = node.property(b"compatible") {
            if compat.contains_string(b"arm,gic-v3") {
                if let Some(reg) = node.property(b"reg") {
                    let mut pairs = reg.reg_iter(2, 2);
                    let dist = pairs.next().map(|(b, _)| b).unwrap_or(0);
                    let redist = pairs.next().map(|(b, _)| b).unwrap_or(0);
                    super::set_irq_controller(super::IrqControllerInfo {
                        kind: 1, _pad: 0, base0: dist, base1: redist,
                    });
                }
                break;
            }
        }
    }

    // 4. Virtio-mmio devices at root level.
    for node in fdt.root_children() {
        if !node_name_starts_with(node.name, b"virtio_mmio") { continue; }
        let (base, size) = node.property(b"reg")
            .and_then(|r| r.reg_iter(2, 2).next())
            .unwrap_or((0, 0));
        if base == 0 { continue; }
        // GIC interrupt specifier: 3 cells <type irq_num flags>.
        // Type 0 = SPI, actual INTID = irq_num + 32.
        let irq = node.property(b"interrupts")
            .map(|p| {
                if p.data.len() >= 8 {
                    let irq_num = be32(p.data, 4);
                    irq_num + 32 // SPI offset
                } else {
                    0
                }
            })
            .unwrap_or(0);
        super::push_virtio(super::VirtioMmioDesc { base, size, irq, _pad: 0 });
    }
}

// ---------------------------------------------------------------------------
// Arch-specific extraction: RISC-V 64
// ---------------------------------------------------------------------------

/// Parse the DTB for RISC-V 64 QEMU virt machine.
/// Extracts memory regions, CPUs, timebase frequency, PLIC info, and virtio devices.
#[cfg(target_arch = "riscv64")]
pub fn parse_riscv64(dtb_addr: usize) {
    if dtb_addr == 0 { return; }
    let data = unsafe { dtb_slice(dtb_addr) };
    let fdt = match Fdt::new(data) {
        Ok(f) => f,
        Err(_) => return,
    };

    // 1. Memory: find nodes with device_type = "memory".
    for node in fdt.root_children() {
        if !node_name_starts_with(node.name, b"memory") { continue; }
        if let Some(reg) = node.property(b"reg") {
            for (base, size) in reg.reg_iter(2, 2) {
                super::push_mem_region(super::MemRegion { base, size });
            }
        }
    }

    // 2. CPUs: find /cpus, read timebase-frequency, iterate cpu@N.
    if let Some(cpus_node) = fdt.find_node(b"/cpus") {
        if let Some(tbf) = cpus_node.property(b"timebase-frequency") {
            if let Some(freq) = tbf.as_u32() {
                super::set_timebase_freq(freq as u64);
            }
        }
        for child in cpus_node.children() {
            if !node_name_starts_with(child.name, b"cpu@") { continue; }
            // Skip non-cpu nodes like cpu-map.
            let is_cpu = child.property(b"device_type")
                .map(|p| p.data.starts_with(b"cpu"))
                .unwrap_or(false);
            if !is_cpu { continue; }
            if let Some(reg) = child.property(b"reg") {
                let id = reg.as_u32().unwrap_or(0);
                super::push_cpu(super::CpuDesc { id, flags: 1 });
            }
        }
    }

    // 3. PLIC: find /soc/plic@* or node with compatible "sifive,plic-1.0.0".
    // On QEMU riscv64 virt, it's under /soc.
    if let Some(soc) = fdt.find_node(b"/soc") {
        for child in soc.children() {
            if let Some(compat) = child.property(b"compatible") {
                if compat.contains_string(b"sifive,plic-1.0.0") || compat.contains_string(b"riscv,plic0") {
                    if let Some(reg) = child.property(b"reg") {
                        let (base, _size) = reg.reg_iter(2, 2).next().unwrap_or((0, 0));
                        super::set_irq_controller(super::IrqControllerInfo {
                            kind: 2, _pad: 0, base0: base, base1: 0,
                        });
                    }
                    break;
                }
            }
        }

        // 4. Virtio-mmio devices under /soc.
        for child in soc.children() {
            if !node_name_starts_with(child.name, b"virtio_mmio") { continue; }
            let (base, size) = child.property(b"reg")
                .and_then(|r| r.reg_iter(2, 2).next())
                .unwrap_or((0, 0));
            if base == 0 { continue; }
            // RISC-V interrupt specifier: 1 cell = PLIC IRQ number.
            let irq = child.property(b"interrupts")
                .and_then(|p| p.as_u32())
                .unwrap_or(0);
            super::push_virtio(super::VirtioMmioDesc { base, size, irq, _pad: 0 });
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Construct a &[u8] slice from a DTB at the given physical address.
/// Reads the totalsize field from the header first.
///
/// # Safety
/// `addr` must point to a valid FDT blob that is identity-mapped and
/// not concurrently modified.
unsafe fn dtb_slice(addr: usize) -> &'static [u8] {
    let ptr = addr as *const u8;
    // Read totalsize from header offset 4.
    let header = core::slice::from_raw_parts(ptr, 8);
    let total_size = be32(header, 4) as usize;
    core::slice::from_raw_parts(ptr, total_size)
}

/// Check if a node name starts with a given prefix.
fn node_name_starts_with(name: &[u8], prefix: &[u8]) -> bool {
    name.len() >= prefix.len() && &name[..prefix.len()] == prefix
}
