//! Capability type: an unforgeable kernel-managed token referencing a kernel object
//! with a set of rights.

/// Rights bitfield for capabilities.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const SEND: Rights = Rights(1 << 0);
    pub const RECV: Rights = Rights(1 << 1);
    pub const GRANT: Rights = Rights(1 << 2);
    pub const READ: Rights = Rights(1 << 3);
    pub const WRITE: Rights = Rights(1 << 4);
    pub const EXEC: Rights = Rights(1 << 5);
    pub const MANAGE: Rights = Rights(1 << 6);  // Create/destroy child objects

    #[allow(dead_code)]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[allow(dead_code)]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Union of two rights sets.
    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Intersection of two rights sets.
    #[allow(dead_code)]
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// Check if self contains all rights in `other`.
    pub const fn contains(self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Check if any rights are set.
    #[allow(dead_code)]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Debug for Rights {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let flags = [
            (Self::SEND, "SEND"),
            (Self::RECV, "RECV"),
            (Self::GRANT, "GRANT"),
            (Self::READ, "READ"),
            (Self::WRITE, "WRITE"),
            (Self::EXEC, "EXEC"),
            (Self::MANAGE, "MANAGE"),
        ];
        let mut first = true;
        for (flag, name) in &flags {
            if self.contains(*flag) {
                if !first {
                    write!(f, "|")?;
                }
                write!(f, "{}", name)?;
                first = false;
            }
        }
        if first {
            write!(f, "NONE")?;
        }
        Ok(())
    }
}

/// The type of kernel object a capability references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum CapType {
    /// Empty/invalid slot.
    Null = 0,
    /// IPC port.
    Port = 1,
    /// Physical memory region.
    Memory = 2,
    /// Task (address space + capability space).
    Task = 3,
    /// Thread (execution context).
    Thread = 4,
    /// CNode (capability storage node).
    CNode = 5,
    /// IRQ handler.
    Irq = 6,
}

/// A capability: a typed reference to a kernel object with rights.
///
/// In-kernel representation. The `object` field is an opaque pointer/ID
/// to the kernel object. The `cdt_node` field links this capability into
/// the capability derivation tree.
#[derive(Clone, Copy)]
pub struct Capability {
    pub cap_type: CapType,
    pub rights: Rights,
    /// Opaque identifier for the kernel object (pointer or index).
    pub object: usize,
    /// Index of this capability's node in the CDT (u32::MAX = not in CDT).
    pub cdt_index: u32,
}

impl Capability {
    pub const fn null() -> Self {
        Self {
            cap_type: CapType::Null,
            rights: Rights::NONE,
            object: 0,
            cdt_index: u32::MAX,
        }
    }

    pub const fn new(cap_type: CapType, rights: Rights, object: usize) -> Self {
        Self {
            cap_type,
            rights,
            object,
            cdt_index: u32::MAX,
        }
    }

    pub const fn is_null(&self) -> bool {
        self.cap_type as u8 == CapType::Null as u8
    }

    /// Derive a new capability with attenuated (equal or fewer) rights.
    /// Returns None if the requested rights exceed the original.
    pub fn derive(&self, new_rights: Rights) -> Option<Self> {
        if self.is_null() {
            return None;
        }
        // New rights must be a subset of existing rights.
        if !self.rights.contains(new_rights) {
            return None;
        }
        Some(Self {
            cap_type: self.cap_type,
            rights: new_rights,
            object: self.object,
            cdt_index: u32::MAX, // Will be set when inserted into CDT.
        })
    }
}

impl core::fmt::Debug for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_null() {
            write!(f, "Cap(Null)")
        } else {
            write!(
                f,
                "Cap({:?}, {:?}, obj={:#x})",
                self.cap_type, self.rights, self.object
            )
        }
    }
}
