# Driver Model

## Overview

Telix's microkernel architecture requires an explicit driver model. Drivers are the primary population of servers that interact with hardware, and their lifecycle, resource access, and communication patterns must be well-defined. The driver model follows the microkernel principle of generality first, performance second: all driver interactions use the standard message-passing IPC and capability mechanisms, with performance-oriented retrenchments (shared-memory polling, co-location) available when pure message-passing proves insufficient.

Drivers in Telix are **userspace servers**. They run in their own address spaces with no kernel privilege. They access hardware through capabilities granted by the kernel and managed by a device manager. If a driver crashes, the kernel survives, and the device manager can restart the driver — a fundamental reliability advantage over monolithic kernels where a driver bug can panic the system.

## Architecture

### Execution Model

Drivers execute as ordinary Telix tasks (userspace processes). A driver holds capabilities to the hardware resources it manages (MMIO regions, interrupt ports, DMA buffer allocation interfaces) and communicates with clients and with the device manager via standard IPC on ports and port sets.

A driver's structure is typically: wait on port set for messages (client requests, interrupt notifications, device manager commands), handle the message, send completions. This is identical to the structure of any other Telix server (filesystem, cache, name server). No special kernel support beyond the standard IPC, capability, and memory management primitives is needed for the basic case.

The server co-location retrenchment (§9.3 of the main design document) applies to drivers as well: if a driver's IPC overhead is unacceptable, it can be co-located into the same address space as a closely-coupled server (e.g., a block device driver co-located with the cache server) without changing its external IPC interface. In the limit, a driver could be co-located into the kernel for maximum performance, but this sacrifices the fault isolation that is the primary motivation for userspace drivers.

### Hardware Resource Access

#### MMIO (Memory-Mapped I/O)

Device register regions are granted to drivers as **memory capabilities** with appropriate caching attributes (uncacheable for device registers, write-combining for framebuffers and similar). The driver maps the granted region into its address space and reads/writes device registers directly. This is the standard path for modern device interaction and is handled entirely by the existing capability and memory grant mechanisms.

The kernel is responsible for identifying MMIO regions from firmware data (UEFI memory map, devicetree, ACPI tables) and creating the initial memory capabilities for them. These capabilities are granted to the device manager, which distributes them to the appropriate drivers.

#### Port I/O (x86 Legacy)

x86 port I/O (`IN`/`OUT` instructions) requires kernel assistance, as these instructions are privileged. The kernel provides a port I/O capability that authorises a driver to access a specified range of I/O ports. The kernel executes the port I/O on behalf of the driver (via a syscall) or, as a performance optimisation, configures the I/O permission bitmap (IOPB) in the driver's TSS to allow direct execution of `IN`/`OUT` for the granted port range.

Port I/O is legacy and declining in relevance. It is needed for some x86 platform devices (legacy serial, PS/2) but not for modern PCIe devices, which use MMIO exclusively.

#### Interrupts

Interrupts are delivered to drivers as **messages**.

When a hardware interrupt fires, the kernel's interrupt handler identifies the associated driver (via an interrupt-to-port mapping configured by the device manager), converts the interrupt into a minimal message (interrupt number, timestamp), sends it to the driver's interrupt port, and masks the interrupt line to prevent re-entry until the driver acknowledges handling.

The driver receives the interrupt message through its port set (alongside client request messages and device manager commands), handles the interrupt (reads device status, processes completed DMA, etc.), and sends an acknowledgement message back to the kernel, which unmasks the interrupt line.

This model is architecturally clean: interrupts are messages like everything else, and the driver's main loop is a single `wait on port set` that handles all event types uniformly.

**Interrupt coalescing:** For devices that generate very high interrupt rates (network cards under heavy load, NVMe with many completions), the kernel can coalesce multiple interrupts into a single message, reducing IPC overhead. The coalescing window is configurable per interrupt line.

**Polling mode retrenchment:** For sustained high-throughput workloads where even coalesced interrupt messages are too expensive, the driver can request a transition to polling mode. In polling mode, the kernel maps a shared-memory status register (or the device's own interrupt status register, if MMIO-accessible) into the driver's address space. The driver polls this register directly without any IPC. The driver can transition back to interrupt-driven mode when the load subsides. This follows the DPDK/SPDK model of adaptive interrupt/polling switching.

Polling mode is a retrenchment, not the default. The pure message-passing model is used unless the driver explicitly requests otherwise and the device manager approves the transition.

#### DMA

DMA (Direct Memory Access) allows devices to read from and write to physical memory without CPU involvement. Drivers need to:

1. **Allocate DMA-suitable memory:** Physically contiguous (or scatter-gather capable) memory whose physical addresses are known.
2. **Learn physical addresses:** The driver must tell the device where to read/write, which requires knowing the physical address of the DMA buffer, not just the virtual address.
3. **Ensure device memory safety:** A misbehaving device must not be able to DMA to arbitrary memory.

The kernel provides a **DMA buffer allocation interface**:

- **Allocate:** Request a physically contiguous buffer of a given size and alignment. The kernel returns a triple: (memory capability for the virtual mapping, physical address for programming the device, buffer identifier for later operations). The memory capability is mappable into the driver's address space for CPU access; the physical address is what the driver writes into the device's DMA descriptor registers.
- **Free:** Release a previously allocated DMA buffer.
- **Sync:** For non-coherent architectures (some ARM systems), synchronise the CPU cache with the DMA buffer contents (cache clean before device reads, cache invalidate before CPU reads after device writes).

**IOMMU integration:** On systems with an IOMMU (Intel VT-d, AMD-Vi, ARM SMMU), the kernel (or a dedicated IOMMU server) configures per-device I/O page tables that restrict which physical memory regions each device can access via DMA. When a DMA buffer is allocated for a specific device, the IOMMU mapping is established for that device only. A misbehaving or compromised device (or driver) cannot DMA to memory outside its granted buffers. The IOMMU configuration is managed through capabilities — the device manager holds the IOMMU capability and configures mappings as part of driver lifecycle management.

On systems without an IOMMU, DMA is inherently unsafe — any device can access any physical memory. This is a hardware limitation, not a software design flaw, but it should be noted: the security guarantees of the capability model do not extend to DMA on systems without IOMMU protection.

## Device Manager

The device manager is a privileged userspace server responsible for the overall lifecycle of drivers and devices. It is the central coordinator between hardware enumeration (bus servers), driver binaries (loaded from the filesystem), and the running system.

### Responsibilities

**Device enumeration coordination:** The device manager receives device discovery notifications from bus servers (PCI, USB, platform/devicetree) and determines which driver should serve each discovered device.

**Driver matching:** The device manager maintains a database mapping device identifiers (PCI vendor/device ID pairs, USB class/subclass/protocol, devicetree compatible strings) to driver binaries. When a new device is discovered, the device manager looks up the matching driver.

**Driver lifecycle management:** The device manager starts driver processes, grants them the appropriate capabilities (MMIO regions, interrupt ports, DMA allocation interface, IOMMU mappings), monitors their health, and restarts them on failure. It also stops drivers when devices are removed (hotplug) or when the system enters a power state transition.

**Capability distribution:** The device manager holds broad capabilities (to all hardware resources discovered by bus servers) and distributes restricted capabilities to individual drivers — each driver receives only the capabilities for its specific device. This is the principle of least privilege applied to hardware access.

**Power management coordination:** When the system transitions between power states (active, suspend, hibernate, shutdown), the device manager sends power state transition messages to all active drivers in the appropriate order (suspend leaf devices before bus controllers, resume bus controllers before leaf devices). Drivers respond with acknowledgement when they have completed their power state transition.

**Hotplug handling:** When a bus server reports a device arrival or departure, the device manager starts or stops the corresponding driver. For device departure, the device manager revokes the driver's capabilities (via the capability derivation tree) and notifies clients that were connected to the driver's service ports.

### Interface

The device manager communicates with:

- **Bus servers:** Receive device discovery/departure notifications. Grant bus servers capabilities to bus-level hardware resources (PCI configuration space, USB host controller registers).
- **Drivers:** Start/stop drivers, grant/revoke capabilities, send power management commands, monitor health (heartbeat or watchdog protocol).
- **Name server:** Register driver service ports so that clients (filesystem servers, application processes) can discover and connect to devices.
- **Root task:** Receive initial capabilities to all hardware resources at boot.

## Bus Servers

Bus servers enumerate devices on a specific bus type and report discoveries to the device manager. Each bus type has its own server:

### PCI Server

Enumerates the PCI/PCIe bus by walking the configuration space (via MMIO for PCIe ECAM, or port I/O for legacy PCI). Reports discovered devices (vendor ID, device ID, class code, BARs, interrupt assignments) to the device manager. Handles PCI-specific configuration (BAR assignment, MSI/MSI-X interrupt setup, bus mastering enable).

The PCI server is needed from Phase 3 (I/O server stack) for NVMe and virtio device access.

### Platform/Devicetree Server

Parses the devicetree blob (DTB) passed by firmware on ARM64 and RISC-V systems. Reports platform devices (UART, interrupt controller, timer, etc.) with their MMIO regions and interrupt assignments to the device manager. Also handles ACPI device enumeration on x86-64 (or a separate ACPI server may be appropriate, given ACPI's complexity).

Required from Phase 1 for basic ARM64 boot (at minimum, the kernel needs to find the interrupt controller and timer; whether this is done by the kernel directly at early boot or by a very-early-start platform server is a design detail).

### USB Server

Enumerates USB devices through the USB host controller driver. The USB server manages the USB protocol stack (device enumeration, configuration, interface/endpoint management) and reports discovered USB devices (class, subclass, protocol, vendor/product ID) to the device manager. USB class drivers (mass storage, HID, network) connect to the USB server to claim specific interfaces.

USB is a later addition (Phase 4 or beyond), as no Phase 1–3 functionality depends on USB.

## Layered Driver Composition

Complex device stacks involve multiple drivers in a layered arrangement. For example, a USB mass storage device involves:

1. **USB host controller driver:** Manages the hardware (xHCI, EHCI). Provides the raw USB transfer interface.
2. **USB bus server:** Manages the USB protocol, enumeration, and device lifecycle. Connects to the host controller driver. Reports discovered devices to the device manager.
3. **USB mass storage class driver:** Implements the USB Mass Storage protocol (SCSI over USB). Connects to the USB bus server for a specific device. Presents a block device interface to the cache server.

Each layer is a separate server communicating via IPC. Discovery and binding are mediated by the device manager and name server: the host controller driver registers with the name server, the USB bus server discovers it and connects, enumerates devices and reports them to the device manager, and the device manager starts class drivers and grants them ports to the USB bus server for their specific devices.

This layered composition is natural in the message-passing architecture. Each layer sees the layer below it as a server it sends messages to, and presents a service port to the layer above. No special framework is needed beyond the standard IPC and capability mechanisms.

## Driver Development Interface

To simplify driver development, a driver support library provides:

- **Port set management:** Helpers for setting up the driver's port set with interrupt ports, client request ports, and device manager command ports.
- **MMIO access wrappers:** Typed, volatile read/write functions for device registers, with appropriate memory ordering.
- **DMA buffer management:** Allocation, freeing, and cache synchronisation wrappers around the kernel DMA interface.
- **Interrupt handling:** Registration of interrupt handler functions that are called when an interrupt message arrives, with automatic acknowledgement.
- **Device manager protocol:** Message types and handlers for lifecycle commands (start, stop, suspend, resume, health check).

This library is a userspace convenience — drivers are not required to use it, and it does not add kernel-side complexity. It is analogous to Linux's driver model infrastructure (device/driver/bus structs, probe/remove callbacks) but implemented entirely in userspace.

## Development Phasing

**Phase 1 (Core Kernel):** The kernel provides the capability and IPC primitives needed for drivers. MMIO capability creation from firmware memory maps. Interrupt-to-port message delivery. No device manager yet; the root task statically binds the minimal set of drivers needed for boot (interrupt controller, timer, serial console).

**Phase 2 (VM Subsystem):** DMA buffer allocation interface added to the kernel. IOMMU support if hardware is available in the emulation environment.

**Phase 3 (I/O Server Stack):** PCI server, NVMe driver (or virtio-blk driver for QEMU), and the device manager are implemented. The device manager handles PCI enumeration-triggered driver loading and capability distribution. Drivers are started from the initramfs.

**Phase 4 (Completeness):** Platform/devicetree server, USB server, hotplug support, power management coordination. Driver matching database populated for the target hardware's device set.

## Retrenchment Strategies

**If message-based interrupt delivery is too slow for a specific device:** Transition that device's driver to polling mode (shared-memory status register). This is per-device and does not affect other drivers.

**If IPC overhead between layered drivers is too high:** Co-locate tightly coupled layers (e.g., USB host controller driver and USB bus server) into a single address space, preserving their internal message interfaces but eliminating cross-process IPC.

**If userspace driver latency is unacceptable for a specific device:** Co-locate that driver into the kernel address space. The driver's code is unchanged; only the deployment (which address space it runs in) changes. This sacrifices fault isolation for that specific driver while preserving it for all others.

## Open Questions

- **Early boot driver chicken-and-egg:** The interrupt controller and timer must be operational before the IPC mechanism works (scheduling depends on the timer, interrupt delivery depends on the interrupt controller). These very-early drivers may need to be kernel-internal components rather than userspace servers, at least during the boot sequence. Whether they can be migrated to userspace after boot is an open question.
- **GPU and display drivers:** Graphics drivers have unique requirements (large MMIO regions, complex DMA patterns, latency-sensitive scanout). Whether the general driver model is sufficient or whether GPU drivers need specialised kernel support (a DRM-like subsystem) is deferred to future work.
- **Network device drivers and the network stack:** High-performance network I/O may require kernel bypass techniques (mapping device queues directly into userspace, as DPDK does). This is compatible with the driver model (the network driver grants queue memory capabilities to a network stack server) but the details of the network stack architecture are beyond the scope of this document.
