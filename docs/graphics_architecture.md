# Graphics Architecture

## Overview

Graphics on Telix must support a path from initial QEMU-based development (where virtio-gpu is the display device) through to running on real hardware (Intel Iris Xe integrated graphics on the development laptop, and eventually discrete GPUs). The goal is to reach a functional desktop environment (Xwayland → GNOME → Firefox) under QEMU first, then boot on real hardware second.

Graphics is one of the most complex subsystem areas in modern operating systems. This document focuses on the architecture that Telix needs to provide rather than on GPU hardware internals, and identifies what must be kernel-provided versus what can be userspace.

## The Graphics Stack: What Needs to Exist

A functional desktop on Telix requires several layers, from bottom to top:

### Display Hardware Interface (KMS Equivalent)

The lowest layer manages display output: setting screen resolution, refresh rate, and color depth (mode setting), managing framebuffers (memory regions containing pixel data that the display controller scans out), and handling page flipping (atomically switching which framebuffer is being displayed, for tear-free updates).

In Linux, this is **Kernel Mode Setting (KMS)**, part of the DRM (Direct Rendering Manager) subsystem. KMS models the display pipeline as a graph of abstract objects:

- **CRTCs** (CRT Controllers): Scanout engines that read pixel data from a framebuffer and generate video timing signals.
- **Encoders:** Convert the CRTC's output into a signal appropriate for a specific connector type (HDMI, DisplayPort, eDP, etc.).
- **Connectors:** Represent physical display outputs. Report connected displays and their supported modes (via EDID).
- **Planes:** Overlay layers within a CRTC. The primary plane carries the main framebuffer; additional planes support hardware cursors and video overlays.
- **Framebuffers:** Memory objects containing pixel data, referenced by planes.

In Telix's microkernel architecture, mode setting is implemented by a **display server** (a privileged userspace server) per GPU/display controller. The display server holds capabilities to the GPU's MMIO registers and manages the display pipeline. It presents a service interface to compositors (Wayland compositors, X servers) for mode enumeration, mode setting, framebuffer allocation, and page flip requests.

### GPU Command Submission (Rendering)

3D rendering and GPU compute require submitting command buffers to the GPU's command processor. On modern GPUs, this involves:

- **Command buffer construction:** Userspace (Mesa, application) builds a sequence of GPU commands in a memory buffer.
- **Command buffer submission:** The buffer is submitted to the GPU for execution, along with references to input/output buffers (textures, vertex buffers, render targets).
- **Synchronization:** Fences/sync objects track command buffer completion so that the CPU knows when results are available and display page flips can be coordinated with rendering completion.
- **Memory management:** GPU-accessible memory must be allocated, mapped, and managed. GPUs have their own virtual address spaces (managed by a GPU page table or GART/IOMMU) separate from the CPU's.

In Linux, this is the other half of DRM — the rendering side, including GEM (Graphics Execution Manager) or TTM (Translation Table Maps) for memory management, and driver-specific ioctls for command submission.

In Telix, GPU command submission is handled by a **GPU server** per GPU (which may be the same server as the display server, or a separate server for GPUs that have rendering capability independent of display output). The GPU server manages GPU memory allocation (from the GPU's dedicated VRAM or from system memory accessible to the GPU), GPU address space management (programming the GPU's page tables or IOMMU), command buffer validation and submission, and fence/sync object management.

Clients (Mesa drivers, compute applications) request GPU memory allocations, construct command buffers, and submit them to the GPU server for execution. Completions are delivered as messages.

### Userspace Graphics Libraries (Mesa)

**Mesa** is the open-source graphics library stack that provides OpenGL, Vulkan, and OpenCL implementations. Mesa is entirely userspace and runs in application processes. It needs:

- **A kernel interface for GPU memory management and command submission.** On Linux, this is DRM ioctls. On Telix, this would be the IPC interface to the GPU server.
- **A way to allocate and share display buffers.** On Linux, this is GBM (Generic Buffer Manager) and dma-buf. On Telix, this would be memory capabilities shared between the application, the GPU server, and the display server.

Mesa's architecture is modular: it has a frontend (OpenGL state tracker, Vulkan runtime) and a backend (driver-specific GPU command generation). The backend must talk to the kernel's GPU interface. For Telix, a new Mesa backend ("Gallium driver" for OpenGL, "Vulkan driver" for Vulkan) would be needed for each GPU type — or, more practically, the existing Mesa backends can be reused if Telix provides a compatible-enough interface.

### Display Compositor (Wayland)

A **Wayland compositor** (e.g., Mutter for GNOME, wlroots-based compositors) manages windows, composites their contents into a final framebuffer, and submits that framebuffer for display via the display server. The compositor is a client of both the display server (for mode setting and page flips) and the GPU server (for rendering the composited output).

**Xwayland** runs X11 applications inside a Wayland session by providing an X11 server that renders into Wayland buffers. It is a client of the Wayland compositor.

## Target Hardware and Phased Approach

### Phase A: QEMU with virtio-gpu (Software/Paravirtual Rendering)

The initial target is QEMU's **virtio-gpu** device. This is a paravirtualized GPU that provides:

**2D mode (no acceleration):** The guest allocates framebuffers in guest memory and sends "resource create" / "resource flush" commands to the virtio-gpu device. QEMU copies the framebuffer contents to the host display. This requires only a simple virtio-gpu driver in Telix — no GPU command submission, no GPU memory management, just mode setting and framebuffer scanout.

**VirGL mode (OpenGL acceleration):** Guest OpenGL calls are translated by Mesa's VirGL Gallium driver into an intermediate representation (based on Gallium3D's TGSI/NIR). This IR is sent via virtio-gpu to the host, where virglrenderer translates it back into OpenGL calls on the host GPU. This gives the guest accelerated OpenGL without needing a hardware-specific GPU driver.

**Venus mode (Vulkan acceleration):** Guest Vulkan calls are serialized by Mesa's Venus Vulkan driver and sent via virtio-gpu to the host, where virglrenderer's Venus backend replays them as Vulkan calls on the host GPU. This gives the guest accelerated Vulkan.

For Telix's initial development, the path is:

1. **virtio-gpu 2D driver:** A Telix driver for the virtio-gpu device that handles mode setting (EDID, mode enumeration, mode set) and framebuffer scanout (allocate guest memory, attach it as a virtio-gpu resource, flush regions to trigger host display update). This is sufficient to run a framebuffer console and, with Xwayland, a basic desktop — albeit with software rendering (Mesa's LLVMpipe) for 3D.

2. **VirGL/Venus support:** Extend the virtio-gpu driver to support 3D command submission (virtio-gpu's 3D capset mechanism). This allows Mesa's VirGL driver (OpenGL) and Venus driver (Vulkan) to run in Telix guests with hardware-accelerated rendering on the host. This requires the GPU server to handle virtio-gpu 3D resource management and command submission.

This phased approach gets pixels on screen early (Phase A.1 is a simple driver) and adds acceleration incrementally (Phase A.2).

### Phase B: Intel Iris Xe (Real Hardware)

The development laptop has Intel Iris Xe integrated graphics (likely Tiger Lake or Alder Lake generation). Intel's GPU has:

- **Display engine:** Handles mode setting, display pipes, connector management. Intel's display hardware is complex (multiple pipes, multiple planes per pipe, display port MST, panel self-refresh, etc.).
- **Render engine:** The EU (Execution Unit) array that runs shaders and processes 3D commands. Managed via the GuC firmware (Guardian microcontroller) on recent generations.
- **Media engine:** Fixed-function video decode/encode hardware (not needed initially but eventually relevant for Firefox video playback).

Mesa already has the **Iris** Gallium driver (for OpenGL) and **ANV** Vulkan driver (for Vulkan) for Intel Gen12+ GPUs. These drivers are mature and well-tested.

The question for Telix is what kernel interface these Mesa drivers need. On Linux, they talk to the **i915** or **xe** kernel DRM driver via ioctls. The i915/xe driver handles GPU memory management (GEM objects), command buffer submission (via execbuffer2 or the newer xe exec ioctl), GPU context management, fence synchronization, and display mode setting.

For Telix, the options are:

**Option 1: Implement a DRM-compatible ioctl interface.** The GPU server presents an interface that looks like Linux DRM to userspace. Mesa's existing Iris/ANV drivers work unmodified (or with minimal patching). This is the pragmatic path — it avoids forking or rewriting Mesa drivers, which are hundreds of thousands of lines of code.

**Option 2: Implement a Telix-native GPU interface and write new Mesa backends.** Architecturally cleaner but enormously more work. Not practical for initial development.

**Option 3: Use Redox's approach.** Redox recently implemented basic DRM read-only APIs to simplify porting. A minimal DRM compatibility shim that translates DRM ioctls into Telix GPU server messages could support existing Mesa drivers.

Option 1 or a variant of Option 3 is recommended. The Linux personality server (§personality servers document) would naturally provide DRM ioctl translation as part of its Linux syscall compatibility surface.

### Phase C: Discrete GPUs (Future)

Discrete GPUs (AMD Radeon, NVIDIA) are a future goal. AMD's GPU is accessible through Mesa's RADV (Vulkan) and RadeonSI (OpenGL) drivers, which talk to the **amdgpu** kernel DRM driver. The same DRM compatibility strategy applies. NVIDIA's open kernel module (and the nouveau open-source driver) follow a similar pattern.

## Telix Graphics Architecture

### Display Server

A privileged userspace server per display controller. Responsibilities:

- **Mode setting:** Enumerate connectors, report supported modes (via EDID parsing), set display mode (resolution, refresh rate, pixel format), manage display pipes and planes.
- **Framebuffer management:** Allocate framebuffer memory (via the kernel's DMA buffer allocation or GPU memory allocator), track framebuffer lifetimes, handle format negotiation.
- **Page flip:** Accept page flip requests from the compositor, program the display controller to scan out from a new framebuffer at the next vertical blank, and deliver a completion event (vblank event) when the flip is done.
- **Hotplug:** Detect display connection/disconnection events and notify clients.

The display server holds capabilities to the GPU/display controller's MMIO registers and interrupts. It receives mode setting and page flip requests via its service port and delivers vblank and hotplug events to clients.

### GPU Server

A privileged userspace server per GPU. Responsibilities:

- **GPU memory management:** Allocate and free GPU-accessible memory objects (from VRAM or system memory). Track object lifetimes, handle eviction under memory pressure (moving objects between VRAM and system memory).
- **GPU address space management:** Program the GPU's page tables (or IOMMU/GART) to make memory objects accessible to the GPU at specific GPU virtual addresses.
- **Command buffer submission:** Accept command buffers from clients, validate them (to prevent GPU hangs or security violations), and submit them to the GPU's command processor.
- **Synchronization:** Manage GPU fences. When a client submits a command buffer, it receives a fence object. The client can wait for the fence (the GPU server delivers a completion message when the GPU finishes executing the command buffer) or pass the fence to the display server for synchronized page flips.
- **GPU context management:** Maintain per-client GPU contexts (hardware contexts that isolate different clients' GPU state).

### Buffer Sharing

Compositors and clients need to share GPU buffers (the client renders into a buffer; the compositor reads it for compositing; the display server scans it out). On Linux, this is done via **dma-buf** — a kernel-managed file descriptor representing a shared memory buffer that can be imported by multiple DRM devices and by userspace.

In Telix, buffer sharing uses the standard **memory capability** mechanism. A GPU memory object is represented as a memory capability. The GPU server grants a capability (with appropriate rights — read-only for the compositor consuming a client's rendered buffer, read-write for the rendering client) to each party. The display server receives a read-only capability to the composited buffer for scanout.

This is architecturally cleaner than dma-buf: no special kernel mechanism is needed beyond the existing capability system. The GPU server creates the buffer, the compositor receives a capability to it, and the display server receives a capability to the final composited output.

### DRM Compatibility Layer

For practical Mesa compatibility, a **DRM compatibility library** (or a DRM personality within the Linux personality server) translates Linux DRM ioctls into messages to the GPU server and display server:

- `DRM_IOCTL_MODE_GETRESOURCES` → query display server for connectors, CRTCs, encoders.
- `DRM_IOCTL_MODE_SETCRTC` → send mode set request to display server.
- `DRM_IOCTL_MODE_PAGE_FLIP` → send page flip request to display server.
- `DRM_IOCTL_*_GEM_CREATE` → send memory allocation request to GPU server.
- `DRM_IOCTL_*_EXECBUFFER` → send command buffer submission to GPU server.
- `DRM_IOCTL_PRIME_HANDLE_TO_FD` / `DRM_IOCTL_PRIME_FD_TO_HANDLE` → translate between DRM GEM handles and Telix memory capabilities.

This compatibility layer allows Mesa's existing GPU-specific drivers (Iris, ANV, RadeonSI, RADV) to run on Telix with minimal modification. The layer is a userspace library, not a kernel component.

### Software Rendering Fallback

When no GPU acceleration is available (or during early development), Mesa's **LLVMpipe** (OpenGL software renderer) and **Lavapipe** (Vulkan software renderer) provide software rendering. These require no GPU server at all — they render entirely in CPU memory. The resulting framebuffer is passed to the display server for scanout. This is the fallback for any hardware where a GPU driver doesn't exist yet.

## Path to Xwayland, GNOME, and Firefox

### Step 1: Framebuffer Console

Implement the virtio-gpu 2D driver (display server). Get pixels on screen in QEMU — a framebuffer console with text rendering. This validates the display server's mode setting and framebuffer scanout path.

### Step 2: Wayland Compositor with Software Rendering

Port a minimal Wayland compositor (wlroots-based, or a simple custom compositor). The compositor uses the display server for mode setting and page flips, and software rendering (LLVMpipe) for compositing. Run Xwayland under this compositor. This validates the full display stack from compositor through display server to screen, without requiring GPU acceleration.

### Step 3: Xwayland Desktop

Run GNOME (Mutter as compositor via Xwayland) and Firefox under the Wayland compositor with software rendering. This will be slow (software rendering) but functionally complete. It validates the POSIX personality, the I/O stack (filesystem for loading application binaries, fonts, and data), and the display stack end-to-end.

### Step 4: Accelerated Rendering under QEMU

Add VirGL/Venus support to the virtio-gpu driver. Mesa's VirGL and Venus drivers provide hardware-accelerated OpenGL and Vulkan in the QEMU guest, using the host GPU for actual rendering. The desktop becomes usably fast under QEMU.

### Step 5: Intel Iris Xe on Real Hardware

Implement the Intel GPU server (or DRM compatibility layer) and port Mesa's Iris/ANV drivers. Boot Telix on the development laptop with accelerated graphics.

## Open Questions

- **GPU reset and hang recovery:** When the GPU hangs (a common occurrence during driver development), the GPU server must be able to reset the GPU and recover. This requires hardware-specific reset sequences and may require kernel assistance if the GPU reset mechanism involves platform-level operations (e.g., PCI function-level reset).
- **GPU memory pressure and eviction:** When GPU VRAM is full, objects must be evicted to system memory. The GPU server manages this, but it interacts with the VM subsystem's page cache and reclaim mechanisms — evicted VRAM objects become system memory allocations that the kernel must track. The interaction between the GPU server's VRAM management and the kernel's physical memory allocator needs careful design.
- **Multi-GPU:** Systems with both integrated and discrete GPUs require buffer sharing between GPU servers and policy decisions about which GPU renders and which displays. Deferred to future work.
- **Display security:** In a multi-user system, display access must be controlled by capabilities. The compositor holds the display capability; applications access the display only through the compositor. This is architecturally natural in Telix but the details of how display capabilities are managed (who grants them, when they're revoked) need specification.
- **VT switching equivalent:** Switching between multiple compositors (or between a compositor and a text console) requires coordinating display ownership. In Linux, this is VT switching. In Telix, this would be revocation and re-granting of the display server's capabilities.

## Development Phasing Summary

| Phase | Target | Key Deliverable |
|-------|--------|----------------|
| A.1 | QEMU virtio-gpu 2D | Framebuffer console, Wayland compositor with software rendering, Xwayland/GNOME/Firefox |
| A.2 | QEMU virtio-gpu 3D | VirGL (OpenGL) and Venus (Vulkan) acceleration in QEMU guest |
| B | Intel Iris Xe | DRM compat layer, Mesa Iris/ANV drivers, accelerated desktop on real hardware |
| C | Discrete GPUs | AMD (RadeonSI/RADV), NVIDIA (nouveau/NVK), via same DRM compat approach |
