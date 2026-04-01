# Network and Storage I/O Architecture

## Overview

Telix's unified I/O model (§5 of the main design document) claims that file I/O, block I/O, and network I/O are all message-passing to endpoints, and that the client need not know which kind of endpoint it is talking to. Storage-over-network protocols — iSCSI, NVMe-oF, Fibre Channel, ATA-over-Ethernet — are the strongest test of this claim, because they are literally block storage accessed over network transports. If the architecture is right, these should not be special cases; they should fall out naturally from the standard server composition and message-passing model.

This document describes how the network protocol stack, the storage protocol stack, and the convergence between them decompose into Telix servers, and identifies three standardised interface boundaries that organise the system to support many different protocol options at every layer.

## Network Stack Decomposition

The network stack decomposes into layered servers, each communicating via standard Telix IPC. Each layer presents a service port to the layer above and connects as a client to the layer below.

### Link Layer

**NIC drivers** (one per network interface) handle hardware directly: DMA ring management, interrupt handling (message-based, with polling retrenchment for high-throughput NICs), packet transmission and reception. A NIC driver presents a raw frame interface to the link layer server above: received frames are sent as messages; frames to transmit are received as request messages.

An **Ethernet server** handles MAC addressing, VLAN tagging (802.1Q), and frame demultiplexing by EtherType. It receives raw frames from NIC drivers, strips/adds Ethernet headers, and delivers payloads to the appropriate network layer server based on EtherType (0x0800 → IPv4, 0x86DD → IPv6, 0x0806 → ARP, 0x8914 → FCoE, etc.).

For non-Ethernet link types, equivalent link layer servers fill the same structural role: an **InfiniBand link server** handles IB packet framing, a **Fibre Channel link server** (FC-0/FC-1/FC-2) handles FC frame encoding and ordered sets, a **Wi-Fi server** handles 802.11 frame management and association state. Each presents the same upward interface: deliver typed payloads to network layer servers.

### Network Layer

An **IP server** handles both IPv4 and IPv6 (either as a combined server or as two cooperating servers, depending on implementation preference). Its responsibilities include:

- **Routing:** Determine the outbound link and next hop for each packet, consulting a routing table managed by a routing daemon or static configuration.
- **Fragmentation and reassembly:** Fragment outbound packets exceeding the path MTU (IPv4) or signal the transport layer to reduce segment size (IPv6, which does not fragment at the network layer). Reassemble inbound fragments.
- **Protocol demultiplexing:** Deliver packets to transport layer servers based on protocol number (6 → TCP, 17 → UDP, 132 → SCTP, etc.).
- **Neighbor discovery:** IPv6 NDP and IPv4 ARP, resolving IP addresses to link-layer addresses. This interacts with the link layer server.
- **ICMPv4/ICMPv6:** Handle control messages (echo request/reply, destination unreachable, packet too big, etc.), either internally or via a dedicated ICMP server.

IPv6 is not architecturally different from IPv4 at this level — it is the same structural role with different header parsing, a larger address space, mandatory IPsec support, and NDP replacing ARP. Both coexist naturally as services within the IP server or as peer servers sharing the same link layer.

### Transport Layer

Each transport protocol is a separate server:

**TCP server:** Manages connection state (SYN/SYN-ACK/ACK handshake, sequence numbers, retransmission, congestion control, flow control, FIN teardown). Presents the standard Telix channel model to clients: connect (active open), send, receive, shutdown. Also supports passive open (listen/accept) for server applications, where the TCP server allocates new channels for incoming connections and delivers them to the listening application's port.

**UDP server:** Thin demultiplexer. Receives datagrams from the IP server, demultiplexes by port number, and delivers to the appropriate client. Presents a datagram-oriented channel model: send and receive carry explicit datagrams rather than byte streams. No connection state.

**SCTP server:** Manages SCTP associations, which are richer than TCP connections. An SCTP association supports:

- **Multi-streaming:** Multiple independent ordered streams within one association. In Telix's model, each stream could be a separate sub-channel within the association's main channel, or could be exposed as separate ports in a port set.
- **Multi-homing:** An association can span multiple IP addresses (multiple paths). The SCTP server interacts with the IP server to send/receive on multiple addresses and handles path failover. Multi-homing is internal to the SCTP server and invisible to the client — the client sees a single association channel.
- **Message-oriented delivery:** SCTP preserves message boundaries (unlike TCP's byte stream), which maps naturally to Telix's message-based IPC. An SCTP message boundary aligns with a Telix message boundary.

SCTP's properties make it a particularly natural fit for Telix's I/O model. Its message orientation avoids the framing problem that TCP imposes on message-based protocols.

**RDMA server:** Manages RDMA queue pairs for protocols that use RDMA transport (NVMe/RDMA, iSER for iSCSI over RDMA, user-level RDMA applications). RDMA's performance model depends on kernel bypass and zero-copy from userspace directly to network hardware. See §RDMA Considerations below for the implications.

### Application Layer Protocols

Application-layer protocols (HTTP, DNS, SSH, NFS, etc.) are implemented as userspace libraries or servers that connect to transport layer channels. They are not part of the kernel's I/O architecture and are mentioned only for completeness.

## Storage Protocol Stack

### Local Block Devices

Local block device drivers (NVMe, SATA/AHCI, virtio-blk) are described in the driver model document. Each presents a **block device interface** on its service port: block read/write requests, flush/barrier, geometry query, completion messages. The cache server connects to these ports as a client.

### Storage-over-Network Protocols

Storage-over-network protocols are implemented as **initiator servers** that bridge the transport layer and the block device interface. Each initiator server connects to a transport channel as a client (downward) and presents a block device service port (upward). The cache server and filesystem servers connect to the block device port without knowing or caring that the storage is remote.

**iSCSI initiator server:** Connects to a TCP channel (via the TCP server), speaks the iSCSI protocol (login, SCSI command encapsulation, data transfer, logout), and presents a block device interface. From the cache server's perspective, an iSCSI LUN is indistinguishable from a local NVMe namespace.

**NVMe-oF initiator server:** Connects to the appropriate transport — TCP (via TCP server) for NVMe/TCP, RDMA (via RDMA server) for NVMe/RDMA, or Fibre Channel (via FC upper-layer server) for FC-NVMe. Speaks the NVMe-oF protocol and presents a block device interface. NVMe-oF's multiple transport options are handled by which transport server the initiator connects to; the block device interface presented upward is identical regardless of transport.

**Fibre Channel initiator servers:** The FC protocol stack has its own layering:

- **FC HBA driver:** Manages the Fibre Channel host bus adapter hardware. Handles FC-0 (physical), FC-1 (encoding), and FC-2 (framing/flow control).
- **FC services server:** Handles FC-3 common services (e.g., multicast, hunt groups) and name service interactions (FLOGI, PLOGI, fabric login).
- **FCP (Fibre Channel Protocol) server:** Implements the FC-4 upper-layer mapping for SCSI commands over FC. Presents a block device interface.
- **FC-NVMe server:** Implements the FC-4 upper-layer mapping for NVMe commands over FC. Presents a block device interface.

In both cases (FCP and FC-NVMe), the upward-facing interface is a standard block device port.

**ATA-over-Ethernet (AoE) initiator server:** Connects to the Ethernet server directly (AoE does not use IP or TCP — it operates at the link layer). Receives and sends AoE frames, translates ATA commands, and presents a block device interface. This is the simplest storage-over-network protocol in terms of stack depth.

**iSER (iSCSI Extensions for RDMA) initiator server:** Combines iSCSI protocol semantics with RDMA transport for high-performance remote storage. Connects to the RDMA server for data transfer and presents the same block device interface as the TCP-based iSCSI initiator.

### Fibre Channel over Ethernet (FCoE)

FCoE encapsulates Fibre Channel frames in Ethernet frames, allowing FC storage to use Ethernet infrastructure. In Telix's decomposition, a **FCoE server** sits between the Ethernet server (receiving FCoE frames identified by their EtherType) and the FC services/FCP/FC-NVMe servers above. It strips/adds FCoE encapsulation, presenting standard FC frames to the FC upper layers. This is a thin translation layer.

## Three Standardised Interface Boundaries

The system is organised around three boundaries where the message interface is standardised, allowing any implementation below the boundary to be substituted without affecting anything above it.

### Block Device Interface

The boundary between **storage consumers** (cache server, filesystem servers) and **storage providers** (local drivers, network storage initiators, multipath server).

Every storage provider — whether local NVMe, local SATA, iSCSI, NVMe-oF, FC-FCP, FC-NVMe, AoE, or a multipath aggregation — presents the same message types on its service port:

- **Block read request:** (offset, length) → completion with data (via memory grant for large reads, inline for small reads)
- **Block write request:** (offset, length, data) → completion with status
- **Flush/barrier:** Durability guarantee for all prior writes
- **Device geometry query:** Block size, device capacity, optimal I/O size
- **Completion messages:** Success or error status, one per request, may arrive out of order

The cache server connects to block device endpoints by port capability. It cannot distinguish a local NVMe device from an iSCSI LUN from an NVMe-oF namespace. This is the payoff of the unified I/O model.

### Transport Interface

The boundary between **transport protocol servers** (TCP, UDP, SCTP, RDMA) and their **consumers** (application clients, storage initiators, other protocol servers).

Every transport server presents the standard Telix channel model:

- **Connect:** Establish a channel to a remote endpoint (address, port/identifier)
- **Send:** Submit data on the channel (positioned or sequential)
- **Receive:** Request data from the channel
- **Shutdown:** Tear down the channel

Transport-specific features (TCP window sizing, SCTP stream management, RDMA queue pair configuration) are exposed as typed control messages on the channel, following the unified I/O model's approach to control operations (§5.2 of the main design document).

An iSCSI initiator connecting to a TCP channel and an HTTP client connecting to a TCP channel use the same interface. An NVMe-oF initiator connecting to an RDMA server and a user-level RDMA application use the same interface.

### Link/Network Interface

The boundary between the **network layer** (IP server) and the **link layer** (Ethernet server, FC link server, InfiniBand link server, Wi-Fi server).

The IP server sends and receives packets through the link layer without knowing whether the underlying link is Ethernet, Wi-Fi, or InfiniBand. The link layer server handles media-specific framing and addressing.

This boundary also allows non-IP protocols (AoE, FCoE) to connect directly to the link layer, bypassing the IP server entirely.

## Multipath I/O

Multipath I/O falls out naturally from the server composition model. A **multipath server** sits between the cache server and multiple block device endpoints (e.g., two FC-FCP paths to the same storage array, or one local NVMe and one NVMe-oF path to a replicated volume).

The multipath server presents a single block device port to the cache server (using the standard block device interface) and internally distributes requests across its downstream paths based on configurable policy:

- **Round-robin:** Distribute requests evenly across healthy paths for throughput.
- **Active/passive:** Use one path, fail over to another on path failure.
- **Least-queue-depth:** Send each request to the path with the fewest outstanding requests.
- **Service-time:** Send each request to the path with the lowest estimated completion time.

Path health monitoring is internal to the multipath server (periodic test requests, timeout detection). Path failure triggers automatic failover; path recovery triggers reintegration.

The cache server does not know multipath is involved. It holds a single port capability to "a block device" and sends block-level messages.

## RDMA Considerations

RDMA (Remote Direct Memory Access) presents a tension with the pure message-passing model. RDMA's performance promise depends on **kernel bypass**: data moves directly between application memory and the network hardware via DMA, without kernel involvement in the data path. In a traditional kernel, this means the RDMA verbs interface (ibverbs) provides userspace applications with direct access to hardware queue pairs.

In Telix's model, the RDMA server manages queue pair setup, connection management, and memory registration. For the **control path** (queue pair creation, memory region registration, connection establishment), standard message-passing IPC to the RDMA server is appropriate.

For the **data path** (post send, post receive, poll completion queue), the performance requirement is that the application (or storage initiator) interact with the hardware queue pair directly, without IPC to the RDMA server on every operation. This is handled by the capability model: the RDMA server grants the client a memory capability for the hardware queue pair memory region. The client maps this region and interacts with the queue pair directly via MMIO — posting work requests and polling completions without any IPC.

This is architecturally analogous to the polling mode retrenchment for interrupt delivery: the standard message-passing model is used for setup and teardown, and a shared-memory/direct-access model is used for the performance-critical data path. The capability model ensures that only authorised clients can access queue pair memory.

For storage-over-RDMA protocols (NVMe/RDMA, iSER), the initiator server holds queue pair capabilities and performs RDMA operations directly, presenting the standard block device interface upward. The RDMA details are encapsulated within the initiator server.

## Zero-Copy Across the Network/Storage Boundary

When the cache server services a read from a network-attached storage device, the data traverses the full stack: NIC DMA → link layer → IP server → transport server → storage initiator → cache server → client. Ideally, the NIC DMA buffer *is* the page cache page — no copies at all from network wire to client read.

Achieving full zero-copy requires the cache server to provide **pre-allocated page cache pages** as DMA targets to the NIC driver, threading the capability through the entire stack:

1. The cache server allocates page cache pages (its normal operation).
2. It grants these pages downward to the storage initiator as "receive buffers."
3. The storage initiator passes them further down to the transport server.
4. The transport server passes them to the NIC driver as DMA receive targets.
5. When data arrives, the NIC DMAs directly into the page cache page.
6. The completion propagates upward; the cache server grants the now-filled page to the client.

This is architecturally feasible — each step is a memory capability grant through standard IPC — but the plumbing is nontrivial. Each layer must support the concept of "use this pre-provided buffer for received data rather than allocating your own."

A simpler initial approach is a single copy at the NIC/transport boundary: the NIC driver DMAs into its own buffers, and the transport server copies the data into a page cache page provided by the cache server. This trades one memory copy for significantly simpler plumbing and is likely acceptable for initial performance.

Full zero-copy from NIC to page cache is a performance optimisation to pursue after the basic stack is functional.

## Protocol-Specific Configuration

Transport-specific configuration (TCP socket options, SCTP association parameters, FC zoning, iSCSI login parameters) uses typed control messages on the channel, as described in §5.2 of the main design document. Each transport server defines its own control message types.

A generic block device consumer (the cache server) does not configure transport parameters — it sends block-level messages and is unaware of the transport. Transport configuration is a **setup-time concern** handled by:

- The **device manager** (for storage-over-network devices: iSCSI target address, FC WWNN, authentication credentials).
- A **network configuration daemon** (for general network configuration: IP addresses, routes, DNS, TCP tuning).
- **Administrative tools** (for manual configuration of advanced parameters).

This separation is clean: the block device interface carries data, and transport configuration flows through a separate administrative path.

## Development Phasing

**Phase 3 (I/O Server Stack):** Minimal network stack (Ethernet server, IPv4/IPv6 server, TCP server, UDP server) sufficient for basic network connectivity. Local block device drivers (NVMe/virtio-blk) via the block device interface. No storage-over-network protocols yet.

**Phase 4 (Completeness):** SCTP server. iSCSI initiator server (first storage-over-network protocol — demonstrates the unified I/O model's block/network convergence). Multipath server. Network configuration daemon.

**Future work:** NVMe-oF initiator (TCP and RDMA transports). Fibre Channel stack (requires FC HBA hardware or emulation). FCoE. AoE. Full zero-copy NIC-to-page-cache path. RDMA verbs server.

## Summary

The unified I/O model's promise is that block I/O and network I/O are not architecturally distinct. Storage-over-network protocols validate this: an iSCSI LUN, an NVMe-oF namespace, an FC-FCP target, and a local NVMe drive all present the same block device interface to the cache server. The client holds a port capability and sends block-level messages; the transport is invisible.

The three standardised interface boundaries (block device, transport, link/network) organise the system so that new protocols can be added at any layer without affecting other layers. A new transport protocol (QUIC, for example) slots in at the transport boundary. A new storage-over-network protocol (a future NVMe-oF transport variant) slots in between the transport and block device boundaries. A new link type (a future wireless technology) slots in at the link boundary.

The architecture does not eliminate complexity — the individual protocol servers are complex — but it confines complexity to the server that implements the protocol and prevents it from leaking across interface boundaries. The cache server remains simple regardless of how many storage transport options exist below it.
