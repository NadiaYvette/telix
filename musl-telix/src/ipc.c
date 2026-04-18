/* Telix IPC helpers: port ops, send, recv_msg, ns_lookup. */
#include <telix/syscall.h>
#include <telix/ipc.h>

/* Assembly stub for blocking recv (defined in syscall.S). */
extern uint64_t __telix_recv_msg(uint32_t port, struct telix_msg *out);

uint32_t telix_port_create(void) {
    return (uint32_t)__telix_syscall0(SYS_PORT_CREATE);
}

void telix_port_destroy(uint32_t port) {
    __telix_syscall1(SYS_PORT_DESTROY, port);
}

uint64_t telix_send(uint32_t port, uint64_t tag, uint64_t d0, uint64_t d1,
                     uint64_t d2, uint64_t d3) {
    return __telix_syscall6(SYS_SEND, port, tag, d0, d1, d2, d3);
}

uint32_t telix_nsrv_port(void) {
    return (uint32_t)__telix_syscall0(SYS_NSRV_PORT);
}

int telix_recv_msg(uint32_t port, struct telix_msg *out) {
    uint64_t status = __telix_recv_msg(port, out);
    return (status == 0) ? 0 : -1;
}

/* Assembly stub for sys_call (SYS_CALL=118). Sends a message and blocks
   until the server replies; reply is written into *out. */
extern uint64_t __telix_call_msg(uint32_t port, uint64_t tag,
                                 uint64_t d0, uint64_t d1,
                                 uint64_t d2, uint64_t d3,
                                 struct telix_msg *out);

int telix_call(uint32_t port, uint64_t tag, uint64_t d0, uint64_t d1,
               uint64_t d2, uint64_t d3, struct telix_msg *reply) {
    uint64_t status = __telix_call_msg(port, tag, d0, d1, d2, d3, reply);
    return (status == 0) ? 0 : -1;
}

void telix_pack_name(const char *name, int len, uint64_t out[3]) {
    out[0] = out[1] = out[2] = 0;
    for (int i = 0; i < len && i < 24; i++) {
        out[i / 8] |= (uint64_t)(unsigned char)name[i] << ((i % 8) * 8);
    }
}

uint32_t telix_ns_lookup(const char *name, int namelen) {
    /* Use the kernel's SYS_SVC_LOOKUP syscall directly (the old IPC-based
       name server was replaced by a kernel-internal service table). */
    uint64_t words[3];
    telix_pack_name(name, namelen, words);
    uint64_t port = __telix_syscall4(SYS_SVC_LOOKUP, words[0], words[1],
                                      words[2], (uint64_t)namelen);
    if (port == 0) return 0xFFFFFFFF;
    return (uint32_t)port;
}
