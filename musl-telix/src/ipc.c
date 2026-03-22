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

void telix_pack_name(const char *name, int len, uint64_t out[3]) {
    out[0] = out[1] = out[2] = 0;
    for (int i = 0; i < len && i < 24; i++) {
        out[i / 8] |= (uint64_t)(unsigned char)name[i] << ((i % 8) * 8);
    }
}

uint32_t telix_ns_lookup(const char *name, int namelen) {
    uint32_t nsrv = telix_nsrv_port();
    if (nsrv == 0xFFFFFFFF) return 0xFFFFFFFF;

    uint32_t reply = telix_port_create();
    uint64_t words[3];
    telix_pack_name(name, namelen, words);
    uint64_t d3 = (uint64_t)namelen | ((uint64_t)reply << 32);

    telix_send(nsrv, NS_LOOKUP, words[0], words[1], words[2], d3);

    struct telix_msg msg;
    int ok = telix_recv_msg(reply, &msg);
    telix_port_destroy(reply);

    if (ok == 0 && msg.tag == NS_LOOKUP_OK) {
        uint32_t p = (uint32_t)msg.data[0];
        if (p != 0xFFFFFFFF) return p;
    }
    return 0xFFFFFFFF;
}
