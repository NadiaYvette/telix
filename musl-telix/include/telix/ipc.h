/* Telix IPC message format and helpers. */
#ifndef TELIX_IPC_H
#define TELIX_IPC_H

#include <stdint.h>

/* IPC message: tag + 6 data words. */
struct telix_msg {
    uint64_t tag;
    uint64_t data[6];
};

/* Name server protocol tags. */
#define NS_REGISTER     0x1000
#define NS_REGISTER_OK  0x1001
#define NS_LOOKUP       0x1100
#define NS_LOOKUP_OK    0x1101

/* Console protocol tags. */
#define CON_WRITE       0x3100
#define CON_WRITE_OK    0x3101

/* UDS protocol tags (Phase 57). */
#define UDS_SOCKET      0x8000
#define UDS_BIND        0x8010
#define UDS_LISTEN      0x8020
#define UDS_CONNECT     0x8030
#define UDS_ACCEPT      0x8040
#define UDS_SEND        0x8050
#define UDS_RECV        0x8060
#define UDS_CLOSE       0x8070
#define UDS_GETPEERCRED 0x8080
#define UDS_OK          0x8100
#define UDS_EOF         0x81FF
#define UDS_ERROR       0x8F00

/* TCP protocol tags (net_srv). */
#define NET_TCP_CONNECT    0x4200
#define NET_TCP_CONNECTED  0x4201
#define NET_TCP_FAIL       0x42FF
#define NET_TCP_SEND       0x4300
#define NET_TCP_SEND_OK    0x4301
#define NET_TCP_RECV       0x4400
#define NET_TCP_DATA       0x4401
#define NET_TCP_CLOSED     0x44FF
#define NET_TCP_CLOSE      0x4500
#define NET_TCP_CLOSE_OK   0x4501

/* IPC wrappers. */
uint32_t telix_port_create(void);
void     telix_port_destroy(uint32_t port);
uint64_t telix_send(uint32_t port, uint64_t tag, uint64_t d0, uint64_t d1,
                     uint64_t d2, uint64_t d3);
int      telix_recv_msg(uint32_t port, struct telix_msg *out);
uint32_t telix_nsrv_port(void);
uint32_t telix_ns_lookup(const char *name, int namelen);

/* Pack up to 24 bytes into 3 u64 words. */
void telix_pack_name(const char *name, int len, uint64_t out[3]);

#endif /* TELIX_IPC_H */
