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
#define NET_TCP_RECV_NB    0x4410
#define NET_TCP_RECV_NONE  0x4412
#define NET_TCP_CLOSED     0x44FF
#define NET_TCP_CLOSE      0x4500
#define NET_TCP_CLOSE_OK   0x4501
#define NET_TCP_BIND       0x4600
#define NET_TCP_BIND_OK    0x4601
#define NET_TCP_LISTEN     0x4700
#define NET_TCP_LISTEN_OK  0x4701
#define NET_TCP_LISTEN_FAIL 0x47FF
#define NET_TCP_ACCEPT     0x4710
#define NET_TCP_ACCEPT_OK  0x4711
#define NET_TCP_ACCEPT_FAIL 0x47FE

/* TCP6 protocol tags (ip6_srv). */
#define TCP6_CONNECT     0x6300
#define TCP6_CONNECTED   0x6301
#define TCP6_FAIL        0x63FF
#define TCP6_SEND        0x6400
#define TCP6_SEND_OK     0x6401
#define TCP6_RECV        0x6500
#define TCP6_DATA        0x6501
#define TCP6_RECV_NB     0x6510
#define TCP6_RECV_NONE   0x6512
#define TCP6_CLOSED      0x65FF
#define TCP6_CLOSE       0x6600
#define TCP6_CLOSE_OK    0x6601
#define TCP6_BIND        0x6700
#define TCP6_BIND_OK     0x6701
#define TCP6_LISTEN      0x6800
#define TCP6_LISTEN_OK   0x6801
#define TCP6_LISTEN_FAIL 0x68FF
#define TCP6_ACCEPT      0x6810
#define TCP6_ACCEPT_OK   0x6811
#define TCP6_ACCEPT_FAIL 0x68FE

/* UDP6 protocol tags (ip6_srv). */
#define UDP6_BIND        0x6900
#define UDP6_BIND_OK     0x6901
#define UDP6_BIND_FAIL   0x69FF
#define UDP6_SEND        0x6A00
#define UDP6_SEND_OK     0x6A01
#define UDP6_SEND_FAIL   0x6AFF
#define UDP6_RECV        0x6B00
#define UDP6_DATA6       0x6B01
#define UDP6_RECV_NB     0x6B10
#define UDP6_RECV_NONE   0x6B12
#define UDP6_CLOSE       0x6C00
#define UDP6_CLOSE_OK    0x6C01

/* DNS resolution via tcp4_srv. */
#define DNS_RESOLVE      0x4800
#define DNS_RESOLVE_OK   0x4801
#define DNS_RESOLVE_FAIL 0x48FF

/* Pipe protocol tags (Phase 59). */
#define PIPE_CREATE_TAG  0x5010
#define PIPE_WRITE_TAG   0x5020
#define PIPE_READ_TAG    0x5030
#define PIPE_CLOSE_TAG   0x5040
#define PIPE_OK_TAG      0x5100
#define PIPE_EOF_TAG     0x51FF
#define PIPE_POLL_TAG    0x5050
#define PIPE_ERROR_TAG   0x5F00

/* File lock protocol tags (Phase 61). */
#define FS_FLOCK_TAG     0x2800
#define FS_FLOCK_OK_TAG  0x2801
#define FS_GETLK_TAG     0x2810
#define FS_GETLK_OK_TAG  0x2811
#define FS_SETLK_TAG     0x2820
#define FS_SETLK_OK_TAG  0x2821
#define FS_SETLKW_TAG    0x2830
#define FS_SETLKW_OK_TAG 0x2831
#define FS_LOCK_ERR_TAG  0x28FF

/* Poll protocol tags (Phase 60). */
#define UDS_POLL_TAG     0x8090
#define CON_POLL_TAG     0x3110
#define CON_POLL_OK_TAG  0x3111

/* IPC wrappers. */
uint32_t telix_port_create(void);
void     telix_port_destroy(uint32_t port);
uint64_t telix_send(uint32_t port, uint64_t tag, uint64_t d0, uint64_t d1,
                     uint64_t d2, uint64_t d3);
int      telix_recv_msg(uint32_t port, struct telix_msg *out);
int      telix_call(uint32_t port, uint64_t tag, uint64_t d0, uint64_t d1,
                    uint64_t d2, uint64_t d3, struct telix_msg *reply);
uint32_t telix_nsrv_port(void);
uint32_t telix_ns_lookup(const char *name, int namelen);

/* Pack up to 24 bytes into 3 u64 words. */
void telix_pack_name(const char *name, int len, uint64_t out[3]);

#endif /* TELIX_IPC_H */
