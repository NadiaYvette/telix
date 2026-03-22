/* Telix IPC message format and helpers. */
#ifndef TELIX_IPC_H
#define TELIX_IPC_H

#include <stdint.h>

/* IPC message: tag + 6 data words. */
struct telix_msg {
    uint64_t tag;
    uint64_t data[6];
};

/* Protocol tags. */
#define NS_REGISTER     0x1000
#define NS_REGISTER_OK  0x1001
#define NS_LOOKUP       0x1100
#define NS_LOOKUP_OK    0x1101
#define CON_WRITE       0x3100
#define CON_WRITE_OK    0x3101

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
