/* Syslog implementation for Telix.
 * Sends messages to the syslog server via IPC.
 */
#include <telix/ipc.h>
#include <telix/syscall.h>
#include <stdint.h>
#include <string.h>

#define SYSLOG_OPEN_TAG  0x9000
#define SYSLOG_MSG_TAG   0x9010
#define SYSLOG_CLOSE_TAG 0x9020
#define SYSLOG_OK        0x9100

static uint32_t syslog_port = 0xFFFFFFFF;
static uint32_t syslog_handle = 0xFFFFFFFF;
static int syslog_facility = 0;

void openlog(const char *ident, int option, int facility) {
    (void)option;
    syslog_facility = facility;

    if (syslog_port == 0xFFFFFFFF) {
        syslog_port = telix_ns_lookup("syslog", 6);
        if (syslog_port == 0xFFFFFFFF) return;
    }

    /* Pack ident into u64. */
    uint64_t ident_w0 = 0;
    if (ident) {
        int len = 0;
        while (ident[len] && len < 8) len++;
        memcpy(&ident_w0, ident, len);
    }

    uint32_t reply = telix_port_create();
    telix_send(syslog_port, SYSLOG_OPEN_TAG,
               (uint64_t)facility, ident_w0,
               (uint64_t)reply << 32, 0);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    if (resp.tag == SYSLOG_OK) {
        syslog_handle = (uint32_t)resp.data[1];
    }
    telix_port_destroy(reply);
}

void syslog(int priority, const char *format, ...) {
    if (syslog_port == 0xFFFFFFFF) {
        syslog_port = telix_ns_lookup("syslog", 6);
        if (syslog_port == 0xFFFFFFFF) return;
    }

    /* Pack message into two u64 words (up to 16 bytes). */
    uint64_t msg_w0 = 0, msg_w1 = 0;
    if (format) {
        int len = 0;
        while (format[len] && len < 16) len++;
        if (len > 0) memcpy(&msg_w0, format, len > 8 ? 8 : len);
        if (len > 8) memcpy(&msg_w1, format + 8, len - 8);
    }

    uint32_t reply = telix_port_create();
    int combined = syslog_facility | (priority & 0x7);
    telix_send(syslog_port, SYSLOG_MSG_TAG,
               (uint64_t)combined, msg_w0, msg_w1,
               (uint64_t)reply << 32);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    telix_port_destroy(reply);
}

void closelog(void) {
    if (syslog_port == 0xFFFFFFFF || syslog_handle == 0xFFFFFFFF) return;

    uint32_t reply = telix_port_create();
    telix_send(syslog_port, SYSLOG_CLOSE_TAG,
               (uint64_t)syslog_handle, 0,
               (uint64_t)reply << 32, 0);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    telix_port_destroy(reply);

    syslog_handle = 0xFFFFFFFF;
}
