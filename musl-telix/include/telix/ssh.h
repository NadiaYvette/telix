/* SSH-2 protocol constants and structures. */
#ifndef TELIX_SSH_H
#define TELIX_SSH_H

#include <stdint.h>
#include <stddef.h>

/* SSH message types. */
#define SSH_MSG_DISCONNECT               1
#define SSH_MSG_IGNORE                   2
#define SSH_MSG_SERVICE_REQUEST          5
#define SSH_MSG_SERVICE_ACCEPT           6
#define SSH_MSG_KEXINIT                  20
#define SSH_MSG_NEWKEYS                  21
#define SSH_MSG_KEX_ECDH_INIT           30
#define SSH_MSG_KEX_ECDH_REPLY          31
#define SSH_MSG_USERAUTH_REQUEST        50
#define SSH_MSG_USERAUTH_FAILURE        51
#define SSH_MSG_USERAUTH_SUCCESS        52
#define SSH_MSG_USERAUTH_BANNER         53
#define SSH_MSG_GLOBAL_REQUEST          80
#define SSH_MSG_CHANNEL_OPEN            90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM    91
#define SSH_MSG_CHANNEL_OPEN_FAILURE    92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST   93
#define SSH_MSG_CHANNEL_DATA            94
#define SSH_MSG_CHANNEL_EOF             96
#define SSH_MSG_CHANNEL_CLOSE           97
#define SSH_MSG_CHANNEL_REQUEST         98
#define SSH_MSG_CHANNEL_SUCCESS         99
#define SSH_MSG_CHANNEL_FAILURE         100

/* Disconnect reason codes. */
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT  1
#define SSH_DISCONNECT_PROTOCOL_ERROR               2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED           3
#define SSH_DISCONNECT_MAC_ERROR                     5

/* Maximum packet size. */
#define SSH_MAX_PACKET  35000
#define SSH_MAX_PAYLOAD 32768

/* SSH transport state. */
typedef struct {
    int fd;                         /* TCP socket fd */

    /* Version strings. */
    char client_version[256];
    char server_version[256];

    /* Key exchange state. */
    uint8_t client_kexinit[1024];   /* Raw KEXINIT payload */
    int client_kexinit_len;
    uint8_t server_kexinit[1024];
    int server_kexinit_len;

    uint8_t session_id[32];         /* First exchange hash becomes session_id */
    int session_id_set;

    /* Encryption keys (after NEWKEYS). */
    uint8_t enc_key_cs[64];         /* Client->server encryption key */
    uint8_t enc_key_sc[64];         /* Server->client encryption key */
    uint8_t int_key_cs[64];         /* Client->server integrity key */
    uint8_t int_key_sc[64];         /* Server->client integrity key */
    int keys_active;

    /* Sequence numbers. */
    uint32_t seq_recv;
    uint32_t seq_send;

    /* Host key. */
    uint8_t host_pk[32];            /* Ed25519 public key */
    uint8_t host_sk[64];            /* Ed25519 secret key (seed||pk) */
} ssh_transport;

/* Initialize transport state. fd must be a connected TCP socket. */
void ssh_transport_init(ssh_transport *t, int fd,
                        const uint8_t host_pk[32], const uint8_t host_sk[64]);

/* Perform version exchange. Returns 0 on success. */
int ssh_version_exchange(ssh_transport *t);

/* Perform key exchange (KEXINIT + ECDH + NEWKEYS). Returns 0 on success. */
int ssh_key_exchange(ssh_transport *t);

/* Read a decrypted SSH packet. Returns payload length, -1 on error.
 * payload_out must be at least SSH_MAX_PAYLOAD bytes. */
int ssh_recv_packet(ssh_transport *t, uint8_t *payload_out);

/* Send an encrypted SSH packet. Returns 0 on success. */
int ssh_send_packet(ssh_transport *t, const uint8_t *payload, int len);

/* Helpers for building SSH payloads. */
void ssh_put_uint32(uint8_t *buf, uint32_t v);
uint32_t ssh_get_uint32(const uint8_t *buf);
void ssh_put_string(uint8_t *buf, int *pos, const uint8_t *data, int len);
void ssh_put_cstring(uint8_t *buf, int *pos, const char *s);
int ssh_get_string(const uint8_t *buf, int pos, int buf_len,
                   const uint8_t **out, int *out_len);

/* -- Session layer (ssh_session.c) -- */

/* SSH channel state. */
typedef struct {
    int active;
    uint32_t local_id;
    uint32_t remote_id;
    uint32_t remote_window;
    uint32_t remote_max_pkt;
    uint32_t local_window;
    int pty_allocated;
    int shell_started;
} ssh_channel;

#define SSH_MAX_CHANNELS 4

/* Handle SSH_MSG_SERVICE_REQUEST ("ssh-userauth"). Returns 0 on success. */
int ssh_handle_service_request(ssh_transport *t);

/* Handle user authentication loop. Returns 0 on success (USERAUTH_SUCCESS sent). */
int ssh_handle_userauth(ssh_transport *t);

/* Handle CHANNEL_OPEN for "session" type. Returns channel index or -1. */
int ssh_handle_channel_open(ssh_transport *t, ssh_channel *channels);

/* Handle a CHANNEL_REQUEST (pty-req, shell, env).
 * Returns: 1=shell requested, 0=continue, -1=error. */
int ssh_handle_channel_request(ssh_transport *t, ssh_channel *ch,
                                const uint8_t *payload, int len,
                                int *want_reply_out);

/* Send channel data. Returns 0 on success. */
int ssh_channel_send_data(ssh_transport *t, ssh_channel *ch,
                           const uint8_t *data, int data_len);

/* Send channel EOF + close. */
int ssh_channel_close(ssh_transport *t, ssh_channel *ch);

/* Process an incoming channel packet.
 * Returns: 0=ok (data in pty_data_out), 1=closed, -1=error. */
int ssh_channel_process_packet(ssh_transport *t, ssh_channel *ch,
                                const uint8_t *payload, int len,
                                uint8_t *pty_data_out, int *pty_data_len);

#endif /* TELIX_SSH_H */
