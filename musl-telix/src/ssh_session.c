/* SSH-2 session layer: service request, user authentication, channel management.
 * Handles userauth (password), channel open/data/close, pty-req, shell request. */
#include <telix/ssh.h>
#include <telix/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <telix/vfs.h>

/* -- Service Request handling -- */

int ssh_handle_service_request(ssh_transport *t) {
    uint8_t payload[SSH_MAX_PAYLOAD];
    int len = ssh_recv_packet(t, payload);
    if (len < 1 || payload[0] != SSH_MSG_SERVICE_REQUEST) return -1;

    const uint8_t *svc_name;
    int svc_len;
    if (ssh_get_string(payload, 1, len, &svc_name, &svc_len) < 0) return -1;

    /* We only accept "ssh-userauth". */
    if (svc_len != 12 || memcmp(svc_name, "ssh-userauth", 12) != 0) return -1;

    /* Send SERVICE_ACCEPT. */
    uint8_t resp[64];
    int rpos = 0;
    resp[rpos++] = SSH_MSG_SERVICE_ACCEPT;
    ssh_put_cstring(resp, &rpos, "ssh-userauth");
    return ssh_send_packet(t, resp, rpos);
}

/* -- Password authentication -- */

/* Inline check_passwd: parse /etc/passwd for user:pass match.
 * Format: user:pass:uid:gid:gecos:home:shell
 * Returns 1 on match. */
static int check_passwd(const char *user, const char *pass) {
    int fd = open("/etc/passwd", 0 /* O_RDONLY */);
    if (fd < 0) {
        /* No passwd file — allow root with empty password. */
        if (strcmp(user, "root") == 0) return 1;
        return 0;
    }

    char buf[512];
    int total = 0;
    int n;
    while ((n = read(fd, buf + total, (int)sizeof(buf) - 1 - total)) > 0)
        total += n;
    buf[total] = '\0';
    close(fd);

    /* Parse lines. */
    char *line = buf;
    while (*line) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';

        /* Split by ':'. */
        char *fields[7];
        int nf = 0;
        char *p = line;
        while (nf < 7) {
            fields[nf++] = p;
            char *colon = strchr(p, ':');
            if (colon) { *colon = '\0'; p = colon + 1; }
            else break;
        }

        if (nf >= 4 && strcmp(fields[0], user) == 0) {
            if (fields[1][0] == '\0' || strcmp(fields[1], pass) == 0)
                return 1;
        }

        if (eol) line = eol + 1;
        else break;
    }
    return 0;
}

/* Handle user authentication. Returns 0 on success. */
int ssh_handle_userauth(ssh_transport *t) {
    /* Loop: client may try "none" first, then password. */
    for (int attempts = 0; attempts < 6; attempts++) {
        uint8_t payload[SSH_MAX_PAYLOAD];
        int len = ssh_recv_packet(t, payload);
        if (len < 1) return -1;

        if (payload[0] != SSH_MSG_USERAUTH_REQUEST) {
            /* Ignore unexpected messages (e.g., SSH_MSG_GLOBAL_REQUEST). */
            if (payload[0] == SSH_MSG_GLOBAL_REQUEST) {
                /* RFC says use REQUEST_FAILURE (82) for global requests. */
                uint8_t rf[1] = { 82 }; /* SSH_MSG_REQUEST_FAILURE */
                ssh_send_packet(t, rf, 1);
                attempts--; /* Don't count this. */
                continue;
            }
            continue;
        }

        /* Parse: string user, string service, string method. */
        int pos = 1;
        const uint8_t *user_raw; int user_len;
        pos = ssh_get_string(payload, pos, len, &user_raw, &user_len);
        if (pos < 0) return -1;

        const uint8_t *svc_raw; int svc_len;
        pos = ssh_get_string(payload, pos, len, &svc_raw, &svc_len);
        if (pos < 0) return -1;

        const uint8_t *method_raw; int method_len;
        pos = ssh_get_string(payload, pos, len, &method_raw, &method_len);
        if (pos < 0) return -1;

        /* Null-terminate user and method. */
        char user[64], method[32];
        int ulen = user_len < 63 ? user_len : 63;
        memcpy(user, user_raw, ulen); user[ulen] = '\0';
        int mlen = method_len < 31 ? method_len : 31;
        memcpy(method, method_raw, mlen); method[mlen] = '\0';

        if (strcmp(method, "none") == 0) {
            /* Reject "none" — tell client we accept password. */
            uint8_t resp[64];
            int rpos = 0;
            resp[rpos++] = SSH_MSG_USERAUTH_FAILURE;
            ssh_put_cstring(resp, &rpos, "password");
            resp[rpos++] = 0; /* partial success = false */
            ssh_send_packet(t, resp, rpos);
            continue;
        }

        if (strcmp(method, "password") == 0) {
            /* bool change_password (must be false). */
            if (pos >= len) return -1;
            /* uint8_t change = payload[pos]; */ pos++;

            /* string password. */
            const uint8_t *pass_raw; int pass_len;
            if (ssh_get_string(payload, pos, len, &pass_raw, &pass_len) < 0)
                return -1;

            char pass[128];
            int plen = pass_len < 127 ? pass_len : 127;
            memcpy(pass, pass_raw, plen); pass[plen] = '\0';

            if (check_passwd(user, pass)) {
                /* Success! */
                uint8_t ok = SSH_MSG_USERAUTH_SUCCESS;
                return ssh_send_packet(t, &ok, 1);
            }

            /* Failed — send failure. */
            uint8_t resp[64];
            int rpos = 0;
            resp[rpos++] = SSH_MSG_USERAUTH_FAILURE;
            ssh_put_cstring(resp, &rpos, "password");
            resp[rpos++] = 0;
            ssh_send_packet(t, resp, rpos);
            continue;
        }

        /* Unknown method — reject. */
        uint8_t resp[64];
        int rpos = 0;
        resp[rpos++] = SSH_MSG_USERAUTH_FAILURE;
        ssh_put_cstring(resp, &rpos, "password");
        resp[rpos++] = 0;
        ssh_send_packet(t, resp, rpos);
    }

    return -1; /* Too many attempts. */
}

/* -- Channel management -- */

/* Handle channel open. Returns channel index on success, -1 on failure. */
int ssh_handle_channel_open(ssh_transport *t, ssh_channel *channels) {
    uint8_t payload[SSH_MAX_PAYLOAD];
    int len = ssh_recv_packet(t, payload);
    if (len < 1) return -1;

    /* May receive GLOBAL_REQUEST before CHANNEL_OPEN. */
    while (payload[0] == SSH_MSG_GLOBAL_REQUEST) {
        uint8_t rf[1] = { 82 }; /* REQUEST_FAILURE */
        ssh_send_packet(t, rf, 1);
        len = ssh_recv_packet(t, payload);
        if (len < 1) return -1;
    }

    if (payload[0] != SSH_MSG_CHANNEL_OPEN) return -1;

    int pos = 1;
    const uint8_t *type_raw; int type_len;
    pos = ssh_get_string(payload, pos, len, &type_raw, &type_len);
    if (pos < 0) return -1;

    if (type_len != 7 || memcmp(type_raw, "session", 7) != 0) {
        /* Reject non-session channel. */
        uint8_t resp[64];
        int rpos = 0;
        resp[rpos++] = SSH_MSG_CHANNEL_OPEN_FAILURE;
        /* sender channel (from request). */
        uint32_t sender = ssh_get_uint32(payload + pos);
        ssh_put_uint32(resp + rpos, sender); rpos += 4;
        ssh_put_uint32(resp + rpos, 1); rpos += 4; /* reason: administratively prohibited */
        ssh_put_cstring(resp, &rpos, "only session channels supported");
        ssh_put_cstring(resp, &rpos, ""); /* language tag */
        ssh_send_packet(t, resp, rpos);
        return -1;
    }

    if (pos + 12 > len) return -1;
    uint32_t sender_channel = ssh_get_uint32(payload + pos); pos += 4;
    uint32_t initial_window = ssh_get_uint32(payload + pos); pos += 4;
    uint32_t max_packet     = ssh_get_uint32(payload + pos); pos += 4;

    /* Find free channel slot. */
    int ch_idx = -1;
    for (int i = 0; i < SSH_MAX_CHANNELS; i++) {
        if (!channels[i].active) { ch_idx = i; break; }
    }
    if (ch_idx < 0) return -1;

    channels[ch_idx].active = 1;
    channels[ch_idx].local_id = (uint32_t)ch_idx;
    channels[ch_idx].remote_id = sender_channel;
    channels[ch_idx].remote_window = initial_window;
    channels[ch_idx].remote_max_pkt = max_packet;
    channels[ch_idx].local_window = 0x100000; /* 1 MB */
    channels[ch_idx].pty_allocated = 0;
    channels[ch_idx].shell_started = 0;

    /* Send CHANNEL_OPEN_CONFIRMATION. */
    uint8_t resp[32];
    int rpos = 0;
    resp[rpos++] = SSH_MSG_CHANNEL_OPEN_CONFIRM;
    ssh_put_uint32(resp + rpos, sender_channel); rpos += 4;   /* recipient channel */
    ssh_put_uint32(resp + rpos, (uint32_t)ch_idx); rpos += 4; /* sender channel */
    ssh_put_uint32(resp + rpos, channels[ch_idx].local_window); rpos += 4;
    ssh_put_uint32(resp + rpos, SSH_MAX_PAYLOAD); rpos += 4;   /* max packet size */
    ssh_send_packet(t, resp, rpos);

    return ch_idx;
}

/* Handle channel requests (pty-req, shell, env, etc.).
 * Returns: 1 = shell request received (caller should start shell),
 *          0 = continue waiting for more requests,
 *         -1 = error. */
int ssh_handle_channel_request(ssh_transport *t, ssh_channel *ch,
                                const uint8_t *payload, int len,
                                int *want_reply_out) {
    int pos = 1;
    if (pos + 4 > len) return -1;
    /* uint32_t recipient = ssh_get_uint32(payload + pos); */ pos += 4;

    const uint8_t *req_type; int req_len;
    pos = ssh_get_string(payload, pos, len, &req_type, &req_len);
    if (pos < 0 || pos >= len) return -1;

    uint8_t want_reply = payload[pos++];
    *want_reply_out = want_reply;

    if (req_len == 7 && memcmp(req_type, "pty-req", 7) == 0) {
        /* Parse: string TERM, uint32 cols, uint32 rows, uint32 wpx, uint32 hpx, string modes. */
        /* We just note that PTY was requested; actual PTY allocation is done in sshd.c. */
        ch->pty_allocated = 1;

        if (want_reply) {
            uint8_t resp[16];
            int rpos = 0;
            resp[rpos++] = SSH_MSG_CHANNEL_SUCCESS;
            ssh_put_uint32(resp + rpos, ch->remote_id); rpos += 4;
            ssh_send_packet(t, resp, rpos);
        }
        return 0;
    }

    if (req_len == 5 && memcmp(req_type, "shell", 5) == 0) {
        ch->shell_started = 1;
        if (want_reply) {
            uint8_t resp[16];
            int rpos = 0;
            resp[rpos++] = SSH_MSG_CHANNEL_SUCCESS;
            ssh_put_uint32(resp + rpos, ch->remote_id); rpos += 4;
            ssh_send_packet(t, resp, rpos);
        }
        return 1; /* Shell requested — caller starts shell. */
    }

    if (req_len == 3 && memcmp(req_type, "env", 3) == 0) {
        /* Ignore env requests silently. */
        if (want_reply) {
            uint8_t resp[16];
            int rpos = 0;
            resp[rpos++] = SSH_MSG_CHANNEL_SUCCESS;
            ssh_put_uint32(resp + rpos, ch->remote_id); rpos += 4;
            ssh_send_packet(t, resp, rpos);
        }
        return 0;
    }

    /* Unknown request. */
    if (want_reply) {
        uint8_t resp[16];
        int rpos = 0;
        resp[rpos++] = SSH_MSG_CHANNEL_FAILURE;
        ssh_put_uint32(resp + rpos, ch->remote_id); rpos += 4;
        ssh_send_packet(t, resp, rpos);
    }
    return 0;
}

/* Send channel data (server -> client). */
int ssh_channel_send_data(ssh_transport *t, ssh_channel *ch,
                           const uint8_t *data, int data_len) {
    while (data_len > 0) {
        int chunk = data_len;
        if (chunk > (int)ch->remote_max_pkt) chunk = (int)ch->remote_max_pkt;
        if (chunk > SSH_MAX_PAYLOAD - 9) chunk = SSH_MAX_PAYLOAD - 9;
        /* Check remote window. */
        if ((uint32_t)chunk > ch->remote_window) {
            if (ch->remote_window == 0) return -1; /* Window exhausted. */
            chunk = (int)ch->remote_window;
        }

        uint8_t pkt[SSH_MAX_PAYLOAD];
        int pos = 0;
        pkt[pos++] = SSH_MSG_CHANNEL_DATA;
        ssh_put_uint32(pkt + pos, ch->remote_id); pos += 4;
        ssh_put_string(pkt, &pos, data, chunk);
        if (ssh_send_packet(t, pkt, pos) != 0) return -1;

        ch->remote_window -= (uint32_t)chunk;
        data += chunk;
        data_len -= chunk;
    }
    return 0;
}

/* Send channel EOF + close. */
int ssh_channel_close(ssh_transport *t, ssh_channel *ch) {
    uint8_t eof[5];
    eof[0] = SSH_MSG_CHANNEL_EOF;
    ssh_put_uint32(eof + 1, ch->remote_id);
    ssh_send_packet(t, eof, 5);

    uint8_t cls[5];
    cls[0] = SSH_MSG_CHANNEL_CLOSE;
    ssh_put_uint32(cls + 1, ch->remote_id);
    ssh_send_packet(t, cls, 5);

    ch->active = 0;
    return 0;
}

/* Process a single incoming packet for a channel session.
 * Returns: 0=ok (data written to pty_data_out), 1=channel closed, -1=error.
 * pty_data_out/pty_data_len: data from CHANNEL_DATA to forward to PTY. */
int ssh_channel_process_packet(ssh_transport *t, ssh_channel *ch,
                                const uint8_t *payload, int len,
                                uint8_t *pty_data_out, int *pty_data_len) {
    *pty_data_len = 0;

    switch (payload[0]) {
    case SSH_MSG_CHANNEL_DATA: {
        if (len < 9) return -1;
        /* uint32_t channel = ssh_get_uint32(payload + 1); */
        const uint8_t *data; int dlen;
        if (ssh_get_string(payload, 5, len, &data, &dlen) < 0) return -1;

        /* Adjust our local window. */
        ch->local_window -= (uint32_t)dlen;
        if (ch->local_window < 0x10000) {
            /* Send window adjust. */
            uint8_t adj[9];
            adj[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
            ssh_put_uint32(adj + 1, ch->remote_id);
            ssh_put_uint32(adj + 5, 0x100000);
            ssh_send_packet(t, adj, 9);
            ch->local_window += 0x100000;
        }

        memcpy(pty_data_out, data, dlen);
        *pty_data_len = dlen;
        return 0;
    }
    case SSH_MSG_CHANNEL_WINDOW_ADJUST: {
        if (len < 9) return -1;
        uint32_t bytes = ssh_get_uint32(payload + 5);
        ch->remote_window += bytes;
        return 0;
    }
    case SSH_MSG_CHANNEL_EOF:
    case SSH_MSG_CHANNEL_CLOSE:
        return 1; /* Closed. */

    case SSH_MSG_CHANNEL_REQUEST: {
        int want_reply;
        ssh_handle_channel_request(t, ch, payload, len, &want_reply);
        return 0;
    }
    default:
        return 0; /* Ignore unknown. */
    }
}
