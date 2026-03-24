/* SysV IPC (semaphores) for Telix — talks to sysv_srv. */
#include <sys/sem.h>
#include <telix/ipc.h>
#include <telix/syscall.h>
#include <stdarg.h>

#define SEM_GET_TAG  0xA000
#define SEM_OP_TAG   0xA010
#define SEM_CTL_TAG  0xA020
#define SEM_OK_TAG   0xA100
#define SEM_VALUE_TAG 0xA110

static uint32_t sysv_port = 0xFFFFFFFF;

static uint32_t get_sysv_port(void) {
    if (sysv_port == 0xFFFFFFFF) {
        sysv_port = telix_ns_lookup("sysv", 4);
    }
    return sysv_port;
}

int semget(key_t key, int nsems, int semflg) {
    uint32_t port = get_sysv_port();
    if (port == 0xFFFFFFFF) return -1;

    uint32_t reply = telix_port_create();
    telix_send(port, SEM_GET_TAG,
               (uint64_t)key, (uint64_t)nsems,
               (uint64_t)semflg | ((uint64_t)reply << 32), 0);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    telix_port_destroy(reply);

    if (resp.tag == SEM_OK_TAG) return (int)resp.data[0];
    return -1;
}

int semop(int semid, struct sembuf *sops, size_t nsops) {
    uint32_t port = get_sysv_port();
    if (port == 0xFFFFFFFF) return -1;

    /* Process one operation at a time (simplified). */
    for (size_t i = 0; i < nsops; i++) {
        uint32_t reply = telix_port_create();
        uint64_t d1 = (uint64_t)sops[i].sem_num | ((uint64_t)(uint16_t)sops[i].sem_op << 16);
        telix_send(port, SEM_OP_TAG,
                   (uint64_t)semid, d1,
                   (uint64_t)reply << 32, 0);

        struct telix_msg resp;
        telix_recv_msg(reply, &resp);
        telix_port_destroy(reply);

        if (resp.tag != SEM_OK_TAG) return -1;
    }
    return 0;
}

int semctl(int semid, int semnum, int cmd, ...) {
    uint32_t port = get_sysv_port();
    if (port == 0xFFFFFFFF) return -1;

    uint64_t value = 0;
    if (cmd == SETVAL) {
        va_list ap;
        va_start(ap, cmd);
        union semun arg = va_arg(ap, union semun);
        value = (uint64_t)(unsigned int)arg.val;
        va_end(ap);
    }

    uint32_t reply = telix_port_create();
    telix_send(port, SEM_CTL_TAG,
               (uint64_t)semid, (uint64_t)semnum,
               (uint64_t)cmd | ((uint64_t)reply << 32), value);

    struct telix_msg resp;
    telix_recv_msg(reply, &resp);
    telix_port_destroy(reply);

    if (resp.tag == SEM_OK_TAG || resp.tag == SEM_VALUE_TAG)
        return (int)resp.data[0];
    return -1;
}
