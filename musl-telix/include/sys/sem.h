#ifndef _SYS_SEM_H
#define _SYS_SEM_H

#include <sys/ipc.h>
#include <stddef.h>

#define GETVAL  12
#define SETVAL  16
#define GETALL  13
#define SETALL  17

struct sembuf {
    unsigned short sem_num;
    short sem_op;
    short sem_flg;
};

union semun {
    int val;
    void *buf;
    unsigned short *array;
};

int semget(key_t key, int nsems, int semflg);
int semop(int semid, struct sembuf *sops, size_t nsops);
int semctl(int semid, int semnum, int cmd, ...);

#endif /* _SYS_SEM_H */
