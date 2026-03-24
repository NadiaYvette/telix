#ifndef DIRENT_H
#define DIRENT_H

#include <telix/types.h>

#define DT_UNKNOWN 0
#define DT_REG     8
#define DT_DIR     4
#define DT_LNK    10

struct dirent {
    unsigned long d_ino;
    unsigned char d_type;
    char d_name[256];
};

typedef struct _DIR DIR;

DIR *opendir(const char *name);
struct dirent *readdir(DIR *dir);
int closedir(DIR *dir);
void rewinddir(DIR *dir);

#endif
