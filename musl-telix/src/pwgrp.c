/* pwgrp.c — hardcoded passwd/group database for Telix. */

#include <pwd.h>
#include <grp.h>
#include <string.h>

/* ---- passwd database ---- */

static char _root_name[]   = "root";
static char _root_pw[]     = "x";
static char _root_gecos[]  = "root";
static char _root_dir[]    = "/";
static char _root_shell[]  = "/bin/shell";

static char _daemon_name[]  = "daemon";
static char _daemon_pw[]    = "x";
static char _daemon_gecos[] = "daemon";
static char _daemon_dir[]   = "/";
static char _daemon_shell[] = "/bin/shell";

static char _nobody_name[]  = "nobody";
static char _nobody_pw[]    = "x";
static char _nobody_gecos[] = "nobody";
static char _nobody_dir[]   = "/";
static char _nobody_shell[] = "/bin/shell";

static struct passwd _pw_db[] = {
    { _root_name,   _root_pw,   0,     0,     _root_gecos,   _root_dir,   _root_shell   },
    { _daemon_name, _daemon_pw, 1,     1,     _daemon_gecos, _daemon_dir, _daemon_shell },
    { _nobody_name, _nobody_pw, 65534, 65534, _nobody_gecos, _nobody_dir, _nobody_shell },
};

#define PW_COUNT (sizeof(_pw_db) / sizeof(_pw_db[0]))

static int _pw_idx = 0;

struct passwd *getpwuid(uid_t uid) {
    for (unsigned i = 0; i < PW_COUNT; i++) {
        if (_pw_db[i].pw_uid == uid)
            return &_pw_db[i];
    }
    return NULL;
}

struct passwd *getpwnam(const char *name) {
    for (unsigned i = 0; i < PW_COUNT; i++) {
        if (strcmp(_pw_db[i].pw_name, name) == 0)
            return &_pw_db[i];
    }
    return NULL;
}

struct passwd *getpwent(void) {
    if ((unsigned)_pw_idx >= PW_COUNT)
        return NULL;
    return &_pw_db[_pw_idx++];
}

void setpwent(void) {
    _pw_idx = 0;
}

void endpwent(void) {
    _pw_idx = 0;
}

/* ---- group database ---- */

static char _grp_root_name[]   = "root";
static char _grp_root_pw[]     = "x";
static char _grp_daemon_name[] = "daemon";
static char _grp_daemon_pw[]   = "x";
static char _grp_nogrp_name[]  = "nogroup";
static char _grp_nogrp_pw[]    = "x";

static char *_grp_empty_mem[] = { NULL };

static struct group _gr_db[] = {
    { _grp_root_name,   _grp_root_pw,   0,     _grp_empty_mem },
    { _grp_daemon_name, _grp_daemon_pw, 1,     _grp_empty_mem },
    { _grp_nogrp_name,  _grp_nogrp_pw,  65534, _grp_empty_mem },
};

#define GR_COUNT (sizeof(_gr_db) / sizeof(_gr_db[0]))

struct group *getgrgid(gid_t gid) {
    for (unsigned i = 0; i < GR_COUNT; i++) {
        if (_gr_db[i].gr_gid == gid)
            return &_gr_db[i];
    }
    return NULL;
}

struct group *getgrnam(const char *name) {
    for (unsigned i = 0; i < GR_COUNT; i++) {
        if (strcmp(_gr_db[i].gr_name, name) == 0)
            return &_gr_db[i];
    }
    return NULL;
}
