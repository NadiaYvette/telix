/* termios.c — stub terminal control for Telix. */

#include <termios.h>
#include <string.h>

int tcgetattr(int fd, struct termios *t) {
    (void)fd;
    memset(t, 0, sizeof(*t));
    t->c_iflag = ICRNL;
    t->c_oflag = OPOST | ONLCR;
    t->c_cflag = CS8;
    t->c_lflag = ECHO | ICANON | ISIG;

    /* Sensible default control characters. */
    t->c_cc[VINTR]  = 3;   /* Ctrl-C */
    t->c_cc[VQUIT]  = 28;  /* Ctrl-\ */
    t->c_cc[VERASE] = 127; /* DEL    */
    t->c_cc[VKILL]  = 21;  /* Ctrl-U */
    t->c_cc[VEOF]   = 4;   /* Ctrl-D */
    t->c_cc[VMIN]   = 1;
    t->c_cc[VTIME]  = 0;
    t->c_cc[VSTART] = 17;  /* Ctrl-Q */
    t->c_cc[VSTOP]  = 19;  /* Ctrl-S */
    t->c_cc[VSUSP]  = 26;  /* Ctrl-Z */
    return 0;
}

int tcsetattr(int fd, int actions, const struct termios *t) {
    (void)fd;
    (void)actions;
    (void)t;
    /* Pure stub — no pty IPC yet. */
    return 0;
}

void cfmakeraw(struct termios *t) {
    t->c_iflag &= ~(unsigned int)(IGNBRK | BRKINT | INPCK | ISTRIP |
                                   INLCR | IGNCR | ICRNL | IXON);
    t->c_oflag &= ~(unsigned int)OPOST;
    t->c_lflag &= ~(unsigned int)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t->c_cflag &= ~(unsigned int)CSIZE;
    t->c_cflag |= CS8;
    t->c_cc[VMIN]  = 1;
    t->c_cc[VTIME] = 0;
}

speed_t cfgetispeed(const struct termios *t) {
    (void)t;
    return 9600;
}

speed_t cfgetospeed(const struct termios *t) {
    (void)t;
    return 9600;
}

int cfsetispeed(struct termios *t, speed_t speed) {
    (void)t;
    (void)speed;
    return 0;
}

int cfsetospeed(struct termios *t, speed_t speed) {
    (void)t;
    (void)speed;
    return 0;
}
