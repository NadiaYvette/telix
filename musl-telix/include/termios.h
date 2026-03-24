#ifndef TERMIOS_H
#define TERMIOS_H

typedef unsigned int tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

#define NCCS 20

struct termios {
    tcflag_t c_iflag;
    tcflag_t c_oflag;
    tcflag_t c_cflag;
    tcflag_t c_lflag;
    cc_t     c_cc[NCCS];
};

/* c_iflag */
#define ICRNL   0x0100
#define IXON    0x0400
#define IXOFF   0x1000
#define IGNBRK  0x0001
#define BRKINT  0x0002
#define INPCK   0x0010
#define ISTRIP  0x0020
#define IGNCR   0x0080
#define INLCR   0x0040

/* c_oflag */
#define OPOST   0x0001
#define ONLCR   0x0004

/* c_lflag */
#define ECHO    0x0008
#define ECHOE   0x0010
#define ECHOK   0x0020
#define ECHONL  0x0040
#define ICANON  0x0002
#define IEXTEN  0x8000
#define ISIG    0x0001

/* c_cflag */
#define CSIZE   0x0030
#define CS8     0x0030

/* c_cc indices */
#define VEOF    4
#define VEOL    11
#define VERASE  2
#define VINTR   0
#define VKILL   3
#define VMIN    6
#define VQUIT   1
#define VSTART  8
#define VSTOP   9
#define VSUSP   10
#define VTIME   5

/* tcsetattr actions */
#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

int tcgetattr(int fd, struct termios *t);
int tcsetattr(int fd, int actions, const struct termios *t);
void cfmakeraw(struct termios *t);
speed_t cfgetispeed(const struct termios *t);
speed_t cfgetospeed(const struct termios *t);
int cfsetispeed(struct termios *t, speed_t speed);
int cfsetospeed(struct termios *t, speed_t speed);

#endif
