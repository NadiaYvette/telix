/* Tier-1 Xwayland porting smoke test: dynamically link Fedora's
 * libXdmcp.so.6 and exercise XdmcpAllocARRAY8 + XdmcpDisposeARRAY8 to
 * verify ld.so resolves a libXdmcp entry point.
 *
 * XdmcpAllocARRAY8 allocates a CARD8 buffer + sets the length field.
 * No syscalls beyond malloc; pure symbol-resolution test.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

typedef uint8_t  CARD8;
typedef uint16_t CARD16;
typedef int      Bool;

typedef struct {
    CARD16 length;
    CARD8 *data;
} ARRAY8;

extern Bool XdmcpAllocARRAY8(ARRAY8 *array, int length);
extern void XdmcpDisposeARRAY8(ARRAY8 *array);

int main(void)
{
    ARRAY8 a = { 0, 0 };
    if (!XdmcpAllocARRAY8(&a, 8)) {
        fprintf(stderr, "[Xdmcp] AllocARRAY8 failed\n");
        fflush(stderr);
        _exit(1);
    }
    printf("[Xdmcp] AllocARRAY8 OK, length=%u\n", a.length);
    fflush(stdout);
    XdmcpDisposeARRAY8(&a);
    _exit(0);
}
