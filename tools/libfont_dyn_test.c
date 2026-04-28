/* Tier-4 Xwayland combined smoke test: link against the three font
 * libs and verify ld.so loads each.  Same pattern as H9: take the
 * address of one symbol per lib via extern decl — that forces ld.so
 * to load via DT_NEEDED and resolve the GOT entry.  Don't call them
 * because they need initialised state we don't bother to set up.
 *
 * Libs covered: libfreetype, libfontenc, libXfont2.
 *
 * Pulls in (transitively): libz, libbz2, libpng16, libharfbuzz,
 * libbrotlidec/common, libglib-2.0, libgraphite2, libpcre2-8, libm.
 */
#include <stdio.h>
#include <unistd.h>

extern int FT_Activate_Size(void);                /* libfreetype */
extern int FontEncDirectory(void);                /* libfontenc  */
extern int FontFileRegisterFpeFunctions(void);    /* libXfont2   */

int main(void)
{
    printf("[freetype] %p\n", (void *)&FT_Activate_Size);
    printf("[fontenc]  %p\n", (void *)&FontEncDirectory);
    printf("[Xfont2]   %p\n", (void *)&FontFileRegisterFpeFunctions);
    fflush(stdout);
    _exit(0);
}
