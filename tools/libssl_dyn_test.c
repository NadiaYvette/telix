/* Tier-5 Xwayland combined smoke test: link against libepoxy +
 * openssl libs (libssl, libcrypto) + libtirpc.  Same address-take
 * pattern as H9/H10.
 *
 * Tier-5 libs are listed in the porting plan as "many paths are
 * runtime-optional"; Xwayland config can disable them.  We smoke-
 * test ld.so loadability so the option is on the table.
 *
 * libtirpc is the heaviest by transitive deps (libgssapi_krb5,
 * libkrb5, libk5crypto, libcom_err, libkrb5support, libkeyutils,
 * libresolv, libselinux, libcrypto, libz, libpcre2-8, libc) — 12-deep
 * walk.
 */
#include <stdio.h>
#include <unistd.h>

extern int epoxy_egl_version(void);   /* libepoxy   */
extern int BIO_f_ssl(void);           /* libssl     */
extern int a2d_ASN1_OBJECT(void);     /* libcrypto  */
extern int authdes_create(void);      /* libtirpc   */

int main(void)
{
    printf("[epoxy]   %p\n", (void *)&epoxy_egl_version);
    printf("[ssl]     %p\n", (void *)&BIO_f_ssl);
    printf("[crypto]  %p\n", (void *)&a2d_ASN1_OBJECT);
    printf("[tirpc]   %p\n", (void *)&authdes_create);
    fflush(stdout);
    _exit(0);
}
