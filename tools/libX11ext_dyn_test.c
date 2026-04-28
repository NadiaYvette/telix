/* Tier-3 Xwayland combined smoke test: link against all 10 X11
 * extension libs in one binary and verify ld.so loads each.
 *
 * We just take the address of one symbol from each lib via extern
 * decls — that's enough to force ld.so to (a) load the lib via
 * DT_NEEDED, (b) resolve the GOT entry.  We don't call them because
 * X11 ext functions overwhelmingly need a Display* and would crash
 * on NULL.
 *
 * One binary covers the bulk of Tier-3 in a single fork+exec, much
 * cheaper than 10 separate Step Hx phases under KVM.
 *
 * Libs covered:
 *   libXext, libXfixes, libXi, libxkbfile, libXmu,
 *   libXrender, libXRes, libXtst, libXv, libXinerama
 */
#include <stdio.h>
#include <unistd.h>

extern int  DPMSCapable(void);                  /* libXext      */
extern int  XFixesChangeCursor(void);           /* libXfixes    */
extern int  XAllowDeviceEvents(void);           /* libXi        */
extern int  XkbAccessXDetailText(void);         /* libxkbfile   */
extern int  XctCreate(void);                    /* libXmu       */
extern int  XRenderAddGlyphs(void);             /* libXrender   */
extern int  XResClientIdsDestroy(void);         /* libXRes      */
extern int  XRecordAllocRange(void);            /* libXtst      */
extern int  XvCreateImage(void);                /* libXv        */
extern int  XineramaIsActive(void);             /* libXinerama  */

int main(void)
{
    printf("[Xext]      %p\n", (void *)&DPMSCapable);
    printf("[Xfixes]    %p\n", (void *)&XFixesChangeCursor);
    printf("[Xi]        %p\n", (void *)&XAllowDeviceEvents);
    printf("[xkbfile]   %p\n", (void *)&XkbAccessXDetailText);
    printf("[Xmu]       %p\n", (void *)&XctCreate);
    printf("[Xrender]   %p\n", (void *)&XRenderAddGlyphs);
    printf("[XRes]      %p\n", (void *)&XResClientIdsDestroy);
    printf("[Xtst]      %p\n", (void *)&XRecordAllocRange);
    printf("[Xv]        %p\n", (void *)&XvCreateImage);
    printf("[Xinerama]  %p\n", (void *)&XineramaIsActive);
    fflush(stdout);
    _exit(0);
}
