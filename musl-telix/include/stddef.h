/* Minimal stddef.h for Telix freestanding environment. */
#ifndef _STDDEF_H
#define _STDDEF_H

#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned long size_t;
#endif

#ifndef _SSIZE_T
#define _SSIZE_T
typedef long ssize_t;
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef long ptrdiff_t;

#endif /* _STDDEF_H */
