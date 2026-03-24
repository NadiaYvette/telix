/* ELF auxiliary vector constants for Telix. */
#ifndef ELF_H
#define ELF_H

/* Auxiliary vector entry types. */
#define AT_NULL   0   /* End of vector */
#define AT_PHDR   3   /* Program headers for program */
#define AT_PHENT  4   /* Size of program header entry */
#define AT_PHNUM  5   /* Number of program headers */
#define AT_PAGESZ 6   /* System page size */
#define AT_BASE   7   /* Base address of interpreter */
#define AT_ENTRY  9   /* Entry point of program */
#define AT_RANDOM 25  /* Address of 16 random bytes */

#endif /* ELF_H */
