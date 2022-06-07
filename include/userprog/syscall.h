#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_address (void *vaddr); /*** team 8 ***/

/*** hyeRexx ***/
int open(const char *file);
void close (int fd);

#endif /* userprog/syscall.h */
