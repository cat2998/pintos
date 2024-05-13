#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void exit(int status);

typedef int pid_t;

#endif /* userprog/syscall.h */
