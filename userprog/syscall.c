#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}
// halt exit check_addr wait exec fork create remove filesize open close read write
/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
    uint64_t syscall_num = f->R.rax;
    // TODO: Your implementation goes here.
    struct thread *curr = thread_current();
    switch (syscall_num) {
    case SYS_HALT:
        power_off(); /* Halt the operating system. */
        break;
    case SYS_EXIT: /* Terminate this process. */
        exit(f->R.rdi);
        break;
    case SYS_FORK:
        break; /* Clone current process. */
    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi);
        break; /* Switch current process. */
    case SYS_WAIT:
        break; /* Wait for a child process to die. */
    case SYS_CREATE:
        break; /* Create a file. */
    case SYS_REMOVE:
        break; /* Delete a file. */
    case SYS_OPEN:
        break; /* Open a file. */
    case SYS_FILESIZE:
        break; /* Obtain a file's size. */
    case SYS_READ:
        break; /* Read from a file. */
    case SYS_WRITE:
        printf("%s", f->R.rsi);
        break; /* Write to a file. */
    case SYS_SEEK:
        break; /* Change position in a file. */
    case SYS_TELL:
        break; /* Report current position in a file. */
    case SYS_CLOSE:
        break; /* Close a file. */
        /* code */
        break;

    default:
        break;
    }
}

void check_addr(uint64_t *ptr) {
    if (ptr == NULL || is_kernel_vaddr(ptr) || !pml4_get_page(thread_current()->pml4, ptr))
        exit(-1);
}

void exit(int status) {
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exit_status);
    thread_exit();
}

int exec(const char *file) {
    char *fn_copy;

    check_addr(file);
    fn_copy = palloc_get_page(PAL_ZERO);
    if (fn_copy == NULL)
        return TID_ERROR;

    strlcpy(fn_copy, file, strlen(file) + 1);
    if (process_exec(fn_copy) < 0)
        exit(-1);
}

// pid_t fork(const char *thread_name);
// int wait(pid_t);
// bool create(const char *file, unsigned initial_size);
// bool remove(const char *file);
// int open(const char *file);
// int filesize(int fd);
// int read(int fd, void *buffer, unsigned length);
// int write(int fd, const void *buffer, unsigned length);
// void seek(int fd, unsigned position);
// unsigned tell(int fd);
// void close(int fd);