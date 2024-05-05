#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
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

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
    uint64_t syscall_num = f->R.rax;
        // TODO: Your implementation goes here.
    struct thread *curr = thread_current();
    switch (syscall_num)
    {
    case SYS_HALT:
        power_off();    /* Halt the operating system. */
    case SYS_EXIT:    /* Terminate this process. */
    case SYS_FORK:     /* Clone current process. */
    case SYS_EXEC:     /* Switch current process. */
    case SYS_WAIT:     /* Wait for a child process to die. */
    case SYS_CREATE:   /* Create a file. */
    case SYS_REMOVE:   /* Delete a file. */
    case SYS_OPEN:     /* Open a file. */
    case SYS_FILESIZE: /* Obtain a file's size. */
    case SYS_READ:     /* Read from a file. */
    case SYS_WRITE:    /* Write to a file. */
    case SYS_SEEK:     /* Change position in a file. */
    case SYS_TELL:     /* Report current position in a file. */
    case SYS_CLOSE: /* Close a file. */
        /* code */
        break;
    
    default:
        break;
    }
    printf("system call!\n");
    thread_exit();
}

void check_addr(struct intr_frame *f UNUSED){

}