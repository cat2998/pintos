#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "lib/string.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void halt(void) NO_RETURN;
void exit(int status) NO_RETURN;
pid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *file);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned length);
int write(int fd, const void *buffer, unsigned length);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

int dup2(int oldfd, int newfd);

/* lock for access file_sys code */
struct lock file_lock;

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
    lock_init(&file_lock);
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
        f->R.rax = fork(f->R.rdi, f);
        break; /* Clone current process. */
    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi);
        break; /* Switch current process. */
    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break; /* Wait for a child process to die. */
    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break; /* Create a file. */
    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break; /* Delete a file. */
    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break; /* Open a file. */
    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break; /* Obtain a file's size. */
    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break; /* Read from a file. */
    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break; /* Write to a file. */
    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break; /* Change position in a file. */
    case SYS_TELL:
        f->R.rax = tell(f->R.rdi);
        break; /* Report current position in a file. */
    case SYS_CLOSE:
        close(f->R.rdi);
        break;
    case SYS_DUP2:
        f->R.rax = dup2(f->R.rdi, f->R.rsi);
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

int open(const char *file) {
    struct thread *curr = thread_current();
    struct file_descriptor *fd;
    struct file *openfile;
    struct file_ *file_wrapper;

    check_addr(file);

    fd = calloc(1, sizeof *fd);
    if (fd == NULL)
        return TID_ERROR;

    lock_acquire(&file_lock);
    openfile = filesys_open(file);
    lock_release(&file_lock);
    if (!openfile) {
        free(fd);
        return -1;
    }
    file_wrapper = calloc(1, sizeof *file_wrapper);
    if (file_wrapper == NULL)
        return TID_ERROR;

    fd->fd = curr->fd_count;
    fd->file_wrapper = file_wrapper;
    fd->file_wrapper->file = openfile;
    list_push_back(&curr->fd_list, &fd->elem);

    return curr->fd_count++;
}

void close(int fd) {
    struct thread *curr = thread_current();
    struct file_descriptor *t;
    struct list_elem *e;
    bool is_find = false;

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        t = list_entry(e, struct file_descriptor, elem);
        if (t->fd == fd) {
            is_find = true;
            e = list_remove(e);
            break;
        }
    }

    if (is_find) {
        if (t->file_wrapper->dup_cnt == 0) {
            lock_acquire(&file_lock);
            file_close(t->file_wrapper->file);
            lock_release(&file_lock);
        } else {
            t->file_wrapper->dup_cnt--;
        }
        free(t->file_wrapper);
        free(t);
    }
}

bool create(const char *file, unsigned initial_size) {
    bool success = false;
    check_addr(file);
    lock_acquire(&file_lock);
    success = filesys_create(file, initial_size);
    lock_release(&file_lock);

    return success;
}

bool remove(const char *file) {
    bool success = false;
    check_addr(file);
    lock_acquire(&file_lock);
    success = filesys_remove(file);
    lock_release(&file_lock);

    return success;
}

void seek(int fd, unsigned position) {
    struct thread *curr = thread_current();
    struct file_descriptor *t;
    struct list_elem *e;

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        t = list_entry(e, struct file_descriptor, elem);
        if (t->fd == fd) {
            lock_acquire(&file_lock);
            file_seek(t->file_wrapper->file, position);
            lock_release(&file_lock);
            break;
        }
    }
}

unsigned tell(int fd) {
    struct thread *curr = thread_current();
    struct file_descriptor *t;
    struct list_elem *e;
    unsigned result;

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        t = list_entry(e, struct file_descriptor, elem);
        if (t->fd == fd) {
            lock_acquire(&file_lock);
            result = file_tell(t->file_wrapper->file);
            lock_release(&file_lock);
            break;
        }
    }
    return result;
}

int filesize(int fd) {
    struct thread *curr = thread_current();
    struct file_descriptor *t;
    struct list_elem *e;
    unsigned result;

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        t = list_entry(e, struct file_descriptor, elem);
        if (t->fd == fd) {
            lock_acquire(&file_lock);
            result = file_length(t->file_wrapper->file);
            lock_release(&file_lock);
            break;
        }
    }
    return result;
}

int read(int fd, void *buffer, unsigned length) {
    struct thread *curr = thread_current();
    struct file_descriptor *t;
    struct list_elem *e;
    off_t result;
    bool is_find = false;

    check_addr(buffer);

    // if (fd == 0) { * 표준입력일때 devices/input_getc(void) 함수 사용
    // }

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        t = list_entry(e, struct file_descriptor, elem);
        if (t->fd == fd) {
            is_find = true;
            lock_acquire(&file_lock);
            result = file_read(t->file_wrapper->file, buffer, length);
            lock_release(&file_lock);
            break;
        }
    }
    if (!is_find)
        result = -1;
    return result;
}

int write(int fd, const void *buffer, unsigned length) {
    struct thread *curr = thread_current();
    struct file_descriptor *t;
    struct list_elem *e;
    off_t result;
    bool is_find = false;

    check_addr(buffer);

    if (fd == 1) {
        putbuf(buffer, length);
        return length;
    }

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        t = list_entry(e, struct file_descriptor, elem);
        if (t->fd == fd) {
            is_find = true;
            lock_acquire(&file_lock);
            result = file_write(t->file_wrapper->file, buffer, length);
            lock_release(&file_lock);
            break;
        }
    }
    if (!is_find)
        result = 0;
    return result;
}

pid_t fork(const char *thread_name, struct intr_frame *f) {
    pid_t child_pid;
    struct thread *curr = thread_current();
    struct list_elem *e;
    struct thread *child;

    check_addr(thread_name);

    memcpy(&curr->if_, f, sizeof(struct intr_frame));
    child_pid = process_fork(thread_name, f);

    for (e = list_begin(&curr->child_list); e != list_end(&curr->child_list); e = list_next(e)) {
        child = list_entry(e, struct thread, c_elem);
        if (child->tid == child_pid) {
            break;
        }
    }
    sema_down(&curr->fork_sema);
    child_pid = child->tid;
    return child_pid;
}

int wait(pid_t pid) {
    pid_t child_pid;

    child_pid = process_wait(pid);
    return child_pid;
}

int dup2(int oldfd, int newfd) {
    struct thread *curr = thread_current();
    struct file_descriptor *file_descriptor;
    struct file_descriptor *o_file_descriptor;
    struct file_descriptor *n_file_descriptor;
    struct list_elem *e;
    bool is_find_o = false;
    bool is_find_n = false;

    for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
        file_descriptor = list_entry(e, struct file_descriptor, elem);
        if (file_descriptor->fd == oldfd) {
            o_file_descriptor = file_descriptor;
            is_find_o = true;
        } else if (file_descriptor->fd == newfd) {
            n_file_descriptor = file_descriptor;
            is_find_n = true;
        }
    }

    if (!is_find_o) {
        return -1;
    }

    if (oldfd == newfd) {
        return newfd;
    }

    if (is_find_n) {
        close(n_file_descriptor->fd);
    }

    n_file_descriptor = malloc(sizeof *n_file_descriptor);
    if (n_file_descriptor == NULL) {
        return TID_ERROR;
    }
    n_file_descriptor->file_wrapper = calloc(1, sizeof *n_file_descriptor->file_wrapper);
    if (n_file_descriptor->file_wrapper == NULL) {
        free(n_file_descriptor);
        return TID_ERROR;
    }
    n_file_descriptor->fd = newfd;
    n_file_descriptor->file_wrapper->file = file_descriptor->file_wrapper->file;
    n_file_descriptor->file_wrapper->dup_cnt++;

    list_push_back(&curr->fd_list, &n_file_descriptor->elem);

    return newfd;
}