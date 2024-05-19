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
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void munmap(void *addr);
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

    curr->user_rsp = f->rsp;
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
    case SYS_MMAP:
        f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
        break;
    case SYS_MUNMAP:
        munmap(f->R.rdi);
        break;
    default:
        break;
    }
}

void check_addr(uint64_t *ptr) {
    if (ptr == NULL || is_kernel_vaddr(ptr) || !spt_find_page(&thread_current()->spt, ptr))
        exit(-1);
}

void check_writable(uint64_t *ptr) {
    struct page *page = NULL;

    page = spt_find_page(&thread_current()->spt, ptr);
    ASSERT(page != NULL);
    if (!page->is_writable)
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
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    struct file *openfile;

    check_addr(file);

    // multi-oom test 속도를 위한 파일개수 제한
    if (list_size(&curr->fd_list) > 128)
        return -1;

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

    while (1) {
        find_fd = get_fd(curr->fd_count, &root_fd);
        if (!find_fd)
            break;
        curr->fd_count++;
    }

    fd->fd = curr->fd_count;
    fd->file = openfile;
    list_init(&fd->dup_list);
    list_push_back(&curr->fd_list, &fd->elem);

    return curr->fd_count++;
}

void close(int fd) {
    struct thread *curr = thread_current();

    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    struct file_descriptor *new_root_fd;

    find_fd = get_fd(fd, &root_fd);
    if (!find_fd)
        return NULL;

    bool not_exsist_dup_list = list_empty(&find_fd->dup_list);
    bool is_root = (find_fd == root_fd);
    list_remove(&find_fd->elem);

    if (is_root) {
        if (not_exsist_dup_list) {
            lock_acquire(&file_lock);
            file_close(find_fd->file);
            lock_release(&file_lock);
        } else {
            new_root_fd = list_entry(list_begin(&root_fd->dup_list), struct file_descriptor, elem);
            list_remove(&new_root_fd->elem);
            if (!list_empty(&root_fd->dup_list))
                memcpy(&new_root_fd->dup_list, &root_fd->dup_list, sizeof(struct list));
            list_push_back(&curr->fd_list, &new_root_fd->elem);
        }
    }

    free(find_fd);
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
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;

    find_fd = get_fd(fd, &root_fd);
    if (find_fd != NULL && find_fd->file != NULL) {
        lock_acquire(&file_lock);
        file_seek(find_fd->file, position);
        lock_release(&file_lock);
    }
}

unsigned tell(int fd) {
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    unsigned result;

    find_fd = get_fd(fd, &root_fd);
    if (find_fd != NULL && find_fd->file != NULL) {
        lock_acquire(&file_lock);
        result = file_tell(find_fd->file);
        lock_release(&file_lock);
    }
    return result;
}

int filesize(int fd) {
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    unsigned result;

    find_fd = get_fd(fd, &root_fd);
    if (find_fd != NULL && find_fd->file != NULL) {
        lock_acquire(&file_lock);
        result = file_length(find_fd->file);
        lock_release(&file_lock);
    }
    return result;
}

int read(int fd, void *buffer, unsigned length) {
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    int result = -1;

    check_addr(buffer);
    check_writable(buffer);

    find_fd = get_fd(fd, &root_fd);
    if (find_fd != NULL) {
        if (find_fd->_stdin)
            return input_getc();
        if (find_fd->file) {
            lock_acquire(&file_lock);
            result = file_read(find_fd->file, buffer, length);
            lock_release(&file_lock);
        }
    }

    return result;
}

int write(int fd, const void *buffer, unsigned length) {
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    int result = 0;

    check_addr(buffer);

    find_fd = get_fd(fd, &root_fd);
    if (find_fd != NULL) {
        if (find_fd->_stdout) {
            putbuf(buffer, length);
            return length;
        }
        if (find_fd->file) {
            lock_acquire(&file_lock);
            result = file_write(find_fd->file, buffer, length);
            lock_release(&file_lock);
        }
    }

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

    child = get_child(child_pid);
    sema_down(&curr->fork_sema);

    return child->tid;
}

int wait(pid_t pid) {
    return process_wait(pid);
}

int dup2(int oldfd, int newfd) {
    struct file_descriptor *old_fd;
    struct file_descriptor *new_fd;
    struct file_descriptor *old_root_fd;
    struct file_descriptor *new_root_fd;

    old_fd = get_fd(oldfd, &old_root_fd);
    if (!old_fd)
        return -1;

    if (oldfd == newfd)
        return newfd;

    new_fd = get_fd(newfd, &new_root_fd);
    if (new_fd)
        close(newfd);

    new_fd = calloc(1, sizeof *new_fd);
    if (new_fd == NULL)
        return TID_ERROR;

    duplicate_fd(new_fd, old_fd, newfd);
    list_push_back(&old_root_fd->dup_list, &new_fd->elem);

    return newfd;
}

void *mmap(void *addr, size_t length, int writable, int fd, off_t offset) {
    struct file_descriptor *find_fd;
    struct file_descriptor *root_fd;
    struct file *find_file;

    find_fd = get_fd(fd, &root_fd);
    if (!find_fd)
        return NULL;

    find_file = find_fd->file;

    if (spt_find_page(&thread_current()->spt, pg_round_down(addr + length))) {
        return NULL;
    }
    if (!find_file || addr == NULL || is_kernel_vaddr(addr) || length == 0)
        return NULL;

    if (find_fd->_stdin || find_fd->_stdout || find_fd->_stderr)
        return NULL;

    return do_mmap(addr, length, writable, find_file, offset);
}
void munmap(void *addr) {
    check_addr(addr);

    do_munmap(addr);
}