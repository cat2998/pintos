#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define WORD_SIZE 8

struct file_descriptor {
    int fd;
    bool _stdin;
    bool _stdout;
    bool _stderr;
    struct file *file;
    struct list_elem elem;
    struct list dup_list;
};

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);

void argument_parsing(char *file_name, uint64_t *argc, char *argv[]);
void setup_user_stack(struct intr_frame *if_, uint64_t argc, char *argv[]);

void duplicate_fd(struct file_descriptor *new_fd, struct file_descriptor *old_fd, int newfd);
struct file_descriptor *get_fd(int fd, struct file_descriptor **root);
struct thread *get_child(tid_t child_pid);
int fd_list_init(void);

struct lazy_load_aux {
    struct file *file;
    off_t offset;
    size_t total_read_bytes;
    size_t page_read_bytes;
    size_t page_zero_bytes;
};

#endif /* userprog/process.h */
