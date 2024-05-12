#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define WORD_SIZE 8

struct file_descriptor {
    int fd;
    bool is_dup;
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

#endif /* userprog/process.h */
