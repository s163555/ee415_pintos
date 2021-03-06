#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>

struct lock filesys_lock;

typedef int pid_t;

struct lock filesys_lock;

void syscall_init (void);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void sigaction(int signum, void(*handler)(void));
void sendsig(pid_t pid, int signum);
void sched_yield(void);

//void argument_parser(void *esp, int *arg, int count);
//void addr_validation(void *);
//static void syscall_handler (struct intr_frame *);
//static void syscall_handler (struct intr_frame *f );
#endif /* userprog/syscall.h */
