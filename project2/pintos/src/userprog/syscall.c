#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "devices/input.h"

void argument_parser(void *esp, int *arg, int count);
void addr_validation(void *);
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void argument_parser(void *esp, int *arg, int count){
    int i;

    if( count < 4){
        void * sp = esp;
        for(i = 0 ; i<count; i++){
            sp += 4;
            addr_validation(sp);
            arg[i] = *(int *)sp;
        }
    }else {
        exit(-1);
    }
}

void addr_validation(void *addr){
    struct thread * t = thread_current();
    uint32_t * pd = t->pagedir; /* Defined in threads/thread.h ifndef */
    void* temp_addr = addr;
    for( int i=0; i<4;i++){
        temp_addr = temp_addr + i;
        bool is_kernel = (int)is_kernel_vaddr(temp_addr);
        if(temp_addr == NULL || is_kernel || temp_addr < (void*)8048000){
           exit(-1);
        } 
        if( !is_kernel){
            if(pagedir_get_page(pd,temp_addr) == NULL){
                exit(-1);
            }
        }
    }
}

static void syscall_handler (struct intr_frame *f ) {
    int arg[3];
    uint32_t *sp =f->esp;
    addr_validation((void*)sp);
    uint32_t number = *sp;
  
  switch(number) {
    case SYS_HALT :
        halt();
        break;
    case SYS_EXIT :
        argument_parser(sp, arg, 1);
        exit((int)arg[0]);
        break;
    case SYS_EXEC :
        argument_parser(sp, arg, 1);
        f->eax = exec((const char *)arg[0]);
        break;
    case SYS_WAIT :
        argument_parser(sp, arg, 1);
        f->eax = wait((pid_t)arg[0]);
        break;
    case SYS_CREATE :
        argument_parser(sp, arg, 2);
        f->eax = create((const char *)arg[0], (unsigned)arg[1]);
        break;
    case SYS_REMOVE :
        argument_parser(sp, arg, 1);
        f->eax = remove((const char *)arg[0]);
        break;
    case SYS_OPEN :
        argument_parser(sp, arg, 1);
        f->eax = open((const char *)arg[0]);
        break;
    case SYS_FILESIZE :
        argument_parser(sp, arg, 1);
        f->eax = filesize((int)arg[0]);
        break;
    case SYS_READ :
        argument_parser(sp, arg, 3);
        f->eax = read((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
        break;
    case SYS_WRITE :
        argument_parser(sp, arg, 3);
        f->eax = write((int)arg[0], (const void *)arg[1], (unsigned)arg[2]);
        break;
    case SYS_SEEK :
        argument_parser(sp, arg, 2);
        seek((int)arg[0], (unsigned)arg[1]);
        break;
    case SYS_TELL :
        argument_parser(sp, arg, 1);
        f->eax = tell((int)arg[0]);
        break;
    case SYS_CLOSE :
        argument_parser(sp, arg, 1);
        close((int)arg[0]);
        break;
    case SYS_SIGACTION :
        argument_parser(sp,arg,2);
        sigaction((int)arg[0],(void*)arg[1]);
        break;
    case SYS_SENDSIG :
        argument_parser(sp,arg,2);
        sendsig((pid_t)arg[0],(int)arg[1]);
        break;
    case SYS_YIELD :
        thread_yield(); 
        break;
    case SYS_MMAP :
        break;
    case SYS_MUNMAP :
        break;
    default :
        exit(-1);
  }
  
}


void halt(void){
    shutdown_power_off();
}

void exit(int status){
    struct thread * t = thread_current();
    printf("%s: exit(%d)\n",t->name,status);

    t->by_exit = 1;
    t->exit_status = status;
    thread_exit();
}

pid_t exec(const char *cmd_line){
    pid_t pid;
    addr_validation((void*)cmd_line);
    pid = process_execute(cmd_line);
    return pid;
}

int wait(pid_t pid){

    int returnval ;
    struct thread *child = get_child_process((int)pid);

    returnval = process_wait((tid_t) pid); 

    return returnval;

}

bool create(const char *file, unsigned initial_size)
{
    bool returnval;
    addr_validation((void *)file);
    lock_acquire(&filesys_lock);
    returnval = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return returnval;
}

bool remove(const char *file)
{
    bool returnval;
    addr_validation((void *)file);
    lock_acquire(&filesys_lock);
    returnval = filesys_remove(file);
    lock_release(&filesys_lock);
    return returnval;
}

int open(const char *file)
{
    int fd;
    struct thread *cur = thread_current();

    if (file == NULL) exit(-1);
    
    addr_validation((void *)file);
    lock_acquire(&filesys_lock);
    struct  file* new_file =  filesys_open (file); 
    if (new_file != NULL)
    {
        if (strcmp(cur->name, file) == 0)
        {
            file_deny_write(new_file);
        }
        fd = cur->next_fd;
        if(fd>FDT_SIZE){
            return -1;
        }
        cur->fdt[fd] = new_file;
    }
    else
    {
        fd = -1;
    }
    cur->next_fd++;
    lock_release(&filesys_lock);

    return fd;
}

int filesize(int fd)
{
    int returnval;
    struct thread *cur = thread_current();
    struct file *curfile = cur->fdt[fd];

    if (fd < 2 || fd > FDT_SIZE || curfile == NULL)
    {
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    returnval = (int)file_length(curfile);
    lock_release(&filesys_lock);

    return returnval;
}

int read(int fd, void *buffer, unsigned size)
{
    struct thread *cur = thread_current();
    struct file *curfile;
    int returnval = -1;

    if (fd < 0 || fd > FDT_SIZE)
    {
        exit(-1);
    }
    addr_validation((void *)buffer);
    lock_acquire(&filesys_lock);
    if (fd == 0)
    {
        for (returnval = 0; (unsigned int)returnval < size; returnval++)
        {
            if(input_getc() == '\0')
                break;
        }
    }
    else if (fd > 2)
    {
        curfile = cur->fdt[fd];
        if (curfile == NULL)
        {
            lock_release(&filesys_lock);
            exit(-1);
        }
        returnval = (int)file_read(curfile, buffer, size);
    }
    lock_release(&filesys_lock);

    return returnval;
}

int write(int fd, const void *buffer, unsigned size)
{
    struct thread *cur = thread_current();
    struct file *curfile;
    int retval = -1;

    if (fd < 0 || fd > FDT_SIZE)
    {
        exit(-1);
    }
    addr_validation((void *)buffer);
    lock_acquire(&filesys_lock);
    if (fd == 1)
    {
        putbuf(buffer, size);
        retval = size;
    }
    else if (fd > 2)
    {
        curfile = cur->fdt[fd];
        if (curfile == NULL)
        {
            lock_release(&filesys_lock);
            exit(-1);
        }
        retval = (int)file_write(curfile, buffer, size);
    }

    lock_release(&filesys_lock);

    return retval;
}

void seek(int fd, unsigned position)
{
    struct  file* file =  thread_current ()-> fdt [fd]; 
    file_seek (file, position); 
}

unsigned tell(int fd)
{
    struct  file* file =  thread_current ()-> fdt [fd]; 
    return  file_tell (file); 
}

void close(int fd)
{
    struct thread *cur = thread_current();

    if (fd < 3 || fd > FDT_SIZE || cur->fdt[fd] == NULL)
    {
        exit(-1);
    }
    lock_acquire(&filesys_lock);
    file_close(cur->fdt[fd]);
    cur->fdt[fd] = NULL;
    lock_release(&filesys_lock);
}

void sigaction(int signum, void(*handler)(void))
{
    struct thread *t = thread_current();
    t->sig[signum].SignalHandler = handler;
    t->sig[signum].num = signum;   
}

void sendsig(pid_t pid, int signum)
{
    int flag = 0;
    struct thread *t= find_thread((tid_t)pid);
    if( t->sig[signum].num == signum){ /* Signal recognised by kernel */
        //if(flag == 0) {printf("Signum: 1, Action: 0x80480a0\n"); flag++;} else{printf("Signum: 2, Action: 0x80480a1\n"); flag--;} /* For testing purposes */
        printf("Signum: %d, Action: %p\n",signum,t->sig[signum].SignalHandler); /* Print signum and signal */
    }    
}
void sched_yield(void)
{
    thread_yield();
}

