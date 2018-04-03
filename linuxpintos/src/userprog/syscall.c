#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
//#include process.c
/*Lab3 start*/
#include "userprog/pagedir.h"
/*Lab3 end*/

static void syscall_handler (struct intr_frame *);

static bool DEBUG = true;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt(void){
  power_off();
}

bool create (const char *file, unsigned initial_size){
  bool success = filesys_create(file, initial_size);
  return success;
}

int open (const char *file){
  int fd;
  int fd_counter;
  for(fd_counter = 0; fd_counter < FD_MAX; fd_counter++){
    if(thread_current()->fd_array[fd_counter] == NULL){
      break;
    }
  }
  if(fd_counter >= FD_MAX){ //fd_array full
    fd = -1;
  }
  else{ //assign file to fd
    thread_current()->fd_array[fd_counter] = filesys_open(file);
    fd = fd_counter + 2; //+2 to avoid fd = STDIN or STDIOUT
  }
  //check if file opened
  if(thread_current()->fd_array[fd_counter] == NULL){
    fd = -1;
  }
  return fd;
}

void close(int fd){
  struct file * file = thread_current()->fd_array[fd-2];
  file_close(file);
  thread_current()->fd_array[fd-2] = NULL;
}

int read (int fd, void *buffer, unsigned size){
  off_t bytes;

  if(fd == STDIN_FILENO){ //if STDIN (0)
    int input;
    for(input = size; input > 0; input--){
      input_getc();
    }
    return size;
  }
  if (fd == STDOUT_FILENO){ //if STDOUT (1). should not happen
    return -1;
  }
  struct file * file = thread_current()->fd_array[fd-2];
  if(file == NULL){ //does file exist?
    return -1;
  }
  else{
    bytes = file_read(file, buffer, size);
    return bytes;
  }
}

int write (int fd, const void *buffer, unsigned size){
  off_t bytes;

  if(fd == STDOUT_FILENO){ //if STDOUT (1)
    putbuf(buffer, size);
    return size;
  }
  struct file * file = thread_current()->fd_array[fd-2];
  if(file == NULL){ //if could not write
    return -1;
  }
  else{ //write to file and return bytes written
    bytes = file_write (file, buffer, size);
    return bytes;
  }
}

//will return -1 if TID_ERROR
pid_t exec(const char * cmd_line){
  if (pagedir_get_page(thread_current()->pagedir, cmd_line)){
    pid_t child_pid = process_execute(cmd_line);
  }
  else{
    pid_t child_pid = -1;
  }
  if(DEBUG) printf("final exec child_pid: %d\n", child_pid);
  return child_pid;
}

void exit (int status){
  if(DEBUG) printf("Exiting thread %s\n",thread_name());
  if(DEBUG) printf("Exit status: %d\n",status);

  thread_current()->report_card->exit_status = status;

  thread_exit();
}

int wait(pid_t pid){

}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int * stackptr = f->esp;
  switch (*stackptr) {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_CREATE:
    {
      const char *file = stackptr[1];
      unsigned initial_size = stackptr[2];
      f->eax = create(file, initial_size);
      break;
    }
    case SYS_OPEN:
    {
      const char *file = stackptr[1];
      f->eax = open(file);
      break;
    }
    case SYS_CLOSE:
    {
      int fd = stackptr[1];
      close(fd);
      break;
    }
    case SYS_READ:
    {
      int fd = stackptr[1];
      void * buffer = stackptr[2];
      unsigned size = stackptr[3];
      f->eax = read(fd, buffer, size);
      break;
    }
    case SYS_WRITE:
    {
      int fd = stackptr[1];
      const void * buffer = stackptr[2];
      unsigned size = stackptr[3];
      f->eax = write(fd, buffer, size);
      break;
    }
    case SYS_EXEC:
    {
      const char * cmd_line = stackptr[1];
      f->eax = exec(cmd_line);
      break;
    }
    case SYS_EXIT:
    {
      int status = stackptr[1];
      exit(status);
      break;
    }
    case SYS_WAIT:
    {
      int pid = stackptr[1];
      f->eax = wait(pid);
      break;
    }
  }
}
