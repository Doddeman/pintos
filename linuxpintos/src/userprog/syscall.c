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

static void syscall_handler (struct intr_frame *);

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
  for(fd_counter = 2; fd_counter < FD_MAX; fd_counter++){
    if(current_thread()->fd_array[fd_counter] == NULL){
      break;
    }
  }
  if(fd_counter >= FD_MAX){ //fd_array full
    fd = -1;
  }
  else{ //assign file to fd
    current_thread()->fd_array[fd_counter] = filesys_open(file);
    fd = fd_counter;
  }
  //check if file opened
  if(current_thread()->fd_array[fd_counter] == NULL){
    fd = -1;
  }
  return fd;
}

void close(int fd){
  struct file * file = current_thread()->fd_array[fd];
  file_close(file);
  current_thread()->fd_array[fd] = NULL;
}

int read (int fd, void *buffer, unsigned size){
  off_t bytes;
  struct file * file = current_thread()->fd_array[fd];
  bytes = file_read(file, buffer, size);

  if(fd == STDIN_FILENO){ //if STDIN
    int input;
    for(input = size; input > 0; input--){
      input_getc();
    }
    return size;
  }

  if(file == NULL){ //does file exist?
    return -1;
  }
  else{
    return bytes;
  }
}

int write (int fd, const void *buffer, unsigned size){
  off_t bytes;
  struct file * file = current_thread()->fd_array[fd];
  bytes = file_write (file, buffer, size);

  if(fd == STDOUT_FILENO){
    putbuf(buffer, size);
  }

  if(file->deny_write){ //if could not write
    return -1;
  }
  else{
    return bytes;
  }

}

void exit (int status){
  printf("Exiting thread %s\n",current_thread->name);
  printf("Exit status: %d\n",status);
  thread_exit();
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int * stackptr = f->esp;

  printf ("system call!\n");

  switch (*stackptr) {
    case SYS_HALT:
      printf ("halter\n");
      halt();
      break;
    case SYS_CREATE:
      printf("creater\n");
      const char *file = stackptr[1];
      unsigned initial_size = stackptr[2];
      create(file, initial_size);
      break;
    case SYS_OPEN:
      printf("opener\n");
      const char *file = stackptr[1];
      open(file);
      break;
    case SYS_CLOSE:
      printf("closer\n");
      int fd = stackptr[1];
      close(fd);
      break;
    case SYS_READ:
      printf("reader\n");
      int fd = stackptr[1];
      void * buffer = stackptr[2];
      unsigned size = stackptr[3];
      read(fd, buffer, size);
      break;
    case SYS_WRITE:
      printf("writer\n");
      int fd = stackptr[1];
      const void * buffer = stackptr[2];
      unsigned size = stackptr[3];
      write(fd, buffer, size);
      break;
    case SYS_EXIT:
      printf("exiter\n");
      break;

  }

}
