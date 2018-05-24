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
/*start lab3*/
#include "userprog/pagedir.h"
#include "lib/string.h"
#include "threads/vaddr.h"
/*end lab3*/

/*start lab1*/
void halt(void);
bool create(const char *file, unsigned initial_size);
int open(const char *file);
void close(int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
/*start lab1*/
/*start lab3*/
int exec(const char * cmd_line);
void exit (int status);
int wait(int pid);
void check_pointer(int *ptr);
void check_page(int *ptr);
void check_string(char *string);
void check_buffer(void *buff, unsigned size);
void check_fd(int fd);
/*end lab3*/
static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt(void){
  power_off();
}

bool create(const char *file, unsigned initial_size){
  bool success = filesys_create(file, initial_size);
  return success;
}

int open(const char *file){
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
    fd = fd_counter + 2; //+2 to avoid fd = STDIN or STDOUT
    if(DEBUG) printf("FD: %d\n",fd);
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

int read(int fd, void *buffer, unsigned size){
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
int exec(const char * cmd_line){
  if(DEBUG) printf("EXEC THREAD NAME + ID: %s + %d. LINE: %d\n",thread_current()->name, thread_current()->tid, __LINE__);
  int child_pid;
  child_pid = process_execute(cmd_line);
  if(DEBUG) printf("final exec child_pid: %d\n", child_pid);
  return child_pid;
}

void exit (int status){
  char *part, *save_ptr;
  for (part = strtok_r (thread_name(), " ", &save_ptr); part != NULL;
    part = strtok_r (NULL, " ", &save_ptr)) {
    printf("%s: exit(%d)\n", part, status);
    break;
   }
  thread_current()->report_card->exit_status = status;
  thread_exit();
}

int wait(int pid){
  if(DEBUG) printf("wait pid: %d\n", pid);
  int exit_status = process_wait(pid);
  if(DEBUG) printf("wait exit_status: %d\n", exit_status);
  return exit_status;
}

/*start lab3 HELP FUNCTIONS */

//Checks if stackptr is at user address (below PHYS_BASE)
//Above PHYS_BASE, the virtual address space belongs to the kernel
void check_pointer(int *ptr){
  if(!is_user_vaddr(ptr)){
    exit(-1);
  }
}

//Checks if page is in page table
void check_page(int *ptr){
  if(pagedir_get_page(thread_current()->pagedir, ptr) == NULL){
    exit(-1);
  }
}

//iterate over every char and check each pointer
void check_string(char *str){
  if (str == NULL){
    exit(-1);
  }
  int i = 0;
	while(true){
    check_pointer(str+i);
    check_page(str+i);
		if(*((char*)(str+i)) == '\0'){
      break;
    }
		i++;
	}
}

//Check that every pointer to the buffer is valid
void check_buffer(void *buff, unsigned size){
  if (buff == NULL){
    exit(-1);
  }
  int i;
  for(i = 0; i < size; i++){
    check_pointer(buff+i);
    check_page(buff+i);
  }
}

void check_fd(int fd){
  //Check if fd in fd_array
  if(fd < 0 || fd >= FD_MAX){
    exit(-1);
  }
  //check that fd is associated with file
  if(thread_current()->fd_array[fd-2] == NULL){
    exit(-1);
  }
}
/*end lab3 HELP FUNCTIONS */

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int * stackptr = f->esp;
  check_pointer(stackptr);
  check_page(stackptr);
  switch (*stackptr) {
    case SYS_HALT:
    {
      halt();
      break;
    }
    case SYS_CREATE:
    {
      check_pointer(stackptr[1]);
      check_pointer(stackptr[2]);
      check_page(stackptr[1]);
      check_string(stackptr[1]);
      const char *file = (const char*)stackptr[1];
      unsigned initial_size = (unsigned)stackptr[2];
      f->eax = create(file, initial_size);
      break;
    }
    case SYS_OPEN:
    {
      check_pointer(stackptr[1]);
      check_page(stackptr[1]);
      check_string(stackptr[1]);
      const char *file = (const char*)stackptr[1];
      f->eax = open(file);
      break;
    }
    case SYS_CLOSE:
    {
      check_pointer(stackptr[1]);
      int fd = (int)stackptr[1];
      check_fd(fd);
      //sys_close check that fd != console output stream
      if (fd == STDOUT_FILENO){
        exit(-1);
      }
      close(fd);
      break;
    }
    case SYS_READ:
    {
      check_pointer(stackptr[1]);
      check_pointer(stackptr[2]);
      check_pointer(stackptr[3]);
      check_page(stackptr[2]);
      check_buffer(stackptr[2], stackptr[3]);
      int fd = (int)stackptr[1];
      check_fd(fd);
      void * buffer = (void*)stackptr[2];
      unsigned size = (unsigned)stackptr[3];
      f->eax = read(fd, buffer, size);
      break;
    }
    case SYS_WRITE:
    {
      check_pointer(stackptr[1]);
      check_pointer(stackptr[2]);
      check_pointer(stackptr[3]);
      check_page(stackptr[2]);
      check_buffer(stackptr[2], stackptr[3]);
      int fd = (int)stackptr[1];
      check_fd(fd);
      const void * buffer = (const void*)stackptr[2];
      unsigned size = (unsigned)stackptr[3];
      f->eax = write(fd, buffer, size);
      break;
    }
    case SYS_EXEC:
    {
      check_pointer(stackptr[1]);
      check_page(stackptr[1]);
      check_string(stackptr[1]);
      const char * cmd_line = (const char*)stackptr[1];
      f->eax = exec(cmd_line);
      break;
    }
    case SYS_EXIT:
    {
      check_pointer(stackptr[1]);
      int status = (int)stackptr[1];
      exit(status);
      break;
    }
    case SYS_WAIT:
    {
      check_pointer(stackptr[1]);
      int pid = (int)stackptr[1];
      f->eax = wait(pid);
      break;
    }
  }
}
