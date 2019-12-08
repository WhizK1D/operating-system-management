#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <user/syscall.h>
#define CLOSE_ALL -1

static void syscall_handler (struct intr_frame *);
static void check_address(const void *addr);
static void check_buffer(void * buf, unsigned size);
struct file* proc_get_file(int fd);
int proc_add_file(struct file *f);
struct process_file* search_file(struct list* files, int fd);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int * address = f -> esp;
  int args[5];
  void *esp_ptr, *page_ptr;
  check_address((const void*) address);
  esp_ptr = pagedir_get_page(thread_current() -> pagedir, address);

  if (!esp_ptr)
  {
    exit(-1);
  }

  int *sys_call = address;

  switch(*sys_call)
  {
    case SYS_HALT:
        shutdown_power_off();
        break;

    case SYS_EXIT:
        get_argument_address(f, &args, 1);
        check_address((void*) args[0]);
        exit(args[0]);
        break;

    case SYS_WAIT:
        get_argument_address(f, &args, 1);
        check_address((void *) args[0]);
        f -> eax = wait(args[0]);
        break;

    case SYS_OPEN:
        get_argument_address(f, &args, 1);
        check_address((void*) args[0]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir,
            args[0]);

        if (!page_ptr)
        {
          exit(-1);
        }

        f -> eax = open((const void *) args[0]);
        break;

    case SYS_WRITE:
        get_argument_address(f, &args[0], 3);
        check_buffer((void *) args[1], (unsigned) args[2]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[1]);

        if (!page_ptr)
        {
          exit(-1);
        }

        f -> eax = write_file(args[0], (const void *) args[1], (unsigned) args[2]);
        break;

    case SYS_FILESIZE:
        get_argument_address(f, &args, 1);
        check_address((void *) args[0]);
        f -> eax = check_filesize(args[0]);
        break;

    case SYS_EXEC:
        get_argument_address(f, &args[0], 1);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if (page_ptr == NULL)
        {
          exit(-1);
        }

        f -> eax = execute(args[0]);
        break;

    case SYS_CREATE:
        get_argument_address(f, &args[0], 2);
        check_buffer((void *) args[0], (unsigned) args[1]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if (!page_ptr)
        {
          exit(-1);
        }

        f -> eax = create(args[0], (unsigned) args[1]);
        break;

    case SYS_READ:
        get_argument_address(f, &args[0], 3);
        check_buffer((void*) args[1], (unsigned) args[2]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[1]);

        if (!page_ptr)
        {
          exit(-1);
        }

        f -> eax = read(args[0], args[1], args[2]);
        break;

    case SYS_CLOSE:
        get_argument_address(f, &args[0], 1);
        check_address((void*) args[0]);
        f -> eax = close_file(args[0]);
        break;

    case SYS_TELL:
        get_argument_address(f, &args[0], 1);
        check_address((void *) args[0]);
        f -> eax = tell(args[0]);
        break;

    case SYS_SEEK:
        get_argument_address(f, &args[0], 2);
        seek(args[0], (unsigned) args[1]);
        break;

    case SYS_REMOVE:
        get_argument_address(f, &args[0], 1);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if (!page_ptr)
        {
          exit(-1);
        }

        acquire_file_lock();

        f -> eax = remove(args[0]);

        release_file_lock();
        break;

    default: break;
  }
}

/* syscall helper functions/structures here */
struct process_file
{
  struct file *file;
  int fd;
  struct list_elem elem;
};

void check_address(const void *address)
{
  if (!is_user_vaddr(address))
  {
    exit(-1);
  }
}

void check_buffer(void* buf, unsigned size)
{
  char* temp = (char *) buf;

  for(int i = 0; i < size; i++)
  {
    check_address((const void *) temp);
    temp++;
  }
}

void get_argument_address(struct intr_frame *frame,
  int *arg_ptr, int arg_count)
{
  int *temp;

  for(int i = 0; i < arg_count; i++)
  {
    temp = (int *) frame -> esp + i + 1;
    check_address((const void *) temp);
    arg_ptr[i] = *temp;
  }
}

struct file *proc_get_file(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *i;

  for(i = list_begin(&t -> file_list);
      i != list_end(&t -> file_list);
      i = list_next(i))
  {
    struct process_file *pf = list_entry(i, struct process_file, elem);

    if (fd == pf -> fd)
    {
      return pf -> file;
    }
  }

  return NULL;
}

int proc_add_file(struct file *f)
{
  struct process_file *pf = malloc(sizeof(struct process_file));

  pf -> file = f;
  pf -> fd = thread_current() -> fd;
  thread_current() -> fd++;
  list_push_back(&thread_current() -> file_list, &pf -> elem);
  return pf -> fd;
}

struct process_file *search_file(struct list* files, int fd)
{
  struct list_elem *i;

  for(i = list_begin(files);
      i != list_end(files);
      i = list_next(i))
      {
        struct process_file *pf = list_entry(i, struct process_file, elem);

        if (pf -> fd == fd)
        {
          return pf;
        }
      }
  return NULL;
}
/* syscall helper functions end */

/* New syscall functions here */
void exit(int exit_code)
{
  struct list_elem *i;

  for(i = list_begin(&thread_current() -> parent -> child_processes);
      i != list_end(&thread_current() -> parent -> child_processes);
      i = list_next(i))
      {
        struct child *c = list_entry(i, struct child, elem);

        if (c -> tid == thread_current() -> tid)
        {
          c -> alive = false;
          c -> exit_code = exit_code;
        }
      } // End of for-loop

  thread_current() -> exit_code = exit_code;

  if (thread_current() -> parent -> wait_child_id == thread_current() -> tid)
  {
    sema_up(&thread_current() -> parent -> child_lock);
  }

  thread_exit();
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

/* open() syscall that returns the FD for opened file */
int open(const char *file)
{
  acquire_file_lock();

  struct file *f = filesys_open(file);

  if(!f)
  {
    release_file_lock();
    return -1;
  }

  int fd = proc_add_file(f);
  release_file_lock();
  return fd;
}

/* write() syscall that returns no of bytes written to file */
int write_file(int fd, const void *buf, unsigned size)
{
  if(fd == STDOUT_FILENO)
  {
    putbuf(buf, size);
    return size;
  }

  acquire_file_lock();

  struct process_file* pf = search_file(&thread_current() -> file_list, fd);

  if(pf == NULL)
  {
    release_file_lock();
    return -1;
  }

  int byte_count = file_write(pf -> file, buf, size);
  release_file_lock();

  return byte_count;
}

/* SYS_FILESIZE that returns the size of the file as int */
int check_filesize(int fd)
{
  acquire_file_lock();

  struct file *f = proc_get_file(fd);

  if (!f)
  {
    release_file_lock();
    return -1;
  }

  int file_size = file_length(f);
  release_file_lock();

  return file_size;
}

/* SYS_EXEC that returns the return code from process_execute() */
int execute(const char *file)
{
  acquire_file_lock();

  char *save, *cmd;
  char *cmd_line = malloc(strlen(file) + 1);
  strlcpy(cmd_line, file, strlen(file) + 1);
  cmd = strtok_r(cmd_line, " ", &save);

  struct file *f = filesys_open(cmd);

  if(f == NULL)
  {
    release_file_lock();
    return -1;
  }
  else
  {
    file_close(f);
    release_file_lock();
    return process_execute(file);
  }
}

/* SYS_CREATE that returns whether creation was successful or not */
bool create(const char *file, unsigned size)
{
  bool ret;
  acquire_file_lock();

  ret = filesys_create(file, size);
  release_file_lock();

  return ret;
}

int read(int fd, void *buf, unsigned size)
{
  /* If input is from STDIN then read specified no of bytes */
  if (fd == STDIN_FILENO)
  {
    int i;
    uint8_t* temp_buf = buf;

    for(i = 0; i < size; i++)
    {
      temp_buf[i] = input_getc();
    }
    return size;
  }
  else
  {
    /* If input is valid file then return the bytes read */
    int byte_count;

    struct process_file* pf = search_file(&thread_current() -> file_list, fd);

    if(pf == NULL)
    {
      return -1;
    }
    else
    {
      acquire_file_lock();

      byte_count = file_read(pf -> file, buf, size);
      release_file_lock();
    }
    return byte_count;
  }
}

void close_file(int fd)
{
  struct list_elem *i;
  struct list *file_list = &thread_current() -> file_list;
  while (!list_empty(file_list))
  {
    i = list_pop_front(file_list);
    struct process_file *pf = list_entry(i, struct process_file, elem);

    /* If file matches and exists then close file and remove from list */
    if(pf -> fd == fd || fd == -1)
    {
      file_close(pf -> file);
      list_remove(i);
    }

    free(pf);
  }
}

unsigned tell(int fd)
{
  acquire_file_lock();

  struct process_file* pf = search_file(&thread_current() -> file_list, fd);
  int ret = file_tell(pf -> file);
  release_file_lock();

  return ret;
}

/* If the file exists move the file pointer to the specified position */
void seek(int fd, unsigned position)
{
  acquire_file_lock();

  struct process_file* pf = search_file(&thread_current() -> file_list, fd);
  file_seek(pf -> file, position);

  release_file_lock();
}

/* Return whether SYS_REMOVE was successful */
bool remove(const char *file)
{
  return filesys_remove(file);
}
/* End of syscall functions */