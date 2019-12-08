#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
void get_argument_address(struct intr_frame *f, int *arg_ptr, int arg_count);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/** HELPER SECTION:
 * Helper methods defined here to implement different system calls
 */

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};


/* Simple helper to check the validity of address */
void check_address (const void *address)
{
  if (!is_user_vaddr(address))
  {
    exit(-1);
  }
}

/* Simple helper to check validity of a buffer */
void check_buffer(void* buffer, unsigned size)
{
  int i;
  char* temp = (char *) buffer;

  /* Check address validity of each item in the buffer */
  for (i = 0; i < size; i++)
  {
    check_address((const void*) temp);
    temp++;
  }
}

struct process_file *search_files(struct list* files, int fd)
{
  struct list_elem *elem;

  for(elem = list_begin(files); elem != list_end(files);
      elem = list_next(elem))
      {
        struct process_file *file_ptr = list_entry(elem,
            struct process_file, elem);

        if(file_ptr -> fd == fd)
        {
          return file_ptr;
        }
      }
  return NULL;
}

int process_add_files(struct file *f)
{
  struct process_file *pf = malloc(sizeof(struct process_file));

  pf -> file = f;
  pf -> fd = thread_current() ->fd;
  thread_current() -> fd++;
  list_push_back(&thread_current() -> file_list, &pf -> elem);
  return pf -> fd;
}
/* Exit implementation required for sys calls */
void exit(int status)
{
  struct list_elem *i;

  for (i = list_begin(&thread_current()->parent->child_processes);
        i != list_end (&thread_current()->parent->child_processes);
        i = list_next (i))
    {
      struct child *c = list_entry(i, struct child, elem);
      if(c -> tid == thread_current() -> tid)
      {
        c -> alive = false;
        c -> exit_code = status;
      }

      thread_current() -> exit_code = status;

      int wait_id = thread_current() -> parent -> wait_child_id;

      if (wait_id == thread_current() -> tid)
      {
        sema_up(&thread_current() -> parent -> child_lock);
      }
      thread_exit();
      printf("Exit() done\n");
    }
}

int execute(const char *file)
{
  acquire_file_lock();

  char *save_ptr, *cmd;

  char *cmd_line = malloc(strlen(file) + 1);
  strlcpy(cmd_line, file, strlen(file) + 1);
  cmd = strtok_r(cmd_line, " ", &save_ptr);
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

int open(const char* file)
{
  acquire_file_lock();

  struct file *f = filesys_open(file);

  if(!f)
  {
    release_file_lock();
    return -1;
  }

  int fd = process_add_files(f);
  release_file_lock();
  return fd;
}

bool create(const char *file, unsigned initial_size)
{
  bool ret;
  acquire_file_lock();
  ret = filesys_create(file, initial_size);
  release_file_lock();
  return ret;
}

int read_buffer(int fd, const void *buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
  {
    int i;
    uint8_t* buf = buffer;
    for (i = 0; i < size; i++)
    {
      buf[i] = input_getc();
    }
    return size;
  }
  else
  {
    int byte_count;

    struct process_file* file_ptr = search_files(&thread_current()->file_list, fd);
    if(file_ptr == NULL)
    {
      return -1;
    }
    else
    {
      acquire_file_lock();
      byte_count = file_read(file_ptr -> file, buffer, size);
      release_file_lock();
    }
    return byte_count;
  }
}

int get_file_size(int fd)
{
  /* TODO: Implement get file size */

  acquire_file_lock();

  struct file *f = process_get_file(fd);
  if(!f)
  {
    release_file_lock();
    return -1;
  }

  int file_size = file_length(f);
  release_file_lock();
  return file_size;
}

unsigned tell(int fd)
{
  acquire_file_lock();

  struct process_file* file_ptr = search_files(&(thread_current() -> file_list), fd);
  int ret = file_tell(file_ptr -> file);
  release_file_lock();
  return ret;
}

void close_file(int fd)
{
  struct list_elem *e;
  struct list *files = &thread_current()->file_list;
  while(!list_empty(files))
  {
    e = list_pop_front(files);
    struct process_file *file_ptr = list_entry (e, struct process_file, elem);
    if(file_ptr->fd == fd || fd == -1)
    {
      file_close(file_ptr->file);
      list_remove(e);
    }
    free(file_ptr);
  }
}

void seek(int fd, unsigned position)
{
  acquire_file_lock();

  struct process_file* file_ptr = search_files(&(thread_current() -> file_list), fd);
  file_seek(file_ptr -> file, position);
  release_file_lock();
}

bool remove(const char *file)
{
  return filesys_remove(file);
}

void get_argument_address(struct intr_frame *f, int *arg_ptr, int arg_count)
{
  /* For each add pointed by esp check and add as
      pointer to a argument */
  for (int i = 0; i < arg_count; i++)
  {
    int *ptr = (int *) f->esp + i + 1;
    check_address((const void*) ptr);
    arg_ptr[i] = ptr;
  }
}

struct file *process_get_file(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *f;

  for (f = list_begin(t -> file_list);
        f != list_end(t -> file_list);
        f = list_next(f))
        {
          struct process_file *pf = list_entry(f, struct process_file, elem);

          if (fd == pf -> fd)
          {
            return pf -> file;
          }
        }
  return NULL;
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int * address = f->esp;

  // Before performing operations, check if the address exists
  check_address((const void*)address);
  void *esp_ptr;

  // Check if the pointer esp pointer to handler is not null
  esp_ptr = pagedir_get_page(thread_current()->pagedir, address);
  if (!esp_ptr)
  {
    exit(-1);
  }

  int args[5]; /* Array of arguments */

  int *sys_call_id = address; /* ID to identify system call */
  void *page_ptr;

  /* TODO: Switch case to follow for following system calls:
    Reference: http://web.stanford.edu/~ouster/cgi-bin/cs140-winter13/pintos/pintos_3.html#SEC45
    - SYS_HALT
    - SYS_EXIT
    - SYS_OPEN
    - SYS_READ
    - SYS_WRITE
    - SYS_EXEC
    - SYS_CLOSE
    - SYS_CREATE
    - SYS_WAIT
    - SYS_FILESIZE
    - SYS_SEEK
    - SYS_TELL
    - SYS_REMOVE
  */

  /* Note the break for each case */
  switch(*sys_call_id)
  {
    case SYS_HALT:
        shutdown_power_off();
        break;

    case SYS_EXIT:
        get_argument_address(f, &args, 1);
        check_address((void*) args[0]); /* Redundant check to be safe */
        exit(args[0]);
        break;

    case SYS_WAIT:
        /* Implement SYS_WAIT */
        get_argument_address(f, &args, 1);
        check_address((void*) args[0]); /* Redundant check to be safe */
        f -> eax = wait(args[0]);
        break;

    case SYS_OPEN:
        /* Implement SYS_OPEN */
        get_argument_address(f, &args, 1);
        check_address((void*) args[0]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if (!page_ptr)
        {
          exit(-1);
        }
        else
        {
          f -> eax = open((const void*) args[0]);
        }
        break;

    case SYS_WRITE:
        /* Implement SYS_WRITE */
        break;

    case SYS_FILESIZE:
        /* Implement SYS_FILESIZE */
        get_argument_address(f, &args[0], 1);
        check_address((void *) args[0]);
        f -> eax = get_file_size(args[0]);
        break;

    case SYS_EXEC:
        /* Implement SYS_EXEC */
        get_argument_address(f, &args[0], 1);
        // check_address((void*) args[0]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if (page_ptr == NULL)
        {
          exit(-1);
        }

        f -> eax = execute(args[0]);
        break;

    case SYS_CREATE:
        /* Implement SYS_CREATE */
        get_argument_address(f, &args[0], 2);
        check_buffer((void *) args[0], (unsigned) args[0]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if(!page_ptr)
        {
          exit(-1);
        }

        f -> eax = create(args[0], (unsigned) args[1]);
        break;

    case SYS_READ:
        /* Implement SYS_READ */
        get_argument_address(f, &args[0], 3);
        check_buffer((void *) args[0], (unsigned) args[0]);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if(!page_ptr)
        {
          exit(-1);
        }

        f -> eax = read_buffer(args[0], args[1], args[2]);
        break;

    case SYS_CLOSE:
        /* Implement SYS_CLOSE */
        get_argument_address(f, &args[0], 1);
        check_address((void*) args[0]);

        f -> eax = close_file(args[0]);
        break;

    case SYS_TELL:
        /* Implement SYS_TELL */
        get_argument_address(f, &args[0], 1);
        check_address((void*) args[0]);

        f -> eax = tell(args[0]);
        break;

    case SYS_SEEK:
        /* Implement SYS_SEEK */
        get_argument_address(f, &args[0], 2);
        seek(args[0], (unsigned) args[1]);
        break;

    case SYS_REMOVE:
        /* Implement SYS_REMOVE */
        get_argument_address(f, &args[0], 1);
        page_ptr = pagedir_get_page(thread_current() -> pagedir, args[0]);

        if(!page_ptr)
        {
          exit(-1);
        }

        acquire_file_lock();

        f -> eax = remove(args[0]);

        release_file_lock();
        break;

    default: break;
  }

  thread_exit ();
}
