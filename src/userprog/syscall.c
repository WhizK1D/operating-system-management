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
    }
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

int open(const char* file)
{
  acquire_file_lock();

  release_file_lock();
}

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

int get_file_size(int fd)
{
  /* Implement get file size */
  return -1;
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
        break;

    case SYS_CREATE:
        /* Implement SYS_CREATE */
        break;

    case SYS_READ:
        /* Implement SYS_READ */
        break;

    case SYS_CLOSE:
        /* Implement SYS_CLOSE */
        break;

    case SYS_TELL:
        /* Implement SYS_TELL */
        break;

    case SYS_SEEK:
        /* Implement SYS_SEEK */
        break;

    case SYS_REMOVE:
        /* Implement SYS_REMOVE */
        break;
  }

  thread_exit ();
}
