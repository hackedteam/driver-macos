/*
 *  task_internal.h
 *  mchook
 *
 *  Created by revenge on 9/23/10.
 *  Copyright 2010 HT srl. All rights reserved.
 *
 */

#define queue_first(q)    ((q)->next)
#define queue_next(qc)    ((qc)->next)
#define queue_end(q, qe)  ((q) == (qe))

struct queue_entry {
  struct queue_entry  *next;    /* next element */
  struct queue_entry  *prev;    /* previous element */
};

typedef	struct queue_entry *queue_entry_t;
typedef struct queue_entry queue_chain_t;
typedef struct queue_entry queue_head_t;

//extern queue_head_t   tasks;

/*
 * Common storage for exception actions.
 * There are arrays of these maintained at the activation, task, and host.
 */
struct exception_action {
  struct ipc_port		*port;		/* exception port */
  thread_state_flavor_t	flavor;		/* state flavor to send */
  exception_behavior_t	behavior;	/* exception type to raise */
  boolean_t		privileged;	/* survives ipc_task_reset */
};

/*
 * Real segment descriptor.
 */
struct real_descriptor {
  uint32_t  limit_low:16, /* limit 0..15 */
            base_low:16,  /* base  0..15 */
            base_med:8,   /* base  16..23 */
            access:8,     /* access byte */
            limit_high:4, /* limit 16..19 */
            granularity:4,/* granularity */
            base_high:8;  /* base 24..31 */
};

struct user_ldt {
  unsigned int start;   /* first descriptor in table */
  unsigned int count;   /* how many descriptors in table */
  struct real_descriptor ldt[0]; /* descriptor table (variable) */
};

#define	MAC_MAX_SLOTS	7

struct label {
  int l_flags;
  union {
    void  *l_ptr;
    long   l_long;
  } l_perpolicy[MAC_MAX_SLOTS];
};

typedef struct ipc_labelh
{
  natural_t         lh_references;
  int               lh_type;
  struct label      lh_label;
  ipc_port_t        lh_port;
  //decl_lck_mtx_data(, lh_lock_data)
  uint32_t lh_lock_data[1];
} *ipc_labelh_t; 


#define MACHINE_TASK \
        struct user_ldt *i386_ldt; \
        void*       task_debug;

#define TASK_PORT_REGISTER_MAX	3

#define task_lock(task)         lck_mtx_lock(&(task)->lock)
#define task_unlock(task)       lck_mtx_unlock(&(task)->lock)

struct task {
  /* Synchronization/destruction information */
  //decl_lck_mtx_data(,lock)		/* Task's lock */
  //lck_mtx_t   *lock;
  uint32_t    lock;
  uint32_t    pad_lock; // leopard/snow padding

  uint32_t	ref_count;	/* Number of references to me */
  boolean_t	active;		/* Task has not been terminated */
  boolean_t	halting;	/* Task is being halted */

  /* Miscellaneous */
  vm_map_t	map;		/* Address space description */
  
  uint32_t pad_tasks; // snow leopard padding
  
  queue_chain_t	tasks;	/* global list of tasks */
  void		*user_data;	/* Arbitrary data settable via IPC */

  /* Threads in this task */
  queue_head_t		threads;

  processor_set_t		pset_hint;
  struct affinity_space	*affinity_space;
  
  int			thread_count;
  uint32_t		active_thread_count;
  int			suspend_count;	/* Internal scheduling only */

  /* User-visible scheduling information */
  integer_t		user_stop_count;	/* outstanding stops */

  task_role_t		role;

  integer_t		priority;			/* base priority for threads */
  integer_t		max_priority;		/* maximum priority for threads */

  /* Task security and audit tokens */
  security_token_t sec_token;
  audit_token_t	audit_token;

  /* Statistics */
  uint64_t		total_user_time;	/* terminated threads only */
  uint64_t		total_system_time;

  /* Virtual timers */
  uint32_t		vtimers;

  /* IPC structures */
  //decl_lck_mtx_data(,itk_lock_data)
  uint32_t itk_lock_data[1];
  struct ipc_port *itk_self;	/* not a right, doesn't hold ref */
  struct ipc_port *itk_nself;	/* not a right, doesn't hold ref */
  struct ipc_port *itk_sself;	/* a send right */
  struct exception_action exc_actions[EXC_TYPES_COUNT];
  /* a send right each valid element  */
  struct ipc_port *itk_host;	/* a send right */
  struct ipc_port *itk_bootstrap;	/* a send right */
  struct ipc_port *itk_seatbelt;	/* a send right */
  struct ipc_port *itk_gssd;	/* yet another send right */
  struct ipc_port *itk_task_access; /* and another send right */ 
  struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
  /* all send rights */

  struct ipc_space *itk_space;

  /* Synchronizer ownership information */
  queue_head_t	semaphore_list;		/* list of owned semaphores   */
  queue_head_t	lock_set_list;		/* list of owned lock sets    */
  int		semaphores_owned;	/* number of semaphores owned */
  int 		lock_sets_owned;	/* number of lock sets owned  */

  /* Ledgers */
  struct ipc_port	*wired_ledger_port;
  struct ipc_port *paged_ledger_port;
  unsigned int	priv_flags;			/* privilege resource flags */
#define VM_BACKING_STORE_PRIV	0x1
  
  MACHINE_TASK
  
  integer_t faults;              /* faults counter */
  integer_t pageins;             /* pageins counter */
  integer_t cow_faults;          /* copy on write fault counter */
  integer_t messages_sent;       /* messages sent counter */
  integer_t messages_received;   /* messages received counter */
  integer_t syscalls_mach;       /* mach system call counter */
  integer_t syscalls_unix;       /* unix system call counter */
  uint32_t  c_switch;			   /* total context switches */
  uint32_t  p_switch;			   /* total processor switches */
  uint32_t  ps_switch;		   /* total pset switches */
  //#ifdef  MACH_BSD
  uint32_t  pad1;
  uint32_t  pad2;
  
  void *bsd_info;
  //#endif
  struct vm_shared_region		*shared_region;
  uint32_t taskFeatures[2];		/* Special feature for this task */
#define tf64BitAddr	0x80000000		/* Task has 64-bit addressing */
#define tf64BitData	0x40000000		/* Task has 64-bit data registers */
#define task_has_64BitAddr(task)	\
        (((task)->taskFeatures[0] & tf64BitAddr) != 0)
#define task_set_64BitAddr(task)	\
        ((task)->taskFeatures[0] |= tf64BitAddr)
#define task_clear_64BitAddr(task)	\
        ((task)->taskFeatures[0] &= ~tf64BitAddr)
  
  mach_vm_address_t	all_image_info_addr; /* dyld __all_image_info     */
  mach_vm_size_t		all_image_info_size; /* section location and size */
#if CONFIG_MACF_MACH
  ipc_labelh_t label;
#endif
  
  //#if CONFIG_COUNTERS
#define TASK_PMC_FLAG 0x1	/* Bit in "t_chud" signifying PMC interest */
  uint32_t t_chud;		/* CHUD flags, used for Shark */
  //#endif
};

struct task_l {
  /* Synchronization/destruction information */
  //decl_lck_mtx_data(,lock)		/* Task's lock */
  //lck_mtx_t   *lock;
  uint32_t    lock;
  uint32_t    pad_lock; // leopard/snow padding
  
  uint32_t	ref_count;	/* Number of references to me */
  boolean_t	active;		/* Task has not been terminated */
  boolean_t	halting;	/* Task is being halted */
  
  /* Miscellaneous */
  vm_map_t	map;		/* Address space description */
  
  queue_chain_t	tasks;	/* global list of tasks */
  void		*user_data;	/* Arbitrary data settable via IPC */
  
  /* Threads in this task */
  queue_head_t		threads;
  
  processor_set_t		pset_hint;
  struct affinity_space	*affinity_space;
  
  int			thread_count;
  uint32_t		active_thread_count;
  int			suspend_count;	/* Internal scheduling only */
  
  /* User-visible scheduling information */
  integer_t		user_stop_count;	/* outstanding stops */
  
  task_role_t		role;
  
  integer_t		priority;			/* base priority for threads */
  integer_t		max_priority;		/* maximum priority for threads */
  
  /* Task security and audit tokens */
  security_token_t sec_token;
  audit_token_t	audit_token;
  
  /* Statistics */
  uint64_t		total_user_time;	/* terminated threads only */
  uint64_t		total_system_time;
  
  /* Virtual timers */
  uint32_t		vtimers;
  
  /* IPC structures */
  //decl_lck_mtx_data(,itk_lock_data)
  uint32_t itk_lock_data[1];
  struct ipc_port *itk_self;	/* not a right, doesn't hold ref */
  struct ipc_port *itk_nself;	/* not a right, doesn't hold ref */
  struct ipc_port *itk_sself;	/* a send right */
  struct exception_action exc_actions[EXC_TYPES_COUNT];
  /* a send right each valid element  */
  struct ipc_port *itk_host;	/* a send right */
  struct ipc_port *itk_bootstrap;	/* a send right */
  struct ipc_port *itk_seatbelt;	/* a send right */
  struct ipc_port *itk_gssd;	/* yet another send right */
  struct ipc_port *itk_task_access; /* and another send right */ 
  struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
  /* all send rights */
  
  struct ipc_space *itk_space;
  
  /* Synchronizer ownership information */
  queue_head_t	semaphore_list;		/* list of owned semaphores   */
  queue_head_t	lock_set_list;		/* list of owned lock sets    */
  int		semaphores_owned;	/* number of semaphores owned */
  int 		lock_sets_owned;	/* number of lock sets owned  */
  
  /* Ledgers */
  struct ipc_port	*wired_ledger_port;
  struct ipc_port *paged_ledger_port;
  unsigned int	priv_flags;			/* privilege resource flags */
#define VM_BACKING_STORE_PRIV	0x1
  
  MACHINE_TASK
  
  integer_t faults;              /* faults counter */
  integer_t pageins;             /* pageins counter */
  integer_t cow_faults;          /* copy on write fault counter */
  integer_t messages_sent;       /* messages sent counter */
  integer_t messages_received;   /* messages received counter */
  integer_t syscalls_mach;       /* mach system call counter */
  integer_t syscalls_unix;       /* unix system call counter */
  uint32_t  c_switch;			   /* total context switches */
  uint32_t  p_switch;			   /* total processor switches */
  uint32_t  ps_switch;		   /* total pset switches */
  //#ifdef  MACH_BSD
  uint32_t  pad1;
  uint32_t  pad2;
  
  void *bsd_info;
  //#endif
  struct vm_shared_region		*shared_region;
  uint32_t taskFeatures[2];		/* Special feature for this task */
#define tf64BitAddr	0x80000000		/* Task has 64-bit addressing */
#define tf64BitData	0x40000000		/* Task has 64-bit data registers */
#define task_has_64BitAddr(task)	\
        (((task)->taskFeatures[0] & tf64BitAddr) != 0)
#define task_set_64BitAddr(task)	\
        ((task)->taskFeatures[0] |= tf64BitAddr)
#define task_clear_64BitAddr(task)	\
        ((task)->taskFeatures[0] &= ~tf64BitAddr)
  
  mach_vm_address_t	all_image_info_addr; /* dyld __all_image_info     */
  mach_vm_size_t		all_image_info_size; /* section location and size */
#if CONFIG_MACF_MACH
  ipc_labelh_t label;
#endif
  
  //#if CONFIG_COUNTERS
#define TASK_PMC_FLAG 0x1	/* Bit in "t_chud" signifying PMC interest */
  uint32_t t_chud;		/* CHUD flags, used for Shark */
  //#endif
};

//typedef struct task_sl *task_sl_t;
typedef struct task_l  *task_l_t;